/**
 * Outbound v2 exchange: fresh unique-name resolution, receiver-proof challenge
 * verification before any body or credential leaves this side, phase-aware
 * retry rules, and the pending-request correlation store. Every failure
 * resolves to a protocol result code; nothing throws into the agent turn.
 */

import { createConnection } from 'node:net';
import type { Socket } from 'node:net';

import {
  BODY_MAX_BYTES,
  CHALLENGE_MAX_BYTES,
  HANDSHAKE_TIMEOUT_MS,
  HELLO_MAX_BYTES,
  MAX_HOP,
  MAX_OUTBOUND_SOCKETS,
  MAX_PENDING_REQUESTS,
  MAX_STATUS_FIELDS,
  PEER_NAME_PATTERN,
  PROTOCOL_VERSION,
  RECEIPT_TIMEOUT_MS,
  REPLY_MAX_BYTES,
  REQUEST_MAX_BYTES,
  REQUEST_TIMEOUT_DEFAULT_MS,
  REQUEST_TIMEOUT_MAX_MS,
  REQUEST_TIMEOUT_MIN_MS,
  canonicalRequestPayload,
  canonicalStatus,
  challengeMac,
  encodeLine,
  generateId,
  identityEquals,
  isCanonicalId,
  isRetryableRefusal,
  isSuccessCode,
  isValidPeerName,
  normalizeNameInput,
  parseChallenge,
  parseReply,
  replyMac,
  requestMac,
  verifyMac,
} from './protocol.js';
import type {
  AcceptanceState,
  MsgPayload,
  PeerIdentity,
  PeerRecordV2,
  PingPayload,
  ReplyFrame,
  RequestPayload,
  ResultCode,
  StatusReqPayload,
  StatusSnapshot,
} from './protocol.js';
import { hasDuplicateRoutableNames } from './ids.js';
import { readPeerRecord } from './presence.js';
import type { PeerScan } from './presence.js';
import { peerEndpoint } from '../store/paths.js';
import type { StateRoots } from '../store/paths.js';
import type { ManagedTimers } from './server.js';
import type { PendingRequest } from '../types.js';

export interface OutboundResult {
  code: ResultCode;
  detail?: string;
  replyBody?: string;
  status?: StatusSnapshot;
  target?: PeerIdentity;
}

export interface OutboundDeps {
  identity: { pid: number; instance: string; token: string };
  roots: StateRoots;
  managed: ManagedTimers;
  scan(): Promise<PeerScan>;
  pending: PendingStore;
  acceptance(): AcceptanceState;
  log(text: string): void;
}

export type ResolvedTarget =
  | { kind: 'unique'; record: PeerRecordV2 }
  | { kind: 'missing'; known: string[] }
  | { kind: 'ambiguous'; known: string[] }
  | { kind: 'self' };

interface Slot extends PendingRequest {
  promise: Promise<string>;
  noDispatch: boolean;
}

/** Carries the protocol result code across a rejected pending slot. */
class PendingClosedError extends Error {
  readonly resultCode: ResultCode;

  constructor(code: ResultCode) {
    super(code);
    this.name = 'PendingClosedError';
    this.resultCode = code;
  }
}

function closedCode(err: unknown): ResultCode {
  return err instanceof PendingClosedError ? err.resultCode : 'shutting_down';
}

/** The exact protocol code carried by a rejected reserved slot. */
interface ClosedMark {
  readonly closed: ResultCode;
}

/** Resolves only when the reserved slot is rejected; a reply settle leaves it pending forever. */
function isClosedMark(value: unknown): value is ClosedMark {
  return typeof value === 'object' && value !== null && 'closed' in value;
}

export class PendingStore {
  private readonly slots = new Map<string, Slot>();
  private outboundSockets = 0;

  /** Reserves one of the MAX_OUTBOUND_SOCKETS concurrent exchange slots. */
  acquireSocket(): boolean {
    if (this.outboundSockets >= MAX_OUTBOUND_SOCKETS) return false;
    this.outboundSockets += 1;
    return true;
  }

  /** Releases an exchange slot on every terminal path; never goes negative. */
  releaseSocket(): void {
    if (this.outboundSockets > 0) this.outboundSockets -= 1;
  }

  /**
   * Reserves the slot and returns its reply promise, captured exactly once
   * here: a settle at any later time resolves this same promise, so a reply
   * arriving before the caller observes it is never lost.
   */
  reserve(id: string, expected: PeerIdentity): Promise<string> | undefined {
    if (id === '' || this.slots.size >= MAX_PENDING_REQUESTS || this.slots.has(id)) return undefined;
    let resolveFn!: (body: string) => void;
    let rejectFn!: (err: Error) => void;
    const promise = new Promise<string>((resolve, reject) => {
      resolveFn = resolve;
      rejectFn = reject;
    });
    // Pre-attach a noop handler so an early rejectAll never surfaces as an
    // unhandled rejection while the exchange is still in flight.
    void promise.catch(() => undefined);
    this.slots.set(id, {
      expected: { pid: expected.pid, instance: expected.instance },
      written: false,
      noDispatch: false,
      resolve: resolveFn,
      reject: rejectFn,
      promise,
    });
    return promise;
  }

  /** Called immediately before socket.write of the request line. */
  markWritten(id: string): void {
    const slot = this.slots.get(id);
    if (slot !== undefined) slot.written = true;
  }

  /** Records an authenticated receiver refusal that proves the request never dispatched. */
  noteNoDispatch(id: string): boolean {
    const slot = this.slots.get(id);
    if (slot === undefined || !slot.written) return false;
    slot.noDispatch = true;
    return true;
  }

  retarget(id: string, expected: PeerIdentity): boolean {
    const slot = this.slots.get(id);
    if (slot === undefined) return false;
    if (slot.written && !slot.noDispatch) return false;
    slot.expected = { pid: expected.pid, instance: expected.instance };
    return true;
  }

  settle(from: PeerIdentity, replyTo: string, body: string): boolean {
    const slot = this.slots.get(replyTo);
    if (slot === undefined || !identityEquals(slot.expected, from)) return false;
    this.slots.delete(replyTo);
    slot.resolve(body);
    return true;
  }

  discard(id: string, code: ResultCode): void {
    const slot = this.slots.get(id);
    if (slot === undefined) return;
    this.slots.delete(id);
    slot.reject(new PendingClosedError(code));
  }

  rejectAll(code: ResultCode): void {
    for (const [id, slot] of this.slots) {
      this.slots.delete(id);
      slot.reject(new PendingClosedError(code));
    }
  }

  size(): number {
    return this.slots.size;
  }
}

const DETAIL_MAX_BYTES = 512;

function clampBytes(value: string, max: number): string {
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length <= max) return value;
  let end = max;
  while (end > 0) {
    const byte = bytes[end];
    if (byte === undefined || (byte & 0xc0) !== 0x80) break;
    end -= 1;
  }
  return bytes.subarray(0, end).toString('utf8');
}

/** Bounded sanitized text: control characters collapsed, UTF-8 clamped. */
function cleanText(value: string, max: number): string | undefined {
  let stripped = '';
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    stripped += code <= 0x1f || (code >= 0x7f && code <= 0x9f) ? ' ' : char;
  }
  stripped = stripped.trim();
  if (stripped === '') return undefined;
  return clampBytes(stripped, max);
}

function errorMessage(err: unknown): string {
  const text = err instanceof Error ? err.message : String(err);
  return cleanText(text, 200) ?? 'local failure';
}

function identityOf(record: PeerRecordV2): PeerIdentity {
  return { pid: record.pid, instance: record.instance };
}

function acceptanceState(deps: OutboundDeps): AcceptanceState {
  try {
    return deps.acceptance();
  } catch {
    return 'shutting_down';
  }
}

function safeLog(deps: OutboundDeps, text: string): void {
  try {
    deps.log(text);
  } catch {
    // Logging is best-effort.
  }
}

export async function resolveTarget(deps: OutboundDeps, to: string): Promise<ResolvedTarget> {
  const name = normalizeNameInput(to ?? '');
  let scan: PeerScan;
  try {
    scan = await deps.scan();
  } catch (err) {
    safeLog(deps, `peer scan failed: ${errorMessage(err)}`);
    scan = { routable: [], incompatible: [] };
  }
  const routable = Array.isArray(scan.routable) ? scan.routable : [];
  const self: PeerIdentity = { pid: deps.identity.pid, instance: deps.identity.instance };
  const known = [
    ...new Set(routable.filter((record) => !identityEquals(record, self)).map((record) => record.name)),
  ].sort();
  if (name === '' || !PEER_NAME_PATTERN.test(name) || !isValidPeerName(name)) {
    return { kind: 'missing', known };
  }
  const matches = routable.filter((record) => record.name === name);
  if (matches.some((record) => identityEquals(record, self))) return { kind: 'self' };
  if (matches.length === 0) {
    let own: PeerRecordV2 | undefined;
    try {
      own = await readPeerRecord(deps.roots, self.pid, self.instance);
    } catch {
      own = undefined;
    }
    if (own !== undefined && own.name === name) return { kind: 'self' };
    return { kind: 'missing', known };
  }
  // A fresh scan that still carries duplicate routable names is ambiguous:
  // never choose the first record.
  if (matches.length > 1 || hasDuplicateRoutableNames(routable)) return { kind: 'ambiguous', known };
  const only = matches[0];
  if (only === undefined) return { kind: 'ambiguous', known };
  return { kind: 'unique', record: only };
}

interface AttemptReport {
  code: ResultCode;
  detail?: string;
  written: boolean;
  authenticated: boolean;
  target?: PeerIdentity;
  reply?: ReplyFrame;
}

function resolutionReport(resolved: Exclude<ResolvedTarget, { kind: 'unique' }>): AttemptReport {
  if (resolved.kind === 'self') return { code: 'self_address', written: false, authenticated: false };
  const detail = resolved.known.length === 0 ? 'live: none' : `live: ${resolved.known.join(', ')}`;
  if (resolved.kind === 'missing') {
    return { code: 'not_found', detail, written: false, authenticated: false };
  }
  return { code: 'ambiguous_target', detail, written: false, authenticated: false };
}

function reportResult(report: AttemptReport): OutboundResult {
  const result: OutboundResult = { code: report.code };
  const detail = report.detail === undefined ? undefined : cleanText(report.detail, DETAIL_MAX_BYTES);
  if (detail !== undefined) result.detail = detail;
  if (report.target !== undefined) result.target = report.target;
  if (report.reply !== undefined && report.reply.status !== undefined) result.status = report.reply.status;
  return result;
}

/** Pre-write transport failures only; never post-write, oversized, or resolution failures. */
const PREWRITE_RETRYABLE: Record<string, true> = {
  connect_timeout: true,
  handshake_timeout: true,
  closed_before_reply: true,
  malformed_reply: true,
  receiver_auth_failed: true,
};

function mayRetry(report: AttemptReport): boolean {
  if (report.reply !== undefined) return report.authenticated && isRetryableRefusal(report.code);
  return report.written !== true && PREWRITE_RETRYABLE[report.code] === true;
}

const STATUS_FIELD_NAMES: Record<string, true> = { busy: true, model: true, activity: true, todos: true };

interface AttemptOptions {
  endpoint: string;
  record: PeerRecordV2;
  sender: { pid: number; instance: string; token: string };
  id: string;
  payload: RequestPayload;
  deadline: number;
  /** Absolute budget expiry: unfinished sockets are destroyed at this instant. */
  budgetDeadline?: number;
  /** Reserved-slot close signal: resolves with its exact code to abort this attempt. */
  closed?: Promise<ClosedMark>;
  acceptance: () => AcceptanceState;
  managed: ManagedTimers;
  onWrite: () => void;
}

/** One bounded hello -> challenge -> request -> reply exchange. Never rejects. */
function runAttempt(opts: AttemptOptions): Promise<AttemptReport> {
  return new Promise<AttemptReport>((resolvePromise) => {
    const self: PeerIdentity = { pid: opts.sender.pid, instance: opts.sender.instance };
    const target: PeerIdentity = identityOf(opts.record);
    const id = opts.id;
    const clientNonce = generateId();
    let socket: Socket | undefined;
    let phase: 'connect' | 'handshake' | 'written' = 'connect';
    let settled = false;
    let buffer: Buffer = Buffer.alloc(0);

    let phaseTimer: unknown;
    let phaseTimerArmed = false;

    function clearPhaseTimer(): void {
      if (!phaseTimerArmed) return;
      phaseTimerArmed = false;
      try {
        opts.managed.clearTimer(phaseTimer);
      } catch {
        // Timer already fired or was cleared.
      }
    }

    function finish(report: AttemptReport): void {
      if (settled) return;
      settled = true;
      clearPhaseTimer();
      try {
        socket?.destroy();
      } catch {
        // Already gone.
      }
      resolvePromise(report);
    }

    function preReport(code: ResultCode): AttemptReport {
      return { code, written: false, authenticated: false, target };
    }

    function failByPhase(preCode: ResultCode): void {
      if (phase === 'written') {
        finish({ code: 'unknown_outcome', detail: 'receipt_timeout', written: true, authenticated: false, target });
      } else {
        finish(preReport(preCode));
      }
    }

    function guard(preCode: ResultCode, body: () => void): void {
      try {
        body();
      } catch {
        failByPhase(preCode);
      }
    }

    /** Phase timeout or absolute-deadline expiry, mapped by the phase reached. */
    function phaseReport(): AttemptReport {
      if (phase === 'connect') return { code: 'connect_timeout', written: false, authenticated: false, target };
      if (phase === 'written') {
        return { code: 'unknown_outcome', detail: 'receipt_timeout', written: true, authenticated: false, target };
      }
      return { code: 'handshake_timeout', written: false, authenticated: false, target };
    }

    /** The absolute deadline passed at the current phase; never extended by trickled bytes. */
    function deadlineReport(): AttemptReport {
      if (opts.budgetDeadline !== undefined && Date.now() >= opts.budgetDeadline) {
        // Budget expiry: never connected is connect_timeout; any connected but
        // unfinished socket is destroyed and reported closed_before_reply.
        return {
          code: phase === 'connect' ? 'connect_timeout' : 'closed_before_reply',
          detail: 'status budget expired',
          written: phase === 'written',
          authenticated: false,
          target,
        };
      }
      return phaseReport();
    }

    function armPhase(dueAt: number, kind: 'deadline' | 'phase'): void {
      clearPhaseTimer();
      try {
        phaseTimer = opts.managed.setTimeout(() => {
          phaseTimerArmed = false;
          finish(kind === 'deadline' ? deadlineReport() : phaseReport());
        }, Math.max(0, dueAt - Date.now()));
        phaseTimerArmed = true;
      } catch {
        finish(kind === 'deadline' ? deadlineReport() : phaseReport());
      }
    }

    function sendRequest(serverNonce: string): void {
      if (settled) return;
      const sentAt = Date.now();
      const auth = requestMac(
        opts.sender.token,
        id,
        clientNonce,
        serverNonce,
        sentAt,
        self,
        target,
        canonicalRequestPayload(opts.payload)
      );
      const line = encodeLine({
        v: PROTOCOL_VERSION,
        type: 'request',
        id,
        clientNonce,
        serverNonce,
        sentAt,
        from: self,
        to: target,
        payload: opts.payload,
        auth,
      });
      if (Buffer.byteLength(line) > REQUEST_MAX_BYTES) {
        failByPhase('oversized');
        return;
      }
      const writeState = opts.acceptance();
      if (writeState !== 'accepting') {
        finish(preReport(writeState));
        return;
      }
      if (opts.deadline <= Date.now()) {
        finish(deadlineReport());
        return;
      }
      phase = 'written';
      armPhase(
        Math.min(Date.now() + RECEIPT_TIMEOUT_MS, opts.deadline),
        opts.deadline <= Date.now() + RECEIPT_TIMEOUT_MS ? 'deadline' : 'phase'
      );
      opts.onWrite();
      try {
        socket?.write(line, (err) => {
          if (err) failByPhase('closed_before_reply');
        });
      } catch {
        failByPhase('closed_before_reply');
      }
    }

    function onChallengeLine(line: string): void {
      const challenge = parseChallenge(line);
      if (challenge === undefined || challenge.id !== id || challenge.clientNonce !== clientNonce) {
        failByPhase('malformed_reply');
        return;
      }
      if (!identityEquals(challenge.from, target)) {
        failByPhase('receiver_auth_failed');
        return;
      }
      const expected = challengeMac(opts.record.token, id, challenge.from, clientNonce, challenge.serverNonce);
      if (!verifyMac(expected, challenge.auth)) {
        failByPhase('receiver_auth_failed');
        return;
      }
      sendRequest(challenge.serverNonce);
    }

    function onReplyLine(line: string): void {
      const reply = parseReply(line);
      if (reply === undefined || reply.id !== id || !identityEquals(reply.from, target)) {
        failByPhase('malformed_reply');
        return;
      }
      const expected = replyMac(
        opts.record.token,
        id,
        reply.from,
        reply.code,
        reply.detail ?? null,
        canonicalStatus(reply.status)
      );
      if (!verifyMac(expected, reply.auth)) {
        failByPhase('malformed_reply');
        return;
      }
      const report: AttemptReport = { code: reply.code, written: true, authenticated: true, target, reply };
      if (reply.detail !== undefined) report.detail = reply.detail;
      finish(report);
    }

    function onData(chunk: Buffer): void {
      if (settled) return;
      const limit = phase === 'written' ? REPLY_MAX_BYTES : CHALLENGE_MAX_BYTES;
      buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) {
        if (buffer.length > limit) failByPhase('malformed_reply');
        return;
      }
      if (newline > limit) {
        failByPhase('malformed_reply');
        return;
      }
      const line = buffer.subarray(0, newline).toString('utf8');
      buffer = buffer.subarray(newline + 1);
      if (phase === 'written') {
        onReplyLine(line);
        return;
      }
      if (buffer.length > 0) {
        failByPhase('malformed_reply');
        return;
      }
      onChallengeLine(line);
    }

    // A rejected reserved slot (epoch commit or shutdown) aborts the whole
    // exchange with its exact code: destroy the in-flight socket now instead
    // of letting the receipt phase expire into unknown_outcome.
    opts.closed?.then((mark) => {
      finish({ code: mark.closed, written: false, authenticated: false, target });
    });

    // Preflight before dialing: an oversized request never reaches the wire.
    if (opts.payload.type === 'msg' && Buffer.byteLength(opts.payload.body) > BODY_MAX_BYTES) {
      finish(preReport('oversized'));
      return;
    }
    const hello = encodeLine({ v: PROTOCOL_VERSION, type: 'hello', id, to: target, clientNonce });
    const dry = encodeLine({
      v: PROTOCOL_VERSION,
      type: 'request',
      id,
      clientNonce,
      serverNonce: '0'.repeat(22),
      sentAt: Date.now(),
      from: self,
      to: target,
      payload: opts.payload,
      auth: '0'.repeat(64),
    });
    if (Buffer.byteLength(hello) > HELLO_MAX_BYTES || Buffer.byteLength(dry) > REQUEST_MAX_BYTES) {
      finish(preReport('oversized'));
      return;
    }
    const dialState = opts.acceptance();
    if (dialState !== 'accepting') {
      finish(preReport(dialState));
      return;
    }
    if (opts.deadline <= Date.now()) {
      finish(deadlineReport());
      return;
    }
    try {
      socket = createConnection(opts.endpoint);
    } catch {
      finish(preReport('connect_timeout'));
      return;
    }
    armPhase(
      Math.min(Date.now() + HANDSHAKE_TIMEOUT_MS, opts.deadline),
      opts.deadline <= Date.now() + HANDSHAKE_TIMEOUT_MS ? 'deadline' : 'phase'
    );
    socket.on('error', () => failByPhase(phase === 'connect' ? 'connect_timeout' : 'closed_before_reply'));
    socket.on('close', () => failByPhase(phase === 'connect' ? 'connect_timeout' : 'closed_before_reply'));
    socket.on('connect', () =>
      guard('closed_before_reply', () => {
        phase = 'handshake';
        const helloState = opts.acceptance();
        if (helloState !== 'accepting') {
          finish(preReport(helloState));
          return;
        }
        if (opts.deadline <= Date.now()) {
          finish(deadlineReport());
          return;
        }
        socket?.write(hello);
      })
    );
    socket.on('data', (chunk: Buffer) => guard('malformed_reply', () => onData(chunk)));
  });
}

async function attemptExchange(
  deps: OutboundDeps,
  record: PeerRecordV2,
  payload: RequestPayload,
  id: string,
  deadline: number,
  pendingId?: string,
  budgetDeadline?: number,
  closed?: Promise<ClosedMark>
): Promise<AttemptReport> {
  const target = identityOf(record);
  let endpoint: string;
  try {
    endpoint = peerEndpoint(deps.roots, record.pid, record.instance);
  } catch (err) {
    safeLog(deps, `peer endpoint failed: ${errorMessage(err)}`);
    return { code: 'connect_timeout', target, written: false, authenticated: false };
  }
  if (!deps.pending.acquireSocket()) {
    return {
      code: 'busy',
      detail: `outbound socket limit ${MAX_OUTBOUND_SOCKETS}`,
      target,
      written: false,
      authenticated: false,
    };
  }
  try {
    return await runAttempt({
      endpoint,
      record,
      sender: deps.identity,
      id,
      payload,
      deadline,
      budgetDeadline,
      closed,
      acceptance: () => acceptanceState(deps),
      managed: deps.managed,
      onWrite: () => {
        if (pendingId !== undefined) deps.pending.markWritten(pendingId);
      },
    });
  } catch (err) {
    safeLog(deps, `peer exchange failed: ${errorMessage(err)}`);
    return { code: 'invalid_request', detail: errorMessage(err), target, written: false, authenticated: false };
  } finally {
    deps.pending.releaseSocket();
  }
}

interface OperationOptions {
  pendingId?: string;
  budgetDeadline?: number;
  /** Receives the reserved slot's reply promise at reserve time. */
  onReserved?: (promise: Promise<string>) => void;
}

/**
 * Resolve, exchange, and apply the retry contract: exactly one retry, only
 * for a pre-write failure or an authenticated retryable refusal, only when a
 * fresh scan uniquely resolves the requested name to a different identity.
 * The correlation id, payload, and semantic deadline are never reset.
 */
async function performOperation(
  deps: OutboundDeps,
  to: string,
  payload: RequestPayload,
  deadline: number,
  opts: OperationOptions = {}
): Promise<AttemptReport> {
  const resolved = await resolveTarget(deps, to);
  if (resolved.kind !== 'unique') return resolutionReport(resolved);
  let record = resolved.record;
  // Close signal for the reserved slot: resolves with the exact rejection
  // code (epoch commit or shutdown) and stays pending on a normal reply
  // settle, so racing it concludes the operation at the rejection itself.
  let closed: Promise<ClosedMark> | undefined;
  if (opts.pendingId !== undefined) {
    const state = acceptanceState(deps);
    if (state !== 'accepting') return { code: state, written: false, authenticated: false };
    const promise = deps.pending.reserve(opts.pendingId, identityOf(record));
    if (promise === undefined) {
      return {
        code: 'busy',
        detail: `pending limit ${MAX_PENDING_REQUESTS}`,
        written: false,
        authenticated: false,
      };
    }
    closed = new Promise<ClosedMark>((mark) => {
      promise.then(
        () => undefined,
        (err) => mark({ closed: closedCode(err) })
      );
    });
    opts.onReserved?.(promise);
  }
  const id = opts.pendingId ?? generateId();
  for (let tries = 0; ; tries += 1) {
    const report = await attemptExchange(
      deps,
      record,
      payload,
      id,
      deadline,
      opts.pendingId,
      opts.budgetDeadline,
      closed
    );
    if (tries >= 1) return report;
    if (!mayRetry(report)) return report;
    if (report.target === undefined) return report;
    if (Date.now() >= deadline) return report;
    if (acceptanceState(deps) !== 'accepting') return report;
    const fresh =
      closed === undefined ? await resolveTarget(deps, to) : await Promise.race([resolveTarget(deps, to), closed]);
    if (isClosedMark(fresh)) return { code: fresh.closed, written: false, authenticated: false };
    if (fresh.kind !== 'unique') return report;
    if (acceptanceState(deps) !== 'accepting') return report;
    if (identityEquals(identityOf(fresh.record), report.target)) return report;
    if (opts.pendingId !== undefined) {
      if (report.written) deps.pending.noteNoDispatch(opts.pendingId);
      if (!deps.pending.retarget(opts.pendingId, identityOf(fresh.record))) return report;
    }
    safeLog(deps, `retrying ${to} against a different live identity`);
    record = fresh.record;
  }
}

function validateAddress(to: string): { name: string } | OutboundResult {
  const name = normalizeNameInput(to ?? '');
  if (name === '' || !PEER_NAME_PATTERN.test(name)) return { code: 'invalid_request', detail: 'invalid name' };
  if (!isValidPeerName(name)) return { code: 'invalid_request', detail: 'reserved name' };
  return { name };
}

function isAddressResult(value: { name: string } | OutboundResult): value is OutboundResult {
  return (value as OutboundResult).code !== undefined;
}

function validateBody(body: string): OutboundResult | undefined {
  if (typeof body !== 'string' || body === '') return { code: 'invalid_request', detail: 'missing body' };
  if (Buffer.byteLength(body) > BODY_MAX_BYTES) return { code: 'oversized' };
  return undefined;
}

function exchangeDeadline(): number {
  return Date.now() + 2 * (HANDSHAKE_TIMEOUT_MS + RECEIPT_TIMEOUT_MS);
}

function caughtResult(deps: OutboundDeps, err: unknown): OutboundResult {
  safeLog(deps, `peer operation failed: ${errorMessage(err)}`);
  return { code: 'invalid_request', detail: errorMessage(err) };
}

export async function sendMsg(
  deps: OutboundDeps,
  to: string,
  body: string,
  opts: { replyTo?: string; hop?: number } = {}
): Promise<OutboundResult> {
  try {
    const state = acceptanceState(deps);
    if (state !== 'accepting') return { code: state };
    const address = validateAddress(to);
    if (isAddressResult(address)) return address;
    const bodyError = validateBody(body);
    if (bodyError !== undefined) return bodyError;
    const hop = opts.hop ?? 0;
    if (!Number.isInteger(hop) || hop < 0 || hop > MAX_HOP) {
      return { code: 'invalid_request', detail: 'invalid hop' };
    }
    if (opts.replyTo !== undefined && !isCanonicalId(opts.replyTo)) {
      return { code: 'invalid_request', detail: 'invalid replyTo' };
    }
    const payload: MsgPayload =
      opts.replyTo !== undefined ? { type: 'msg', body, hop, replyTo: opts.replyTo } : { type: 'msg', body, hop };
    const report = await performOperation(deps, address.name, payload, exchangeDeadline());
    const afterState = acceptanceState(deps);
    if (afterState !== 'accepting') return { code: afterState };
    return reportResult(report);
  } catch (err) {
    return caughtResult(deps, err);
  }
}

export async function requestMsg(
  deps: OutboundDeps,
  to: string,
  body: string,
  opts: { timeoutMs?: number; hop?: number } = {}
): Promise<OutboundResult> {
  const requested = opts.timeoutMs;
  let timeoutMs = REQUEST_TIMEOUT_DEFAULT_MS;
  if (typeof requested === 'number' && Number.isFinite(requested) && requested > 0) {
    timeoutMs = Math.min(REQUEST_TIMEOUT_MAX_MS, Math.max(REQUEST_TIMEOUT_MIN_MS, Math.trunc(requested)));
  }
  const deadline = Date.now() + timeoutMs;
  const id = generateId();
  let report: AttemptReport;
  let replyPromise: Promise<string> | undefined;
  try {
    const state = acceptanceState(deps);
    if (state !== 'accepting') return { code: state };
    const address = validateAddress(to);
    if (isAddressResult(address)) return address;
    const bodyError = validateBody(body);
    if (bodyError !== undefined) return bodyError;
    const hop = opts.hop ?? 0;
    if (!Number.isSafeInteger(hop) || hop < 0) {
      return { code: 'invalid_request', detail: 'invalid hop' };
    }
    if (hop > MAX_HOP) {
      return { code: 'invalid_request', detail: `hop ${hop} exceeds limit ${MAX_HOP}` };
    }
    const payload: MsgPayload = { type: 'msg', body, hop };
    report = await performOperation(deps, address.name, payload, deadline, {
      pendingId: id,
      onReserved: (promise) => {
        replyPromise = promise;
      },
    });
    const afterState = acceptanceState(deps);
    if (afterState !== 'accepting') {
      deps.pending.discard(id, afterState);
      return { code: afterState };
    }
  } catch (err) {
    deps.pending.discard(id, 'invalid_request');
    return caughtResult(deps, err);
  }
  const result = reportResult(report);
  if (!isSuccessCode(report.code)) {
    deps.pending.discard(id, report.code);
    return result;
  }
  if (replyPromise === undefined) {
    deps.pending.discard(id, 'unknown_outcome');
    const out: OutboundResult = { code: 'unknown_outcome' };
    if (report.target !== undefined) out.target = report.target;
    return out;
  }
  // Accepted by the receiver's host: wait out the semantic deadline for the
  // reply promise captured at reserve time. A late or foreign reply resolves
  // nothing once this wait expires.
  const settled = await waitForReply(deps, replyPromise, deadline);
  const finalState = acceptanceState(deps);
  if (finalState !== 'accepting') {
    deps.pending.discard(id, finalState);
    return { code: finalState };
  }
  if (settled.kind === 'reply') {
    const out: OutboundResult = { code: 'reply_consumed', replyBody: settled.body };
    if (report.target !== undefined) out.target = report.target;
    return out;
  }
  if (settled.kind === 'rejected') {
    const out: OutboundResult = { code: settled.code };
    if (report.target !== undefined) out.target = report.target;
    return out;
  }
  // Only the reply wait expired: the verified transport receipt stands.
  deps.pending.discard(id, report.code);
  const out: OutboundResult = {
    code: report.code,
    detail: `${report.code}, no reply within ${timeoutMs}ms; a late reply may still arrive as a peer message`,
  };
  if (report.target !== undefined) out.target = report.target;
  return out;
}

export async function statusOf(
  deps: OutboundDeps,
  to: string,
  fields: string[],
  budget?: { deadlineAt: number }
): Promise<OutboundResult> {
  try {
    const state = acceptanceState(deps);
    if (state !== 'accepting') return { code: state };
    const address = validateAddress(to);
    if (isAddressResult(address)) return address;
    const requested = (Array.isArray(fields) ? fields : [])
      .filter((field) => STATUS_FIELD_NAMES[field] === true)
      .slice(0, MAX_STATUS_FIELDS);
    const payload: StatusReqPayload =
      requested.length > 0 ? { type: 'status', fields: requested } : { type: 'status' };
    let budgetDeadline: number | undefined;
    if (budget !== undefined) {
      if (!Number.isFinite(budget.deadlineAt)) {
        return { code: 'invalid_request', detail: 'invalid budget deadline' };
      }
      budgetDeadline = Math.trunc(budget.deadlineAt);
    }
    const deadline =
      budgetDeadline === undefined ? exchangeDeadline() : Math.min(exchangeDeadline(), budgetDeadline);
    const report = await performOperation(deps, address.name, payload, deadline, { budgetDeadline });
    const afterState = acceptanceState(deps);
    if (afterState !== 'accepting') return { code: afterState };
    return reportResult(report);
  } catch (err) {
    return caughtResult(deps, err);
  }
}

export async function pingPeer(deps: OutboundDeps, to: string): Promise<OutboundResult> {
  try {
    const state = acceptanceState(deps);
    if (state !== 'accepting') return { code: state };
    const address = validateAddress(to);
    if (isAddressResult(address)) return address;
    const payload: PingPayload = { type: 'ping' };
    const report = await performOperation(deps, address.name, payload, exchangeDeadline());
    const afterState = acceptanceState(deps);
    if (afterState !== 'accepting') return { code: afterState };
    return reportResult(report);
  } catch (err) {
    return caughtResult(deps, err);
  }
}

type SettleOutcome =
  | { kind: 'reply'; body: string }
  | { kind: 'rejected'; code: ResultCode }
  | { kind: 'timeout' };

function waitForReply(deps: OutboundDeps, reply: Promise<string>, deadline: number): Promise<SettleOutcome> {
  return new Promise<SettleOutcome>((resolveOutcome) => {
    let done = false;
    let timer: unknown;
    const finish = (outcome: SettleOutcome): void => {
      if (done) return;
      done = true;
      if (timer !== undefined) {
        try {
          deps.managed.clearTimer(timer);
        } catch {
          // Timer already fired or was cleared.
        }
      }
      resolveOutcome(outcome);
    };
    reply.then(
      (body) => finish({ kind: 'reply', body }),
      (err) => finish({ kind: 'rejected', code: closedCode(err) })
    );
    try {
      timer = deps.managed.setTimeout(() => finish({ kind: 'timeout' }), Math.max(0, deadline - Date.now()));
    } catch {
      finish({ kind: 'timeout' });
      return;
    }
    if (done && timer !== undefined) {
      try {
        deps.managed.clearTimer(timer);
      } catch {
        // Nothing to clear.
      }
    }
  });
}
