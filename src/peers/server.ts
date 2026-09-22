/**
 * Protocol v2 receiver: one bounded hello -> challenge -> request exchange per
 * connection with receiver proof before body disclosure, an exhaustive
 * one-request router, per-sender FIFO batching, and held retention/pump.
 * Never throws into the host and never waits for EOF (Bun 1.3.14 Windows
 * pipes do not support the required half-close).
 */

import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';

import type { StateRoots } from '../store/paths.js';
import {
  CHALLENGE_MAX_BYTES,
  COALESCE_MS,
  DRAIN_GRACE_MS,
  HANDSHAKE_TIMEOUT_MS,
  HELLO_MAX_BYTES,
  HOLD_TIMEOUT_MS,
  MAX_BATCH_BYTES,
  MAX_BATCH_MESSAGES,
  MAX_BATCHES_PER_SENDER,
  MAX_INBOUND_SOCKETS,
  MAX_SENDER_QUEUES,
  PROTOCOL_VERSION,
  REPLY_MAX_BYTES,
  REQUEST_MAX_BYTES,
  ReplayCache,
  canonicalRequestPayload,
  canonicalStatus,
  challengeMac,
  encodeLine,
  generateId,
  identityEquals,
  identityKey,
  isCanonicalId,
  isFreshTimestamp,
  parseHello,
  parseRequest,
  replyMac,
  requestMac,
  verifyMac,
} from './protocol.js';
import type {
  AcceptanceState,
  HelloFrame,
  MsgPayload,
  PeerIdentity,
  ReplyFrame,
  RequestFrame,
  ResultCode,
  StatusSnapshot,
} from './protocol.js';
import { formatPeerText } from './inbound.js';
import { readPeerRecord } from './presence.js';

export interface EpochSnapshot {
  binding: number;
  transcript: number;
}

export interface AuthenticatedEnvelope {
  id: string;
  from: PeerIdentity;
  to: PeerIdentity;
  sentAt: number;
  hop: number;
  body: string;
  replyTo?: string;
  epoch: EpochSnapshot;
}

export interface ManagedTimers {
  setInterval: Function;
  setTimeout: Function;
  clearTimer: Function;
}

export interface HostDelivery {
  captureEpoch(): EpochSnapshot;
  isEpochValid(captured: EpochSnapshot): boolean;
  submitBatch(envelopes: AuthenticatedEnvelope[]): Promise<{ code: ResultCode; detail?: string }>;
  canSubmitNow(): boolean;
  /** Pre-dispatch admission: undefined to proceed, else the exact refusal code with bounded detail.
   *  Subsumes acceptance(): closed => shutting_down, transitionPending => session_transition, and
   *  not-yet-armed (before record publication) => host_unavailable with the shared diagnostic. */
  admissionCode(): { code: ResultCode; detail?: string } | undefined;
  reserveHeld(): boolean;
  releaseHeld(): void;
  statusSnapshot(fields: string[] | undefined): StatusSnapshot;
  consumeReply(from: PeerIdentity, replyTo: string, body: string): boolean;
  acceptance(): AcceptanceState;
}

export interface ServerHandle {
  endpoint: string;
  ready: Promise<'listening'>;
  /** Commit purge: settle each stale waiting socket once with session_transition,
   *  drop its frames, and silently drop stale retained held copies. */
  purgeStaleWork(isStale: (captured: EpochSnapshot) => boolean): void;
  close(): Promise<void>;
}

interface Conn {
  socket: Socket;
  phase: 'hello' | 'request';
  buffer: string;
  hello: HelloFrame | undefined;
  serverNonce: string | undefined;
  replyId: string | undefined;
  epoch: EpochSnapshot | undefined;
  requestAccepted: boolean;
  owed: boolean;
  replied: boolean;
  handshakeTimer: unknown;
  graceTimer: unknown;
}

interface SenderQueue {
  key: string;
  collecting: Array<{ conn: Conn; envelope: AuthenticatedEnvelope }>;
  collectingBytes: number;
  coalesceTimer: unknown;
  batches: Batch[];
}

interface Batch {
  queue: SenderQueue;
  envelopes: AuthenticatedEnvelope[];
  /** Sockets awaiting one terminal result; undefined once settled or held. */
  waiters: Conn[] | undefined;
  reserved: boolean;
  force: boolean;
  timer: unknown;
}

export function startPeerServer(opts: {
  endpoint: string;
  roots: StateRoots;
  identity: { pid: number; instance: string; token: string };
  delivery: HostDelivery;
  managed: ManagedTimers;
  log: (text: string) => void;
}): ServerHandle {
  const { endpoint, roots, identity, delivery, managed, log } = opts;
  const self: PeerIdentity = { pid: identity.pid, instance: identity.instance };
  const replay = new ReplayCache();
  const sockets = new Set<Conn>();
  const senderQueues = new Map<string, SenderQueue>();
  const heldFifo: Batch[] = [];
  let closing = false;
  let listening = false;
  let pumpTimer: unknown;
  let pumping = false;
  let closePromise: Promise<void> | undefined;

  function warn(text: string): void {
    try {
      log(text);
    } catch {
      // Warning delivery is best-effort.
    }
  }

  function boundText(raw: string): string {
    let out = '';
    for (const ch of raw) {
      const cp = ch.codePointAt(0) ?? 0;
      const drop =
        cp < 0x20 ||
        (cp >= 0x7f && cp <= 0x9f) ||
        (cp >= 0x202a && cp <= 0x202e) ||
        (cp >= 0x2066 && cp <= 0x2069);
      if (drop) continue;
      if (Buffer.byteLength(out + ch, 'utf8') > 160) break;
      out += ch;
    }
    return out;
  }

  function later(fn: () => void, ms: number): unknown {
    try {
      return managed.setTimeout(fn, ms);
    } catch {
      return undefined;
    }
  }

  function every(fn: () => void, ms: number): unknown {
    try {
      return managed.setInterval(fn, ms);
    } catch {
      return undefined;
    }
  }

  function clearManaged(handle: unknown): void {
    if (handle === undefined) return;
    try {
      managed.clearTimer(handle);
    } catch {
      // Clearing is best-effort.
    }
  }

  function acceptanceState(): AcceptanceState {
    try {
      return delivery.acceptance();
    } catch {
      return 'shutting_down';
    }
  }

  function canSubmitNow(): boolean {
    try {
      return delivery.canSubmitNow();
    } catch {
      return false;
    }
  }

  function staleEpoch(captured: EpochSnapshot): boolean {
    try {
      return !delivery.isEpochValid(captured);
    } catch {
      return true;
    }
  }

  function refusal(): ResultCode {
    const state = acceptanceState();
    return state === 'accepting' ? 'shutting_down' : state;
  }

  function destroySocket(socket: Socket): void {
    if (socket.destroyed) return;
    try {
      socket.destroy();
    } catch {
      // Destroy is best-effort.
    }
  }

  function rawObject(line: string): Record<string, unknown> | undefined {
    try {
      const value = JSON.parse(line) as unknown;
      if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
      return value as Record<string, unknown>;
    } catch {
      return undefined;
    }
  }

  function replyLine(id: string, code: ResultCode, detail: string | undefined, status: StatusSnapshot | undefined): string {
    const attempt = (d: string | undefined, s: StatusSnapshot | undefined): string => {
      const reply: ReplyFrame = {
        v: PROTOCOL_VERSION,
        type: 'reply',
        id,
        from: self,
        code,
        auth: replyMac(identity.token, id, self, code, d ?? null, canonicalStatus(s)),
      };
      if (d !== undefined) reply.detail = d;
      if (s !== undefined) reply.status = s;
      return encodeLine(reply);
    };
    const bounded = detail !== undefined ? boundText(detail) : undefined;
    const fits = (line: string): boolean => Buffer.byteLength(line, 'utf8') <= REPLY_MAX_BYTES;
    let line = attempt(bounded, status);
    if (fits(line)) return line;
    if (bounded !== undefined) {
      line = attempt(undefined, status);
      if (fits(line)) return line;
    }
    if (status !== undefined && status.todos !== undefined) {
      const slim: StatusSnapshot = { busy: status.busy };
      if (status.model !== undefined) slim.model = status.model;
      if (status.activity !== undefined) slim.activity = status.activity;
      line = attempt(undefined, slim);
      if (fits(line)) return line;
    }
    if (status !== undefined && (status.model !== undefined || status.activity !== undefined)) {
      line = attempt(undefined, { busy: status.busy });
      if (fits(line)) return line;
    }
    return attempt(undefined, undefined);
  }

  function terminal(conn: Conn, code: ResultCode, opts?: { detail?: string; status?: StatusSnapshot }): void {
    if (conn.replied) return;
    conn.replied = true;
    clearManaged(conn.handshakeTimer);
    conn.handshakeTimer = undefined;
    // Stop reads: exactly one terminal reply, parsing finished.
    try {
      conn.socket.pause();
    } catch {
      // Pausing is best-effort.
    }
    if (conn.socket.destroyed) {
      destroySocket(conn.socket);
      return;
    }
    // An unparseable first line leaves no correlated id; refuse with a fresh
    // canonical id rather than destroying silently (unknown frames are
    // protocol errors: never success or silent drop).
    const id = conn.replyId ?? generateId();
    const line = replyLine(id, code, opts?.detail, opts?.status);
    try {
      conn.graceTimer = later(() => {
        conn.graceTimer = undefined;
        destroySocket(conn.socket);
      }, DRAIN_GRACE_MS);
      conn.socket.write(line, () => {
        try {
          conn.socket.end();
        } catch {
          // Ending is best-effort.
        }
      });
    } catch {
      clearManaged(conn.graceTimer);
      conn.graceTimer = undefined;
      destroySocket(conn.socket);
    }
  }

  function settleBatch(batch: Batch, code: ResultCode, opts?: { detail?: string }): void {
    const waiters = batch.waiters;
    if (waiters === undefined) return;
    batch.waiters = undefined;
    for (const conn of waiters) terminal(conn, code, opts);
  }

  function deleteQueueIfIdle(queue: SenderQueue): void {
    if (queue.collecting.length > 0 || queue.batches.length > 0) return;
    clearManaged(queue.coalesceTimer);
    queue.coalesceTimer = undefined;
    senderQueues.delete(queue.key);
  }

  function removeFromQueue(batch: Batch): void {
    const queue = batch.queue;
    const idx = queue.batches.indexOf(batch);
    if (idx === -1) return;
    queue.batches.splice(idx, 1);
    deleteQueueIfIdle(queue);
  }

  function releaseReservation(batch: Batch): void {
    if (!batch.reserved) return;
    batch.reserved = false;
    try {
      delivery.releaseHeld();
    } catch {
      // Releasing is best-effort.
    }
  }

  function finishHeld(batch: Batch): void {
    clearManaged(batch.timer);
    batch.timer = undefined;
    const idx = heldFifo.indexOf(batch);
    if (idx !== -1) heldFifo.splice(idx, 1);
    releaseReservation(batch);
    removeFromQueue(batch);
  }

  function armHold(batch: Batch): void {
    clearManaged(batch.timer);
    batch.timer = later(() => {
      batch.timer = undefined;
      batch.force = true;
      void pumpHeld();
    }, HOLD_TIMEOUT_MS);
  }

  function ensurePump(): void {
    if (closing || pumpTimer !== undefined) return;
    pumpTimer = every(() => {
      void pumpHeld();
    }, COALESCE_MS);
  }

  async function pumpHeld(): Promise<void> {
    if (pumping || closing) return;
    pumping = true;
    try {
      while (!closing && heldFifo.length > 0) {
        const head = heldFifo[0];
        if (staleEpoch(head.envelopes[0].epoch)) {
          warn(
            `peers: discarded ${head.envelopes.length} retained message(s); the captured epoch is stale`
          );
          finishHeld(head);
          continue;
        }
        const state = acceptanceState();
        if (state === 'shutting_down') {
          warn(
            `peers: discarded ${head.envelopes.length} retained message(s); the binding is shutting down`
          );
          finishHeld(head);
          continue;
        }
        if (state !== 'accepting') {
          // A pending transition may still cancel or roll back: retain the
          // batch and retry. Only a stale committed epoch or shutdown drops
          // acknowledged retained work (plan section 6.2).
          break;
        }
        if (!head.force) {
          if (head.queue.batches[0] !== head) break;
          if (!canSubmitNow()) break;
        }
        try {
          await delivery.submitBatch(head.envelopes);
        } catch (err) {
          warn(
            `peers: retained batch submission failed: ${boundText(err instanceof Error ? err.message : String(err))}`
          );
        }
        // No second network reply exists for a retained batch.
        finishHeld(head);
      }
    } finally {
      pumping = false;
      if (heldFifo.length === 0 && pumpTimer !== undefined) {
        clearManaged(pumpTimer);
        pumpTimer = undefined;
      }
    }
  }

  async function submitImmediate(batch: Batch): Promise<void> {
    let result: { code: ResultCode; detail?: string };
    try {
      result = await delivery.submitBatch(batch.envelopes);
    } catch (err) {
      warn(
        `peers: batch submission failed: ${boundText(err instanceof Error ? err.message : String(err))}`
      );
      result = { code: 'host_unavailable' };
    }
    removeFromQueue(batch);
    settleBatch(
      batch,
      result.code,
      result.detail !== undefined ? { detail: result.detail } : undefined
    );
  }

  function decide(batch: Batch): void {
    // One decision per sealed batch: only an unblocked queue head submits;
    // a batch blocked by typing, in-flight work, or an older held batch
    // reserves held capacity (or refuses busy) here, at seal.
    if (staleEpoch(batch.envelopes[0].epoch)) {
      settleBatch(batch, 'session_transition');
      removeFromQueue(batch);
      return;
    }
    if (closing || acceptanceState() !== 'accepting') {
      settleBatch(batch, refusal());
      removeFromQueue(batch);
      return;
    }
    if (batch.queue.batches[0] === batch && heldFifo.length === 0 && canSubmitNow()) {
      void submitImmediate(batch);
      return;
    }
    let reserved = false;
    try {
      reserved = delivery.reserveHeld();
    } catch {
      reserved = false;
    }
    if (!reserved) {
      settleBatch(batch, 'busy');
      removeFromQueue(batch);
      return;
    }
    batch.reserved = true;
    heldFifo.push(batch);
    armHold(batch);
    settleBatch(batch, 'held');
    ensurePump();
  }

  function seal(queue: SenderQueue): void {
    clearManaged(queue.coalesceTimer);
    queue.coalesceTimer = undefined;
    if (queue.collecting.length === 0) return;
    const envelopes: AuthenticatedEnvelope[] = [];
    const waiters: Conn[] = [];
    for (const entry of queue.collecting) {
      envelopes.push(entry.envelope);
      waiters.push(entry.conn);
    }
    queue.collecting = [];
    queue.collectingBytes = 0;
    const batch: Batch = { queue, envelopes, waiters, reserved: false, force: false, timer: undefined };
    queue.batches.push(batch);
    decide(batch);
  }

  function ensureQueue(key: string): SenderQueue | undefined {
    const existing = senderQueues.get(key);
    if (existing !== undefined) return existing;
    if (senderQueues.size >= MAX_SENDER_QUEUES) return undefined;
    const queue: SenderQueue = { key, collecting: [], collectingBytes: 0, coalesceTimer: undefined, batches: [] };
    senderQueues.set(key, queue);
    return queue;
  }

  function enqueue(conn: Conn, frame: RequestFrame, payload: MsgPayload, senderName: string): void {
    if (conn.epoch === undefined) {
      terminal(conn, 'session_transition');
      return;
    }
    const key = identityKey(frame.from);
    const existing = ensureQueue(key);
    if (existing === undefined) {
      terminal(conn, 'busy');
      return;
    }
    let queue: SenderQueue = existing;
    if (queue.batches.length >= MAX_BATCHES_PER_SENDER) {
      terminal(conn, 'busy');
      return;
    }
    const body = formatPeerText(senderName, payload.body, { id: frame.id });
    const envelope: AuthenticatedEnvelope = {
      id: frame.id,
      from: frame.from,
      to: frame.to,
      sentAt: frame.sentAt,
      hop: payload.hop,
      body,
      epoch: conn.epoch,
    };
    if (payload.replyTo !== undefined) envelope.replyTo = payload.replyTo;
    const bodyBytes = Buffer.byteLength(body, 'utf8');
    if (queue.collecting.length > 0 && queue.collectingBytes + bodyBytes > MAX_BATCH_BYTES) {
      // Seal before appending so the summed body ceiling is never exceeded.
      seal(queue);
      const next = ensureQueue(key);
      if (next === undefined || next.batches.length >= MAX_BATCHES_PER_SENDER) {
        terminal(conn, 'busy');
        return;
      }
      queue = next;
    }
    queue.collecting.push({ conn, envelope });
    queue.collectingBytes += bodyBytes;
    if (queue.collecting.length === 1) {
      queue.coalesceTimer = later(() => {
        queue.coalesceTimer = undefined;
        seal(queue);
      }, COALESCE_MS);
    }
    if (queue.collecting.length >= MAX_BATCH_MESSAGES || queue.collectingBytes >= MAX_BATCH_BYTES) {
      seal(queue);
    }
  }

  function dispatch(conn: Conn, frame: RequestFrame, senderName: string): void {
    const payload = frame.payload;
    if (payload.type === 'ping') {
      terminal(conn, 'pong');
      return;
    }
    if (payload.type === 'status') {
      let status: StatusSnapshot;
      try {
        status = delivery.statusSnapshot(payload.fields);
      } catch {
        terminal(conn, 'host_unavailable');
        return;
      }
      terminal(conn, 'status', { status });
      return;
    }
    if (payload.replyTo !== undefined) {
      let consumed = false;
      try {
        consumed = delivery.consumeReply(frame.from, payload.replyTo, payload.body);
      } catch {
        consumed = false;
      }
      if (consumed) {
        terminal(conn, 'reply_consumed');
        return;
      }
    }
    enqueue(conn, frame, payload, senderName);
  }

  async function processRequest(conn: Conn, frame: RequestFrame): Promise<void> {
    const hello = conn.hello;
    const serverNonce = conn.serverNonce;
    const now = Date.now();
    if (closing) {
      terminal(conn, refusal());
      return;
    }
    if (!identityEquals(frame.to, self)) {
      terminal(conn, 'wrong_recipient');
      return;
    }
    if (
      hello === undefined ||
      serverNonce === undefined ||
      frame.clientNonce !== hello.clientNonce ||
      frame.serverNonce !== serverNonce
    ) {
      terminal(conn, 'unauthenticated');
      return;
    }
    let epoch: EpochSnapshot;
    try {
      epoch = delivery.captureEpoch();
    } catch {
      terminal(conn, 'session_transition');
      return;
    }
    conn.epoch = epoch;
    const record = await readPeerRecord(roots, frame.from.pid, frame.from.instance);
    if (staleEpoch(epoch)) {
      // A commit overlapped the auth read; purge may already have replied.
      terminal(conn, 'session_transition');
      return;
    }
    if (record === undefined) {
      terminal(conn, 'unauthenticated');
      return;
    }
    const expected = requestMac(
      record.token,
      frame.id,
      frame.clientNonce,
      frame.serverNonce,
      frame.sentAt,
      frame.from,
      frame.to,
      canonicalRequestPayload(frame.payload)
    );
    if (!verifyMac(expected, frame.auth)) {
      terminal(conn, 'unauthenticated');
      return;
    }
    if (!isFreshTimestamp(frame.sentAt, now)) {
      terminal(conn, 'stale_sender');
      return;
    }
    if (closing) {
      terminal(conn, refusal());
      return;
    }
    const seen = replay.tryInsert(frame.from, frame.id, now);
    if (seen === 'replay') {
      terminal(conn, 'replay');
      return;
    }
    if (seen === 'full') {
      terminal(conn, 'busy');
      return;
    }
    const admission = delivery.admissionCode();
    if (admission !== undefined) {
      terminal(
        conn,
        admission.code,
        admission.detail !== undefined ? { detail: admission.detail } : undefined
      );
      return;
    }
    dispatch(conn, frame, record.name);
  }

  function handleHello(conn: Conn, line: string, rest: string): void {
    const raw = rawObject(line);
    if (raw !== undefined && isCanonicalId(raw['id'])) conn.replyId = raw['id'];
    if (raw === undefined) {
      terminal(conn, 'bad_frame');
      return;
    }
    if (raw['v'] !== PROTOCOL_VERSION) {
      terminal(conn, 'unsupported_version');
      return;
    }
    const hello = parseHello(line);
    if (hello === undefined) {
      terminal(conn, 'bad_frame');
      return;
    }
    if (rest !== '') {
      terminal(conn, 'bad_frame');
      return;
    }
    if (!identityEquals(hello.to, self)) {
      terminal(conn, 'wrong_recipient');
      return;
    }
    const serverNonce = generateId();
    const challenge = encodeLine({
      v: PROTOCOL_VERSION,
      type: 'challenge',
      id: hello.id,
      from: self,
      clientNonce: hello.clientNonce,
      serverNonce,
      auth: challengeMac(identity.token, hello.id, self, hello.clientNonce, serverNonce),
    });
    if (Buffer.byteLength(challenge, 'utf8') > CHALLENGE_MAX_BYTES) {
      destroySocket(conn.socket);
      return;
    }
    conn.hello = hello;
    conn.serverNonce = serverNonce;
    conn.replyId = hello.id;
    try {
      conn.socket.write(challenge);
    } catch {
      destroySocket(conn.socket);
      return;
    }
    conn.phase = 'request';
  }

  function handleRequest(conn: Conn, line: string, rest: string): void {
    if (rest !== '') {
      terminal(conn, 'bad_frame');
      return;
    }
    const raw = rawObject(line);
    if (raw === undefined) {
      terminal(conn, 'bad_frame');
      return;
    }
    if (raw['v'] !== PROTOCOL_VERSION) {
      terminal(conn, 'unsupported_version');
      return;
    }
    const frame = parseRequest(line);
    if (frame === undefined) {
      terminal(conn, 'bad_frame');
      return;
    }
    conn.replyId = frame.id;
    conn.owed = true;
    void processRequest(conn, frame);
  }

  function accept(socket: Socket): void {
    if (closing || sockets.size >= MAX_INBOUND_SOCKETS) {
      destroySocket(socket);
      return;
    }
    const conn: Conn = {
      socket,
      phase: 'hello',
      buffer: '',
      hello: undefined,
      serverNonce: undefined,
      replyId: undefined,
      epoch: undefined,
      requestAccepted: false,
      owed: false,
      replied: false,
      handshakeTimer: undefined,
      graceTimer: undefined,
    };
    sockets.add(conn);
    try {
      socket.setEncoding('utf8');
    } catch {
      // Encoding is best-effort.
    }
    socket.on('error', () => {
      destroySocket(socket);
    });
    socket.on('close', () => {
      clearManaged(conn.handshakeTimer);
      conn.handshakeTimer = undefined;
      clearManaged(conn.graceTimer);
      conn.graceTimer = undefined;
      sockets.delete(conn);
    });
    conn.handshakeTimer = later(() => {
      conn.handshakeTimer = undefined;
      if (!conn.replied && !conn.requestAccepted) destroySocket(socket);
    }, HANDSHAKE_TIMEOUT_MS);
    const onData = (chunk: string): void => {
      if (conn.replied) return;
      conn.buffer += chunk;
      const max = conn.phase === 'hello' ? HELLO_MAX_BYTES : REQUEST_MAX_BYTES;
      const nl = conn.buffer.indexOf('\n');
      if (nl === -1) {
        if (Buffer.byteLength(conn.buffer, 'utf8') > max) terminal(conn, 'bad_frame');
        return;
      }
      const line = conn.buffer.slice(0, nl);
      const rest = conn.buffer.slice(nl + 1);
      conn.buffer = rest;
      if (Buffer.byteLength(line, 'utf8') > max) {
        terminal(conn, 'bad_frame');
        return;
      }
      if (conn.phase === 'hello') {
        handleHello(conn, line, rest);
        return;
      }
      // One authenticated request boundary: detach and pause parsing for good.
      socket.off('data', onData);
      try {
        socket.pause();
      } catch {
        // Pausing is best-effort.
      }
      conn.requestAccepted = true;
      clearManaged(conn.handshakeTimer);
      conn.handshakeTimer = undefined;
      handleRequest(conn, line, rest);
    };
    socket.on('data', onData);
  }

  const server: Server = createServer(accept);
  server.unref();
  let resolveReady: (() => void) | undefined;
  let rejectReady: ((err: Error) => void) | undefined;
  const ready = new Promise<'listening'>((resolve, reject) => {
    resolveReady = () => resolve('listening');
    rejectReady = reject;
  });
  // The binding awaits `ready`; this only keeps a failed listen from surfacing
  // as an unhandled rejection first.
  void ready.catch(() => undefined);
  server.on('listening', () => {
    listening = true;
    resolveReady?.();
  });
  server.on('error', (err: unknown) => {
    const text = boundText(err instanceof Error ? err.message : String(err));
    if (!listening) {
      warn(`peers: listener failed on ${endpoint}: ${text}`);
      rejectReady?.(err instanceof Error ? err : new Error(text));
      return;
    }
    warn(`peers: listener error: ${text}`);
  });
  try {
    server.listen(endpoint);
  } catch (err) {
    const text = boundText(err instanceof Error ? err.message : String(err));
    warn(`peers: listener failed on ${endpoint}: ${text}`);
    rejectReady?.(err instanceof Error ? err : new Error(text));
  }

  function purgeStaleWork(isStale: (captured: EpochSnapshot) => boolean): void {
    // Authenticating sockets hold a captured epoch before any queue entry.
    for (const conn of [...sockets]) {
      if (conn.epoch !== undefined && !conn.replied && isStale(conn.epoch)) {
        terminal(conn, 'session_transition');
      }
    }
    for (const queue of [...senderQueues.values()]) {
      if (queue.collecting.some((entry) => isStale(entry.envelope.epoch))) {
        const kept: Array<{ conn: Conn; envelope: AuthenticatedEnvelope }> = [];
        let bytes = 0;
        for (const entry of queue.collecting) {
          if (isStale(entry.envelope.epoch)) {
            terminal(entry.conn, 'session_transition');
            continue;
          }
          kept.push(entry);
          bytes += Buffer.byteLength(entry.envelope.body, 'utf8');
        }
        queue.collecting = kept;
        queue.collectingBytes = bytes;
      }
      for (const batch of [...queue.batches]) {
        if (!isStale(batch.envelopes[0].epoch)) continue;
        if (batch.waiters !== undefined) settleBatch(batch, 'session_transition');
        // Held copies were already acknowledged `held`: drop silently and
        // release the reservation (finishHeld is a no-op for the rest).
        finishHeld(batch);
      }
      deleteQueueIfIdle(queue);
    }
  }

  async function close(): Promise<void> {
    if (closePromise !== undefined) return closePromise;
    closing = true;
    closePromise = (async (): Promise<void> => {
      if (pumpTimer !== undefined) {
        clearManaged(pumpTimer);
        pumpTimer = undefined;
      }
      for (const queue of senderQueues.values()) {
        clearManaged(queue.coalesceTimer);
        queue.coalesceTimer = undefined;
        for (const batch of queue.batches) {
          clearManaged(batch.timer);
          batch.timer = undefined;
        }
      }
      for (const batch of [...heldFifo]) {
        clearManaged(batch.timer);
        batch.timer = undefined;
        releaseReservation(batch);
      }
      heldFifo.length = 0;
      senderQueues.clear();
      for (const conn of [...sockets]) {
        if (conn.replied) continue;
        if (conn.owed) {
          terminal(conn, 'shutting_down');
        } else {
          conn.replied = true;
          clearManaged(conn.handshakeTimer);
          conn.handshakeTimer = undefined;
          destroySocket(conn.socket);
        }
      }
      try {
        await ready;
      } catch {
        // The listener never started; there is nothing to close.
      }
      await new Promise<void>((resolve) => {
        if (!listening) {
          resolve();
          return;
        }
        try {
          server.close(() => {
            resolve();
          });
        } catch {
          resolve();
        }
      });
    })();
    return closePromise;
  }

  return { endpoint, ready, purgeStaleWork, close };
}
