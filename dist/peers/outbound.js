/**
 * Outbound v2 exchange: fresh unique-name resolution, receiver-proof challenge
 * verification before any body or credential leaves this side, phase-aware
 * retry rules, and the pending-request correlation store. Every failure
 * resolves to a protocol result code; nothing throws into the agent turn.
 */
import { createConnection } from 'node:net';
import { BODY_MAX_BYTES, CHALLENGE_MAX_BYTES, HANDSHAKE_TIMEOUT_MS, HELLO_MAX_BYTES, MAX_HOP, MAX_OUTBOUND_SOCKETS, MAX_PENDING_REQUESTS, MAX_STATUS_FIELDS, PEER_NAME_PATTERN, PROTOCOL_VERSION, RECEIPT_TIMEOUT_MS, REPLY_MAX_BYTES, REQUEST_MAX_BYTES, REQUEST_TIMEOUT_DEFAULT_MS, REQUEST_TIMEOUT_MAX_MS, REQUEST_TIMEOUT_MIN_MS, canonicalRequestPayload, canonicalStatus, challengeMac, encodeLine, generateId, identityEquals, isCanonicalId, isRetryableRefusal, isSuccessCode, isValidPeerName, normalizeNameInput, parseChallenge, parseReply, replyMac, requestMac, verifyMac, } from './protocol.js';
import { hasDuplicateRoutableNames } from './ids.js';
import { readPeerRecord } from './presence.js';
import { peerEndpoint } from '../store/paths.js';
/** Carries the protocol result code across a rejected pending slot. */
class PendingClosedError extends Error {
    resultCode;
    constructor(code) {
        super(code);
        this.name = 'PendingClosedError';
        this.resultCode = code;
    }
}
function closedCode(err) {
    return err instanceof PendingClosedError ? err.resultCode : 'shutting_down';
}
/** Resolves only when the reserved slot is rejected; a reply settle leaves it pending forever. */
function isClosedMark(value) {
    return typeof value === 'object' && value !== null && 'closed' in value;
}
export class PendingStore {
    slots = new Map();
    outboundSockets = 0;
    /** Reserves one of the MAX_OUTBOUND_SOCKETS concurrent exchange slots. */
    acquireSocket() {
        if (this.outboundSockets >= MAX_OUTBOUND_SOCKETS)
            return false;
        this.outboundSockets += 1;
        return true;
    }
    /** Releases an exchange slot on every terminal path; never goes negative. */
    releaseSocket() {
        if (this.outboundSockets > 0)
            this.outboundSockets -= 1;
    }
    /**
     * Reserves the slot and returns its reply promise, captured exactly once
     * here: a settle at any later time resolves this same promise, so a reply
     * arriving before the caller observes it is never lost.
     */
    reserve(id, expected) {
        if (id === '' || this.slots.size >= MAX_PENDING_REQUESTS || this.slots.has(id))
            return undefined;
        let resolveFn;
        let rejectFn;
        const promise = new Promise((resolve, reject) => {
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
    markWritten(id) {
        const slot = this.slots.get(id);
        if (slot !== undefined)
            slot.written = true;
    }
    /** Records an authenticated receiver refusal that proves the request never dispatched. */
    noteNoDispatch(id) {
        const slot = this.slots.get(id);
        if (slot === undefined || !slot.written)
            return false;
        slot.noDispatch = true;
        return true;
    }
    retarget(id, expected) {
        const slot = this.slots.get(id);
        if (slot === undefined)
            return false;
        if (slot.written && !slot.noDispatch)
            return false;
        slot.expected = { pid: expected.pid, instance: expected.instance };
        return true;
    }
    settle(from, replyTo, body) {
        const slot = this.slots.get(replyTo);
        if (slot === undefined || !identityEquals(slot.expected, from))
            return false;
        this.slots.delete(replyTo);
        slot.resolve(body);
        return true;
    }
    discard(id, code) {
        const slot = this.slots.get(id);
        if (slot === undefined)
            return;
        this.slots.delete(id);
        slot.reject(new PendingClosedError(code));
    }
    rejectAll(code) {
        for (const [id, slot] of this.slots) {
            this.slots.delete(id);
            slot.reject(new PendingClosedError(code));
        }
    }
    size() {
        return this.slots.size;
    }
}
const DETAIL_MAX_BYTES = 512;
function clampBytes(value, max) {
    const bytes = Buffer.from(value, 'utf8');
    if (bytes.length <= max)
        return value;
    let end = max;
    while (end > 0) {
        const byte = bytes[end];
        if (byte === undefined || (byte & 0xc0) !== 0x80)
            break;
        end -= 1;
    }
    return bytes.subarray(0, end).toString('utf8');
}
/** Bounded sanitized text: control characters collapsed, UTF-8 clamped. */
function cleanText(value, max) {
    let stripped = '';
    for (const char of value) {
        const code = char.codePointAt(0) ?? 0;
        stripped += code <= 0x1f || (code >= 0x7f && code <= 0x9f) ? ' ' : char;
    }
    stripped = stripped.trim();
    if (stripped === '')
        return undefined;
    return clampBytes(stripped, max);
}
function errorMessage(err) {
    const text = err instanceof Error ? err.message : String(err);
    return cleanText(text, 200) ?? 'local failure';
}
function identityOf(record) {
    return { pid: record.pid, instance: record.instance };
}
function acceptanceState(deps) {
    try {
        return deps.acceptance();
    }
    catch {
        return 'shutting_down';
    }
}
function safeLog(deps, text) {
    try {
        deps.log(text);
    }
    catch {
        // Logging is best-effort.
    }
}
export async function resolveTarget(deps, to) {
    const name = normalizeNameInput(to ?? '');
    let scan;
    try {
        scan = await deps.scan();
    }
    catch (err) {
        safeLog(deps, `peer scan failed: ${errorMessage(err)}`);
        scan = { routable: [], incompatible: [] };
    }
    const routable = Array.isArray(scan.routable) ? scan.routable : [];
    const self = { pid: deps.identity.pid, instance: deps.identity.instance };
    const known = [
        ...new Set(routable.filter((record) => !identityEquals(record, self)).map((record) => record.name)),
    ].sort();
    if (name === '' || !PEER_NAME_PATTERN.test(name) || !isValidPeerName(name)) {
        return { kind: 'missing', known };
    }
    const matches = routable.filter((record) => record.name === name);
    if (matches.some((record) => identityEquals(record, self)))
        return { kind: 'self' };
    if (matches.length === 0) {
        let own;
        try {
            own = await readPeerRecord(deps.roots, self.pid, self.instance);
        }
        catch {
            own = undefined;
        }
        if (own !== undefined && own.name === name)
            return { kind: 'self' };
        return { kind: 'missing', known };
    }
    // A fresh scan that still carries duplicate routable names is ambiguous:
    // never choose the first record.
    if (matches.length > 1 || hasDuplicateRoutableNames(routable))
        return { kind: 'ambiguous', known };
    const only = matches[0];
    if (only === undefined)
        return { kind: 'ambiguous', known };
    return { kind: 'unique', record: only };
}
function resolutionReport(resolved) {
    if (resolved.kind === 'self')
        return { code: 'self_address', written: false, authenticated: false };
    const detail = resolved.known.length === 0 ? 'live: none' : `live: ${resolved.known.join(', ')}`;
    if (resolved.kind === 'missing') {
        return { code: 'not_found', detail, written: false, authenticated: false };
    }
    return { code: 'ambiguous_target', detail, written: false, authenticated: false };
}
function reportResult(report) {
    const result = { code: report.code };
    const detail = report.detail === undefined ? undefined : cleanText(report.detail, DETAIL_MAX_BYTES);
    if (detail !== undefined)
        result.detail = detail;
    if (report.target !== undefined)
        result.target = report.target;
    if (report.reply !== undefined && report.reply.status !== undefined)
        result.status = report.reply.status;
    return result;
}
/** Pre-write transport failures only; never post-write, oversized, or resolution failures. */
const PREWRITE_RETRYABLE = {
    connect_timeout: true,
    handshake_timeout: true,
    closed_before_reply: true,
    malformed_reply: true,
    receiver_auth_failed: true,
};
function mayRetry(report) {
    if (report.reply !== undefined)
        return report.authenticated && isRetryableRefusal(report.code);
    return report.written !== true && PREWRITE_RETRYABLE[report.code] === true;
}
const STATUS_FIELD_NAMES = { busy: true, model: true, activity: true, todos: true };
/** One bounded hello -> challenge -> request -> reply exchange. Never rejects. */
function runAttempt(opts) {
    return new Promise((resolvePromise) => {
        const self = { pid: opts.sender.pid, instance: opts.sender.instance };
        const target = identityOf(opts.record);
        const id = opts.id;
        const clientNonce = generateId();
        let socket;
        let phase = 'connect';
        let settled = false;
        let buffer = Buffer.alloc(0);
        let phaseTimer;
        let phaseTimerArmed = false;
        function clearPhaseTimer() {
            if (!phaseTimerArmed)
                return;
            phaseTimerArmed = false;
            try {
                opts.managed.clearTimer(phaseTimer);
            }
            catch {
                // Timer already fired or was cleared.
            }
        }
        function finish(report) {
            if (settled)
                return;
            settled = true;
            clearPhaseTimer();
            try {
                socket?.destroy();
            }
            catch {
                // Already gone.
            }
            resolvePromise(report);
        }
        function preReport(code) {
            return { code, written: false, authenticated: false, target };
        }
        function failByPhase(preCode) {
            if (phase === 'written') {
                finish({ code: 'unknown_outcome', detail: 'receipt_timeout', written: true, authenticated: false, target });
            }
            else {
                finish(preReport(preCode));
            }
        }
        function guard(preCode, body) {
            try {
                body();
            }
            catch {
                failByPhase(preCode);
            }
        }
        /** Phase timeout or absolute-deadline expiry, mapped by the phase reached. */
        function phaseReport() {
            if (phase === 'connect')
                return { code: 'connect_timeout', written: false, authenticated: false, target };
            if (phase === 'written') {
                return { code: 'unknown_outcome', detail: 'receipt_timeout', written: true, authenticated: false, target };
            }
            return { code: 'handshake_timeout', written: false, authenticated: false, target };
        }
        /** The absolute deadline passed at the current phase; never extended by trickled bytes. */
        function deadlineReport() {
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
        function armPhase(dueAt, kind) {
            clearPhaseTimer();
            try {
                phaseTimer = opts.managed.setTimeout(() => {
                    phaseTimerArmed = false;
                    finish(kind === 'deadline' ? deadlineReport() : phaseReport());
                }, Math.max(0, dueAt - Date.now()));
                phaseTimerArmed = true;
            }
            catch {
                finish(kind === 'deadline' ? deadlineReport() : phaseReport());
            }
        }
        function sendRequest(serverNonce) {
            if (settled)
                return;
            const sentAt = Date.now();
            const auth = requestMac(opts.sender.token, id, clientNonce, serverNonce, sentAt, self, target, canonicalRequestPayload(opts.payload));
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
            armPhase(Math.min(Date.now() + RECEIPT_TIMEOUT_MS, opts.deadline), opts.deadline <= Date.now() + RECEIPT_TIMEOUT_MS ? 'deadline' : 'phase');
            opts.onWrite();
            try {
                socket?.write(line, (err) => {
                    if (err)
                        failByPhase('closed_before_reply');
                });
            }
            catch {
                failByPhase('closed_before_reply');
            }
        }
        function onChallengeLine(line) {
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
        function onReplyLine(line) {
            const reply = parseReply(line);
            if (reply === undefined || reply.id !== id || !identityEquals(reply.from, target)) {
                failByPhase('malformed_reply');
                return;
            }
            const expected = replyMac(opts.record.token, id, reply.from, reply.code, reply.detail ?? null, canonicalStatus(reply.status));
            if (!verifyMac(expected, reply.auth)) {
                failByPhase('malformed_reply');
                return;
            }
            const report = { code: reply.code, written: true, authenticated: true, target, reply };
            if (reply.detail !== undefined)
                report.detail = reply.detail;
            finish(report);
        }
        function onData(chunk) {
            if (settled)
                return;
            const limit = phase === 'written' ? REPLY_MAX_BYTES : CHALLENGE_MAX_BYTES;
            buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
            const newline = buffer.indexOf(0x0a);
            if (newline === -1) {
                if (buffer.length > limit)
                    failByPhase('malformed_reply');
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
        }
        catch {
            finish(preReport('connect_timeout'));
            return;
        }
        armPhase(Math.min(Date.now() + HANDSHAKE_TIMEOUT_MS, opts.deadline), opts.deadline <= Date.now() + HANDSHAKE_TIMEOUT_MS ? 'deadline' : 'phase');
        socket.on('error', () => failByPhase(phase === 'connect' ? 'connect_timeout' : 'closed_before_reply'));
        socket.on('close', () => failByPhase(phase === 'connect' ? 'connect_timeout' : 'closed_before_reply'));
        socket.on('connect', () => guard('closed_before_reply', () => {
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
        }));
        socket.on('data', (chunk) => guard('malformed_reply', () => onData(chunk)));
    });
}
async function attemptExchange(deps, record, payload, id, deadline, pendingId, budgetDeadline, closed) {
    const target = identityOf(record);
    let endpoint;
    try {
        endpoint = peerEndpoint(deps.roots, record.pid, record.instance);
    }
    catch (err) {
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
                if (pendingId !== undefined)
                    deps.pending.markWritten(pendingId);
            },
        });
    }
    catch (err) {
        safeLog(deps, `peer exchange failed: ${errorMessage(err)}`);
        return { code: 'invalid_request', detail: errorMessage(err), target, written: false, authenticated: false };
    }
    finally {
        deps.pending.releaseSocket();
    }
}
/**
 * Resolve, exchange, and apply the retry contract: exactly one retry, only
 * for a pre-write failure or an authenticated retryable refusal, only when a
 * fresh scan uniquely resolves the requested name to a different identity.
 * The correlation id, payload, and semantic deadline are never reset.
 */
async function performOperation(deps, to, payload, deadline, opts = {}) {
    const resolved = await resolveTarget(deps, to);
    if (resolved.kind !== 'unique')
        return resolutionReport(resolved);
    let record = resolved.record;
    // Close signal for the reserved slot: resolves with the exact rejection
    // code (epoch commit or shutdown) and stays pending on a normal reply
    // settle, so racing it concludes the operation at the rejection itself.
    let closed;
    if (opts.pendingId !== undefined) {
        const state = acceptanceState(deps);
        if (state !== 'accepting')
            return { code: state, written: false, authenticated: false };
        const promise = deps.pending.reserve(opts.pendingId, identityOf(record));
        if (promise === undefined) {
            return {
                code: 'busy',
                detail: `pending limit ${MAX_PENDING_REQUESTS}`,
                written: false,
                authenticated: false,
            };
        }
        closed = new Promise((mark) => {
            promise.then(() => undefined, (err) => mark({ closed: closedCode(err) }));
        });
        opts.onReserved?.(promise);
    }
    const id = opts.pendingId ?? generateId();
    for (let tries = 0;; tries += 1) {
        const report = await attemptExchange(deps, record, payload, id, deadline, opts.pendingId, opts.budgetDeadline, closed);
        if (tries >= 1)
            return report;
        if (!mayRetry(report))
            return report;
        if (report.target === undefined)
            return report;
        if (Date.now() >= deadline)
            return report;
        if (acceptanceState(deps) !== 'accepting')
            return report;
        const fresh = closed === undefined ? await resolveTarget(deps, to) : await Promise.race([resolveTarget(deps, to), closed]);
        if (isClosedMark(fresh))
            return { code: fresh.closed, written: false, authenticated: false };
        if (fresh.kind !== 'unique')
            return report;
        if (acceptanceState(deps) !== 'accepting')
            return report;
        if (identityEquals(identityOf(fresh.record), report.target))
            return report;
        if (opts.pendingId !== undefined) {
            if (report.written)
                deps.pending.noteNoDispatch(opts.pendingId);
            if (!deps.pending.retarget(opts.pendingId, identityOf(fresh.record)))
                return report;
        }
        safeLog(deps, `retrying ${to} against a different live identity`);
        record = fresh.record;
    }
}
function validateAddress(to) {
    const name = normalizeNameInput(to ?? '');
    if (name === '' || !PEER_NAME_PATTERN.test(name))
        return { code: 'invalid_request', detail: 'invalid name' };
    if (!isValidPeerName(name))
        return { code: 'invalid_request', detail: 'reserved name' };
    return { name };
}
function isAddressResult(value) {
    return value.code !== undefined;
}
function validateBody(body) {
    if (typeof body !== 'string' || body === '')
        return { code: 'invalid_request', detail: 'missing body' };
    if (Buffer.byteLength(body) > BODY_MAX_BYTES)
        return { code: 'oversized' };
    return undefined;
}
function exchangeDeadline() {
    return Date.now() + 2 * (HANDSHAKE_TIMEOUT_MS + RECEIPT_TIMEOUT_MS);
}
function caughtResult(deps, err) {
    safeLog(deps, `peer operation failed: ${errorMessage(err)}`);
    return { code: 'invalid_request', detail: errorMessage(err) };
}
export async function sendMsg(deps, to, body, opts = {}) {
    try {
        const state = acceptanceState(deps);
        if (state !== 'accepting')
            return { code: state };
        const address = validateAddress(to);
        if (isAddressResult(address))
            return address;
        const bodyError = validateBody(body);
        if (bodyError !== undefined)
            return bodyError;
        const hop = opts.hop ?? 0;
        if (!Number.isInteger(hop) || hop < 0 || hop > MAX_HOP) {
            return { code: 'invalid_request', detail: 'invalid hop' };
        }
        if (opts.replyTo !== undefined && !isCanonicalId(opts.replyTo)) {
            return { code: 'invalid_request', detail: 'invalid replyTo' };
        }
        const payload = opts.replyTo !== undefined ? { type: 'msg', body, hop, replyTo: opts.replyTo } : { type: 'msg', body, hop };
        const report = await performOperation(deps, address.name, payload, exchangeDeadline());
        const afterState = acceptanceState(deps);
        if (afterState !== 'accepting')
            return { code: afterState };
        return reportResult(report);
    }
    catch (err) {
        return caughtResult(deps, err);
    }
}
export async function requestMsg(deps, to, body, opts = {}) {
    const requested = opts.timeoutMs;
    let timeoutMs = REQUEST_TIMEOUT_DEFAULT_MS;
    if (typeof requested === 'number' && Number.isFinite(requested) && requested > 0) {
        timeoutMs = Math.min(REQUEST_TIMEOUT_MAX_MS, Math.max(REQUEST_TIMEOUT_MIN_MS, Math.trunc(requested)));
    }
    const deadline = Date.now() + timeoutMs;
    const id = generateId();
    let report;
    let replyPromise;
    try {
        const state = acceptanceState(deps);
        if (state !== 'accepting')
            return { code: state };
        const address = validateAddress(to);
        if (isAddressResult(address))
            return address;
        const bodyError = validateBody(body);
        if (bodyError !== undefined)
            return bodyError;
        const hop = opts.hop ?? 0;
        if (!Number.isSafeInteger(hop) || hop < 0) {
            return { code: 'invalid_request', detail: 'invalid hop' };
        }
        if (hop > MAX_HOP) {
            return { code: 'invalid_request', detail: `hop ${hop} exceeds limit ${MAX_HOP}` };
        }
        const payload = { type: 'msg', body, hop };
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
    }
    catch (err) {
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
        const out = { code: 'unknown_outcome' };
        if (report.target !== undefined)
            out.target = report.target;
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
        const out = { code: 'reply_consumed', replyBody: settled.body };
        if (report.target !== undefined)
            out.target = report.target;
        return out;
    }
    if (settled.kind === 'rejected') {
        const out = { code: settled.code };
        if (report.target !== undefined)
            out.target = report.target;
        return out;
    }
    // Only the reply wait expired: the verified transport receipt stands.
    deps.pending.discard(id, report.code);
    const out = {
        code: report.code,
        detail: `${report.code}, no reply within ${timeoutMs}ms; a late reply may still arrive as a peer message`,
    };
    if (report.target !== undefined)
        out.target = report.target;
    return out;
}
export async function statusOf(deps, to, fields, budget) {
    try {
        const state = acceptanceState(deps);
        if (state !== 'accepting')
            return { code: state };
        const address = validateAddress(to);
        if (isAddressResult(address))
            return address;
        const requested = (Array.isArray(fields) ? fields : [])
            .filter((field) => STATUS_FIELD_NAMES[field] === true)
            .slice(0, MAX_STATUS_FIELDS);
        const payload = requested.length > 0 ? { type: 'status', fields: requested } : { type: 'status' };
        let budgetDeadline;
        if (budget !== undefined) {
            if (!Number.isFinite(budget.deadlineAt)) {
                return { code: 'invalid_request', detail: 'invalid budget deadline' };
            }
            budgetDeadline = Math.trunc(budget.deadlineAt);
        }
        const deadline = budgetDeadline === undefined ? exchangeDeadline() : Math.min(exchangeDeadline(), budgetDeadline);
        const report = await performOperation(deps, address.name, payload, deadline, { budgetDeadline });
        const afterState = acceptanceState(deps);
        if (afterState !== 'accepting')
            return { code: afterState };
        return reportResult(report);
    }
    catch (err) {
        return caughtResult(deps, err);
    }
}
export async function pingPeer(deps, to) {
    try {
        const state = acceptanceState(deps);
        if (state !== 'accepting')
            return { code: state };
        const address = validateAddress(to);
        if (isAddressResult(address))
            return address;
        const payload = { type: 'ping' };
        const report = await performOperation(deps, address.name, payload, exchangeDeadline());
        const afterState = acceptanceState(deps);
        if (afterState !== 'accepting')
            return { code: afterState };
        return reportResult(report);
    }
    catch (err) {
        return caughtResult(deps, err);
    }
}
function waitForReply(deps, reply, deadline) {
    return new Promise((resolveOutcome) => {
        let done = false;
        let timer;
        const finish = (outcome) => {
            if (done)
                return;
            done = true;
            if (timer !== undefined) {
                try {
                    deps.managed.clearTimer(timer);
                }
                catch {
                    // Timer already fired or was cleared.
                }
            }
            resolveOutcome(outcome);
        };
        reply.then((body) => finish({ kind: 'reply', body }), (err) => finish({ kind: 'rejected', code: closedCode(err) }));
        try {
            timer = deps.managed.setTimeout(() => finish({ kind: 'timeout' }), Math.max(0, deadline - Date.now()));
        }
        catch {
            finish({ kind: 'timeout' });
            return;
        }
        if (done && timer !== undefined) {
            try {
                deps.managed.clearTimer(timer);
            }
            catch {
                // Nothing to clear.
            }
        }
    });
}
