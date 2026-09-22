/**
 * Protocol v2 core: release constants, canonical identities, closed frame
 * schemas, fixed-position MAC tuples, bounded strict parsers, replay
 * tracking, and result codes. Pure module: no fs, no net, no host types
 * beyond `import type { PeerTodo }`.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
// Release constants (plan section 3). The single exported source every slice reads.
export const PROTOCOL_VERSION = 2;
export const HELLO_MAX_BYTES = 1024;
export const CHALLENGE_MAX_BYTES = 1024;
export const REQUEST_MAX_BYTES = 262144;
export const BODY_MAX_BYTES = 65536;
export const REPLY_MAX_BYTES = 8192;
export const RECORD_MAX_BYTES = 8192;
export const MAX_DIR_ENTRIES = 1024;
export const MAX_ROUTABLE_PEERS = 256;
export const PROJECT_MAX_BYTES = 64;
export const MAX_INBOUND_SOCKETS = 64;
export const MAX_OUTBOUND_SOCKETS = 32;
export const MAX_SENDER_QUEUES = 32;
export const MAX_BATCHES_PER_SENDER = 2;
export const MAX_BATCH_MESSAGES = 8;
export const MAX_BATCH_BYTES = 131072;
export const COALESCE_MS = 400;
export const DRAIN_GRACE_MS = 250;
export const MAX_PENDING_REQUESTS = 16;
export const REPLAY_CACHE_SIZE = 4096;
export const REPLAY_TTL_MS = 120000;
export const MAX_PAST_MS = 120000;
export const MAX_FUTURE_MS = 30000;
export const HANDSHAKE_TIMEOUT_MS = 2000;
export const RECEIPT_TIMEOUT_MS = 8000;
export const REQUEST_TIMEOUT_DEFAULT_MS = 30000;
export const REQUEST_TIMEOUT_MIN_MS = 5000;
export const REQUEST_TIMEOUT_MAX_MS = 120000;
export const HEARTBEAT_MS = 15000;
export const PRESENCE_TTL_MS = 45000;
export const MAX_HELD_BATCHES = 20;
export const HOLD_TIMEOUT_MS = 120000;
export const STATUS_FANOUT = 8;
export const STATUS_BUDGET_MS = 1200;
export const MAX_STATUS_FIELDS = 3;
export const MAX_STATUS_TODOS = 20;
export const MAX_STATUS_TEXT_BYTES = 200;
export const MAX_STATUS_ACTIVITY_BYTES = 256;
export const MAX_HOP = 4;
export const WAKES_PER_HOUR = 20;
export const MAX_WAKE_IDENTITIES = 256;
export const PROCESS_WAKES_PER_HOUR = 60;
export const WAKE_WINDOW_MS = 3600000;
export const ID_BYTES = 16;
export const TOKEN_BYTES = 32;
export const INSTANCE_HEX_CHARS = 32;
export const ID_B64_CHARS = 22;
export const TOKEN_B64_CHARS = 43;
const INSTANCE_PATTERN = /^[0-9a-f]{32}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAC_PATTERN = /^[0-9a-f]{64}$/;
/** 16 random bytes as 32 lowercase hex characters. */
export function generateInstance() {
    return randomBytes(ID_BYTES).toString('hex');
}
/** 32 random bytes as canonical unpadded base64url (43 characters). */
export function generateToken() {
    return randomBytes(TOKEN_BYTES).toString('base64url');
}
/** 16 random bytes as canonical unpadded base64url (22 characters). */
export function generateId() {
    return randomBytes(ID_BYTES).toString('base64url');
}
export function isCanonicalInstance(v) {
    return typeof v === 'string' && v.length === INSTANCE_HEX_CHARS && INSTANCE_PATTERN.test(v);
}
function isCanonicalBase64(v, chars, bytes) {
    if (typeof v !== 'string' || v.length !== chars || !BASE64URL_PATTERN.test(v))
        return false;
    const decoded = Buffer.from(v, 'base64url');
    // Re-encoding must reproduce the input exactly: rejects non-canonical trailing bits.
    return decoded.length === bytes && decoded.toString('base64url') === v;
}
export function isCanonicalToken(v) {
    return isCanonicalBase64(v, TOKEN_B64_CHARS, TOKEN_BYTES);
}
export function isCanonicalId(v) {
    return isCanonicalBase64(v, ID_B64_CHARS, ID_BYTES);
}
export function identityKey(id) {
    return `${id.pid}:${id.instance}`;
}
export function identityEquals(a, b) {
    return a.pid === b.pid && a.instance === b.instance;
}
// Peer names.
/** Canonical peer names: 1-24 lowercase characters starting alphanumeric. */
export const PEER_NAME_PATTERN = /^[a-z0-9][a-z0-9._-]{0,23}$/;
const RESERVED_NAMES = { all: true, main: true };
const ALIAS_PATTERN = /^p-[0-9a-f]{22}$/;
/** True for usable user-facing names; rejects `all`, `main`, and `p-<22 hex>` aliases. */
export function isValidPeerName(name) {
    return PEER_NAME_PATTERN.test(name) && RESERVED_NAMES[name] !== true && !ALIAS_PATTERN.test(name);
}
/** Trim, lowercase, strip control characters; empty string when unusable. */
export function normalizeNameInput(raw) {
    const cleaned = raw.replace(/[\p{Cc}]/gu, '').toLowerCase().trim();
    return PEER_NAME_PATTERN.test(cleaned) ? cleaned : '';
}
/** Stable collision alias: `p-` plus the first 22 hex chars of sha256 of the full instance. */
export function aliasNameFor(instance) {
    const digest = createHash('sha256').update(instance, 'utf8').digest('hex');
    return `p-${digest.slice(0, 22)}`;
}
/** Default name: `<project clamped to 15 chars>-<first 8 instance hex chars>`. */
export function defaultNameFor(project, instance) {
    return `${project.slice(0, 15)}-${instance.slice(0, 8)}`;
}
function isPlainObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function isPid(value) {
    return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 2147483647;
}
function hasExactKeys(value, required, optional = []) {
    const keys = Object.keys(value);
    if (keys.length < required.length || keys.length > required.length + optional.length)
        return false;
    for (const key of keys) {
        if (!required.includes(key) && !optional.includes(key))
            return false;
    }
    return required.every((key) => Object.hasOwn(value, key));
}
function parseV2Record(value) {
    if (!hasExactKeys(value, [
        'v',
        'pid',
        'instance',
        'token',
        'name',
        'project',
        'harness',
        'startedAt',
        'beatAt',
        'busy',
    ])) {
        return undefined;
    }
    const pid = value['pid'];
    const instance = value['instance'];
    const token = value['token'];
    const name = value['name'];
    const project = value['project'];
    const startedAt = value['startedAt'];
    const beatAt = value['beatAt'];
    const busy = value['busy'];
    if (!isPid(pid))
        return undefined;
    if (!isCanonicalInstance(instance))
        return undefined;
    if (!isCanonicalToken(token))
        return undefined;
    // Pattern only, not isValidPeerName: collision losers legitimately store `p-<22 hex>` aliases.
    if (typeof name !== 'string' || !PEER_NAME_PATTERN.test(name))
        return undefined;
    if (typeof project !== 'string')
        return undefined;
    const projectBytes = Buffer.byteLength(project, 'utf8');
    if (projectBytes < 1 || projectBytes > PROJECT_MAX_BYTES)
        return undefined;
    if (value['harness'] !== 'omp')
        return undefined;
    if (typeof startedAt !== 'number' || !Number.isSafeInteger(startedAt) || startedAt < 0)
        return undefined;
    if (typeof beatAt !== 'number' || !Number.isSafeInteger(beatAt) || beatAt < 0)
        return undefined;
    if (typeof busy !== 'boolean')
        return undefined;
    return { v: 2, pid, instance, token, name, project, harness: 'omp', startedAt, beatAt, busy };
}
/** Strict bounded record parse; never throws. Extra fields and non-canonical encodings fail. */
export function parseRecord(raw) {
    if (Buffer.byteLength(raw, 'utf8') > RECORD_MAX_BYTES)
        return { kind: 'malformed' };
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch {
        return { kind: 'malformed' };
    }
    if (!isPlainObject(value))
        return { kind: 'malformed' };
    const version = value['v'];
    if (version === 1)
        return { kind: 'v1' };
    if (version === 2) {
        const record = parseV2Record(value);
        return record ? { kind: 'v2', record } : { kind: 'malformed' };
    }
    if (typeof version === 'number' && Number.isSafeInteger(version) && version > 2) {
        return { kind: 'future', version };
    }
    return { kind: 'malformed' };
}
export function recordFileName(pid, instance) {
    return `${pid}-${instance}.json`;
}
/** A beat is fresh through exactly PRESENCE_TTL_MS after it lands, expired just after. */
export function isRecordFresh(beatAt, now) {
    return now - beatAt <= PRESENCE_TTL_MS;
}
const SUCCESS_CODES = {
    submitted: true,
    followup_submitted: true,
    held: true,
    reply_consumed: true,
    status: true,
    pong: true,
};
const REFUSAL_CODES = {
    bad_frame: true,
    unsupported_version: true,
    wrong_recipient: true,
    unauthenticated: true,
    stale_sender: true,
    replay: true,
    busy: true,
    session_transition: true,
    shutting_down: true,
    host_unavailable: true,
};
const LOCAL_CODES = {
    connect_timeout: true,
    handshake_timeout: true,
    closed_before_reply: true,
    malformed_reply: true,
    receiver_auth_failed: true,
    unknown_outcome: true,
    not_found: true,
    ambiguous_target: true,
    self_address: true,
    invalid_request: true,
    oversized: true,
};
const RETRYABLE_REFUSALS = {
    wrong_recipient: true,
    busy: true,
    session_transition: true,
    shutting_down: true,
    host_unavailable: true,
};
function isResultCode(value) {
    return (typeof value === 'string' &&
        (SUCCESS_CODES[value] === true || REFUSAL_CODES[value] === true || LOCAL_CODES[value] === true));
}
/** Only these refusals are safe to retry, and only against a newly unique target. */
export function isRetryableRefusal(code) {
    return RETRYABLE_REFUSALS[code] === true;
}
export function isSuccessCode(code) {
    return SUCCESS_CODES[code] === true;
}
function parseIdentity(value) {
    if (!isPlainObject(value))
        return undefined;
    if (!hasExactKeys(value, ['pid', 'instance']))
        return undefined;
    const pid = value['pid'];
    const instance = value['instance'];
    if (!isPid(pid) || !isCanonicalInstance(instance))
        return undefined;
    return { pid, instance };
}
function parseFrame(line, maxBytes) {
    if (Buffer.byteLength(line, 'utf8') > maxBytes)
        return undefined;
    let value;
    try {
        value = JSON.parse(line);
    }
    catch {
        return undefined;
    }
    return isPlainObject(value) ? value : undefined;
}
const TODO_STATUSES = {
    pending: true,
    in_progress: true,
    completed: true,
    abandoned: true,
    blocked: true,
};
function parsePeerTodo(value) {
    if (!isPlainObject(value))
        return undefined;
    if (!hasExactKeys(value, ['text'], ['id', 'phase', 'status', 'blocker']))
        return undefined;
    const text = value['text'];
    if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > MAX_STATUS_TEXT_BYTES)
        return undefined;
    const todo = { text };
    const id = value['id'];
    if (typeof id === 'string' && Buffer.byteLength(id, 'utf8') <= MAX_STATUS_TEXT_BYTES) {
        todo.id = id;
    }
    const phase = value['phase'];
    if (phase !== undefined) {
        if (typeof phase !== 'string' || Buffer.byteLength(phase, 'utf8') > MAX_STATUS_TEXT_BYTES)
            return undefined;
        todo.phase = phase;
    }
    const blocker = value['blocker'];
    if (blocker !== undefined) {
        if (typeof blocker !== 'string' || Buffer.byteLength(blocker, 'utf8') > MAX_STATUS_TEXT_BYTES)
            return undefined;
        todo.blocker = blocker;
    }
    const status = value['status'];
    if (status !== undefined) {
        if (typeof status !== 'string' || TODO_STATUSES[status] !== true)
            return undefined;
        todo.status = status;
    }
    return todo;
}
function parseStatusSnapshot(value) {
    if (!isPlainObject(value))
        return undefined;
    if (!hasExactKeys(value, ['busy'], ['model', 'activity', 'todos']))
        return undefined;
    const busy = value['busy'];
    if (typeof busy !== 'boolean')
        return undefined;
    const snapshot = { busy };
    const model = value['model'];
    if (model !== undefined) {
        if (typeof model !== 'string' || Buffer.byteLength(model, 'utf8') > MAX_STATUS_ACTIVITY_BYTES)
            return undefined;
        snapshot.model = model;
    }
    const activity = value['activity'];
    if (activity !== undefined) {
        if (typeof activity !== 'string' || Buffer.byteLength(activity, 'utf8') > MAX_STATUS_ACTIVITY_BYTES) {
            return undefined;
        }
        snapshot.activity = activity;
    }
    const todos = value['todos'];
    if (todos !== undefined) {
        if (!Array.isArray(todos) || todos.length > MAX_STATUS_TODOS)
            return undefined;
        const parsed = [];
        for (const entry of todos) {
            const todo = parsePeerTodo(entry);
            if (!todo)
                return undefined;
            parsed.push(todo);
        }
        snapshot.todos = parsed;
    }
    return snapshot;
}
function parsePayload(value) {
    if (!isPlainObject(value))
        return undefined;
    const type = value['type'];
    if (type === 'msg') {
        if (!hasExactKeys(value, ['type', 'body', 'hop'], ['replyTo']))
            return undefined;
        const body = value['body'];
        if (typeof body !== 'string' || Buffer.byteLength(body, 'utf8') > BODY_MAX_BYTES)
            return undefined;
        const hop = value['hop'];
        if (typeof hop !== 'number' || !Number.isInteger(hop) || hop < 0 || hop > MAX_HOP)
            return undefined;
        const replyTo = value['replyTo'];
        if (replyTo !== undefined && !isCanonicalId(replyTo))
            return undefined;
        const payload = { type: 'msg', body, hop };
        if (typeof replyTo === 'string')
            payload.replyTo = replyTo;
        return payload;
    }
    if (type === 'status') {
        if (!hasExactKeys(value, ['type'], ['fields']))
            return undefined;
        const fields = value['fields'];
        if (fields === undefined)
            return { type: 'status' };
        if (!Array.isArray(fields) || fields.length > MAX_STATUS_FIELDS)
            return undefined;
        const names = [];
        for (const field of fields) {
            if (typeof field !== 'string' || Buffer.byteLength(field, 'utf8') > MAX_STATUS_TEXT_BYTES)
                return undefined;
            names.push(field);
        }
        return { type: 'status', fields: names };
    }
    if (type === 'ping') {
        if (!hasExactKeys(value, ['type']))
            return undefined;
        return { type: 'ping' };
    }
    // Unknown payload type is a protocol error, never a silent drop.
    return undefined;
}
export function parseHello(line) {
    const frame = parseFrame(line, HELLO_MAX_BYTES);
    if (!frame)
        return undefined;
    if (!hasExactKeys(frame, ['v', 'type', 'id', 'to', 'clientNonce']))
        return undefined;
    if (frame['v'] !== PROTOCOL_VERSION || frame['type'] !== 'hello')
        return undefined;
    const id = frame['id'];
    const to = parseIdentity(frame['to']);
    const clientNonce = frame['clientNonce'];
    if (!to || !isCanonicalId(id) || !isCanonicalId(clientNonce))
        return undefined;
    return { v: PROTOCOL_VERSION, type: 'hello', id, to, clientNonce };
}
export function parseChallenge(line) {
    const frame = parseFrame(line, CHALLENGE_MAX_BYTES);
    if (!frame)
        return undefined;
    if (!hasExactKeys(frame, ['v', 'type', 'id', 'from', 'clientNonce', 'serverNonce', 'auth']))
        return undefined;
    if (frame['v'] !== PROTOCOL_VERSION || frame['type'] !== 'challenge')
        return undefined;
    const id = frame['id'];
    const from = parseIdentity(frame['from']);
    const clientNonce = frame['clientNonce'];
    const serverNonce = frame['serverNonce'];
    const auth = frame['auth'];
    if (!from || !isCanonicalId(id) || !isCanonicalId(clientNonce) || !isCanonicalId(serverNonce))
        return undefined;
    if (!isMac(auth))
        return undefined;
    return { v: PROTOCOL_VERSION, type: 'challenge', id, from, clientNonce, serverNonce, auth };
}
export function parseRequest(line) {
    const frame = parseFrame(line, REQUEST_MAX_BYTES);
    if (!frame)
        return undefined;
    if (!hasExactKeys(frame, ['v', 'type', 'id', 'clientNonce', 'serverNonce', 'sentAt', 'from', 'to', 'payload', 'auth'])) {
        return undefined;
    }
    if (frame['v'] !== PROTOCOL_VERSION || frame['type'] !== 'request')
        return undefined;
    const id = frame['id'];
    const clientNonce = frame['clientNonce'];
    const serverNonce = frame['serverNonce'];
    const sentAt = frame['sentAt'];
    const from = parseIdentity(frame['from']);
    const to = parseIdentity(frame['to']);
    const payload = parsePayload(frame['payload']);
    const auth = frame['auth'];
    if (!from || !to || !payload)
        return undefined;
    if (!isCanonicalId(id) || !isCanonicalId(clientNonce) || !isCanonicalId(serverNonce))
        return undefined;
    if (typeof sentAt !== 'number' || !Number.isSafeInteger(sentAt))
        return undefined;
    if (!isMac(auth))
        return undefined;
    return { v: PROTOCOL_VERSION, type: 'request', id, clientNonce, serverNonce, sentAt, from, to, payload, auth };
}
export function parseReply(line) {
    const frame = parseFrame(line, REPLY_MAX_BYTES);
    if (!frame)
        return undefined;
    if (!hasExactKeys(frame, ['v', 'type', 'id', 'from', 'code', 'auth'], ['detail', 'status']))
        return undefined;
    if (frame['v'] !== PROTOCOL_VERSION || frame['type'] !== 'reply')
        return undefined;
    const id = frame['id'];
    const from = parseIdentity(frame['from']);
    const code = frame['code'];
    const auth = frame['auth'];
    if (!from || !isCanonicalId(id) || !isResultCode(code) || !isMac(auth))
        return undefined;
    const reply = { v: PROTOCOL_VERSION, type: 'reply', id, from, code, auth };
    const detail = frame['detail'];
    if (detail !== undefined) {
        if (typeof detail !== 'string')
            return undefined;
        reply.detail = detail;
    }
    const status = frame['status'];
    if (status !== undefined) {
        const snapshot = parseStatusSnapshot(status);
        if (!snapshot)
            return undefined;
        reply.status = snapshot;
    }
    return reply;
}
function isMac(value) {
    return typeof value === 'string' && MAC_PATTERN.test(value);
}
/** Compact JSON plus trailing newline. */
export function encodeLine(value) {
    return `${JSON.stringify(value) ?? 'null'}\n`;
}
// Canonical MAC tuples: fixed-position UTF-8 JSON arrays with explicit null slots.
function hmacTuple(key, parts) {
    // An array of primitives always serializes; the fallback only keeps the type exact.
    const tuple = JSON.stringify(parts) ?? '[]';
    return createHmac('sha256', key).update(tuple, 'utf8').digest('hex');
}
/** Tuple: [id, fromPid, fromInstance, clientNonce, serverNonce], keyed by the receiver token. */
export function challengeMac(receiverToken, id, from, clientNonce, serverNonce) {
    return hmacTuple(receiverToken, [id, from.pid, from.instance, clientNonce, serverNonce]);
}
/** Tuple: [id, clientNonce, serverNonce, sentAt, fromPid, fromInstance, toPid, toInstance, payload]. */
export function requestMac(senderToken, id, clientNonce, serverNonce, sentAt, from, to, payloadCanonical) {
    return hmacTuple(senderToken, [
        id,
        clientNonce,
        serverNonce,
        sentAt,
        from.pid,
        from.instance,
        to.pid,
        to.instance,
        payloadCanonical,
    ]);
}
/** Tuple: [id, fromPid, fromInstance, code, detail, status], keyed by the receiver token. */
export function replyMac(receiverToken, id, from, code, detail, statusCanonical) {
    return hmacTuple(receiverToken, [id, from.pid, from.instance, code, detail ?? null, statusCanonical ?? null]);
}
/** Deterministic JSON: object keys sorted at every depth, undefined dropped, arrays kept in order. */
function stableStringify(value) {
    if (value === null)
        return 'null';
    if (Array.isArray(value)) {
        return `[${value.map((item) => stableStringify(item === undefined ? null : item)).join(',')}]`;
    }
    if (typeof value === 'object') {
        const source = value;
        const parts = [];
        for (const key of Object.keys(source).sort()) {
            const item = source[key];
            if (item === undefined)
                continue;
            parts.push(`${JSON.stringify(key)}:${stableStringify(item)}`);
        }
        return `{${parts.join(',')}}`;
    }
    return JSON.stringify(value) ?? 'null';
}
export function canonicalRequestPayload(payload) {
    return stableStringify(payload);
}
/** Stable sorted-key JSON of the snapshot, or null when absent. */
export function canonicalStatus(snapshot) {
    if (snapshot === undefined)
        return null;
    return stableStringify(snapshot);
}
/** Constant-time comparison of two MAC strings; length mismatch fails without throwing. */
export function verifyMac(expected, provided) {
    if (typeof provided !== 'string')
        return false;
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(provided, 'utf8');
    return a.length === b.length && timingSafeEqual(a, b);
}
// Freshness and replay tracking.
/** True when sentAt sits inside [-MAX_PAST_MS, +MAX_FUTURE_MS] around now, inclusive. */
export function isFreshTimestamp(sentAt, now) {
    return (typeof sentAt === 'number' &&
        Number.isSafeInteger(sentAt) &&
        sentAt >= now - MAX_PAST_MS &&
        sentAt <= now + MAX_FUTURE_MS);
}
/**
 * Per-binding dedupe of authenticated (sender, id) pairs: up to
 * REPLAY_CACHE_SIZE entries with REPLAY_TTL_MS lifetime. tryInsert is
 * synchronous and atomic; a full cache returns 'full' and never evicts an
 * unexpired id.
 */
export class ReplayCache {
    seen = new Map();
    tryInsert(sender, id, now = Date.now()) {
        for (const [key, at] of this.seen) {
            if (now - at > REPLAY_TTL_MS)
                this.seen.delete(key);
        }
        const key = `${identityKey(sender)}:${id}`;
        if (this.seen.has(key))
            return 'replay';
        if (this.seen.size >= REPLAY_CACHE_SIZE)
            return 'full';
        this.seen.set(key, now);
        return 'ok';
    }
}
