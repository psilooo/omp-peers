/**
 * Protocol v2 core: release constants, canonical identities, closed frame
 * schemas, fixed-position MAC tuples, bounded strict parsers, replay
 * tracking, and result codes. Pure module: no fs, no net, no host types
 * beyond `import type { PeerTodo }`.
 */
import type { PeerTodo } from '../types.js';
export declare const PROTOCOL_VERSION = 2;
export declare const HELLO_MAX_BYTES = 1024;
export declare const CHALLENGE_MAX_BYTES = 1024;
export declare const REQUEST_MAX_BYTES = 262144;
export declare const BODY_MAX_BYTES = 65536;
export declare const REPLY_MAX_BYTES = 8192;
export declare const RECORD_MAX_BYTES = 8192;
export declare const MAX_DIR_ENTRIES = 1024;
export declare const MAX_ROUTABLE_PEERS = 256;
export declare const PROJECT_MAX_BYTES = 64;
export declare const MAX_INBOUND_SOCKETS = 64;
export declare const MAX_OUTBOUND_SOCKETS = 32;
export declare const MAX_SENDER_QUEUES = 32;
export declare const MAX_BATCHES_PER_SENDER = 2;
export declare const MAX_BATCH_MESSAGES = 8;
export declare const MAX_BATCH_BYTES = 131072;
export declare const COALESCE_MS = 400;
export declare const DRAIN_GRACE_MS = 250;
export declare const MAX_PENDING_REQUESTS = 16;
export declare const REPLAY_CACHE_SIZE = 4096;
export declare const REPLAY_TTL_MS = 120000;
export declare const MAX_PAST_MS = 120000;
export declare const MAX_FUTURE_MS = 30000;
export declare const HANDSHAKE_TIMEOUT_MS = 2000;
export declare const RECEIPT_TIMEOUT_MS = 8000;
export declare const REQUEST_TIMEOUT_DEFAULT_MS = 30000;
export declare const REQUEST_TIMEOUT_MIN_MS = 5000;
export declare const REQUEST_TIMEOUT_MAX_MS = 120000;
export declare const HEARTBEAT_MS = 15000;
export declare const PRESENCE_TTL_MS = 45000;
export declare const MAX_HELD_BATCHES = 20;
export declare const HOLD_TIMEOUT_MS = 120000;
export declare const STATUS_FANOUT = 8;
export declare const STATUS_BUDGET_MS = 1200;
export declare const MAX_STATUS_FIELDS = 3;
export declare const MAX_STATUS_TODOS = 20;
export declare const MAX_STATUS_TEXT_BYTES = 200;
export declare const MAX_STATUS_ACTIVITY_BYTES = 256;
export declare const MAX_HOP = 4;
export declare const WAKES_PER_HOUR = 20;
export declare const MAX_WAKE_IDENTITIES = 256;
export declare const PROCESS_WAKES_PER_HOUR = 60;
export declare const WAKE_WINDOW_MS = 3600000;
export declare const ID_BYTES = 16;
export declare const TOKEN_BYTES = 32;
export declare const INSTANCE_HEX_CHARS = 32;
export declare const ID_B64_CHARS = 22;
export declare const TOKEN_B64_CHARS = 43;
export interface PeerIdentity {
    pid: number;
    instance: string;
}
/** 16 random bytes as 32 lowercase hex characters. */
export declare function generateInstance(): string;
/** 32 random bytes as canonical unpadded base64url (43 characters). */
export declare function generateToken(): string;
/** 16 random bytes as canonical unpadded base64url (22 characters). */
export declare function generateId(): string;
export declare function isCanonicalInstance(v: unknown): v is string;
export declare function isCanonicalToken(v: unknown): v is string;
export declare function isCanonicalId(v: unknown): v is string;
export declare function identityKey(id: PeerIdentity): string;
export declare function identityEquals(a: PeerIdentity, b: PeerIdentity): boolean;
/** Canonical peer names: 1-24 lowercase characters starting alphanumeric. */
export declare const PEER_NAME_PATTERN: RegExp;
/** True for usable user-facing names; rejects `all`, `main`, and `p-<22 hex>` aliases. */
export declare function isValidPeerName(name: string): boolean;
/** Trim, lowercase, strip control characters; empty string when unusable. */
export declare function normalizeNameInput(raw: string): string;
/** Stable collision alias: `p-` plus the first 22 hex chars of sha256 of the full instance. */
export declare function aliasNameFor(instance: string): string;
/** Default name: `<project clamped to 15 chars>-<first 8 instance hex chars>`. */
export declare function defaultNameFor(project: string, instance: string): string;
export interface PeerRecordV2 {
    v: 2;
    pid: number;
    instance: string;
    token: string;
    name: string;
    project: string;
    harness: 'omp';
    startedAt: number;
    beatAt: number;
    busy: boolean;
}
export type ParsedRecord = {
    kind: 'v2';
    record: PeerRecordV2;
} | {
    kind: 'v1';
} | {
    kind: 'future';
    version: number;
} | {
    kind: 'malformed';
};
/** Strict bounded record parse; never throws. Extra fields and non-canonical encodings fail. */
export declare function parseRecord(raw: string): ParsedRecord;
export declare function recordFileName(pid: number, instance: string): string;
/** A beat is fresh through exactly PRESENCE_TTL_MS after it lands, expired just after. */
export declare function isRecordFresh(beatAt: number, now: number): boolean;
export type SuccessCode = 'submitted' | 'followup_submitted' | 'held' | 'reply_consumed' | 'status' | 'pong';
export type RefusalCode = 'bad_frame' | 'unsupported_version' | 'wrong_recipient' | 'unauthenticated' | 'stale_sender' | 'replay' | 'busy' | 'session_transition' | 'shutting_down' | 'host_unavailable';
export type LocalCode = 'connect_timeout' | 'handshake_timeout' | 'closed_before_reply' | 'malformed_reply' | 'receiver_auth_failed' | 'unknown_outcome' | 'not_found' | 'ambiguous_target' | 'self_address' | 'invalid_request' | 'oversized';
export type ResultCode = SuccessCode | RefusalCode | LocalCode;
/**
 * Liveness state projected onto refusal codes: closed answers `shutting_down`,
 * a fenced transcript transition answers `session_transition`, else accepting.
 */
export type AcceptanceState = 'accepting' | 'session_transition' | 'shutting_down';
/** Only these refusals are safe to retry, and only against a newly unique target. */
export declare function isRetryableRefusal(code: ResultCode): boolean;
export declare function isSuccessCode(code: ResultCode): code is SuccessCode;
export interface HelloFrame {
    v: 2;
    type: 'hello';
    id: string;
    to: PeerIdentity;
    clientNonce: string;
}
export interface ChallengeFrame {
    v: 2;
    type: 'challenge';
    id: string;
    from: PeerIdentity;
    clientNonce: string;
    serverNonce: string;
    auth: string;
}
export type MsgPayload = {
    type: 'msg';
    body: string;
    replyTo?: string;
    hop: number;
};
export type StatusReqPayload = {
    type: 'status';
    fields?: string[];
};
export type PingPayload = {
    type: 'ping';
};
export type RequestPayload = MsgPayload | StatusReqPayload | PingPayload;
export interface RequestFrame {
    v: 2;
    type: 'request';
    id: string;
    clientNonce: string;
    serverNonce: string;
    sentAt: number;
    from: PeerIdentity;
    to: PeerIdentity;
    payload: RequestPayload;
    auth: string;
}
export interface StatusSnapshot {
    busy: boolean;
    model?: string;
    activity?: string;
    todos?: PeerTodo[];
}
export interface ReplyFrame {
    v: 2;
    type: 'reply';
    id: string;
    from: PeerIdentity;
    code: ResultCode;
    detail?: string;
    status?: StatusSnapshot;
    auth: string;
}
export declare function parseHello(line: string): HelloFrame | undefined;
export declare function parseChallenge(line: string): ChallengeFrame | undefined;
export declare function parseRequest(line: string): RequestFrame | undefined;
export declare function parseReply(line: string): ReplyFrame | undefined;
/** Compact JSON plus trailing newline. */
export declare function encodeLine(value: unknown): string;
/** Tuple: [id, fromPid, fromInstance, clientNonce, serverNonce], keyed by the receiver token. */
export declare function challengeMac(receiverToken: string, id: string, from: PeerIdentity, clientNonce: string, serverNonce: string): string;
/** Tuple: [id, clientNonce, serverNonce, sentAt, fromPid, fromInstance, toPid, toInstance, payload]. */
export declare function requestMac(senderToken: string, id: string, clientNonce: string, serverNonce: string, sentAt: number, from: PeerIdentity, to: PeerIdentity, payloadCanonical: string): string;
/** Tuple: [id, fromPid, fromInstance, code, detail, status], keyed by the receiver token. */
export declare function replyMac(receiverToken: string, id: string, from: PeerIdentity, code: string, detail: string | null, statusCanonical: string | null): string;
export declare function canonicalRequestPayload(payload: RequestPayload): string;
/** Stable sorted-key JSON of the snapshot, or null when absent. */
export declare function canonicalStatus(snapshot: StatusSnapshot | undefined): string | null;
/** Constant-time comparison of two MAC strings; length mismatch fails without throwing. */
export declare function verifyMac(expected: string, provided: unknown): boolean;
/** True when sentAt sits inside [-MAX_PAST_MS, +MAX_FUTURE_MS] around now, inclusive. */
export declare function isFreshTimestamp(sentAt: unknown, now: number): boolean;
/**
 * Per-binding dedupe of authenticated (sender, id) pairs: up to
 * REPLAY_CACHE_SIZE entries with REPLAY_TTL_MS lifetime. tryInsert is
 * synchronous and atomic; a full cache returns 'full' and never evicts an
 * unexpired id.
 */
export declare class ReplayCache {
    private readonly seen;
    tryInsert(sender: PeerIdentity, id: string, now?: number): 'ok' | 'replay' | 'full';
}
