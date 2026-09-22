/**
 * Protocol v2 receiver: one bounded hello -> challenge -> request exchange per
 * connection with receiver proof before body disclosure, an exhaustive
 * one-request router, per-sender FIFO batching, and held retention/pump.
 * Never throws into the host and never waits for EOF (Bun 1.3.14 Windows
 * pipes do not support the required half-close).
 */
import type { StateRoots } from '../store/paths.js';
import type { AcceptanceState, PeerIdentity, ResultCode, StatusSnapshot } from './protocol.js';
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
    submitBatch(envelopes: AuthenticatedEnvelope[]): Promise<{
        code: ResultCode;
        detail?: string;
    }>;
    canSubmitNow(): boolean;
    /** Pre-dispatch admission: undefined to proceed, else the exact refusal code with bounded detail.
     *  Subsumes acceptance(): closed => shutting_down, transitionPending => session_transition, and
     *  not-yet-armed (before record publication) => host_unavailable with the shared diagnostic. */
    admissionCode(): {
        code: ResultCode;
        detail?: string;
    } | undefined;
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
export declare function startPeerServer(opts: {
    endpoint: string;
    roots: StateRoots;
    identity: {
        pid: number;
        instance: string;
        token: string;
    };
    delivery: HostDelivery;
    managed: ManagedTimers;
    log: (text: string) => void;
}): ServerHandle;
