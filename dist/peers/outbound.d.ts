/**
 * Outbound v2 exchange: fresh unique-name resolution, receiver-proof challenge
 * verification before any body or credential leaves this side, phase-aware
 * retry rules, and the pending-request correlation store. Every failure
 * resolves to a protocol result code; nothing throws into the agent turn.
 */
import type { AcceptanceState, PeerIdentity, PeerRecordV2, ResultCode, StatusSnapshot } from './protocol.js';
import type { PeerScan } from './presence.js';
import type { StateRoots } from '../store/paths.js';
import type { ManagedTimers } from './server.js';
export interface OutboundResult {
    code: ResultCode;
    detail?: string;
    replyBody?: string;
    status?: StatusSnapshot;
    target?: PeerIdentity;
}
export interface OutboundDeps {
    identity: {
        pid: number;
        instance: string;
        token: string;
    };
    roots: StateRoots;
    managed: ManagedTimers;
    scan(): Promise<PeerScan>;
    pending: PendingStore;
    acceptance(): AcceptanceState;
    log(text: string): void;
}
export type ResolvedTarget = {
    kind: 'unique';
    record: PeerRecordV2;
} | {
    kind: 'missing';
    known: string[];
} | {
    kind: 'ambiguous';
    known: string[];
} | {
    kind: 'self';
};
export declare class PendingStore {
    private readonly slots;
    private outboundSockets;
    /** Reserves one of the MAX_OUTBOUND_SOCKETS concurrent exchange slots. */
    acquireSocket(): boolean;
    /** Releases an exchange slot on every terminal path; never goes negative. */
    releaseSocket(): void;
    /**
     * Reserves the slot and returns its reply promise, captured exactly once
     * here: a settle at any later time resolves this same promise, so a reply
     * arriving before the caller observes it is never lost.
     */
    reserve(id: string, expected: PeerIdentity): Promise<string> | undefined;
    /** Called immediately before socket.write of the request line. */
    markWritten(id: string): void;
    /** Records an authenticated receiver refusal that proves the request never dispatched. */
    noteNoDispatch(id: string): boolean;
    retarget(id: string, expected: PeerIdentity): boolean;
    settle(from: PeerIdentity, replyTo: string, body: string): boolean;
    discard(id: string, code: ResultCode): void;
    rejectAll(code: ResultCode): void;
    size(): number;
}
export declare function resolveTarget(deps: OutboundDeps, to: string): Promise<ResolvedTarget>;
export declare function sendMsg(deps: OutboundDeps, to: string, body: string, opts?: {
    replyTo?: string;
    hop?: number;
    hopFor?: (record: PeerRecordV2) => number;
}): Promise<OutboundResult>;
export declare function requestMsg(deps: OutboundDeps, to: string, body: string, opts?: {
    timeoutMs?: number;
    hop?: number;
    hopFor?: (record: PeerRecordV2) => number;
}): Promise<OutboundResult>;
export declare function statusOf(deps: OutboundDeps, to: string, fields: string[], budget?: {
    deadlineAt: number;
}): Promise<OutboundResult>;
export declare function pingPeer(deps: OutboundDeps, to: string): Promise<OutboundResult>;
