/**
 * v2 shared contracts for the peers extension: the published todo shape and
 * the in-flight request slot. Presence records, frames, and constants live in
 * `peers/protocol.ts`.
 */
import type { PeerIdentity } from './peers/protocol.js';
/** Statuses mirrored from the host's native todo state. */
export type PeerTodoStatus = 'pending' | 'in_progress' | 'completed' | 'abandoned' | 'blocked';
/**
 * One entry in a peer's published todo list, mirrored from the host's native
 * todo state, not a peer-owned list (see `readNativeTodos`).
 */
export interface PeerTodo {
    id?: string;
    /** Owning phase name from the native list. */
    phase?: string;
    text: string;
    status?: PeerTodoStatus;
    /** What a `blocked` task waits on. */
    blocker?: string;
}
/** In-flight `peer_request` a peer is waiting for a reply to. */
export interface PendingRequest {
    /** Identity the reply must come from. */
    expected: PeerIdentity;
    resolve: (body: string) => void;
    reject: (err: Error) => void;
    timer?: unknown;
    /** True once a request body write started. */
    written: boolean;
}
