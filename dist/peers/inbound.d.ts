/**
 * Inbound delivery: hand accepted peer envelopes to the LOCAL agent through
 * the extension-host surface.
 *
 * One sealed batch is one host submission joining its already-rendered
 * bodies with newlines. Wake budgeting is per verified (pid, instance)
 * plus one process-global ring; that ring is the only module-scoped
 * mutable state allowed in the repo.
 */
import type { CommandContextLike, ExtensionHostLike } from './host.js';
import type { PendingStore } from './outbound.js';
import type { AcceptanceState, PeerIdentity } from './protocol.js';
import type { AuthenticatedEnvelope, EpochSnapshot, HostDelivery } from './server.js';
/** Per-verified-(pid,instance) wake budget over the rolling hour. */
export declare class WakeLimiter {
    private readonly wakes;
    /**
     * True when `key` has no wake budget left. An unseen key is over budget
     * once MAX_WAKE_IDENTITIES fresh identities fill the table, until entries
     * age past WAKE_WINDOW_MS and prune away.
     */
    overBudget(key: PeerIdentity, now?: number): boolean;
    /** Records one real wake for `key`; false when over WAKES_PER_HOUR or the identity table is full. */
    noteWake(key: PeerIdentity, now?: number): boolean;
    private prune;
}
/**
 * The one process-global wake gate: a fixed ring of at most
 * PROCESS_WAKES_PER_HOUR timestamps per rolling hour, shared by every
 * binding. Holds timestamps only.
 */
export declare function processWakeAllowed(now?: number): boolean;
/** `[peer <name>]: <body> [id <id>]` so the agent can quote the exact message id when replying. */
export declare function formatPeerText(from: string, body: string, opts: {
    id: string;
}): string;
export declare function createHostDelivery(opts: {
    getHost: () => {
        pi: ExtensionHostLike;
        ctx: CommandContextLike;
    } | undefined;
    pending: PendingStore;
    wakes: WakeLimiter;
    heldCount: () => number;
    acceptance: () => AcceptanceState;
    /** Whether the binding is armed: record published and live. */
    armed: () => boolean;
    /** Shared not-armed diagnostic; identical to the binding's gate text. */
    notArmedDetail: () => string;
    onSubmitted: (envelopes: AuthenticatedEnvelope[]) => void;
    captureEpoch: () => EpochSnapshot;
    isEpochValid: (captured: EpochSnapshot) => boolean;
    getActivity?: () => string | undefined;
}): HostDelivery;
