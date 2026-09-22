/**
 * `/peers` - sanitized text list of the peer snapshot: routable rows, held
 * count, incompatible v1/future rows (shown, never dialed), and the armed or
 * diagnostic state. The interactive picker runs only when `ctx.ui.select` is
 * callable and `ctx.mode === 'tui'`; the text list always renders otherwise.
 * Every untrusted field passes `sanitizeDisplay` with bounds from the
 * protocol constants, so status data cannot escape the rendering.
 */
import type { ExtensionHostLike } from '../peers/host.js';
import type { RosterRow } from '../peers/roster.js';
export interface PeersSnapshot {
    self: {
        name: string;
        project: string;
    };
    rows: RosterRow[];
    /** Live v1/future records: shown as incompatible, never dialed. */
    incompatible: Array<{
        pid: number;
        version: number;
    }>;
    held: number;
    armed: boolean;
    /** Exact diagnostic text when not armed. */
    diagnostic?: string;
}
/** `` `name` · project · working · beat 3s ago · model ... · you `` */
export declare function formatPeerLine(row: RosterRow, selfName: string): string;
export declare function formatPeersText(snap: PeersSnapshot, now: number): string;
export declare function registerPeersCommand(pi: ExtensionHostLike, getSnapshot: () => Promise<PeersSnapshot>): void;
