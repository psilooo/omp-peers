/**
 * Presence v2: one owner-written heartbeat record per peer process under
 * <roots.peersDir>. Reads are bounded and ownership-checked; retention
 * follows plan section 3 exactly:
 *
 *  - a beat is fresh through exactly PRESENCE_TTL_MS and expired just after;
 *  - only an ESRCH pid probe may unlink a record (and, for an exact v2
 *    (pid, instance) pair, its derived endpoint); EPERM, access denied, and
 *    unknown probe errors mean alive/unknown, so the record is retained;
 *  - expired or malformed records owned by a live pid are ignored, retained,
 *    and never dialed;
 *  - future versions are ignored, never deleted; live v1 records are shown
 *    as incompatible and never dialed; a dead v1 record may be removed but
 *    its legacy PID-only socket is never unlinked automatically;
 *  - every path comes from the trusted roots plus a validated (pid,
 *    instance), never from record content.
 */
import type { StateRoots } from '../store/paths.js';
import type { PeerIdentity, PeerRecordV2 } from './protocol.js';
export interface PeerScan {
    /** Fresh, live-pid, valid v2 records; name convergence is the caller's job. */
    routable: PeerRecordV2[];
    /** Live v1/future records: shown for diagnostics, never dialed. */
    incompatible: Array<{
        pid: number;
        version: number;
    }>;
}
/** Write (or refresh) this process's record atomically at 0600 on POSIX. */
export declare function writeOwnRecord(roots: StateRoots, record: PeerRecordV2): Promise<void>;
/**
 * Bounded directory scan: at most MAX_DIR_ENTRIES entries examined, each
 * record read through an 8 KiB bound after regular/non-symlink/owner/mode
 * checks. Never throws; a missing or unreadable directory yields an empty
 * scan.
 */
export declare function scanPeers(roots: StateRoots, self: PeerIdentity, now?: number): Promise<PeerScan>;
/**
 * Read a single record under exactly the scan acceptance rules (8 KiB bound,
 * regular/non-symlink/owner/mode, identity match, freshness, live pid).
 * Returns undefined when unusable, stale, or the pid is provably dead.
 */
export declare function readPeerRecord(roots: StateRoots, pid: number, instance: string, now?: number): Promise<PeerRecordV2 | undefined>;
/**
 * Remove only this process's exact (pid, instance) record and its derived
 * endpoint. Invalid identity arguments are ignored rather than resolved into
 * a path; unlink failures never propagate.
 */
export declare function removeOwnRecord(roots: StateRoots, pid: number, instance: string): Promise<void>;
/** `3s ago` / `12m ago` / `2h ago` for the `/peers` beat-age column. */
export declare function formatBeatAge(beatAt: number, now?: number): string;
