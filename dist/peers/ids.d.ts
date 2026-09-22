/**
 * Peer identity generation, project metadata, and cross-process name
 * deconfliction (plan section 3). Canonical name rules and alias/default
 * name construction live in `protocol.js`; this module owns the contention
 * decision: (startedAt, pid, instance) ascending owns a contested name and
 * each loser falls back to the stable alias for its own instance.
 */
import type { PeerIdentity, PeerRecordV2 } from './protocol.js';
/** One fresh instance identity: canonical hex instance plus capability token. */
export declare function newIdentity(): {
    instance: string;
    token: string;
};
/**
 * Sanitized basename of the project directory: control characters and path
 * separators stripped, 1-64 UTF-8 bytes, `peer` when nothing usable remains.
 * Never returns an absolute path.
 */
export declare function projectFor(cwd: string): string;
export interface ResolveNameInput {
    requested: string;
    self: PeerIdentity & {
        startedAt: number;
    };
    peers: PeerRecordV2[];
}
/**
 * Resolve a contested name: (startedAt, pid, instance) ascending among the
 * requester and every fresh peer already holding the normalized candidate
 * decides ownership; a losing requester falls back to `aliasNameFor` of its
 * own instance. An unusable or reserved request resolves directly to that
 * alias. Same input set always converges to the same owner on every process.
 */
export declare function resolveName(input: ResolveNameInput): {
    name: string;
    aliased: boolean;
};
/** True when two or more fresh peers share a routable name (ambiguous target). */
export declare function hasDuplicateRoutableNames(peers: PeerRecordV2[]): boolean;
