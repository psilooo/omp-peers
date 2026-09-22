/**
 * State-root policy (plan section 4): one fail-closed resolution shared by
 * the default root, the OMP_PEERS_DIR override, and the peers/ child, plus
 * the derived record and endpoint paths.
 *
 * POSIX: both directories must be real (non-symlink) directories owned by
 * the current user with no group/other permission bits; missing directories
 * are created 0700 and re-verified; pre-existing directories are never
 * chmodded, only rejected. macOS is the only supported platform; any other
 * platform fails closed before any filesystem work. OMP_PEERS_DIR must be
 * absolute and is canonicalized before endpoint hashing.
 */
export interface StateRoots {
    /** Canonical absolute state root. */
    root: string;
    /** Canonical absolute presence directory beneath `root`. */
    peersDir: string;
}
/** Resolve, create, and verify the state root and its peers/ child. */
export declare function ensureStateRoots(env?: NodeJS.ProcessEnv): Promise<StateRoots>;
/** Presence record path for one exact (pid, instance) pair. */
export declare function peerRecordPath(roots: StateRoots, pid: number, instance: string): string;
/** POSIX socket path for one exact (pid, instance) pair. */
export declare function peerEndpoint(roots: StateRoots, pid: number, instance: string): string;
/** First 32 lowercase hex characters of sha256 over the canonical allowed root. */
export declare function rootHash(roots: StateRoots): string;
/** Enforce the sun_path ceiling before bind: 103 bytes on macOS. */
export declare function validateUnixEndpoint(endpoint: string): void;
