/**
 * State-root policy (plan section 4): one fail-closed resolution shared by
 * the default root, the OMP_PEERS_DIR override, the peers/ child, and the
 * per-codebase scope directory, plus the derived record and endpoint paths.
 *
 * Layout: `<root>/peers/<scopeId>/` holds the presence records and sockets
 * of every session in one codebase (see peers/scope.ts). Scans and inbound
 * sender authentication only ever read the session's own scope directory,
 * so sessions in other codebases are invisible and unreachable by
 * construction. Flat records left directly in `peers/` by older versions are
 * never scanned and are therefore ignored.
 *
 * POSIX: every directory must be a real (non-symlink) directory owned by
 * the current user with no group/other permission bits; missing directories
 * are created 0700 and re-verified; pre-existing directories are never
 * chmodded, only rejected. macOS is the only supported platform; any other
 * platform fails closed before any filesystem work. OMP_PEERS_DIR must be
 * absolute and is canonicalized before endpoint hashing.
 */
export interface StateRoots {
    /** Canonical absolute state root. */
    root: string;
    /** Canonical absolute presence directory for this codebase: `<root>/peers/<scope>`. */
    peersDir: string;
    /** Scope id of the codebase (scopeId of the scope key) naming `peersDir`. */
    scope: string;
}
/**
 * Resolve, create, and verify the state root, its peers/ child, and the
 * per-codebase scope directory for `scopeKey` (an absolute scope key from
 * resolveWorkspaceScope).
 */
export declare function ensureStateRoots(scopeKey: string, env?: NodeJS.ProcessEnv): Promise<StateRoots>;
/** Presence record path for one exact (pid, instance) pair. */
export declare function peerRecordPath(roots: StateRoots, pid: number, instance: string): string;
/**
 * POSIX socket path for one exact (pid, instance) pair:
 * `<peersDir>/<16 hex>.sock`, the first 16 lowercase hex characters of
 * sha256 over `${pid}-${instance}`. The scoped path
 * (`<root>/peers/<16 hex scope>/<16 hex>.sock`) is a fixed 45 bytes past
 * the root whatever the pid, so it stays within the 103-byte macOS ceiling
 * for ordinary home directories. Like the record path, it is derived only
 * from the trusted roots plus a validated identity.
 */
export declare function peerEndpoint(roots: StateRoots, pid: number, instance: string): string;
/** First 32 lowercase hex characters of sha256 over the canonical allowed root. */
export declare function rootHash(roots: StateRoots): string;
/** Enforce the sun_path ceiling before bind: 103 bytes on macOS. */
export declare function validateUnixEndpoint(endpoint: string): void;
