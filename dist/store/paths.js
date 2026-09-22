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
import { createHash } from 'node:crypto';
import { lstat, mkdir, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { recordFileName } from '../peers/protocol.js';
import { scopeId } from '../peers/scope.js';
/**
 * Resolve, create, and verify the state root, its peers/ child, and the
 * per-codebase scope directory for `scopeKey` (an absolute scope key from
 * resolveWorkspaceScope).
 */
export async function ensureStateRoots(scopeKey, env = process.env) {
    if (process.platform !== 'darwin') {
        throw new Error('peers: unsupported platform, macOS is the only supported target');
    }
    if (scopeKey.trim() === '' || !isAbsolute(scopeKey)) {
        throw new Error(`peers scope key must be an absolute path, got: ${JSON.stringify(scopeKey)}`);
    }
    const requested = resolveRoot(env);
    await tryMkdir(requested);
    await assertPosixDir(requested, 'state root');
    const root = await canonicalize(requested, 'state root');
    const peers = join(root, 'peers');
    await tryMkdir(peers);
    await assertPosixDir(peers, 'peers state directory');
    const scope = scopeId(scopeKey);
    const peersDir = join(peers, scope);
    await tryMkdir(peersDir);
    await assertPosixDir(peersDir, 'peers scope directory');
    return { root, peersDir, scope };
}
/** Presence record path for one exact (pid, instance) pair. */
export function peerRecordPath(roots, pid, instance) {
    return join(roots.peersDir, recordFileName(pid, instance));
}
/**
 * POSIX socket path for one exact (pid, instance) pair:
 * `<peersDir>/<16 hex>.sock`, the first 16 lowercase hex characters of
 * sha256 over `${pid}-${instance}`. The scoped path
 * (`<root>/peers/<16 hex scope>/<16 hex>.sock`) is a fixed 45 bytes past
 * the root whatever the pid, so it stays within the 103-byte macOS ceiling
 * for ordinary home directories. Like the record path, it is derived only
 * from the trusted roots plus a validated identity.
 */
export function peerEndpoint(roots, pid, instance) {
    const name = createHash('sha256').update(`${pid}-${instance}`, 'utf8').digest('hex').slice(0, 16);
    return join(roots.peersDir, `${name}.sock`);
}
/** First 32 lowercase hex characters of sha256 over the canonical allowed root. */
export function rootHash(roots) {
    return createHash('sha256').update(roots.root, 'utf8').digest('hex').slice(0, 32);
}
/** Enforce the sun_path ceiling before bind: 103 bytes on macOS. */
export function validateUnixEndpoint(endpoint) {
    const limit = 103;
    const bytes = Buffer.byteLength(endpoint, 'utf8');
    if (bytes > limit) {
        throw new Error(`unix socket path is ${bytes} bytes; macOS sun_path limit is ${limit}: ${endpoint}`);
    }
}
function resolveRoot(env) {
    const override = env.OMP_PEERS_DIR;
    if (override !== undefined) {
        // A supplied override must be usable: empty or relative values fail closed
        // instead of silently joining the default shared roster.
        if (override.trim() === '' || !isAbsolute(override)) {
            throw new Error(`OMP_PEERS_DIR must be an absolute path, got: ${JSON.stringify(override)}`);
        }
        return resolve(override);
    }
    const home = homedir();
    if (home === '' || !isAbsolute(home)) {
        throw new Error('cannot determine an absolute user home directory for the state root');
    }
    return join(resolve(home), '.omp', 'var', 'omp-peers');
}
async function tryMkdir(dir) {
    try {
        await mkdir(dir, { recursive: true, mode: 0o700 });
    }
    catch {
        // The lstat verification below reports the actionable policy failure.
    }
}
async function assertPosixDir(dir, label) {
    let stats;
    try {
        stats = await lstat(dir);
    }
    catch (err) {
        throw new Error(`${label} is missing or unreadable (${codeOf(err) ?? 'lstat failed'}): ${dir}`);
    }
    if (!stats.isDirectory() || stats.isSymbolicLink()) {
        throw new Error(`${label} must be a real directory, not a symlink or other file: ${dir}`);
    }
    const uid = process.getuid?.();
    if (uid === undefined || stats.uid !== uid) {
        throw new Error(`${label} must be owned by the current user (uid ${stats.uid}, want ${uid ?? 'unknown'}): ${dir}`);
    }
    if ((stats.mode & 0o077) !== 0) {
        const mode = (stats.mode & 0o777).toString(8).padStart(3, '0');
        throw new Error(`${label} has group/other permission bits (mode ${mode}); tighten it to 0700 manually: ${dir}`);
    }
}
async function canonicalize(path, label) {
    try {
        return await realpath(path);
    }
    catch (err) {
        throw new Error(`${label} cannot be canonicalized (${codeOf(err) ?? 'realpath failed'}): ${path}`);
    }
}
function codeOf(err) {
    if (typeof err === 'object' && err !== null && 'code' in err) {
        const code = err.code;
        if (typeof code === 'string')
            return code;
    }
    return undefined;
}
