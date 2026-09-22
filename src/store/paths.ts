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

import { createHash } from 'node:crypto';
import { lstat, mkdir, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

import { recordFileName } from '../peers/protocol.js';

export interface StateRoots {
  /** Canonical absolute state root. */
  root: string;
  /** Canonical absolute presence directory beneath `root`. */
  peersDir: string;
}

/** Resolve, create, and verify the state root and its peers/ child. */
export async function ensureStateRoots(env: NodeJS.ProcessEnv = process.env): Promise<StateRoots> {
  if (process.platform !== 'darwin') {
    throw new Error('peers: unsupported platform, macOS is the only supported target');
  }
  const requested = resolveRoot(env);
  await tryMkdir(requested);
  await assertPosixDir(requested, 'state root');
  const root = await canonicalize(requested, 'state root');
  const peers = join(root, 'peers');
  await tryMkdir(peers);
  await assertPosixDir(peers, 'peers state directory');
  return { root, peersDir: peers };
}

/** Presence record path for one exact (pid, instance) pair. */
export function peerRecordPath(roots: StateRoots, pid: number, instance: string): string {
  return join(roots.peersDir, recordFileName(pid, instance));
}

/** POSIX socket path for one exact (pid, instance) pair. */
export function peerEndpoint(roots: StateRoots, pid: number, instance: string): string {
  return join(roots.peersDir, `${pid}-${instance}.sock`);
}

/** First 32 lowercase hex characters of sha256 over the canonical allowed root. */
export function rootHash(roots: StateRoots): string {
  return createHash('sha256').update(roots.root, 'utf8').digest('hex').slice(0, 32);
}

/** Enforce the sun_path ceiling before bind: 103 bytes on macOS. */
export function validateUnixEndpoint(endpoint: string): void {
  const limit = 103;
  const bytes = Buffer.byteLength(endpoint, 'utf8');
  if (bytes > limit) {
    throw new Error(`unix socket path is ${bytes} bytes; macOS sun_path limit is ${limit}: ${endpoint}`);
  }
}

function resolveRoot(env: NodeJS.ProcessEnv): string {
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

async function tryMkdir(dir: string): Promise<void> {
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
  } catch {
    // The lstat verification below reports the actionable policy failure.
  }
}

async function assertPosixDir(dir: string, label: string): Promise<void> {
  let stats;
  try {
    stats = await lstat(dir);
  } catch (err) {
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

async function canonicalize(path: string, label: string): Promise<string> {
  try {
    return await realpath(path);
  } catch (err) {
    throw new Error(`${label} cannot be canonicalized (${codeOf(err) ?? 'realpath failed'}): ${path}`);
  }
}

function codeOf(err: unknown): string | undefined {
  if (typeof err === 'object' && err !== null && 'code' in err) {
    const code = (err as { code?: unknown }).code;
    if (typeof code === 'string') return code;
  }
  return undefined;
}
