/**
 * Codebase scope: the key that locks peer discovery and messaging to one
 * codebase.
 *
 * The scope key is the canonical path of the git COMMON directory when the
 * working directory is inside a git repository or a linked worktree, else the
 * canonical working directory itself. The common dir (not the worktree root)
 * is used because every linked worktree of one repository shares it: they are
 * the same codebase checked out in several places, so their sessions must see
 * each other. Subdirectories of one repository resolve to the same key.
 *
 * Each scope owns a separate presence and socket directory derived from
 * scopeId(scopeKey), so sessions in other codebases are never scanned and
 * cannot authenticate inbound. Resolution reads only small files, spawns no
 * child processes, and never throws: any failure falls back to the canonical
 * working directory, which yields a narrower (never wider) scope.
 */

import { createHash } from 'node:crypto';
import { lstat, open, realpath, type FileHandle } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

/** Upper bound for `.git` pointer files and `commondir` contents. */
const MAX_POINTER_BYTES = 4096;

/** Resolve the canonical codebase scope key for `cwd`. Never throws. */
export async function resolveWorkspaceScope(cwd: string): Promise<string> {
  const start = await canonicalOr(cwd);
  try {
    const gitDir = await findGitDir(start);
    if (gitDir === undefined) return start;
    const common = await commonDirOf(gitDir);
    if (common === undefined) return start;
    return await canonicalOr(common);
  } catch {
    return start;
  }
}

/** First 16 lowercase hex characters of sha256 over the scope key. */
export function scopeId(scopeKey: string): string {
  return createHash('sha256').update(scopeKey, 'utf8').digest('hex').slice(0, 16);
}

/**
 * Walk from `start` to the filesystem root and return the git dir named by
 * the first `.git` entry found. `undefined` means none was found or the
 * first one could not be parsed; either way the caller falls back.
 */
async function findGitDir(start: string): Promise<string | undefined> {
  let dir = start;
  for (;;) {
    const dotGit = join(dir, '.git');
    const stats = await lstat(dotGit).catch(() => undefined);
    if (stats?.isDirectory()) return dotGit;
    if (stats?.isFile()) {
      const text = await readSmallText(dotGit);
      if (text === undefined || !text.startsWith('gitdir:')) return undefined;
      const value = text.slice('gitdir:'.length).trim();
      return value === '' ? undefined : resolve(dir, value);
    }
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/** The common dir for `gitDir`: its `commondir` target when present, else itself. */
async function commonDirOf(gitDir: string): Promise<string | undefined> {
  const pointer = join(gitDir, 'commondir');
  const stats = await lstat(pointer).catch(() => undefined);
  if (!stats?.isFile()) return gitDir;
  const text = await readSmallText(pointer);
  const value = text?.trim();
  if (value === undefined || value === '') return undefined;
  return resolve(gitDir, value);
}

/** Read a regular file of at most MAX_POINTER_BYTES as utf8, else undefined. */
async function readSmallText(path: string): Promise<string | undefined> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, 'r');
    const stats = await handle.stat();
    if (!stats.isFile() || stats.size > MAX_POINTER_BYTES) return undefined;
    const buffer = Buffer.alloc(MAX_POINTER_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > MAX_POINTER_BYTES) return undefined;
    return buffer.toString('utf8', 0, bytesRead);
  } catch {
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function canonicalOr(path: string): Promise<string> {
  try {
    return await realpath(path);
  } catch {
    return resolve(path);
  }
}
