/**
 * Origin classification for the factory's first `session_start`. The result is
 * latched once per factory: `nested` and `unknown` are terminal-inert.
 */

import { existsSync } from 'node:fs';
import { dirname } from 'node:path';

import type { SessionManagerLike } from './host.js';

export type SessionKind = 'top-level' | 'nested' | 'unknown';

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
}

/**
 * Plan section 2, in order: a `session_init` entry means a task subagent; a
 * non-empty `.jsonl` path inside an artifact directory (sibling parent
 * `.jsonl` exists) means a nested artifact session even without
 * `session_init`; missing getters or malformed id/path mean unknown; a lazy
 * path the file does not carry yet is still a valid top-level root.
 */
export function classifySession(manager: SessionManagerLike | undefined): SessionKind {
  if (manager === undefined || manager === null) return 'unknown';

  let entriesReadable = false;
  const lists: unknown[][] = [];
  for (const read of [manager.getBranch, manager.getEntries]) {
    if (typeof read !== 'function') continue;
    try {
      const value = read.call(manager);
      entriesReadable = true;
      if (Array.isArray(value)) lists.push(value);
    } catch {
      // Getter presence is recorded; unreadable data yields no evidence.
    }
  }
  for (const entries of lists) {
    for (const entry of entries) {
      if (asRecord(entry)?.['type'] === 'session_init') return 'nested';
    }
  }

  // The path getter is present on the real host manager even though it is not
  // part of the minimal structural contract above.
  let file: string | undefined;
  const readFile = asRecord(manager)?.['getSessionFile'];
  if (typeof readFile === 'function') {
    try {
      const value = (readFile as () => unknown).call(manager);
      if (typeof value === 'string') file = value;
    } catch {
      file = undefined;
    }
  }
  if (file !== undefined && file.endsWith('.jsonl') && file !== '') {
    try {
      if (existsSync(`${dirname(file)}.jsonl`)) return 'nested';
    } catch {
      // Filesystem probing is best-effort; no match counts as top-level evidence.
    }
  }

  let id: unknown;
  try {
    id = manager.getSessionId?.();
  } catch {
    id = undefined;
  }
  const idValid = typeof id === 'string' && id.trim() !== '';
  const fileValid = typeof file === 'string' && file !== '' && file.endsWith('.jsonl');
  if (!entriesReadable || !idValid || !fileValid) return 'unknown';
  return 'top-level';
}
