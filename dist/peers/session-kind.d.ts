/**
 * Origin classification for the factory's first `session_start`. The result is
 * latched once per factory: `nested` and `unknown` are terminal-inert.
 */
import type { SessionManagerLike } from './host.js';
export type SessionKind = 'top-level' | 'nested' | 'unknown';
/**
 * Plan section 2, in order: a `session_init` entry means a task subagent; a
 * non-empty `.jsonl` path inside an artifact directory (sibling parent
 * `.jsonl` exists) means a nested artifact session even without
 * `session_init`; missing getters or malformed id/path mean unknown; a lazy
 * path the file does not carry yet is still a valid top-level root.
 */
export declare function classifySession(manager: SessionManagerLike | undefined): SessionKind;
