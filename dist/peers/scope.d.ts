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
/** Resolve the canonical codebase scope key for `cwd`. Never throws. */
export declare function resolveWorkspaceScope(cwd: string): Promise<string>;
/** First 16 lowercase hex characters of sha256 over the scope key. */
export declare function scopeId(scopeKey: string): string;
