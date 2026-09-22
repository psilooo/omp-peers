/**
 * Durable JSON write primitives.
 *
 * The old plugin died on EPERM races when moving a fresh file over a live one,
 * so this module NEVER moves files over live targets. Target replacement is
 * exclusively the copy-a-sidecar-over-the-target pattern (`copyFile`).
 *
 * Conventions:
 *  - Presence files: owner-only writers, no lock, sidecar + copy pattern.
 *  - Readers of any JSON file tolerate a partial read (a copy can be observed
 *    mid-flight) with one bounded retry.
 */
/**
 * Read and parse one JSON file. Missing file → undefined. A read that lands
 * mid-copy (partial content → parse error, or a transient EPERM/EBUSY) is
 * retried `retries` times with `retryDelayMs` between attempts; persistent
 * parse failure throws CorruptStateError.
 */
export declare function readJsonFile<T = unknown>(filePath: string, opts?: {
    retries?: number;
    retryDelayMs?: number;
}): Promise<T | undefined>;
/**
 * Durably replace a JSON file: write a unique sidecar next to the target,
 * fsync it, copy it over the target, delete the sidecar. The sidecar never
 * coexists with a move over a live file: the target is replaced in place by
 * the copy, so any reader sees either the old or the new content.
 *
 * `mode` (default 0600) applies to the sidecar and is enforced on the target
 * after the copy so records keep their owner-only permission even when a
 * pre-existing target carried different bits.
 */
export declare function durableWriteJson(filePath: string, data: unknown, opts?: {
    pretty?: boolean;
    mode?: number;
}): Promise<void>;
/**
 * Read one file as raw text under a hard byte bound. Returns undefined for a
 * missing or unreadable file, a non-regular file (lstat, so symlinks and
 * sockets are rejected without following them), or content over maxBytes.
 * Reads at most maxBytes + 1 bytes so a file that grows past the bound
 * between stat and read is rejected rather than truncated.
 */
export declare function readJsonBounded(filePath: string, maxBytes: number): Promise<string | undefined>;
