/**
 * Presence v2: one owner-written heartbeat record per peer process under
 * <roots.peersDir>. Reads are bounded and ownership-checked; retention
 * follows plan section 3 exactly:
 *
 *  - a beat is fresh through exactly PRESENCE_TTL_MS and expired just after;
 *  - only an ESRCH pid probe may unlink a record (and, for an exact v2
 *    (pid, instance) pair, its derived endpoint); EPERM, access denied, and
 *    unknown probe errors mean alive/unknown, so the record is retained;
 *  - expired or malformed records owned by a live pid are ignored, retained,
 *    and never dialed;
 *  - future versions are ignored, never deleted; live v1 records are shown
 *    as incompatible and never dialed; a dead v1 record may be removed but
 *    its legacy PID-only socket is never unlinked automatically;
 *  - every path comes from the trusted roots plus a validated (pid,
 *    instance), never from record content.
 */
import { unlinkSync } from 'node:fs';
import { lstat, opendir, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delayMs } from 'node:timers/promises';
import { durableWriteJson, readJsonBounded } from '../store/atomic.js';
import { peerEndpoint, peerRecordPath } from '../store/paths.js';
import { MAX_DIR_ENTRIES, MAX_ROUTABLE_PEERS, RECORD_MAX_BYTES, isCanonicalInstance, isRecordFresh, parseRecord, } from './protocol.js';
const PID_MAX = 2147483647;
const V2_ENTRY_NAME = /^([1-9]\d*)-([0-9a-f]{32})\.json$/;
const V1_ENTRY_NAME = /^([1-9]\d*)\.json$/;
/** Signal 0 probe: ESRCH is the only ground for `dead`; EPERM means alive. */
function probePid(pid) {
    if (!Number.isInteger(pid) || pid < 1 || pid > PID_MAX) {
        return 'unknown';
    }
    try {
        process.kill(pid, 0);
        return 'alive';
    }
    catch (err) {
        const code = err.code;
        if (code === 'ESRCH')
            return 'dead';
        if (code === 'EPERM')
            return 'alive';
        return 'unknown';
    }
}
/** True only for a regular, non-symlink file that is ours and owner-only on POSIX. */
async function recordFileOk(path) {
    let stats;
    try {
        stats = await lstat(path);
    }
    catch {
        return false;
    }
    if (!stats.isFile()) {
        // lstat: symlinks, sockets, and directories are all non-files.
        return false;
    }
    const uid = process.getuid?.();
    if (uid === undefined || stats.uid !== uid) {
        return false;
    }
    return (stats.mode & 0o077) === 0;
}
async function unlinkQuiet(path) {
    try {
        await unlink(path);
    }
    catch {
        // Absent or not removable; cleanup paths never propagate errors.
    }
}
const READ_RETRY_DELAY_MS = 50;
/** One bounded read; a torn parse or transient failure is retryable, a
 * confirmed oversize body fails deterministically. */
async function readParsedOnce(path) {
    const raw = await readJsonBounded(path, RECORD_MAX_BYTES);
    const parsed = raw === undefined ? undefined : parseRecord(raw);
    if (parsed !== undefined && parsed.kind !== 'malformed')
        return { parsed, retryable: false };
    if (raw === undefined) {
        let size = -1;
        try {
            size = (await lstat(path)).size;
        }
        catch {
            size = -1;
        }
        if (size > RECORD_MAX_BYTES)
            return { parsed, retryable: false };
    }
    return { parsed, retryable: true };
}
/**
 * Single-record path: exactly one delayed reread after an unusable first
 * read. Records are overwritten in place, so a concurrent heartbeat can
 * expose a partial body. The scan path batches its rereads behind one shared
 * window instead (scanPeers), so retained unusable records can never
 * serialize their delays into the status or send deadlines.
 */
async function readParsedRecord(path) {
    const first = await readParsedOnce(path);
    if (!first.retryable)
        return first.parsed;
    await delayMs(READ_RETRY_DELAY_MS);
    const retried = await readParsedOnce(path);
    return retried.parsed;
}
function parseEntryName(name) {
    const v2 = V2_ENTRY_NAME.exec(name);
    if (v2 !== null) {
        const pid = Number(v2[1]);
        return pid <= PID_MAX ? { pid, instance: v2[2] } : undefined;
    }
    const v1 = V1_ENTRY_NAME.exec(name);
    if (v1 !== null) {
        const pid = Number(v1[1]);
        return pid <= PID_MAX ? { pid, instance: null } : undefined;
    }
    return undefined;
}
async function classifyEntry(roots, self, now, name, deferred) {
    const id = parseEntryName(name);
    if (id === undefined) {
        return undefined;
    }
    const legacy = id.instance === null;
    const recordPath = legacy ? join(roots.peersDir, name) : peerRecordPath(roots, id.pid, id.instance ?? '');
    const isSelf = id.instance !== null && id.pid === self.pid && id.instance === self.instance;
    const liveness = isSelf ? 'alive' : probePid(id.pid);
    const readable = await recordFileOk(recordPath);
    const first = readable ? await readParsedOnce(recordPath) : { parsed: undefined, retryable: false };
    if (first.retryable) {
        deferred.push({ id, legacy, liveness, recordPath, firstParsed: first.parsed });
        return undefined;
    }
    return finishEntry(roots, now, id, legacy, liveness, recordPath, first.parsed);
}
async function finishEntry(roots, now, id, legacy, liveness, recordPath, parsed) {
    if (liveness === 'dead') {
        // Never delete a future version, and never delete what cannot be read:
        // either could belong to a newer plugin.
        if (parsed === undefined || parsed.kind === 'future') {
            return undefined;
        }
        await unlinkQuiet(recordPath);
        if (id.instance !== null) {
            await unlinkQuiet(peerEndpoint(roots, id.pid, id.instance));
        }
        return undefined;
    }
    if (parsed === undefined) {
        return undefined;
    }
    if (parsed.kind === 'future') {
        return { kind: 'incompatible', pid: id.pid, version: parsed.version };
    }
    if (legacy) {
        return parsed.kind === 'v1' ? { kind: 'incompatible', pid: id.pid, version: 1 } : undefined;
    }
    if (parsed.kind !== 'v2') {
        // Filename/content identity mismatch or malformed body: ignore, retain.
        return undefined;
    }
    const record = parsed.record;
    if (record.pid !== id.pid || record.instance !== id.instance) {
        return undefined;
    }
    if (!isRecordFresh(record.beatAt, now)) {
        return undefined;
    }
    return { kind: 'routable', record };
}
/** Write (or refresh) this process's record atomically at 0600 on POSIX. */
export async function writeOwnRecord(roots, record) {
    if (!Number.isInteger(record.pid) || record.pid < 1 || record.pid > PID_MAX) {
        throw new Error('refusing to write a presence record with an out-of-range pid');
    }
    if (!isCanonicalInstance(record.instance)) {
        throw new Error('refusing to write a presence record with a non-canonical instance');
    }
    await durableWriteJson(peerRecordPath(roots, record.pid, record.instance), record, {
        pretty: false,
        mode: 0o600,
    });
}
/**
 * Bounded directory scan: at most MAX_DIR_ENTRIES entries examined, each
 * record read through an 8 KiB bound after regular/non-symlink/owner/mode
 * checks. Never throws; a missing or unreadable directory yields an empty
 * scan.
 */
export async function scanPeers(roots, self, now = Date.now()) {
    const routable = [];
    const incompatible = [];
    let handle;
    try {
        handle = await opendir(roots.peersDir);
    }
    catch {
        return { routable, incompatible };
    }
    let seen = 0;
    // Torn or transiently unreadable entries wait for one shared healing
    // window and are reread together, so retained unusable records can never
    // serialize 50 ms delays into the status or send deadlines.
    const deferred = [];
    try {
        for await (const entry of handle) {
            if (seen >= MAX_DIR_ENTRIES) {
                break;
            }
            seen += 1;
            try {
                const outcome = await classifyEntry(roots, self, now, entry.name, deferred);
                if (outcome === undefined) {
                    continue;
                }
                if (outcome.kind === 'incompatible') {
                    incompatible.push({ pid: outcome.pid, version: outcome.version });
                }
                else if (routable.length < MAX_ROUTABLE_PEERS) {
                    routable.push(outcome.record);
                }
            }
            catch {
                // One bad entry never aborts or fails the scan.
            }
        }
    }
    catch {
        // Iteration failure returns whatever was classified so far.
    }
    if (deferred.length > 0) {
        await delayMs(READ_RETRY_DELAY_MS);
        for (const candidate of deferred) {
            try {
                const retried = await readParsedOnce(candidate.recordPath);
                const outcome = await finishEntry(roots, now, candidate.id, candidate.legacy, candidate.liveness, candidate.recordPath, retried.parsed ?? candidate.firstParsed);
                if (outcome === undefined) {
                    continue;
                }
                if (outcome.kind === 'incompatible') {
                    incompatible.push({ pid: outcome.pid, version: outcome.version });
                }
                else if (routable.length < MAX_ROUTABLE_PEERS) {
                    routable.push(outcome.record);
                }
            }
            catch {
                // One bad entry never aborts or fails the scan.
            }
        }
    }
    return { routable, incompatible };
}
/**
 * Read a single record under exactly the scan acceptance rules (8 KiB bound,
 * regular/non-symlink/owner/mode, identity match, freshness, live pid).
 * Returns undefined when unusable, stale, or the pid is provably dead.
 */
export async function readPeerRecord(roots, pid, instance, now = Date.now()) {
    if (!Number.isInteger(pid) || pid < 1 || pid > PID_MAX) {
        return undefined;
    }
    if (!isCanonicalInstance(instance)) {
        return undefined;
    }
    const path = peerRecordPath(roots, pid, instance);
    if (!(await recordFileOk(path))) {
        return undefined;
    }
    const parsed = await readParsedRecord(path);
    if (parsed === undefined || parsed.kind !== 'v2') {
        return undefined;
    }
    const record = parsed.record;
    if (record.pid !== pid || record.instance !== instance) {
        return undefined;
    }
    if (!isRecordFresh(record.beatAt, now)) {
        return undefined;
    }
    if (probePid(pid) === 'dead') {
        return undefined;
    }
    return record;
}
/**
 * Remove only this process's exact (pid, instance) record and its derived
 * endpoint. Invalid identity arguments are ignored rather than resolved into
 * a path; unlink failures never propagate.
 */
export async function removeOwnRecord(roots, pid, instance) {
    if (!Number.isInteger(pid) || pid < 1 || pid > PID_MAX) {
        return;
    }
    if (!isCanonicalInstance(instance)) {
        return;
    }
    await unlinkQuiet(peerRecordPath(roots, pid, instance));
    await unlinkQuiet(peerEndpoint(roots, pid, instance));
}
/**
 * Synchronous teardown twin for the shutdown path: the host may exit the
 * moment the shutdown handler returns, so the own record and endpoint must be
 * gone before that. Same identity validation and silent-absence semantics.
 */
export function removeOwnRecordSync(roots, pid, instance) {
    if (!Number.isInteger(pid) || pid < 1 || pid > PID_MAX) {
        return;
    }
    if (!isCanonicalInstance(instance)) {
        return;
    }
    for (const path of [peerRecordPath(roots, pid, instance), peerEndpoint(roots, pid, instance)]) {
        try {
            unlinkSync(path);
        }
        catch {
            // Absent or not removable; teardown never propagates errors.
        }
    }
}
/** `3s ago` / `12m ago` / `2h ago` for the `/peers` beat-age column. */
export function formatBeatAge(beatAt, now = Date.now()) {
    const secs = Math.max(0, Math.floor((now - beatAt) / 1000));
    if (secs < 60)
        return `${secs}s ago`;
    const mins = Math.floor(secs / 60);
    if (mins < 60)
        return `${mins}m ago`;
    return `${Math.floor(mins / 60)}h ago`;
}
