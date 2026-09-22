/**
 * Peer identity generation, project metadata, and cross-process name
 * deconfliction (plan section 3). Canonical name rules and alias/default
 * name construction live in `protocol.js`; this module owns the contention
 * decision: (startedAt, pid, instance) ascending owns a contested name and
 * each loser falls back to the stable alias for its own instance.
 */
import { basename } from 'node:path';
import { PROJECT_MAX_BYTES, aliasNameFor, generateInstance, generateToken, isValidPeerName, normalizeNameInput, } from './protocol.js';
/** One fresh instance identity: canonical hex instance plus capability token. */
export function newIdentity() {
    return { instance: generateInstance(), token: generateToken() };
}
/**
 * Sanitized basename of the project directory: control characters and path
 * separators stripped, 1-64 UTF-8 bytes, `peer` when nothing usable remains.
 * Never returns an absolute path.
 */
export function projectFor(cwd) {
    const cleaned = basename(cwd)
        .replace(/[\u0000-\u001f\u007f]/g, '')
        .replace(/[\\/]/g, '')
        .trim();
    if (cleaned === '' || cleaned === '.' || cleaned === '..') {
        return 'peer';
    }
    if (Buffer.byteLength(cleaned, 'utf8') <= PROJECT_MAX_BYTES) {
        return cleaned;
    }
    let clamped = '';
    let bytes = 0;
    for (const char of cleaned) {
        const size = Buffer.byteLength(char, 'utf8');
        if (bytes + size > PROJECT_MAX_BYTES) {
            break;
        }
        clamped += char;
        bytes += size;
    }
    return clamped === '' ? 'peer' : clamped;
}
/**
 * Resolve a contested name: (startedAt, pid, instance) ascending among the
 * requester and every fresh peer already holding the normalized candidate
 * decides ownership; a losing requester falls back to `aliasNameFor` of its
 * own instance. An unusable or reserved request resolves directly to that
 * alias. Same input set always converges to the same owner on every process.
 */
export function resolveName(input) {
    const candidate = normalizeNameInput(input.requested);
    if (candidate === '' || !isValidPeerName(candidate)) {
        return { name: aliasNameFor(input.self.instance), aliased: true };
    }
    const contenders = [
        { pid: input.self.pid, instance: input.self.instance, startedAt: input.self.startedAt },
        ...input.peers
            .filter((peer) => peer.name === candidate)
            .map((peer) => ({ pid: peer.pid, instance: peer.instance, startedAt: peer.startedAt })),
    ];
    contenders.sort((a, b) => {
        if (a.startedAt !== b.startedAt)
            return a.startedAt - b.startedAt;
        if (a.pid !== b.pid)
            return a.pid - b.pid;
        return a.instance < b.instance ? -1 : a.instance > b.instance ? 1 : 0;
    });
    const owner = contenders[0];
    const selfOwns = owner.pid === input.self.pid && owner.instance === input.self.instance;
    if (selfOwns) {
        return { name: candidate, aliased: false };
    }
    return { name: aliasNameFor(input.self.instance), aliased: true };
}
/** True when two or more fresh peers share a routable name (ambiguous target). */
export function hasDuplicateRoutableNames(peers) {
    const seen = new Set();
    for (const peer of peers) {
        if (seen.has(peer.name)) {
            return true;
        }
        seen.add(peer.name);
    }
    return false;
}
