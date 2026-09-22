/**
 * Inbound delivery: hand accepted peer envelopes to the LOCAL agent through
 * the extension-host surface.
 *
 * One sealed batch is one host submission joining its already-rendered
 * bodies with newlines. Wake budgeting is per verified (pid, instance)
 * plus one process-global ring; that ring is the only module-scoped
 * mutable state allowed in the repo.
 */
import { readBusy, readModel, readNativeTodos } from './host.js';
import { MAX_HELD_BATCHES, MAX_STATUS_ACTIVITY_BYTES, MAX_STATUS_TODOS, MAX_STATUS_TEXT_BYTES, MAX_WAKE_IDENTITIES, PROCESS_WAKES_PER_HOUR, WAKE_WINDOW_MS, WAKES_PER_HOUR, identityKey, } from './protocol.js';
/** Per-verified-(pid,instance) wake budget over the rolling hour. */
export class WakeLimiter {
    wakes = new Map();
    /**
     * True when `key` has no wake budget left. An unseen key is over budget
     * once MAX_WAKE_IDENTITIES fresh identities fill the table, until entries
     * age past WAKE_WINDOW_MS and prune away.
     */
    overBudget(key, now = Date.now()) {
        this.prune(now);
        const stamps = this.wakes.get(identityKey(key));
        if (stamps === undefined)
            return this.wakes.size >= MAX_WAKE_IDENTITIES;
        return stamps.length >= WAKES_PER_HOUR;
    }
    /** Records one real wake for `key`; false when over WAKES_PER_HOUR or the identity table is full. */
    noteWake(key, now = Date.now()) {
        if (this.overBudget(key, now))
            return false;
        const entry = identityKey(key);
        const stamps = this.wakes.get(entry) ?? [];
        stamps.push(now);
        this.wakes.set(entry, stamps);
        return true;
    }
    prune(now) {
        for (const [entry, stamps] of this.wakes) {
            const fresh = stamps.filter((stamp) => now - stamp < WAKE_WINDOW_MS);
            if (fresh.length === 0)
                this.wakes.delete(entry);
            else if (fresh.length !== stamps.length)
                this.wakes.set(entry, fresh);
        }
    }
}
const PROCESS_WAKE_RING = [];
/**
 * The one process-global wake gate: a fixed ring of at most
 * PROCESS_WAKES_PER_HOUR timestamps per rolling hour, shared by every
 * binding. Holds timestamps only.
 */
export function processWakeAllowed(now = Date.now()) {
    for (;;) {
        const oldest = PROCESS_WAKE_RING[0];
        if (oldest === undefined || now - oldest < WAKE_WINDOW_MS)
            break;
        PROCESS_WAKE_RING.shift();
    }
    if (PROCESS_WAKE_RING.length >= PROCESS_WAKES_PER_HOUR)
        return false;
    PROCESS_WAKE_RING.push(now);
    return true;
}
/** `[peer <name>]: <body> [id <id>]` so the agent can quote the exact message id when replying. */
export function formatPeerText(from, body, opts) {
    // The body crosses an envelope-line boundary: runs of C0/C1 controls (CR/LF
    // included) collapse to one space, then marker lookalikes are rewritten, so
    // the trailing id marker is the only bracket marker in the output. Backticks
    // and ordinary text pass through untouched.
    let safe = '';
    let controlRun = false;
    for (const char of body) {
        const code = char.codePointAt(0) ?? 0;
        if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) {
            controlRun = true;
            continue;
        }
        if (controlRun) {
            safe += ' ';
            controlRun = false;
        }
        safe += char;
    }
    if (controlRun)
        safe += ' ';
    const marked = safe.replaceAll('[id ', '(id ').replaceAll('[peer ', '(peer ');
    return `[peer ${from}]: ${marked} [id ${opts.id}]`;
}
/** Control characters collapsed to spaces, trimmed, UTF-8 clamped to `max` bytes. */
function clampText(value, max) {
    let cleaned = '';
    for (const char of value) {
        const code = char.codePointAt(0) ?? 0;
        cleaned += code <= 0x1f || (code >= 0x7f && code <= 0x9f) ? ' ' : char;
    }
    cleaned = cleaned.trim();
    const bytes = Buffer.from(cleaned, 'utf8');
    if (bytes.length <= max)
        return cleaned;
    let end = max;
    while (end > 0) {
        const byte = bytes[end];
        if (byte === undefined || (byte & 0xc0) !== 0x80)
            break;
        end -= 1;
    }
    return bytes.subarray(0, end).toString('utf8');
}
function failureText(err) {
    const raw = err instanceof Error ? err.message : String(err);
    return clampText(raw, 200);
}
function clampTodo(todo) {
    const out = { ...todo };
    if (typeof out.phase === 'string')
        out.phase = clampText(out.phase, MAX_STATUS_TEXT_BYTES);
    if (typeof out.text === 'string')
        out.text = clampText(out.text, MAX_STATUS_TEXT_BYTES);
    if (typeof out.blocker === 'string')
        out.blocker = clampText(out.blocker, MAX_STATUS_TEXT_BYTES);
    return out;
}
function warn(ctx, text) {
    try {
        ctx.ui.notify(text, 'warning');
    }
    catch {
        // Warning delivery is best-effort.
    }
}
export function createHostDelivery(opts) {
    function acceptanceState() {
        try {
            return opts.acceptance();
        }
        catch {
            return 'shutting_down';
        }
    }
    function epochValid(captured) {
        try {
            return opts.isEpochValid(captured);
        }
        catch {
            return false;
        }
    }
    function currentHost() {
        try {
            return opts.getHost();
        }
        catch {
            return undefined;
        }
    }
    // Identity ring first, then the process-global ring; both must pass to
    // count and record the wake. Limiter failures degrade to allowed so a
    // broken budget never blocks delivery.
    function wakeAllowed(from) {
        try {
            if (opts.wakes.overBudget(from))
                return false;
            if (!processWakeAllowed())
                return false;
            opts.wakes.noteWake(from);
            return true;
        }
        catch {
            return true;
        }
    }
    return {
        captureEpoch: () => opts.captureEpoch(),
        isEpochValid: (captured) => epochValid(captured),
        // One admission decision for every server-visible operation (msg, status,
        // ping, held-reserve): undefined to proceed. Before record publication
        // every operation is refused with host_unavailable plus the shared
        // diagnostic; host_unavailable never enters AcceptanceState.
        admissionCode: () => {
            const state = acceptanceState();
            if (state !== 'accepting')
                return { code: state };
            let ready = false;
            try {
                ready = opts.armed();
            }
            catch {
                // A broken armed probe fails closed.
            }
            if (ready)
                return undefined;
            let detail = 'peers: not armed';
            try {
                detail = opts.notArmedDetail();
            }
            catch {
                // A broken diagnostic falls back to the shared default text.
            }
            return { code: 'host_unavailable', detail };
        },
        submitBatch: async (envelopes) => {
            const first = envelopes[0];
            if (first === undefined)
                return { code: 'invalid_request', detail: 'empty batch' };
            // Recheck closed, transitionPending and every accept-time epoch
            // immediately before the host call; a stale batch injects nothing.
            const state = acceptanceState();
            if (state !== 'accepting')
                return { code: state };
            for (const envelope of envelopes) {
                const captured = envelope.epoch;
                if (captured === undefined || !epochValid(captured))
                    return { code: 'session_transition' };
            }
            const host = currentHost();
            if (host === undefined)
                return { code: 'host_unavailable', detail: 'no live session context' };
            if (typeof host.pi.sendUserMessage !== 'function') {
                return { code: 'host_unavailable', detail: 'host has no sendUserMessage' };
            }
            const allowed = wakeAllowed(first.from);
            const text = envelopes.map((envelope) => envelope.body).join('\n');
            let returned;
            try {
                returned = host.pi.sendUserMessage(text, allowed ? { attribution: 'agent' } : { attribution: 'agent', deliverAs: 'followUp' });
            }
            catch (err) {
                const detail = failureText(err);
                return detail === '' ? { code: 'host_unavailable' } : { code: 'host_unavailable', detail };
            }
            // `submitted` means the plugin synchronously invoked the host call; an
            // async host failure is warned about and never re-coded.
            if (returned !== undefined && typeof returned.catch === 'function') {
                void returned.catch((err) => {
                    warn(host.ctx, `peers: async host submission failed (${failureText(err)})`);
                });
            }
            try {
                opts.onSubmitted(envelopes);
            }
            catch (err) {
                warn(host.ctx, `peers: onSubmitted hook failed (${failureText(err)})`);
            }
            return { code: allowed ? 'submitted' : 'followup_submitted' };
        },
        canSubmitNow: () => {
            // The host can accept a submission right now: no live session, draft
            // text in the composer, or a non-accepting binding all say no. Held
            // capacity and the FIFO-behind-held rule belong to the server.
            if (acceptanceState() !== 'accepting')
                return false;
            const host = currentHost();
            if (host === undefined)
                return false;
            try {
                const draft = host.ctx.ui.getEditorText?.();
                if (typeof draft === 'string' && draft !== '')
                    return false;
            }
            catch {
                // An unreadable composer is treated as clear rather than blocking forever.
            }
            return true;
        },
        reserveHeld: () => {
            try {
                return opts.heldCount() < MAX_HELD_BATCHES;
            }
            catch {
                return false;
            }
        },
        // The caller owns the held count behind heldCount(); releasing simply
        // re-opens reserveHeld's MAX_HELD_BATCHES budget on the caller's
        // decrement, so there is nothing to mutate here.
        releaseHeld: () => { },
        statusSnapshot: (fields) => {
            const requested = Array.isArray(fields)
                ? fields.filter((field) => typeof field === 'string')
                : undefined;
            const host = currentHost();
            if (host === undefined)
                return { busy: false };
            const wants = (field) => requested === undefined || requested.includes(field);
            const ctx = host.ctx;
            const snapshot = { busy: readBusy(ctx) };
            if (wants('model')) {
                const model = clampText(readModel(ctx), MAX_STATUS_ACTIVITY_BYTES);
                if (model !== '')
                    snapshot.model = model;
            }
            if (wants('activity')) {
                let activity;
                try {
                    activity = opts.getActivity?.();
                }
                catch {
                    activity = undefined;
                }
                if (typeof activity === 'string') {
                    const bounded = clampText(activity, MAX_STATUS_ACTIVITY_BYTES);
                    if (bounded !== '')
                        snapshot.activity = bounded;
                }
            }
            if (wants('todos')) {
                let todos = [];
                try {
                    todos = readNativeTodos(ctx.sessionManager);
                }
                catch {
                    todos = [];
                }
                snapshot.todos = todos.slice(0, MAX_STATUS_TODOS).map(clampTodo);
            }
            return snapshot;
        },
        consumeReply: (from, replyTo, body) => {
            try {
                return opts.pending.settle(from, replyTo, body);
            }
            catch {
                return false;
            }
        },
        acceptance: acceptanceState,
    };
}
