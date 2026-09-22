/**
 * Per-factory peer binding: one latch for the session origin, generation-
 * fenced arm/shutdown, transcript transition fencing, and the live peer tool
 * surface. Every piece of runtime state lives in this closure; the module
 * exports only the factory and its types.
 */
import { chmod, lstat, rm } from 'node:fs/promises';
import { registerPeerTools } from '../tools.js';
import { ensureStateRoots, peerEndpoint, validateUnixEndpoint } from '../store/paths.js';
import { defaultNameFor, HEARTBEAT_MS, identityKey, isValidPeerName, isSuccessCode, MAX_STATUS_ACTIVITY_BYTES, MAX_STATUS_TEXT_BYTES, MAX_STATUS_TODOS, normalizeNameInput, PRESENCE_TTL_MS, STATUS_BUDGET_MS, STATUS_FANOUT, } from './protocol.js';
import { newIdentity, projectFor, resolveName } from './ids.js';
import { formatBeatAge, readPeerRecord, removeOwnRecord, removeOwnRecordSync, scanPeers, writeOwnRecord } from './presence.js';
import { managedTimers, readBusy, readNativeTodos, readSessionName } from './host.js';
import { createHostDelivery, WakeLimiter } from './inbound.js';
import { PendingStore, requestMsg, sendMsg, statusOf } from './outbound.js';
import { buildPeersNote, sanitizeDisplay, withRosterNote } from './roster.js';
import { resolveWorkspaceScope, scopeId } from './scope.js';
import { classifySession } from './session-kind.js';
import { startPeerServer, } from './server.js';
/** Status fields requested from a peer, at the release-table cap of 3. */
const STATUS_FIELDS = ['model', 'activity', 'todos'];
/** Tool names this binding registers and waits for on both tool surfaces. */
const TOOL_NAMES = ['peer_send', 'peer_request', 'peer_status'];
/** Convergence poll cadence and deadline (plan section 2). */
const CONVERGE_INTERVAL_MS = 10;
const CONVERGE_DEADLINE_MS = 1000;
export function createPeerBinding(pi) {
    // Origin latch: classified exactly once at the first session_start.
    let originKind;
    // Terminal diagnostics: one shared text used by every gated handler.
    let diagnostic;
    let failed = false;
    let toolsRegistered = false;
    let arming = false;
    let armed = false;
    let contextInstalled = false;
    let contextHookRegistered = false;
    // Generation fencing.
    let bindingEpoch = 0;
    let transcriptEpoch = 0;
    let closed = false;
    // Executor form is required: Promise.withResolvers is outside lib ES2023.
    let resolveShutdown = () => undefined;
    const shutdownSignal = new Promise((resolve) => {
        resolveShutdown = resolve;
    });
    // Transition fencing.
    let transitionPending = false;
    let postEventObserved = false;
    let oldKey = null;
    let candidateKey = null;
    // Identity, state, and listener.
    let identity;
    let roots;
    let record;
    /** Last session-derived requested name handed to resolveName. */
    let lastNameRequested;
    let activeHandle;
    let closedHandle;
    let recordWritten = false;
    let depsRef;
    let deliveryRef;
    let cachedPeers = [];
    // Codebase scope. armedCwd is the cwd string the current arm resolved its
    // scope from and armedScope is that scope's id. Commit points compare the
    // live cwd against armedCwd (one string compare); only a differing cwd
    // queues an async rescope. targetCwd is the newest differing cwd seen, so
    // concurrent changes collapse to the latest one. rescopeRuns counts queued
    // plus running rescopes; while it is nonzero the armed scope is fenced
    // exactly like a pending transcript transition, because the live context
    // may already belong to another codebase.
    let armedCwd;
    let armedScope;
    let targetCwd;
    let rescopeQueued = false;
    let rescopeRuns = 0;
    let armTask;
    let scopeChain = Promise.resolve();
    // Host context, timers, and scheduling.
    let lastCtx;
    let timers;
    let pollTimer;
    let heartbeatTimer;
    let beatChain = Promise.resolve();
    const tracked = new Set();
    // Correlation and held capacity owned by this binding.
    const pending = new PendingStore();
    let heldCount = 0;
    // Hop chain: honest-relay guard state, reset by human prompts.
    let lastInboundFrom;
    let lastInboundHop = 0;
    // Bounded in-memory activity/todo feed for statusSnapshot only.
    let activityText;
    let todosCache;
    let todosAt = 0;
    function bounded(text) {
        return text.length > 200 ? `${text.slice(0, 197)}...` : text;
    }
    function messageOf(err) {
        return err instanceof Error ? err.message : String(err);
    }
    function log(text) {
        try {
            pi.logger?.warn(`omp-peers: ${bounded(text)}`);
        }
        catch {
            // The logger is a host boundary.
        }
    }
    function track(promise) {
        tracked.add(promise);
        const release = () => {
            tracked.delete(promise);
        };
        promise.then(release, release);
        return promise;
    }
    async function safeClose(handle) {
        if (handle === undefined || closedHandle === handle)
            return;
        closedHandle = handle;
        try {
            await handle.close();
        }
        catch {
            // Close is best-effort at this boundary.
        }
    }
    async function removeEndpointIfOurs() {
        if (roots === undefined || identity === undefined)
            return;
        const endpoint = peerEndpoint(roots, identity.pid, identity.instance);
        const stats = await lstat(endpoint);
        if (!stats.isSocket())
            return;
        const uid = process.getuid?.();
        if (uid !== undefined && stats.uid !== uid)
            return;
        await rm(endpoint, { force: true });
    }
    async function verifySocket(endpoint) {
        const stats = await lstat(endpoint);
        if (!stats.isSocket())
            throw new Error('the peer endpoint is not a socket');
        const uid = process.getuid?.();
        if (uid !== undefined && stats.uid !== uid)
            throw new Error('the peer endpoint is owned by another user');
        await chmod(endpoint, 0o600);
    }
    function notArmedText() {
        return diagnostic ?? 'peers: not armed';
    }
    /** A transcript transition or an unsettled codebase scope fences the arm. */
    function fenced() {
        return transitionPending || rescopeRuns > 0;
    }
    function acceptance() {
        if (closed)
            return 'shutting_down';
        if (fenced())
            return 'session_transition';
        return 'accepting';
    }
    function gateResult() {
        if (closed)
            return { code: 'shutting_down' };
        if (fenced())
            return { code: 'session_transition' };
        if (!armed || depsRef === undefined)
            return { code: 'host_unavailable', detail: notArmedText() };
        return undefined;
    }
    // --- Session key and transition bookkeeping.
    function asRecord(value) {
        return typeof value === 'object' && value !== null ? value : undefined;
    }
    function keyOf(ctx) {
        const manager = ctx?.sessionManager;
        if (manager === undefined)
            return '';
        let id = '';
        let path = '';
        try {
            id = manager.getSessionId?.() ?? '';
        }
        catch {
            // Defensive read.
        }
        try {
            const directGetters = ['getSessionFile', 'getSessionPath'];
            for (const getter of directGetters) {
                const value = manager[getter];
                if (typeof value === 'function') {
                    const result = value.call(manager);
                    if (typeof result === 'string' && result !== '')
                        path = result;
                }
                if (path !== '')
                    break;
            }
            if (path === '') {
                const sources = [];
                try {
                    sources.push(asRecord(manager.getHeader?.()));
                }
                catch {
                    sources.push(undefined);
                }
                try {
                    sources.push(asRecord(manager.getBranch?.()));
                }
                catch {
                    sources.push(undefined);
                }
                for (const source of sources) {
                    if (source === undefined)
                        continue;
                    for (const field of ['file', 'path', 'sessionFile']) {
                        const value = source[field];
                        if (typeof value === 'string' && value !== '') {
                            path = value;
                            break;
                        }
                    }
                    if (path !== '')
                        break;
                }
            }
        }
        catch {
            // Defensive read: a path-less key stays comparable across both sides.
        }
        return `${id}|${path}`;
    }
    function clearTransition() {
        transitionPending = false;
        postEventObserved = false;
        oldKey = null;
        candidateKey = null;
    }
    function commitTransition() {
        if (closed)
            return;
        transcriptEpoch += 1;
        if (record !== undefined && lastCtx !== undefined)
            scheduleNameRefresh();
        try {
            // Amendment: purge every stale collecting/sealed/held/waiting-socket item
            // before acceptance() returns to 'accepting'; the server settles waiting
            // sockets once with session_transition and releases stale held
            // reservations silently (no second network reply).
            activeHandle?.purgeStaleWork((captured) => captured.binding !== bindingEpoch || captured.transcript !== transcriptEpoch);
        }
        catch {
            // Purge is synchronous in-process work; never throw into the host.
        }
        try {
            pending.rejectAll('session_transition');
        }
        catch {
            // PendingStore settles synchronously.
        }
        heldCount = 0;
        cachedPeers = [];
        clearTransition();
        noteCwd(lastCtx);
    }
    // --- Codebase scope: arm-time resolution and cwd-change rescoping.
    /** Working directory the session runs in: ctx.cwd when set, else the process cwd. */
    function cwdOf(ctx) {
        return typeof ctx.cwd === 'string' && ctx.cwd !== '' ? ctx.cwd : process.cwd();
    }
    /**
     * Scope check at a commit point: one string compare against the armed cwd.
     * A differing cwd (OMP relocating the session in-process, or a switch or
     * resume bringing a context from another directory) fences the armed scope
     * at once and queues one serialized async rescope; repeated changes before
     * it runs collapse to the latest cwd. Before an arm has claimed a cwd the
     * change is already recorded in lastCtx, which every arm reads when it
     * starts and reconciles against when it finishes.
     */
    function noteCwd(ctx) {
        if (closed || failed || ctx === undefined || armedCwd === undefined)
            return;
        let cwd;
        try {
            cwd = cwdOf(ctx);
        }
        catch {
            // process.cwd throws when the directory is gone; keep the current scope.
            return;
        }
        if (cwd === (targetCwd ?? armedCwd))
            return;
        targetCwd = cwd;
        if (rescopeQueued)
            return;
        rescopeQueued = true;
        rescopeRuns += 1;
        scopeChain = scopeChain.then(runRescope);
        void track(scopeChain);
    }
    /** Settle every presence write already chained, including ones queued while draining. */
    async function drainPresenceWrites() {
        for (let chain = beatChain;; chain = beatChain) {
            await chain;
            if (chain === beatChain)
                return;
        }
    }
    /**
     * Resolve the newest differing cwd. The same scope only adopts the new cwd
     * string and lifts the fence; another scope tears the arm down and re-arms
     * with the latest context so the session moves to that codebase's peer
     * group. A newer cwd observed during the resolve supersedes this run
     * (latest wins) and keeps the fence up until it settles.
     */
    async function runRescope() {
        rescopeQueued = false;
        const cwd = targetCwd;
        try {
            // An arm still in flight settles before its scope is compared.
            if (armTask !== undefined)
                await armTask;
            if (closed || failed || cwd === undefined || cwd !== targetCwd)
                return;
            if (cwd === armedCwd) {
                targetCwd = undefined;
                return;
            }
            const scopeKey = await resolveWorkspaceScope(cwd);
            if (closed || failed || cwd !== targetCwd)
                return;
            targetCwd = undefined;
            if (armedScope !== undefined && scopeId(scopeKey) === armedScope) {
                armedCwd = cwd;
                return;
            }
            if (!armed)
                return;
            await disarm();
            // Every beat and name write the old arm started settles before any
            // re-arm, so a stale write's cleanup can never unlink the record or
            // socket a re-arm into the same scope directory publishes.
            await drainPresenceWrites();
            const ctx = lastCtx;
            if (closed || ctx === undefined)
                return;
            armTask = track(arm(ctx, { cwd, scopeKey }));
            await armTask;
        }
        catch (err) {
            log(`rescope failed: ${messageOf(err)}`);
        }
        finally {
            rescopeRuns -= 1;
        }
    }
    /**
     * Tear the live arm down so the session can re-arm in another codebase
     * scope. Same fencing as a transition commit plus shutdown, without closing
     * the binding (the rescope run that calls this keeps acceptance fenced):
     * the epoch bump fences every in-flight arm, beat, and name write (each
     * removes its late record from the roots it captured), waiting inbound work
     * settles with session_transition, pending requests reject with
     * session_transition, and the own record and endpoint leave the old scope
     * directory.
     */
    async function disarm() {
        bindingEpoch += 1;
        armed = false;
        depsRef = undefined;
        if (heartbeatTimer !== undefined && timers !== undefined) {
            try {
                timers.clearTimer(heartbeatTimer);
            }
            catch {
                // Timer clearing is best-effort.
            }
        }
        heartbeatTimer = undefined;
        const handle = activeHandle;
        try {
            handle?.purgeStaleWork((captured) => captured.binding !== bindingEpoch || captured.transcript !== transcriptEpoch);
        }
        catch {
            // Purge is synchronous in-process work; never throw into the host.
        }
        try {
            pending.rejectAll('session_transition');
        }
        catch {
            // PendingStore settles synchronously.
        }
        heldCount = 0;
        cachedPeers = [];
        record = undefined;
        recordWritten = false;
        lastNameRequested = undefined;
        const oldRoots = roots;
        const self = identity;
        try {
            if (oldRoots !== undefined && self !== undefined) {
                try {
                    await removeOwnRecord(oldRoots, self.pid, self.instance);
                }
                catch {
                    // Removal is best-effort at teardown.
                }
            }
            await safeClose(handle);
            try {
                await removeEndpointIfOurs();
            }
            catch {
                // Endpoint removal is best-effort at teardown.
            }
        }
        finally {
            roots = undefined;
            activeHandle = undefined;
            armedCwd = undefined;
            armedScope = undefined;
        }
    }
    /**
     * Cleanup for a presence write that lost its epoch: it may have resurrected
     * the record under the roots it captured. A later arm that owns the same
     * scope directory again keeps its record and socket; otherwise both go.
     */
    async function removeStaleRecord(staleRoots, self) {
        if (!closed && roots !== undefined && roots !== staleRoots && roots.peersDir === staleRoots.peersDir)
            return;
        try {
            await removeOwnRecord(staleRoots, self.pid, self.instance);
        }
        catch {
            // Removal is best-effort during teardown.
        }
    }
    // --- Naming: one requested-name computation, one serialized refresh.
    /**
     * Session-derived requested name: the normalized session title when it is a
     * usable peer name, otherwise the stable default for this project. Contested
     * resolution belongs to resolveName inside refreshName.
     */
    function requestedNameFor(ctx, project, self) {
        let sessionName = '';
        if (ctx !== undefined) {
            try {
                sessionName = normalizeNameInput(readSessionName(pi, ctx) ?? '');
            }
            catch {
                // The default name is used when the host cannot supply one.
            }
        }
        return isValidPeerName(sessionName) ? sessionName : defaultNameFor(project, self.instance);
    }
    /**
     * Re-resolve the requested name over a fresh scan and, when it changed,
     * rewrite the record atomically inside this refresh. pid, instance and the
     * record path never rotate; only the display name moves. Contested names go
     * to the (startedAt, pid, instance) winner and losers take the alias.
     */
    async function refreshName(fresh) {
        const bindingAtStart = bindingEpoch;
        const current = record;
        const currentRoots = roots;
        const currentIdentity = identity;
        if (closed || current === undefined || currentRoots === undefined || currentIdentity === undefined)
            return;
        const requested = requestedNameFor(lastCtx, current.project, currentIdentity);
        lastNameRequested = requested;
        const resolved = resolveName({
            requested,
            self: { pid: currentIdentity.pid, instance: currentIdentity.instance, startedAt: current.startedAt },
            peers: fresh.routable,
        });
        if (resolved.name === current.name)
            return;
        if (closed || bindingAtStart !== bindingEpoch)
            return;
        try {
            await writeOwnRecord(currentRoots, { ...current, name: resolved.name });
        }
        catch (err) {
            log(`name refresh failed: ${messageOf(err)}`);
            return;
        }
        if (closed || bindingAtStart !== bindingEpoch) {
            // A late write must not resurrect the record after shutdown.
            await removeStaleRecord(currentRoots, currentIdentity);
            return;
        }
        if (record === current)
            current.name = resolved.name;
        recordWritten = true;
    }
    /**
     * Queue one naming refresh behind the same single tracked promise as the
     * heartbeat write, so refresh triggers share one in-flight chain and are
     * drained at shutdown.
     */
    function scheduleNameRefresh() {
        const currentRoots = roots;
        const currentIdentity = identity;
        if (closed || !armed || record === undefined || currentRoots === undefined || currentIdentity === undefined) {
            return;
        }
        beatChain = beatChain.then(async () => {
            if (closed || !armed)
                return;
            const bindingAtStart = bindingEpoch;
            try {
                const fresh = await scanPeers(currentRoots, {
                    pid: currentIdentity.pid,
                    instance: currentIdentity.instance,
                });
                if (closed || bindingAtStart !== bindingEpoch)
                    return;
                await refreshName(fresh);
            }
            catch {
                // A failed scan keeps the current name; the heartbeat retries.
            }
        });
        void track(beatChain);
    }
    /**
     * Commit and rename point: refresh only when the session title actually
     * changed, so ordinary commits cost one comparison and no scan. A pending
     * transition refreshes at its own commit instead.
     */
    function refreshNameAtCommit() {
        if (closed || !armed || transitionPending || originKind !== 'top-level')
            return;
        if (record === undefined || identity === undefined)
            return;
        const requested = requestedNameFor(lastCtx, record.project, identity);
        if (requested === lastNameRequested)
            return;
        lastNameRequested = requested;
        scheduleNameRefresh();
    }
    /**
     * Stable entry point: decides cancellation, same-file reload, rollback, or
     * a real commit. Human prompts additionally reset the hop chain.
     */
    function commitPoint(ctx, resetHop) {
        if (closed)
            return;
        if (ctx !== undefined)
            lastCtx = ctx;
        noteCwd(lastCtx);
        if (resetHop) {
            lastInboundFrom = undefined;
            lastInboundHop = 0;
        }
        refreshNameAtCommit();
        if (originKind !== 'top-level' || !transitionPending || oldKey === null)
            return;
        const current = keyOf(lastCtx);
        if (current !== oldKey) {
            commitTransition();
            return;
        }
        if (postEventObserved) {
            if (candidateKey !== null && candidateKey !== oldKey) {
                // Observed a different candidate but the old key was restored: rollback.
                clearTransition();
                return;
            }
            // Observed post-event with the same key: same-file reload commits.
            commitTransition();
            return;
        }
        // No post-event with the old key: cancellation.
        clearTransition();
    }
    // --- Roster and status rendering.
    function recordRow(row, now) {
        return { name: row.name, project: row.project, busy: row.busy, beatAge: formatBeatAge(row.beatAt, now) };
    }
    function rowsOf(peers, now) {
        return peers
            .filter((row) => identity === undefined || row.pid !== identity.pid || row.instance !== identity.instance)
            .map((row) => recordRow(row, now));
    }
    function boundTodos(todos) {
        return todos.slice(0, MAX_STATUS_TODOS).map((todo) => ({
            ...todo,
            text: sanitizeDisplay(todo.text, MAX_STATUS_TEXT_BYTES),
            ...(todo.phase !== undefined ? { phase: sanitizeDisplay(todo.phase, MAX_STATUS_TEXT_BYTES) } : {}),
            ...(todo.blocker !== undefined ? { blocker: sanitizeDisplay(todo.blocker, MAX_STATUS_TEXT_BYTES) } : {}),
        }));
    }
    function overlayStatus(base, fields) {
        const wants = (field) => fields === undefined || fields.includes(field);
        const out = { busy: base.busy };
        if (wants('model') && base.model !== undefined && base.model !== '') {
            out.model = sanitizeDisplay(base.model, MAX_STATUS_ACTIVITY_BYTES);
        }
        if (wants('activity')) {
            const text = base.activity !== undefined && base.activity !== '' ? base.activity : activityText;
            if (text !== undefined && text !== '')
                out.activity = sanitizeDisplay(text, MAX_STATUS_ACTIVITY_BYTES);
        }
        if (wants('todos')) {
            let todos = base.todos !== undefined && base.todos.length > 0 ? boundTodos(base.todos) : undefined;
            if (todos === undefined && todosCache !== undefined && Date.now() - todosAt <= PRESENCE_TTL_MS) {
                todos = todosCache;
            }
            if (todos !== undefined)
                out.todos = todos;
        }
        return out;
    }
    /**
     * Bounded status fan-out: STATUS_FANOUT concurrent pulls over the routable
     * rows, one STATUS_BUDGET_MS total budget measured from fan-out start. Every
     * pull is handed that same deadline so statusOf clamps itself to the
     * remaining time and destroys its own unfinished socket at the deadline.
     * On expiry the fan-out stops, abandoned rows render without detail, and no
     * lane outlives the budget wall-clock.
     */
    async function fanOutStatus(rows) {
        const deps = depsRef;
        if (rows.length === 0 || deps === undefined)
            return rows;
        const out = rows.map((row) => ({ ...row }));
        const deadline = Date.now() + STATUS_BUDGET_MS;
        let cursor = 0;
        let exhausted = false;
        const detailFrom = (result) => {
            if (!isSuccessCode(result.code) || result.status === undefined)
                return undefined;
            const detail = {};
            if (result.status.model !== undefined && result.status.model !== '') {
                detail.model = sanitizeDisplay(result.status.model, MAX_STATUS_ACTIVITY_BYTES);
            }
            if (result.status.activity !== undefined && result.status.activity !== '') {
                detail.activity = sanitizeDisplay(result.status.activity, MAX_STATUS_ACTIVITY_BYTES);
            }
            if (result.status.todos !== undefined)
                detail.todoCount = result.status.todos.length;
            if (detail.model === undefined && detail.activity === undefined && detail.todoCount === undefined) {
                return undefined;
            }
            return detail;
        };
        const worker = async () => {
            for (;;) {
                if (exhausted || closed)
                    return;
                const index = cursor;
                cursor += 1;
                if (index >= out.length)
                    return;
                const remaining = deadline - Date.now();
                if (remaining <= 0) {
                    exhausted = true;
                    return;
                }
                const winner = await Promise.race([
                    statusOf(deps, out[index].name, STATUS_FIELDS, { deadlineAt: deadline }).then((result) => ({ kind: 'done', result }), () => ({ kind: 'skip' })),
                    // Executor form: Promise.withResolvers is outside lib ES2023.
                    new Promise((resolve) => {
                        try {
                            timers?.setTimeout(() => resolve({ kind: 'timeout' }), remaining);
                        }
                        catch {
                            resolve({ kind: 'timeout' });
                        }
                    }),
                    shutdownSignal.then(() => ({ kind: 'shutdown' })),
                ]);
                if (winner.kind === 'done') {
                    const detail = detailFrom(winner.result);
                    if (detail !== undefined)
                        out[index].detail = detail;
                    continue;
                }
                if (winner.kind === 'skip')
                    continue;
                exhausted = true;
                return;
            }
        };
        const lanes = Math.min(STATUS_FANOUT, out.length);
        await Promise.all(Array.from({ length: lanes }, () => worker()));
        return out;
    }
    // --- Delivery wiring.
    function buildDelivery() {
        const base = createHostDelivery({
            getHost: () => (closed || !armed || lastCtx === undefined ? undefined : { pi, ctx: lastCtx }),
            pending,
            wakes: new WakeLimiter(),
            heldCount: () => heldCount,
            acceptance,
            armed: () => armed,
            notArmedDetail: notArmedText,
            captureEpoch: () => ({ binding: bindingEpoch, transcript: transcriptEpoch }),
            isEpochValid: (captured) => captured.binding === bindingEpoch && captured.transcript === transcriptEpoch,
            getActivity: () => activityText,
            onSubmitted: (envelopes) => {
                for (const envelope of envelopes) {
                    lastInboundFrom = identityKey(envelope.from);
                    lastInboundHop = Number.isFinite(envelope.hop) ? Math.max(0, Math.trunc(envelope.hop)) : 0;
                }
            },
        });
        const delivery = {
            captureEpoch: () => ({ binding: bindingEpoch, transcript: transcriptEpoch }),
            isEpochValid: (captured) => captured.binding === bindingEpoch && captured.transcript === transcriptEpoch,
            admissionCode: base.admissionCode,
            submitBatch: (envelopes) => {
                if (closed)
                    return Promise.resolve({ code: 'shutting_down' });
                if (fenced())
                    return Promise.resolve({ code: 'session_transition' });
                if (!armed || depsRef === undefined) {
                    return Promise.resolve({ code: 'host_unavailable', detail: notArmedText() });
                }
                // A batch whose accept-time epoch predates a commit injects nothing.
                for (const envelope of envelopes) {
                    const captured = envelope.epoch;
                    if (captured === undefined || !delivery.isEpochValid(captured)) {
                        return Promise.resolve({ code: 'session_transition' });
                    }
                }
                // sendUserMessage runs synchronously inside base.submitBatch; once
                // delegated, a transition landing later cannot recall the host call.
                // The delegated receipt therefore stands exactly as returned, because
                // a false session_transition here is sender-retryable and would
                // duplicate the message. Every refusal happens above, pre-call.
                return Promise.resolve(base.submitBatch(envelopes));
            },
            canSubmitNow: () => armed && acceptance() === 'accepting' && base.canSubmitNow(),
            reserveHeld: () => {
                if (!base.reserveHeld())
                    return false;
                heldCount += 1;
                return true;
            },
            releaseHeld: () => {
                base.releaseHeld();
                if (heldCount > 0)
                    heldCount -= 1;
            },
            statusSnapshot: (fields) => overlayStatus(base.statusSnapshot(fields), fields),
            consumeReply: (from, replyTo, body) => base.consumeReply(from, replyTo, body),
            acceptance,
        };
        deliveryRef = delivery;
        return delivery;
    }
    // --- Heartbeat.
    async function runBeat() {
        try {
            const bindingAtStart = bindingEpoch;
            const currentRecord = record;
            const currentRoots = roots;
            const currentIdentity = identity;
            if (closed || !armed || currentRecord === undefined || currentRoots === undefined || currentIdentity === undefined) {
                return;
            }
            currentRecord.beatAt = Date.now();
            if (lastCtx !== undefined) {
                try {
                    currentRecord.busy = readBusy(lastCtx);
                }
                catch {
                    // Busy detection degrades to the last known value.
                }
            }
            try {
                await writeOwnRecord(currentRoots, currentRecord);
            }
            catch (err) {
                log(`presence refresh failed: ${messageOf(err)}`);
            }
            if (closed || bindingAtStart !== bindingEpoch) {
                // A late write must not resurrect the record after shutdown.
                await removeStaleRecord(currentRoots, currentIdentity);
                return;
            }
            recordWritten = true;
            if (lastCtx !== undefined) {
                try {
                    todosCache = boundTodos(readNativeTodos(lastCtx.sessionManager));
                    todosAt = Date.now();
                }
                catch {
                    // Todo reading degrades to the last cached snapshot.
                }
            }
            try {
                const scan = await scanPeers(currentRoots, currentIdentity);
                if (closed || bindingAtStart !== bindingEpoch)
                    return;
                cachedPeers = scan.routable;
                // The fresh scan also re-resolves this peer's own name; a collision
                // loser adopts its stable alias inside the same serialized beat.
                await refreshName(scan);
            }
            catch {
                // The roster keeps its last snapshot when a scan fails.
            }
        }
        catch (err) {
            log(`heartbeat cycle failed: ${messageOf(err)}`);
        }
    }
    // --- Session start: latch, capability gate, tool registration, convergence.
    function missingCapability(ctx) {
        const checks = [
            ['registerTool', typeof pi.registerTool === 'function'],
            ['sendUserMessage', typeof pi.sendUserMessage === 'function'],
            ['getAllTools', typeof pi.getAllTools === 'function'],
            ['getActiveTools', typeof pi.getActiveTools === 'function'],
            ['sessionManager.getSessionId', typeof ctx.sessionManager?.getSessionId === 'function'],
            ['sessionManager.getSessionName', typeof ctx.sessionManager?.getSessionName === 'function'],
            ['sessionManager.getBranch', typeof ctx.sessionManager?.getBranch === 'function'],
            ['sessionManager.getEntries', typeof ctx.sessionManager?.getEntries === 'function'],
            ['setInterval', typeof ctx.setInterval === 'function'],
            ['setTimeout', typeof ctx.setTimeout === 'function'],
            ['clearTimer', typeof ctx.clearTimer === 'function'],
            ['ui.notify', typeof ctx.ui?.notify === 'function'],
            ['ui.getEditorText', typeof ctx.ui?.getEditorText === 'function'],
        ];
        for (const [name, present] of checks) {
            if (!present)
                return name;
        }
        return undefined;
    }
    function toolNames(view) {
        if (Array.isArray(view)) {
            const names = [];
            for (const entry of view) {
                if (typeof entry === 'string') {
                    names.push(entry);
                    continue;
                }
                if (typeof entry === 'object' && entry !== null) {
                    const name = entry.name;
                    if (typeof name === 'string')
                        names.push(name);
                }
            }
            return names;
        }
        if (view instanceof Map) {
            const names = [];
            for (const key of view.keys())
                if (typeof key === 'string')
                    names.push(key);
            return names;
        }
        if (typeof view === 'object' && view !== null)
            return Object.keys(view);
        return [];
    }
    function toolSurfacesConverged() {
        let live;
        let active;
        try {
            live = toolNames(pi.getAllTools?.());
        }
        catch {
            return false;
        }
        try {
            active = toolNames(pi.getActiveTools?.());
        }
        catch {
            return false;
        }
        return TOOL_NAMES.every((name) => live.includes(name) && active.includes(name));
    }
    function stopPoll() {
        if (pollTimer !== undefined && timers !== undefined) {
            try {
                timers.clearTimer(pollTimer);
            }
            catch {
                // Timer clearing is best-effort.
            }
        }
        pollTimer = undefined;
    }
    function fail(reason) {
        failed = true;
        diagnostic = `peers: ${reason}; peer tools are unavailable`;
    }
    function startConvergence(ctx) {
        const managed = managedTimers(ctx);
        if (managed === undefined) {
            fail('managed timers are unavailable');
            return;
        }
        timers = managed;
        const deadline = Date.now() + CONVERGE_DEADLINE_MS;
        try {
            pollTimer = managed.setInterval(() => {
                try {
                    if (closed) {
                        stopPoll();
                        return;
                    }
                    if (toolSurfacesConverged()) {
                        stopPoll();
                        contextInstalled = true;
                        // The newest context wins: a cwd change seen before this timer
                        // fired is armed directly instead of being dropped.
                        armTask = track(arm(lastCtx ?? ctx));
                        return;
                    }
                    if (Date.now() >= deadline) {
                        stopPoll();
                        fail('peer tools were registered but never became active on this restricted host');
                    }
                }
                catch {
                    // Never throw into the host from a timer callback.
                }
            }, CONVERGE_INTERVAL_MS);
        }
        catch {
            fail('the convergence poll could not be scheduled');
        }
    }
    // --- Arm: fixed activation order with epoch rechecks after every await.
    function buildRecord(ctx, self, startedAt, scan) {
        const project = projectFor(cwdOf(ctx));
        const requested = requestedNameFor(ctx, project, self);
        lastNameRequested = requested;
        const resolved = resolveName({
            requested,
            self: { pid: self.pid, instance: self.instance, startedAt },
            peers: scan.routable,
        });
        let busy = false;
        try {
            busy = readBusy(ctx);
        }
        catch {
            // Busy detection degrades to idle.
        }
        return {
            v: 2,
            pid: self.pid,
            instance: self.instance,
            token: self.token,
            name: resolved.name,
            project,
            harness: 'omp',
            startedAt,
            beatAt: startedAt,
            busy,
        };
    }
    /**
     * `known` carries a scope key a rescope already resolved; it is reused only
     * when it was resolved for the cwd this arm actually runs in.
     */
    async function arm(ctx, known) {
        if (closed || armed || arming || failed)
            return;
        arming = true;
        const bindingAtStart = bindingEpoch;
        const stale = () => closed || bindingAtStart !== bindingEpoch;
        let handle;
        try {
            if (process.platform !== 'darwin')
                throw new Error('unsupported platform: macOS is the only supported target');
            const cwd = cwdOf(ctx);
            armedCwd = cwd;
            const scopeKey = known !== undefined && known.cwd === cwd ? known.scopeKey : await resolveWorkspaceScope(cwd);
            if (stale())
                return;
            const stateRoots = await ensureStateRoots(scopeKey);
            if (stale())
                return;
            roots = stateRoots;
            armedScope = stateRoots.scope;
            if (identity === undefined)
                identity = { pid: process.pid, ...newIdentity() };
            const self = identity;
            const endpoint = peerEndpoint(stateRoots, self.pid, self.instance);
            validateUnixEndpoint(endpoint);
            const managed = timers;
            if (managed === undefined)
                throw new Error('managed timers are unavailable');
            const deps = {
                identity: self,
                roots: stateRoots,
                managed,
                scan: () => scanPeers(stateRoots, { pid: self.pid, instance: self.instance }),
                pending,
                acceptance,
                log,
            };
            handle = startPeerServer({
                endpoint,
                roots: stateRoots,
                identity: self,
                delivery: buildDelivery(),
                managed,
                log,
            });
            activeHandle = handle;
            const ready = await Promise.race([handle.ready, shutdownSignal.then(() => 'shutdown')]);
            if (ready === 'shutdown' || stale()) {
                await safeClose(handle);
                return;
            }
            await verifySocket(endpoint);
            if (stale()) {
                await safeClose(handle);
                return;
            }
            const scan = await scanPeers(stateRoots, { pid: self.pid, instance: self.instance });
            if (stale()) {
                await safeClose(handle);
                return;
            }
            const startedAt = Date.now();
            const firstRecord = buildRecord(ctx, self, startedAt, scan);
            record = firstRecord;
            await writeOwnRecord(stateRoots, firstRecord);
            recordWritten = true;
            if (stale()) {
                try {
                    await removeOwnRecord(stateRoots, self.pid, self.instance);
                }
                catch {
                    // Teardown removal is best-effort.
                }
                await safeClose(handle);
                return;
            }
            const verify = await readPeerRecord(stateRoots, self.pid, self.instance);
            if (verify === undefined)
                throw new Error('the presence record failed read-back verification');
            if (stale()) {
                try {
                    await removeOwnRecord(stateRoots, self.pid, self.instance);
                }
                catch {
                    // Teardown removal is best-effort.
                }
                await safeClose(handle);
                return;
            }
            record = verify;
            cachedPeers = scan.routable.filter((row) => row.pid !== self.pid || row.instance !== self.instance);
            depsRef = deps;
            heartbeatTimer = managed.setInterval(() => {
                beatChain = beatChain.then(runBeat);
                void track(beatChain);
            }, HEARTBEAT_MS);
            armed = true;
            // A cwd change seen while this arm resolved (or recorded before it
            // started) reconciles through the rescope path before traffic flows.
            noteCwd(lastCtx);
            // Plan section 2/4: the host context hook installs only after a successful
            // top-level arm; nested/unknown/restricted factories register no handler.
            if (!contextHookRegistered) {
                contextHookRegistered = true;
                try {
                    pi.on('context', (event, eventCtx) => {
                        try {
                            return onContext(event, eventCtx);
                        }
                        catch {
                            // Never throw into the host.
                            return undefined;
                        }
                    });
                }
                catch {
                    // A failed hook registration leaves the host with no context handler.
                }
            }
        }
        catch (err) {
            failed = true;
            depsRef = undefined;
            deliveryRef = undefined;
            await safeClose(handle);
            if (roots !== undefined && identity !== undefined) {
                try {
                    await removeOwnRecord(roots, identity.pid, identity.instance);
                }
                catch {
                    // Nothing published, nothing to remove.
                }
                if (handle !== undefined) {
                    try {
                        await removeEndpointIfOurs();
                    }
                    catch {
                        // Endpoint removal is best-effort during rollback.
                    }
                }
            }
            const reason = bounded(messageOf(err));
            diagnostic = `peers: startup failed (${reason}); peers stay unavailable until OMP restarts`;
            const warning = `startup failed: ${reason}. Check that OMP_PEERS_DIR is a private owner-only directory, then restart OMP.`;
            try {
                ctx.ui.notify(`omp-peers: ${warning}`, 'warning');
            }
            catch {
                log(warning);
            }
        }
        finally {
            arming = false;
        }
    }
    function onSessionStart(ctx) {
        if (closed)
            return;
        lastCtx = ctx;
        noteCwd(ctx);
        if (originKind === undefined) {
            let kind = 'unknown';
            try {
                kind = classifySession(ctx.sessionManager);
            }
            catch {
                kind = 'unknown';
            }
            originKind = kind;
            if (kind !== 'top-level') {
                diagnostic =
                    kind === 'nested'
                        ? 'peers: this session is nested, so peer tools are unavailable here'
                        : 'peers: this session origin could not be classified, so peer tools are unavailable';
                return;
            }
        }
        if (originKind !== 'top-level')
            return;
        if (armed || arming || failed || toolsRegistered)
            return;
        const missing = missingCapability(ctx);
        if (missing !== undefined) {
            fail(`host capability ${missing} is missing`);
            return;
        }
        const toolDeps = { send, request, status };
        try {
            registerPeerTools(pi, toolDeps);
        }
        catch (err) {
            fail(`peer tool registration failed (${bounded(messageOf(err))})`);
            return;
        }
        toolsRegistered = true;
        startConvergence(ctx);
    }
    // --- Transition surface.
    function onBeforeTransition(_kind, ctx) {
        if (closed || originKind !== 'top-level')
            return;
        lastCtx = ctx;
        oldKey = keyOf(ctx);
        transitionPending = true;
        postEventObserved = false;
        candidateKey = null;
    }
    function onTransition(kind, _event, ctx) {
        if (closed || originKind !== 'top-level')
            return;
        lastCtx = ctx;
        if (kind === 'tree') {
            // The tree post-event is its own commit point.
            if (transitionPending)
                commitTransition();
            return;
        }
        if (!transitionPending)
            return;
        postEventObserved = true;
        candidateKey = keyOf(ctx);
    }
    function onCommitPoint(ctx, human) {
        // Human entries reset the relay-hop chain; peer-sourced entries keep the
        // inbound hop context so relay loops stay bounded.
        commitPoint(ctx, human);
    }
    function onContext(event, ctx) {
        commitPoint(ctx, false);
        if (closed || !contextInstalled || !armed || fenced() || originKind !== 'top-level')
            return undefined;
        const selfName = record?.name;
        if (selfName === undefined)
            return undefined;
        const payload = asRecord(event);
        const messages = payload?.['messages'];
        if (!Array.isArray(messages))
            return undefined;
        try {
            const note = buildPeersNote(selfName, rowsOf(cachedPeers, Date.now()));
            return { messages: withRosterNote(messages, note) };
        }
        catch {
            return undefined;
        }
    }
    function onActivity(kind, event, ctx) {
        if (closed || originKind !== 'top-level')
            return;
        lastCtx = ctx;
        if (kind === 'todo_reminder') {
            try {
                todosCache = boundTodos(readNativeTodos(ctx.sessionManager));
                todosAt = Date.now();
            }
            catch {
                // Todo reading degrades to the last cached snapshot.
            }
            return;
        }
        if (kind === 'agent_end' || kind === 'tool_end') {
            activityText = undefined;
            return;
        }
        if (kind === 'tool_start') {
            const payload = asRecord(event);
            const tool = asRecord(payload?.['tool']);
            const candidates = [payload?.['toolName'], payload?.['name'], tool?.['name']];
            const name = candidates.find((value) => typeof value === 'string' && value !== '');
            if (typeof name === 'string') {
                activityText = sanitizeDisplay(`tool ${name}`, MAX_STATUS_ACTIVITY_BYTES);
            }
        }
    }
    // --- Snapshot.
    async function snapshot() {
        // Running /peers is a local command entry point.
        commitPoint(lastCtx, true);
        const now = Date.now();
        let self = { name: '', project: projectFor(lastCtx !== undefined ? cwdOf(lastCtx) : process.cwd()) };
        let selfRow;
        if (record !== undefined) {
            self = { name: record.name, project: record.project };
            selfRow = recordRow(record, now);
        }
        else if (identity !== undefined) {
            self.name = defaultNameFor(self.project, identity.instance);
        }
        if (closed || !armed || roots === undefined || identity === undefined || depsRef === undefined) {
            return {
                self,
                rows: [],
                incompatible: [],
                held: heldCount,
                armed: false,
                diagnostic: notArmedText(),
            };
        }
        try {
            const scan = await scanPeers(roots, identity);
            const detailed = await fanOutStatus(rowsOf(scan.routable, now));
            return {
                self,
                rows: selfRow !== undefined ? [selfRow, ...detailed] : detailed,
                incompatible: scan.incompatible,
                held: heldCount,
                armed: true,
            };
        }
        catch {
            return {
                self,
                rows: selfRow !== undefined ? [selfRow] : [],
                incompatible: [],
                held: heldCount,
                armed: true,
            };
        }
    }
    // --- Tool surface: peer-tool executions are commit points.
    /**
     * Relay-hop level for one outbound attempt: a send back to the last inbound
     * peer identity keeps that message's level; any other target advances by
     * one from the human prompt. The comparison is identity-to-identity and is
     * computed per attempt against the actually resolved record.
     */
    function hopForRecord(record) {
        if (lastInboundFrom === undefined)
            return 0;
        return identityKey(record) === lastInboundFrom ? lastInboundHop : lastInboundHop + 1;
    }
    async function send(to, body, opts) {
        commitPoint(lastCtx, false);
        const gate = gateResult();
        if (gate !== undefined)
            return gate;
        const deps = depsRef;
        if (deps === undefined)
            return { code: 'host_unavailable', detail: notArmedText() };
        const replyTo = opts?.replyTo;
        try {
            return await sendMsg(deps, to, body, {
                ...(replyTo !== undefined && replyTo !== '' ? { replyTo } : {}),
                hopFor: hopForRecord,
            });
        }
        catch (err) {
            log(`send failed: ${messageOf(err)}`);
            return { code: 'unknown_outcome', detail: bounded(messageOf(err)) };
        }
    }
    async function request(to, body, opts) {
        commitPoint(lastCtx, false);
        const gate = gateResult();
        if (gate !== undefined)
            return gate;
        const deps = depsRef;
        if (deps === undefined)
            return { code: 'host_unavailable', detail: notArmedText() };
        const timeoutMs = opts?.timeoutMs;
        // Same hop semantics as the send path: the hop is computed per attempt
        // against the resolved destination identity.
        try {
            return await requestMsg(deps, to, body, {
                ...(timeoutMs !== undefined ? { timeoutMs } : {}),
                hopFor: hopForRecord,
            });
        }
        catch (err) {
            log(`request failed: ${messageOf(err)}`);
            return { code: 'unknown_outcome', detail: bounded(messageOf(err)) };
        }
    }
    async function status(to) {
        commitPoint(lastCtx, false);
        const gate = gateResult();
        if (gate !== undefined)
            return gate;
        const deps = depsRef;
        if (deps === undefined)
            return { code: 'host_unavailable', detail: notArmedText() };
        try {
            return await statusOf(deps, to, STATUS_FIELDS);
        }
        catch (err) {
            log(`status pull failed: ${messageOf(err)}`);
            return { code: 'unknown_outcome', detail: bounded(messageOf(err)) };
        }
    }
    // --- Shutdown.
    let shutdownPromise;
    function shutdown() {
        if (shutdownPromise !== undefined)
            return shutdownPromise;
        closed = true;
        bindingEpoch += 1;
        arming = false;
        stopPoll();
        if (heartbeatTimer !== undefined && timers !== undefined) {
            try {
                timers.clearTimer(heartbeatTimer);
            }
            catch {
                // Timer clearing is best-effort.
            }
        }
        heartbeatTimer = undefined;
        try {
            pending.rejectAll('shutting_down');
        }
        catch {
            // PendingStore settles synchronously.
        }
        // Own state is gone synchronously; the returned promise then drains
        // tracked writes and re-removes afterward, and the host awaits it (the
        // runner caps session_shutdown handlers at 2,000 ms).
        if (roots !== undefined && identity !== undefined) {
            removeOwnRecordSync(roots, identity.pid, identity.instance);
        }
        resolveShutdown();
        shutdownPromise = finalize();
        return shutdownPromise;
    }
    async function finalize() {
        try {
            for (let round = 0; round < 16 && tracked.size > 0; round += 1) {
                await Promise.allSettled([...tracked]);
            }
        }
        catch {
            // Draining never fails outward.
        }
        await safeClose(activeHandle);
        if (roots !== undefined && identity !== undefined) {
            if (recordWritten) {
                try {
                    await removeOwnRecord(roots, identity.pid, identity.instance);
                }
                catch {
                    // Removal is best-effort at teardown.
                }
            }
            try {
                await removeEndpointIfOurs();
            }
            catch {
                // Endpoint removal is best-effort at teardown.
            }
        }
    }
    return {
        onSessionStart,
        onBeforeTransition,
        onTransition,
        onCommitPoint,
        onContext,
        onActivity,
        snapshot,
        send,
        request,
        status,
        shutdown,
    };
}
