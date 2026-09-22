/**
 * Host seam: narrow structural types plus guarded public helpers for title
 * source, session name, native todos, busy/model reads, and managed timers.
 * No host singletons; the host is touched only through `ctx`/`pi` surfaces.
 */
/**
 * Who named this session. The host marks explicit renames `"user"` and
 * model-generated titles `"auto"` on the session header and on the manager
 * itself. Returns undefined when the host exposes neither; every read is
 * guarded so unknown host shapes fall through instead of throwing.
 */
export function readTitleSource(manager) {
    if (manager === undefined || manager === null)
        return undefined;
    const candidates = [];
    try {
        candidates.push(manager.getHeader?.());
    }
    catch {
        // Header read is best-effort.
    }
    candidates.push(manager);
    for (const candidate of candidates) {
        if (typeof candidate !== 'object' || candidate === null)
            continue;
        if (!('titleSource' in candidate))
            continue;
        const source = candidate.titleSource;
        if (typeof source === 'string' && source !== '')
            return source;
    }
    return undefined;
}
/** The session's display name: ctx manager first, then the host-level getter. */
export function readSessionName(pi, ctx) {
    try {
        const fromCtx = ctx.sessionManager?.getSessionName?.();
        if (typeof fromCtx === 'string' && fromCtx !== '')
            return fromCtx;
    }
    catch {
        // Manager read is best-effort.
    }
    try {
        const fromHost = pi.getSessionName?.();
        if (typeof fromHost === 'string' && fromHost !== '')
            return fromHost;
    }
    catch {
        // Host read is best-effort.
    }
    return undefined;
}
/** True while the host reports the session is not idle. */
export function readBusy(ctx) {
    try {
        return ctx.isIdle() === false;
    }
    catch {
        return false;
    }
}
/** The ctx model id, or '' when the host exposes none. */
export function readModel(ctx) {
    const id = ctx.model?.id;
    return typeof id === 'string' ? id : '';
}
/**
 * The ctx-managed timer trio, or undefined unless all three are callable.
 * All scheduling must route through these so shutdown can clear every timer.
 */
export function managedTimers(ctx) {
    const interval = ctx.setInterval;
    const timeout = ctx.setTimeout;
    const clear = ctx.clearTimer;
    if (typeof interval !== 'function' ||
        typeof timeout !== 'function' ||
        typeof clear !== 'function') {
        return undefined;
    }
    return {
        setInterval: (callback, ms) => ctx.setInterval?.(callback, ms),
        setTimeout: (callback, ms) => ctx.setTimeout?.(callback, ms),
        clearTimer: (timer) => ctx.clearTimer?.(timer),
    };
}
/** Marker the host stamps on a user todo edit entry (`tools/todo.ts`). */
const USER_TODO_EDIT_CUSTOM_TYPE = 'user_todo_edit';
/** Cap on published todos: the heartbeat is a glance, not a transcript. */
export const MAX_PEER_TODOS = 20;
/** Cap on each published text field (phase, task, blocker), in UTF-8 bytes. */
export const MAX_PEER_TODO_TEXT_CHARS = 200;
function asRecord(value) {
    return typeof value === 'object' && value !== null ? value : undefined;
}
/** Trim, then clamp to the UTF-8 byte ceiling without splitting a code point. */
function clampTodoText(value) {
    const text = typeof value === 'string' ? value.trim() : '';
    if (text === '')
        return '';
    const bytes = new TextEncoder().encode(text);
    if (bytes.length <= MAX_PEER_TODO_TEXT_CHARS)
        return text;
    let end = MAX_PEER_TODO_TEXT_CHARS;
    while (end > 0) {
        const byte = bytes[end];
        if (byte === undefined || (byte & 0xc0) !== 0x80)
            break;
        end -= 1;
    }
    return new TextDecoder().decode(bytes.subarray(0, end));
}
/** Native todo status, defaulting anything unrecognized to pending. */
function nativeTodoStatus(raw) {
    switch (raw) {
        case 'in_progress':
            return 'in_progress';
        case 'completed':
            return 'completed';
        case 'abandoned':
            return 'abandoned';
        case 'blocked':
            return 'blocked';
        default:
            return 'pending';
    }
}
/** Phases carried by one session entry, or undefined when the entry is not a todo snapshot. */
function nativePhasesFromEntry(entry) {
    const e = asRecord(entry);
    if (e === undefined)
        return undefined;
    if (e['type'] === 'custom' && e['customType'] === USER_TODO_EDIT_CUSTOM_TYPE) {
        const phases = asRecord(e['data'])?.['phases'];
        return Array.isArray(phases) ? phases : undefined;
    }
    if (e['type'] !== 'message')
        return undefined;
    const message = asRecord(e['message']);
    if (message === undefined)
        return undefined;
    if (message['role'] !== 'toolResult' || message['toolName'] !== 'todo' || message['isError'])
        return undefined;
    const phases = asRecord(message['details'])?.['phases'];
    return Array.isArray(phases) ? phases : undefined;
}
/** Flatten native phases/tasks into bounded peer todos. */
function mapNativeTodos(phases) {
    const flat = [];
    let order = 0;
    for (const rawPhase of phases) {
        const phase = asRecord(rawPhase);
        if (phase === undefined)
            continue;
        const tasks = phase['tasks'];
        if (!Array.isArray(tasks))
            continue;
        const phaseName = clampTodoText(phase['name']);
        for (const rawTask of tasks) {
            const task = asRecord(rawTask);
            if (task === undefined)
                continue;
            const text = clampTodoText(task['content']);
            if (text === '')
                continue;
            const status = nativeTodoStatus(task['status']);
            const blocker = status === 'blocked' ? clampTodoText(task['blocker']) : '';
            flat.push({
                order: order++,
                todo: {
                    text,
                    status,
                    ...(phaseName !== '' ? { phase: phaseName } : {}),
                    ...(blocker !== '' ? { blocker } : {}),
                },
            });
        }
    }
    if (flat.length > MAX_PEER_TODOS) {
        // Trim by usefulness, then restore the host's own order for display.
        const priority = (todo) => todo.status === 'in_progress' ? 0 : todo.status === 'pending' ? 1 : 2;
        flat.sort((a, b) => priority(a.todo) - priority(b.todo) || a.order - b.order);
        flat.length = MAX_PEER_TODOS;
        flat.sort((a, b) => a.order - b.order);
    }
    return flat.map((entry) => entry.todo);
}
/**
 * Read the host's NATIVE todo state out of the session transcript, newest
 * entry first: a `user_todo_edit` custom entry, else the latest successful
 * `todo` toolResult. Never throws: a host without the surface reads as [].
 */
export function readNativeTodos(manager) {
    let entries;
    try {
        entries = manager?.getBranch?.() ?? manager?.getEntries?.() ?? [];
    }
    catch {
        return [];
    }
    if (!Array.isArray(entries))
        return [];
    for (let index = entries.length - 1; index >= 0; index -= 1) {
        const phases = nativePhasesFromEntry(entries[index]);
        if (phases !== undefined)
            return mapNativeTodos(phases);
    }
    return [];
}
