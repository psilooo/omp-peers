/**
 * Host seam: narrow structural types plus guarded public helpers for title
 * source, session name, native todos, busy/model reads, and managed timers.
 * No host singletons; the host is touched only through `ctx`/`pi` surfaces.
 */
import type { PeerTodo } from '../types.js';
export interface SessionManagerLike {
    getSessionId?: () => string | undefined;
    getSessionName?: () => string | undefined;
    getHeader?: () => unknown;
    titleSource?: unknown;
    getBranch?: () => unknown;
    getEntries?: () => unknown;
}
export interface SelectOption {
    label: string;
    description?: string;
}
export interface UiLike {
    notify(message: string, type?: 'info' | 'warning' | 'error'): void;
    select?: (title: string, options: SelectOption[], dialogOptions?: unknown) => Promise<string | undefined>;
    getEditorText?: () => string;
    [key: string]: unknown;
}
export interface CommandContextLike {
    cwd: string;
    mode: string;
    ui: UiLike;
    sessionManager: SessionManagerLike;
    model?: {
        id?: string;
    };
    isIdle: () => boolean;
    setInterval?: (callback: () => void, ms?: number) => unknown;
    setTimeout?: (callback: () => void, ms?: number) => unknown;
    clearTimer?: (timer: unknown) => void;
    [key: string]: unknown;
}
export interface ToolInvokeResult {
    content: Array<{
        type: string;
        text: string;
    }>;
    details?: unknown;
}
export interface SendOptions {
    attribution?: 'agent';
    deliverAs?: 'steer' | 'followUp' | 'aside';
}
export interface ExtensionHostLike {
    on(event: string, handler: (event: unknown, ctx: CommandContextLike) => unknown): void;
    registerCommand(name: string, opts: {
        description?: string;
        handler: (args: string, ctx: CommandContextLike) => unknown;
    }): void;
    registerTool(tool: {
        name: string;
        label: string;
        description: string;
        parameters: unknown;
        execute: (toolCallId: string, params: Record<string, unknown>, signal?: AbortSignal) => Promise<ToolInvokeResult>;
    }): void;
    sendUserMessage?: (content: string, options?: SendOptions) => void | Promise<void>;
    /** Live tool surface; callable required before arming. */
    getAllTools?: () => unknown;
    /** Active tool surface; callable required before arming. */
    getActiveTools?: () => unknown;
    getSessionName?: () => string | undefined;
    logger?: {
        warn(message: string): void;
    };
    /** Public host version surface, read as `pi.pi.VERSION`. */
    pi?: {
        VERSION?: unknown;
    };
}
/**
 * Who named this session. The host marks explicit renames `"user"` and
 * model-generated titles `"auto"` on the session header and on the manager
 * itself. Returns undefined when the host exposes neither; every read is
 * guarded so unknown host shapes fall through instead of throwing.
 */
export declare function readTitleSource(manager: SessionManagerLike | undefined | null): string | undefined;
/** The session's display name: ctx manager first, then the host-level getter. */
export declare function readSessionName(pi: ExtensionHostLike, ctx: CommandContextLike): string | undefined;
/** True while the host reports the session is not idle. */
export declare function readBusy(ctx: CommandContextLike): boolean;
/** The ctx model id, or '' when the host exposes none. */
export declare function readModel(ctx: CommandContextLike): string;
/**
 * The ctx-managed timer trio, or undefined unless all three are callable.
 * All scheduling must route through these so shutdown can clear every timer.
 */
export declare function managedTimers(ctx: CommandContextLike): {
    setInterval: Function;
    setTimeout: Function;
    clearTimer: Function;
} | undefined;
/** Cap on published todos: the heartbeat is a glance, not a transcript. */
export declare const MAX_PEER_TODOS = 20;
/** Cap on each published text field (phase, task, blocker), in UTF-8 bytes. */
export declare const MAX_PEER_TODO_TEXT_CHARS = 200;
/**
 * Read the host's NATIVE todo state out of the session transcript, newest
 * entry first: a `user_todo_edit` custom entry, else the latest successful
 * `todo` toolResult. Never throws: a host without the surface reads as [].
 */
export declare function readNativeTodos(manager: SessionManagerLike | undefined | null): PeerTodo[];
