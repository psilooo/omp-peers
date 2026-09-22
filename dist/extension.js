/**
 * peers OMP extension entry: factory-time compatibility gates, the
 * diagnostic-only `/peers` command, and the event wiring that drives one
 * PeerBinding per factory. Runtime state lives entirely inside the binding.
 */
import { createPeerBinding } from './peers/binding.js';
import { registerPeersCommand } from './commands/peers.js';
/** Supported host range: OMP >=18.2.6 and <19.0.0 (plan section 5). */
const MIN_MAJOR = 18;
const MIN_MINOR = 2;
const MIN_PATCH = 6;
const MAX_MAJOR_EXCLUSIVE = 19;
function parseVersion(raw) {
    if (typeof raw !== 'string')
        return undefined;
    const match = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.exec(raw);
    if (match === null)
        return undefined;
    const [, major, minor, patch] = match;
    if (major === undefined || minor === undefined || patch === undefined)
        return undefined;
    return [Number(major), Number(minor), Number(patch)];
}
function isSupported(version) {
    const [major, minor, patch] = version;
    if (major < MIN_MAJOR || major >= MAX_MAJOR_EXCLUSIVE)
        return false;
    if (minor !== MIN_MINOR)
        return minor > MIN_MINOR;
    return patch >= MIN_PATCH;
}
export default function peersExtension(pi) {
    if (pi === null || typeof pi !== 'object')
        return;
    if (typeof pi.registerCommand !== 'function')
        return;
    // Factory-time command first: TUI completions snapshot before session_start.
    let binding;
    try {
        binding = createPeerBinding(pi);
        registerPeersCommand(pi, () => binding.snapshot());
    }
    catch {
        // A failed binding or command registration leaves the factory inert.
        return;
    }
    // Only after the command surface: event-handler compatibility gate.
    let version;
    try {
        if (typeof pi.on !== 'function')
            return;
        if (typeof pi.logger?.warn !== 'function')
            return;
        version = parseVersion(pi.pi?.VERSION);
    }
    catch {
        version = undefined;
    }
    if (version === undefined || !isSupported(version))
        return;
    const on = (name, handler) => {
        try {
            pi.on(name, (event, ctx) => {
                try {
                    return handler(event, ctx);
                }
                catch {
                    // Never throw into the host.
                    return undefined;
                }
            });
        }
        catch {
            // A rejected registration leaves this event unwired.
        }
    };
    on('session_start', (_event, ctx) => {
        binding.onSessionStart(ctx);
    });
    on('session_before_switch', (_event, ctx) => {
        binding.onBeforeTransition('switch', ctx);
    });
    on('session_switch', (event, ctx) => {
        binding.onTransition('switch', event, ctx);
    });
    on('session_before_branch', (_event, ctx) => {
        binding.onBeforeTransition('branch', ctx);
    });
    on('session_branch', (event, ctx) => {
        binding.onTransition('branch', event, ctx);
    });
    on('session_before_tree', (_event, ctx) => {
        binding.onBeforeTransition('tree', ctx);
    });
    on('session_tree', (event, ctx) => {
        binding.onTransition('tree', event, ctx);
    });
    on('session_shutdown', () => {
        binding.shutdown();
    });
    // The 'context' hook is registered by the binding itself, only after a
    // successful top-level arm (plan sections 2 and 4).
    on('input', (_event, ctx) => {
        binding.onCommitPoint(ctx);
    });
    on('before_agent_start', (_event, ctx) => {
        binding.onCommitPoint(ctx);
    });
    on('tool_execution_start', (event, ctx) => {
        binding.onActivity?.('tool_start', event, ctx);
    });
    on('tool_execution_end', (event, ctx) => {
        binding.onActivity?.('tool_end', event, ctx);
    });
    on('agent_end', (event, ctx) => {
        binding.onActivity?.('agent_end', event, ctx);
    });
    on('todo_reminder', (event, ctx) => {
        binding.onActivity?.('todo_reminder', event, ctx);
    });
}
