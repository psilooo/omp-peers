/**
 * Per-factory peer binding: one latch for the session origin, generation-
 * fenced arm/shutdown, transcript transition fencing, and the live peer tool
 * surface. Every piece of runtime state lives in this closure; the module
 * exports only the factory and its types.
 */
import type { PeersSnapshot } from '../commands/peers.js';
import type { CommandContextLike, ExtensionHostLike } from './host.js';
import { type OutboundResult } from './outbound.js';
import type { RosterMessage } from './roster.js';
export type ActivityKind = 'tool_start' | 'tool_end' | 'agent_end' | 'todo_reminder';
export interface PeerBinding {
    onSessionStart(ctx: CommandContextLike): void;
    onBeforeTransition(kind: 'switch' | 'branch' | 'tree', ctx: CommandContextLike): void;
    onTransition(kind: 'switch' | 'branch' | 'tree', event: unknown, ctx: CommandContextLike): void;
    onCommitPoint(ctx: CommandContextLike): void;
    onContext(event: unknown, ctx: CommandContextLike): {
        messages: RosterMessage[];
    } | undefined;
    onActivity?(kind: ActivityKind, event: unknown, ctx: CommandContextLike): void;
    snapshot(): Promise<PeersSnapshot>;
    send(to: string, body: string, opts: {
        replyTo?: string;
    }): Promise<OutboundResult>;
    request(to: string, body: string, opts: {
        timeoutMs?: number;
    }): Promise<OutboundResult>;
    status(to: string): Promise<OutboundResult>;
    shutdown(): void;
}
export declare function createPeerBinding(pi: ExtensionHostLike): PeerBinding;
