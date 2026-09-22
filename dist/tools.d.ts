/**
 * Agent tool surface: `peer_send`, `peer_request`, and `peer_status`.
 *
 * Explicit peer names only - `to:"all"` is refused by the outbound pipeline.
 * Every execute handler returns text and never throws. Results render through
 * `renderReceipt`, which prints the protocol machine codes verbatim
 * (`submitted`, `followup_submitted`, `held`, `reply_consumed`, `status`,
 * `pong`, every refusal and local transport code) and never claims more than
 * the plugin synchronously did.
 */
import type { ExtensionHostLike } from './peers/host.js';
import type { OutboundResult } from './peers/outbound.js';
export interface PeerToolDeps {
    send(to: string, body: string, opts: {
        replyTo?: string;
    }): Promise<OutboundResult>;
    request(to: string, body: string, opts: {
        timeoutMs?: number;
    }): Promise<OutboundResult>;
    status(to: string): Promise<OutboundResult>;
}
/**
 * Render one outbound result: target plus the exact machine code vocabulary,
 * bounded sanitized detail, and bounded status detail when present. Never
 * substitutes softer words for a code.
 */
export declare function renderReceipt(to: string, result: OutboundResult): string;
export declare function registerPeerTools(pi: ExtensionHostLike, deps: PeerToolDeps): void;
