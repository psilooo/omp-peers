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

import type { ExtensionHostLike, ToolInvokeResult } from './peers/host.js';
import type { OutboundResult } from './peers/outbound.js';
import {
  BODY_MAX_BYTES,
  MAX_STATUS_ACTIVITY_BYTES,
  MAX_STATUS_TEXT_BYTES,
  MAX_STATUS_TODOS,
  PROJECT_MAX_BYTES,
  REQUEST_TIMEOUT_DEFAULT_MS,
  REQUEST_TIMEOUT_MAX_MS,
  REQUEST_TIMEOUT_MIN_MS,
  isSuccessCode,
} from './peers/protocol.js';
import type { StatusSnapshot } from './peers/protocol.js';
import { sanitizeDisplay } from './peers/roster.js';
import type { PeerTodo } from './types.js';

export interface PeerToolDeps {
  send(to: string, body: string, opts: { replyTo?: string }): Promise<OutboundResult>;
  request(to: string, body: string, opts: { timeoutMs?: number }): Promise<OutboundResult>;
  status(to: string): Promise<OutboundResult>;
}

type ToolSpec = Parameters<ExtensionHostLike['registerTool']>[0];

function textResult(text: string): ToolInvokeResult {
  return { content: [{ type: 'text', text }] };
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function errText(err: unknown): string {
  return sanitizeDisplay(err instanceof Error ? err.message : String(err), MAX_STATUS_TEXT_BYTES);
}

/** Register one tool without throwing into the host; the convergence poll detects a missing name. */
function tryRegisterTool(pi: ExtensionHostLike, spec: ToolSpec): void {
  try {
    pi.registerTool(spec);
  } catch (err) {
    try {
      pi.logger?.warn(`peer tool ${spec.name} not registered: ${errText(err)}`);
    } catch {
      // Logger is best-effort.
    }
  }
}

/** Checklist box for one todo status. */
function todoBox(status: PeerTodo['status']): string {
  switch (status) {
    case 'completed':
      return '[x]';
    case 'in_progress':
      return '[~]';
    case 'blocked':
      return '[!]';
    case 'abandoned':
      return '[-]';
    default:
      return '[ ]';
  }
}

function todoLine(todo: PeerTodo): string {
  const text = sanitizeDisplay(str(todo.text), MAX_STATUS_TEXT_BYTES);
  const blocker =
    typeof todo.blocker === 'string' && todo.blocker !== ''
      ? ` (blocker: ${sanitizeDisplay(todo.blocker, MAX_STATUS_TEXT_BYTES)})`
      : '';
  return `- ${todoBox(todo.status)} ${text}${blocker}`;
}

/** Bounded status detail: state, model, activity, todos grouped by phase. */
function renderStatusSnapshot(status: StatusSnapshot): string[] {
  const lines = [`state: ${status.busy ? 'working' : 'idle'}`];
  if (typeof status.model === 'string' && status.model !== '') {
    lines.push(`model: ${sanitizeDisplay(status.model, MAX_STATUS_ACTIVITY_BYTES)}`);
  }
  if (typeof status.activity === 'string' && status.activity !== '') {
    lines.push(`activity: ${sanitizeDisplay(status.activity, MAX_STATUS_ACTIVITY_BYTES)}`);
  }
  const todos = Array.isArray(status.todos) ? status.todos.slice(0, MAX_STATUS_TODOS) : [];
  if (todos.length === 0) {
    lines.push('todos: none');
    return lines;
  }
  lines.push(`todos (${todos.length}):`);
  const groups = new Map<string, PeerTodo[]>();
  for (const todo of todos) {
    if (typeof todo !== 'object' || todo === null) continue;
    const phase = str(todo.phase);
    const group = groups.get(phase);
    if (group === undefined) groups.set(phase, [todo]);
    else group.push(todo);
  }
  for (const [phase, group] of groups) {
    if (phase !== '') lines.push(`phase: ${sanitizeDisplay(phase, MAX_STATUS_TEXT_BYTES)}`);
    for (const todo of group) lines.push(todoLine(todo));
  }
  return lines;
}

/**
 * Render one outbound result: target plus the exact machine code vocabulary,
 * bounded sanitized detail, and bounded status detail when present. Never
 * substitutes softer words for a code.
 */
export function renderReceipt(to: string, result: OutboundResult): string {
  const code = typeof result.code === 'string' ? result.code : 'invalid_request';
  const lines = [`\`${sanitizeDisplay(to, PROJECT_MAX_BYTES)}\`: ${code}`];
  if (code === 'held') {
    lines.push('hint: retained only, not read; do not resend');
  }
  if (typeof result.detail === 'string' && result.detail !== '') {
    lines.push(`detail: ${sanitizeDisplay(result.detail, MAX_STATUS_TEXT_BYTES)}`);
  }
  if (result.status !== undefined && typeof result.status === 'object' && result.status !== null) {
    lines.push(...renderStatusSnapshot(result.status));
  }
  return lines.join('\n');
}

/** Status hint for a semantic request timeout: a live status pull, degraded to text on failure. */
async function statusHint(to: string, deps: PeerToolDeps): Promise<string> {
  try {
    return renderReceipt(to, await deps.status(to));
  } catch (err) {
    return `peer_status failed: ${errText(err)}`;
  }
}

export function registerPeerTools(pi: ExtensionHostLike, deps: PeerToolDeps): void {
  tryRegisterTool(pi, {
    name: 'peer_send',
    label: 'Peer Send',
    description:
      'Fire-and-forget message to one explicitly named live peer (see /peers); `to:"all"` is refused by the pipeline. Receipts name exactly what happened: only the local submission outcome, never more; the peer reply arrives later as a separate peer message, not in this result.',
    parameters: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Explicit peer name as listed by /peers' },
        message: { type: 'string', description: 'Message body' },
        replyTo: { type: 'string', description: 'Message id being answered, from an inbound [id ...] marker' },
      },
      required: ['to', 'message'],
      additionalProperties: false,
    },
    execute: async (_toolCallId, params) => {
      try {
        const to = str(params['to']).trim();
        const message = str(params['message']);
        if (to === '' || message.trim() === '') {
          return textResult('Both `to` and `message` are required.');
        }
        const replyTo = str(params['replyTo']).trim();
        const result = await deps.send(to, message, replyTo === '' ? {} : { replyTo });
        return textResult(renderReceipt(to, result));
      } catch (err) {
        return textResult(`peer_send failed: ${errText(err)}`);
      }
    },
  });

  tryRegisterTool(pi, {
    name: 'peer_request',
    label: 'Peer Request',
    description: `Ask one explicitly named live peer (see /peers); \`to:"all"\` is refused by the pipeline. Waits for the matching reply: timeout_ms defaults to ${REQUEST_TIMEOUT_DEFAULT_MS} ms and is clamped to ${REQUEST_TIMEOUT_MIN_MS}-${REQUEST_TIMEOUT_MAX_MS} ms. Returns the reply text on success, or the receipt and a status hint when no reply arrives in time (a late reply may still arrive as a peer message). Receipts name exactly what happened, never more.`,
    parameters: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Explicit peer name as listed by /peers' },
        message: { type: 'string', description: 'Message body' },
        timeout_ms: {
          type: 'number',
          description: `Reply wait in milliseconds (default ${REQUEST_TIMEOUT_DEFAULT_MS}, clamped ${REQUEST_TIMEOUT_MIN_MS}-${REQUEST_TIMEOUT_MAX_MS})`,
        },
      },
      required: ['to', 'message'],
      additionalProperties: false,
    },
    execute: async (_toolCallId, params) => {
      try {
        const to = str(params['to']).trim();
        const message = str(params['message']);
        if (to === '' || message.trim() === '') {
          return textResult('Both `to` and `message` are required.');
        }
        let timeoutMs = REQUEST_TIMEOUT_DEFAULT_MS;
        if ('timeout_ms' in params) {
          const n = Number(params['timeout_ms']);
          if (!Number.isFinite(n)) {
            return textResult(
              `\`timeout_ms\` must be a number between ${REQUEST_TIMEOUT_MIN_MS} and ${REQUEST_TIMEOUT_MAX_MS} ms.`
            );
          }
          timeoutMs = Math.max(REQUEST_TIMEOUT_MIN_MS, Math.min(REQUEST_TIMEOUT_MAX_MS, Math.trunc(n)));
        }
        const result = await deps.request(to, message, { timeoutMs });
        const head = renderReceipt(to, result);
        if (typeof result.replyBody === 'string' && result.replyBody !== '') {
          return textResult(`${head}\nreply: ${sanitizeDisplay(result.replyBody, BODY_MAX_BYTES)}`);
        }
        if (isSuccessCode(result.code)) {
          const hint = await statusHint(to, deps);
          return textResult(
            `${head}\nno reply within ${timeoutMs} ms; a late reply may still arrive as a peer message; status hint:\n${hint}`
          );
        }
        return textResult(head);
      } catch (err) {
        return textResult(`peer_request failed: ${errText(err)}`);
      }
    },
  });

  tryRegisterTool(pi, {
    name: 'peer_status',
    label: 'Peer Status',
    description: `Pull bounded status detail from one explicitly named live peer (see /peers); \`to:"all"\` is refused by the pipeline. Returns busy/idle, model, activity, and at most ${MAX_STATUS_TODOS} todos. Receipts name exactly what happened, never more.`,
    parameters: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Explicit peer name as listed by /peers' },
      },
      required: ['to'],
      additionalProperties: false,
    },
    execute: async (_toolCallId, params) => {
      try {
        const to = str(params['to']).trim();
        if (to === '') {
          return textResult('Peer name (`to`) is required.');
        }
        const result = await deps.status(to);
        return textResult(renderReceipt(to, result));
      } catch (err) {
        return textResult(`peer_status failed: ${errText(err)}`);
      }
    },
  });
}
