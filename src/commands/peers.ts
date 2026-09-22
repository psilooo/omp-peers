/**
 * `/peers` - sanitized text list of the peer snapshot: routable rows, held
 * count, incompatible v1/future rows (shown, never dialed), and the armed or
 * diagnostic state. The interactive picker runs only when `ctx.ui.select` is
 * callable and `ctx.mode === 'tui'`; the text list always renders otherwise.
 * Every untrusted field passes `sanitizeDisplay` with bounds from the
 * protocol constants, so status data cannot escape the rendering.
 */

import type { CommandContextLike, ExtensionHostLike } from '../peers/host.js';
import {
  MAX_STATUS_ACTIVITY_BYTES,
  MAX_STATUS_TEXT_BYTES,
  PROJECT_MAX_BYTES,
} from '../peers/protocol.js';
import type { RosterRow } from '../peers/roster.js';
import { sanitizeDisplay } from '../peers/roster.js';

export interface PeersSnapshot {
  self: { name: string; project: string };
  rows: RosterRow[];
  /** Live v1/future records: shown as incompatible, never dialed. */
  incompatible: Array<{ pid: number; version: number }>;
  held: number;
  armed: boolean;
  /** Exact diagnostic text when not armed. */
  diagnostic?: string;
}

function notify(ctx: CommandContextLike, message: string, type: 'info' | 'error'): void {
  try {
    ctx.ui?.notify(message, type);
  } catch {
    // Notify is best-effort.
  }
}

/** Row fields after the name: project, state, beat age, bounded detail, self marker. */
function rowFields(row: RosterRow, selfName: string): string[] {
  const fields = [
    sanitizeDisplay(row.project, PROJECT_MAX_BYTES),
    row.busy ? 'working' : 'idle',
    `beat ${sanitizeDisplay(row.beatAge, MAX_STATUS_TEXT_BYTES)}`,
  ];
  const detail = row.detail;
  if (detail !== undefined) {
    if (typeof detail.model === 'string' && detail.model !== '') {
      fields.push(`model ${sanitizeDisplay(detail.model, MAX_STATUS_ACTIVITY_BYTES)}`);
    }
    if (typeof detail.activity === 'string' && detail.activity !== '') {
      fields.push(sanitizeDisplay(detail.activity, MAX_STATUS_ACTIVITY_BYTES));
    }
    if (typeof detail.todoCount === 'number' && Number.isFinite(detail.todoCount)) {
      const count = Math.max(0, Math.trunc(detail.todoCount));
      fields.push(`${count} todo${count === 1 ? '' : 's'}`);
    }
  }
  if (row.name === selfName) fields.push('you');
  return fields;
}

/** `` `name` · project · working · beat 3s ago · model ... · you `` */
export function formatPeerLine(row: RosterRow, selfName: string): string {
  return `\`${sanitizeDisplay(row.name, PROJECT_MAX_BYTES)}\` · ${rowFields(row, selfName).join(' · ')}`;
}

export function formatPeersText(snap: PeersSnapshot, now: number): string {
  const sorted = [...snap.rows].sort((a, b) => a.name.localeCompare(b.name));
  const selfIndex = sorted.findIndex((row) => row.name === snap.self.name);
  const selfRow = selfIndex >= 0 ? sorted.splice(selfIndex, 1)[0] : undefined;
  const held = Number.isFinite(snap.held) ? Math.trunc(snap.held) : 0;
  const parts = [
    `peers (${snap.rows.length})`,
    `you are \`${sanitizeDisplay(snap.self.name, PROJECT_MAX_BYTES)}\` in ${sanitizeDisplay(snap.self.project, PROJECT_MAX_BYTES)}`,
  ];
  if (held > 0) parts.push(`held ${held}`);
  parts.push(snap.armed ? 'armed' : 'not armed');
  const lines = [parts.join(' · ')];
  if (typeof snap.diagnostic === 'string' && snap.diagnostic !== '') {
    lines.push(`diagnostic: ${sanitizeDisplay(snap.diagnostic, MAX_STATUS_TEXT_BYTES)}`);
  }
  const seen = new Set<string>();
  let duplicated = false;
  for (const row of snap.rows) {
    const name = sanitizeDisplay(row.name, PROJECT_MAX_BYTES);
    if (seen.has(name)) {
      duplicated = true;
      break;
    }
    seen.add(name);
  }
  if (duplicated) {
    lines.push('names duplicated or scan incomplete: address by name is ambiguous right now');
  }
  if (selfRow !== undefined) {
    lines.push(formatPeerLine(selfRow, snap.self.name));
  } else {
    lines.push(
      `\`${sanitizeDisplay(snap.self.name, PROJECT_MAX_BYTES)}\` · ${sanitizeDisplay(snap.self.project, PROJECT_MAX_BYTES)} · you`
    );
  }
  lines.push('this is you; other sessions message you at this name');
  if (sorted.length === 0 && selfRow === undefined) {
    lines.push('(no live peers)');
  } else {
    for (const row of sorted) lines.push(formatPeerLine(row, snap.self.name));
  }
  for (const item of snap.incompatible) {
    lines.push(`pid ${item.pid} · presence v${item.version} · incompatible · never dialed`);
  }
  return lines.join('\n');
}

export function registerPeersCommand(
  pi: ExtensionHostLike,
  getSnapshot: () => Promise<PeersSnapshot>
): void {
  try {
    pi.registerCommand('peers', {
      description: 'List live peer sessions in this codebase',
      handler: async (_args: string, ctx: CommandContextLike) => {
        try {
          const snap = await getSnapshot();
          const now = Date.now();
          const select = ctx.ui?.select;
          if (typeof select === 'function' && ctx.mode === 'tui' && snap.rows.length > 0) {
            try {
              const options = [...snap.rows]
                .sort((a, b) => {
                  const aSelf = a.name === snap.self.name ? 0 : 1;
                  const bSelf = b.name === snap.self.name ? 0 : 1;
                  return aSelf - bSelf || a.name.localeCompare(b.name);
                })
                .map((row) => ({
                  label: sanitizeDisplay(row.name, PROJECT_MAX_BYTES),
                  description: rowFields(row, snap.self.name).join(' · '),
                }));
              const picked = await select.call(ctx.ui, 'Peers - pick one for details', options);
              if (typeof picked === 'string' && picked !== '') {
                const row = snap.rows.find(
                  (candidate) => sanitizeDisplay(candidate.name, PROJECT_MAX_BYTES) === picked
                );
                notify(
                  ctx,
                  row !== undefined ? formatPeerLine(row, snap.self.name) : formatPeersText(snap, now),
                  'info'
                );
              }
              return;
            } catch {
              // Picker failed - fall through to the text list.
            }
          }
          notify(ctx, formatPeersText(snap, now), 'info');
        } catch (err) {
          const reason = sanitizeDisplay(
            err instanceof Error ? err.message : String(err),
            MAX_STATUS_TEXT_BYTES
          );
          notify(ctx, `/peers failed: ${reason}`, 'error');
        }
      },
    });
  } catch (err) {
    const reason = sanitizeDisplay(
      err instanceof Error ? err.message : String(err),
      MAX_STATUS_TEXT_BYTES
    );
    try {
      pi.logger?.warn(`/peers command not registered: ${reason}`);
    } catch {
      // Logger is best-effort.
    }
  }
}
