/**
 * Roster: the record-only `<peers>` note and the pure context transform that
 * folds it into a provider-bound message list.
 */
export interface RosterMessage {
    role: string;
    content: string | Array<{
        type: string;
        text?: string;
    }>;
}
export interface RosterRow {
    name: string;
    project: string;
    busy: boolean;
    beatAge: string;
    /** Optional bounded detail from an authenticated status pull only (never from presence records). */
    detail?: {
        model?: string;
        activity?: string;
        todoCount?: number;
    };
}
/** Strip control characters (C0, DEL, C1, bidi/format overrides), CR/LF, and ANSI escapes; escape markdown backticks; clamp UTF-8 bytes. */
export declare function sanitizeDisplay(raw: string, maxBytes: number): string;
/**
 * Render the automatic `<peers>` note: identity line plus one record-only row
 * per peer (name, project, busy, beat age) and the untrusted-data label. No
 * token, cwd, session id, model, activity, or todos ever enter this note.
 */
export declare function buildPeersNote(ownName: string, rows: RosterRow[]): string;
/**
 * Fold `note` into the last user message (string content is suffixed, array
 * content gets a pushed text part) or append a fresh user message when none
 * exists. Pure: returns a new array with a copied target message/content,
 * leaves the input and unsupported content unchanged.
 */
export declare function withRosterNote(messages: RosterMessage[], note: string): RosterMessage[];
