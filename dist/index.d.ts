/**
 * peers library barrel: the public protocol v2 surface of the extension.
 * No v1 names and no bridge names.
 */
export * from './peers/protocol.js';
export type { PeerTodo, PeerTodoStatus, PendingRequest } from './types.js';
export { CorruptStateError, PeerNameError } from './errors.js';
export { durableWriteJson, readJsonBounded } from './store/atomic.js';
export { ensureStateRoots, peerEndpoint, peerRecordPath, rootHash, validateUnixEndpoint } from './store/paths.js';
export type { StateRoots } from './store/paths.js';
export { hasDuplicateRoutableNames, newIdentity, projectFor, resolveName } from './peers/ids.js';
export type { ResolveNameInput } from './peers/ids.js';
export { formatBeatAge, readPeerRecord, removeOwnRecord, scanPeers, writeOwnRecord } from './peers/presence.js';
export type { PeerScan } from './peers/presence.js';
export { MAX_PEER_TODOS, MAX_PEER_TODO_TEXT_CHARS, managedTimers, readBusy, readModel, readNativeTodos, readSessionName, readTitleSource, } from './peers/host.js';
export type { CommandContextLike, ExtensionHostLike, SelectOption, SendOptions, SessionManagerLike, ToolInvokeResult, UiLike, } from './peers/host.js';
export { buildPeersNote, sanitizeDisplay, withRosterNote } from './peers/roster.js';
export type { RosterMessage, RosterRow } from './peers/roster.js';
export { classifySession } from './peers/session-kind.js';
export type { SessionKind } from './peers/session-kind.js';
export { startPeerServer } from './peers/server.js';
export type { AuthenticatedEnvelope, HostDelivery, ManagedTimers, ServerHandle } from './peers/server.js';
export { PendingStore, pingPeer, requestMsg, resolveTarget, sendMsg, statusOf } from './peers/outbound.js';
export type { OutboundDeps, OutboundResult, ResolvedTarget } from './peers/outbound.js';
export { WakeLimiter, createHostDelivery, formatPeerText, processWakeAllowed } from './peers/inbound.js';
export { registerPeerTools, renderReceipt } from './tools.js';
export type { PeerToolDeps } from './tools.js';
export { formatPeerLine, formatPeersText, registerPeersCommand } from './commands/peers.js';
export type { PeersSnapshot } from './commands/peers.js';
export { createPeerBinding } from './peers/binding.js';
export type { ActivityKind, PeerBinding } from './peers/binding.js';
