/**
 * peers OMP extension entry: factory-time compatibility gates, the
 * diagnostic-only `/peers` command, and the event wiring that drives one
 * PeerBinding per factory. Runtime state lives entirely inside the binding.
 */
import type { ExtensionHostLike } from './peers/host.js';
export default function peersExtension(pi: ExtensionHostLike): void;
