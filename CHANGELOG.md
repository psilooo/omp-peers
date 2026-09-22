# Changelog

## Unreleased

## 2.0.0

First release of the psilooo fork of nikkoxgonzales/omp-peers.

Breaking changes:

- Hub bridge removed. The private synthetic Agent Hub bridge and its registry probing are gone; no replacement Hub integration exists.
- Wire protocol v2 is incompatible with upstream v1.4.0. Live v1 records show as incompatible and are never dialed; v1 frames are never injected.
- Presence records are privacy-minimal. Records carry only routing fields (pid, instance, token, name, project, harness, timestamps, busy) with no session id, model, activity, or todos.
- OMP-only support. The compatibility window is OMP 18.2.6 inclusive to 19.0.0 exclusive with a Bun 1.3.14 floor; pi-support surfaces were removed and unsupported hosts fail closed.
- Peer tools are top-level-only. The `/peers` command is registered at factory time in every session as the diagnostic surface, while `peer_send`, `peer_request`, `peer_status`, and live rosters exist only in armed top-level sessions; nested, unknown, and incompatible sessions show the diagnostic command only and are otherwise inert.
