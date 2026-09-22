# Changelog

## Unreleased

Breaking changes:

- Peer discovery and messaging are locked to one codebase. A session's codebase is the git common directory of its working directory, so every subdirectory and linked worktree of one repository shares it; outside git it is the exact working directory. Sessions in other codebases no longer appear in `/peers` or the roster note, and `peer_send`, `peer_request`, and `peer_status` answer `not_found` for them.
- Presence records and sockets moved to a per-codebase directory, `peers/<scope id>/` under the state directory. A session scans only its own codebase directory and authenticates inbound senders only against it, so other codebases are unreachable by construction, not hidden by a filter. Flat records written directly in `peers/` by older versions are ignored.
- Records keep their `<pid>-<instance>.json` names, but each socket is now `<16 hex>.sock`, a hash of the session's pid and instance, so the full socket path stays within the 103-byte macOS limit under the default state directory even for long usernames.
- Sessions started before the upgrade keep the old layout and see only each other; restart them to join their codebase.

## 2.0.0

First release of the psilooo fork of nikkoxgonzales/omp-peers.

Breaking changes:

- Hub bridge removed. The private synthetic Agent Hub bridge and its registry probing are gone; no replacement Hub integration exists.
- Wire protocol v2 is incompatible with upstream v1.4.0. Live v1 records show as incompatible and are never dialed; v1 frames are never injected.
- Presence records are privacy-minimal. Records carry only routing fields (pid, instance, token, name, project, harness, timestamps, busy) with no session id, model, activity, or todos.
- OMP-only support. The compatibility window is OMP 18.2.6 inclusive to 19.0.0 exclusive with a Bun 1.3.14 floor; pi-support surfaces were removed and unsupported hosts fail closed.
- Peer tools are top-level-only. The `/peers` command is registered at factory time in every session as the diagnostic surface, while `peer_send`, `peer_request`, `peer_status`, and live rosters exist only in armed top-level sessions; nested, unknown, and incompatible sessions show the diagnostic command only and are otherwise inert.
