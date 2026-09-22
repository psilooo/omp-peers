# omp-peers

Cross-session peer awareness for Oh My Pi (OMP). Every top-level OMP session working in the same codebase on one machine, running as the same local OS user, can see and message every other by explicit name. Sessions in other codebases are invisible and unreachable. No broker process, no cross-machine transport.

```text
/peers                   list live peers by name
peer_send to="backend"   injects a real prompt into that session's agent
peer_request to="qa"     sends a message and waits for the reply
```

Peers are other top-level OMP sessions, not subagents. Two sessions in the same repository working on different tasks is a supported and intended setup.

## Codebase scope

Visibility is per codebase:

- Inside a git repository, the codebase is the repository's git common directory. Every subdirectory of the repository and every linked worktree (`git worktree add`) belongs to the same codebase, so all of their sessions see each other.
- Outside any git repository, the codebase is the exact working directory. A parent or child directory is a different codebase.

Sessions in other codebases are invisible and unreachable. They never appear in `/peers` or the `<peers>` roster note, and `peer_send`, `peer_request`, and `peer_status` answer `not_found` for their names. This is enforced by the storage layout, not by a display filter: each codebase has its own presence and socket directory (`peers/<scope id>/` under the state directory), a session only ever scans its own directory, and a receiver authenticates senders only against records in its own directory.

The codebase is resolved from the session's working directory when the session arms. Sessions started before the upgrade to codebase scoping keep the old shared layout: they see only each other and cannot reach upgraded sessions. Restart them to join their codebase.

## Install

Requirements: OMP `18.2.6` through `19.0.0` (18.2.6 inclusive, 19.0.0 exclusive), Bun `1.3.14` or newer at runtime, Node 22 for development.

```sh
# Fresh marketplace install
omp plugin marketplace add psilooo/omp-peers
omp plugin install omp-peers@omp-peers

# Future marketplace upgrade
omp plugin marketplace update omp-peers
omp plugin upgrade omp-peers@omp-peers

# Immutable direct install
omp plugin install github:psilooo/omp-peers#v2.0.0
```

Every path requires restarting OMP after install or upgrade. Verify with `/peers`.

## Migration

From the upstream marketplace, in order:

1. Stop all peer sessions.
2. `omp plugin marketplace remove omp-peers`
3. `omp plugin marketplace add psilooo/omp-peers`
4. `omp plugin upgrade omp-peers@omp-peers` (the plugin stays installed under that name)
5. Restart every top-level session.

If upstream was installed directly from Git instead, inspect `omp plugin list --json`, uninstall the direct plugin ID it reports, then install the fork.

Direct installs update by installing a newer explicit tag with `--force`.

The attested `.tgz` release artifact is archival and offline use only. Extract it before installing from a local path; the archive itself cannot be installed directly.

## Native subagent isolation

The `/peers` command is registered at factory time in every session as the diagnostic surface: it always renders the snapshot header and, when the session is not armed, the exact diagnostic reason. The peer tools (`peer_send`, `peer_request`, `peer_status`) and live rosters exist only in armed top-level OMP sessions. Native subagents (task children) and nested, unknown, or incompatible sessions show the diagnostic command only and are otherwise inert: no peer tools, no roster context, no listener, no presence record. The native Agent Hub/IRC is untouched and remains exclusively for a top-level session and its real OMP subagents.

## Compatibility

- OMP `18.2.6` inclusive to `19.0.0` exclusive. Unknown, malformed, older, and `19.x` versions fail closed: the plugin stays inert instead of arming.
- Bun `1.3.14` floor (the transport is verified over unix domain sockets on macOS).
- Node 22 for development and tests.
- macOS is the only supported and tested target. Any other platform fails closed as unsupported.

## Protocol v2 and upstream incompatibility

This fork speaks protocol v2, which is intentionally incompatible with upstream `v1.4.0`. Live v1 peer records are shown as incompatible in `/peers` and are never dialed; v1 frames are never injected. Migration to the fork (above) is the path for sessions that previously ran upstream.

## Receipts

Tool receipts use exactly the protocol's vocabulary: `submitted`, `followup_submitted`, `held`, `reply_consumed`, plus refusal codes (`busy`, `unauthenticated`, `session_transition`, and the rest) and transport results (including `unknown_outcome`). Each word means exactly what the protocol defines:

- `submitted` / `followup_submitted`: the plugin synchronously invoked the host's agent-attributed send call. Nothing more.
- `held`: a copy is currently retained in the plugin's bounded in-memory queue.
- `reply_consumed`: a verified reply from the expected peer resolved the local pending request.

No receipt promises queue durability, model processing, or a generated response. A post-write transport failure is reported as `unknown_outcome` and is never retried automatically.

## Threat and privacy boundary

The owner-only state directory (`~/.omp/var/omp-peers/`, override with `OMP_PEERS_DIR`) is a cooperative trust boundary, not a sandbox. Nonces and HMACs stop stale or cross-instance traffic, but another process running as the same OS user can read peer tokens, impersonate peers, alter state, and deny service. That is out of scope.

Inside the boundary:

- Peer tokens never enter frames, logs, prompts, receipts, or status rendering.
- Presence records carry only what routing needs: no session id, model, activity, or todos.
- The automatic `<peers>` roster note contains only name, project, busy flag, and beat age, and is labeled untrusted peer status data.
- Addressing is explicit only. There is no broadcast, no `to: "all"`.
- Discovery and messaging are locked to one codebase (see [Codebase scope](#codebase-scope)). The scope separates cooperating sessions; it is not a defense against a same-user process, which can read and write every scope directory.

State files are ephemeral; deleting the state directory is safe. Each codebase directory holds one `<pid>-<instance>.json` presence record and one `<16 hex>.sock` socket (a hash of the same pid and instance) per session, so a socket path is the state directory plus 45 bytes. The default `~/.omp/var/omp-peers/` fits the 103-byte macOS socket path limit for any ordinary home directory; an `OMP_PEERS_DIR` override longer than 58 bytes after symlinks resolve does not, and peers stay disabled rather than truncating the path.

## Upstream credit

This is a fork of [nikkoxgonzales/omp-peers](https://github.com/nikkoxgonzales/omp-peers), which built the original cross-session peer tooling, presence model, and injection path this release hardens. Credit for the underlying design and first implementation goes to that project and its author.

## Usage

| Command / tool | What it does |
|---|---|
| `/peers` | List live peers in this codebase: name, project, busy/idle, beat age. Incompatible (v1/future) records shown but never dialed. |
| `peer_send` (agent tool) | `to` (peer name), `message`, optional `replyTo`. Injects a real prompt into the named peer. |
| `peer_status` (agent tool) | `to` (peer name). Authenticated pull of bounded status fields (busy, up to 20 todos, beat age). |
| `peer_request` (agent tool) | `to`, `message`, `timeout_ms` (default 30 s, clamped 5 to 120 s). Waits for a matching reply from that peer. |
| `<peers>` context note | Record-only roster injected into top-level prompts, labeled untrusted. |

## Development

```sh
npm ci
npm run build:clean
npm test
```

`dist/` is committed so marketplace installs load without a build step; run `npm run build` after changing `src/` and commit both.

## License

[MIT](LICENSE)
