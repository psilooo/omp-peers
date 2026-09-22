# Security policy

## Reporting a vulnerability

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/psilooo/omp-peers/security/advisories/new) for `psilooo/omp-peers`. Do not open a public issue for a security report.

## Scope and threat model

omp-peers runs entirely on one machine: top-level OMP sessions under the same local OS user, talking over local unix domain sockets. macOS is the only supported and tested target; any other platform fails closed as unsupported.

The owner-only state directory (`~/.omp/var/omp-peers/`, override with `OMP_PEERS_DIR`) is a cooperative trust boundary. Nonces and HMAC-SHA-256 authentication prevent stale or cross-instance traffic. They do not provide isolation from another process running as the same OS user: such a process can read peer tokens, impersonate peers, alter state, and deny service. Hostile same-user isolation, cross-machine transport, and durable offline mail are out of scope.

In-scope expectations inside the boundary: tokens never appear in frames, logs, prompts, receipts, or status rendering; presence records carry no session id, model, activity, or todos; frames are strictly bounded and authenticated before dispatch.

This document makes no response-time or support commitments. Report a vulnerability and expect a human reply when maintainers are available.
