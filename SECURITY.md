# Security Policy

SSHMap must only be used against systems you own or are explicitly authorized to assess.

## Current Safety Boundaries

- No brute force
- No exploit execution
- No password spraying
- No private key collection
- No password storage
- Discovery mode only performs TCP connect checks and SSH banner reads
- Scan mode runs a fixed read-only command manifest validated at startup (`sshmap doctor`)
- Scan mode uses `BatchMode=yes` and disables password prompts

## SSH Scan Transports

SSHMap supports two scan backends. Both use the same read-only remote command manifest.

| Transport | Flag | When to use |
|-----------|------|-------------|
| **OpenSSH** (default) | `--transport openssh` | Production and hardened environments. Uses the system `ssh` binary, supports connection multiplexing, and matches familiar OpenSSH behavior. |
| **Native** | `--transport native` | Environments without a suitable `ssh` CLI or when an in-process client is preferred. Requires an identity file (`--key`). Uses the `russh` crate. |

OpenSSH is the default because it is widely deployed and does not embed SSH cryptography in the application binary. Native transport remains fully supported for compatibility and air-gapped tooling scenarios.

### Native transport dependency note

The native transport depends on `russh`, which transitively pulls `rsa` (RUSTSEC-2023-0071, Marvin timing side-channel). No fixed upstream release was available at the time of writing. Mitigations:

- Prefer `--transport openssh` when auditing sensitive infrastructure.
- Track `russh` / `rsa` releases and update dependencies promptly.
- Run `cargo audit` in CI (see `.cargo/audit.toml` for the documented ignore).
- Run `scripts/check-rustsec-rsa.sh` periodically or in release prep to detect when a fixed `russh`/`rsa` release is available.

## Graph analysis limits

Path, blast-radius, and related analysis load a bounded subset of graph edges to keep memory and latency predictable:

| Context | Default limit | Full analysis |
|---------|---------------|---------------|
| CLI (`path`, `paths`, `blast-radius`, `key-blast-radius`) | 10,000 edges | `--full-graph` (100,000) |
| HTTP API analysis endpoints | 10,000 edges | Set `SSHMAP_GRAPH_EDGE_LIMIT` on the server |
| `GET /api/graph` listing | 1,000 edges (query `limit`, max 10,000) | — |

When the inventory exceeds the limit, responses include `edges_truncated: true` (analysis) or `truncated: true` (`GET /api/graph`). Re-run with `--full-graph` or raise `SSHMAP_GRAPH_EDGE_LIMIT` only on trusted hosts with sufficient memory.

## HTTP API

- Token authentication uses constant-time comparison (`X-SSHMap-Token`).
- API errors return generic messages; internal details are logged at debug level only.
- Read endpoints use a SQLite connection pool; write endpoints require `--allow-write-api` and a write token.
- Rate limiting is applied per client IP on `/api/*` routes (20 req/s, burst 40). `/health` is not rate limited.
- Listening on non-loopback addresses without a token is rejected unless explicitly configured.
- Set `SSHMAP_REQUIRE_TOKEN=1` to require tokens even on loopback.

## Webhooks

- URLs are validated before use (HTTPS required except `http://` to loopback).
- Private, link-local, metadata, and cloud-internal hostnames are blocked.
- DNS is resolved at request time; all resolved addresses must be public (or loopback for local HTTP).
- HTTP redirects are disabled; resolved addresses are pinned for the request.

Report security issues privately to the project maintainers.
