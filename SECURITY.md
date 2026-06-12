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
- Run `cargo audit` in CI.

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
