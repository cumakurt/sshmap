# Changelog

## 2.0.3

- Add shared IPv6-aware host target parser for imports, discovery scope, and proxy jumps
- Cap graph path and blast-radius analysis at 100,000 edges on API and CLI
- Stop overwriting host FQDN with short hostname hints during host updates
- Validate CLI risk severity and exception expiry timestamps at write time
- Fix broken GitHub Actions CI workflow (dashboard build and bench jobs)
- Add core smoke integration tests for host/user/key/graph, serve API, reports, IPv6 imports, and validation

## 2.0.2

- Merge host records when the same target is reached by hostname, FQDN, or IP alias instead of creating duplicate rows
- Expand evidence redaction for secret assignments while preserving sshd directive lines
- Include group-based passwordless sudo membership in combined SSH key reuse risk detection

## 2.0.1

- Harden read-only API server: require `--token` on non-loopback binds, constant-time token comparison, generic 500 responses, graph list limit, severity validation, and empty query param checks
- Fix API summary critical/high counts using database severity totals instead of capped risk lists
- Escape LIKE wildcards in host and user search queries; skip WAL pragmas on read-only database connections
- Deduplicate raw evidence before analysis to avoid inflated risk counts from rescans
- Limit incremental analyze skip to graph-only scope so risk regeneration still runs after policy or exception changes
- Fix root `authorized_keys` import path, blast-radius passwordless sudo counting, invalid exception expiry handling, and sshd false positive for `StrictHostKeyChecking`
- Improve native transport: per-command timeouts, proxy-jump session cleanup on failure, bracketed IPv6 hop parsing, and unique OpenSSH control socket paths under concurrency

## 2.0.0

- Add native transport ProxyJump support via russh direct-tcpip chaining (`--proxy-jump` / `-J`)
- Parse hop syntax with optional `user@host:port` segments and comma-separated multi-hop chains
- Remove the native-transport rejection for `--proxy-jump`; OpenSSH and native transports now both honor jump hosts

## 1.28.0

- Extract `build_app` from `sshmap serve` for testable router construction
- Add in-process API integration tests for auth, summary, host/user/risk list filters, and 404 handling

## 1.27.0

- Add `docs/api.md` with REST endpoint reference, query parameters, and curl examples
- Update README and integrations docs with filtered list endpoints and API doc link

## 1.26.0

- Add user list API filters for username search, minimum host count, minimum risk count, and limit
- Extend React users page with matching toolbar filters and URL query parameters

## 1.25.0

- Add host list API filters for SSH state, source, hostname/IP search, and result limit
- Extend React hosts page with matching toolbar filters and URL query parameters

## 1.24.0

- Filter risks server-side by severity and risk code with configurable result limits (100–1000)
- Persist keys and risks list filters in URL query parameters for shareable dashboard views

## 1.23.0

- Add keys list filter to switch between reused keys and the full inventory
- Replace detail back links with breadcrumb navigation on host, user, key, and risk pages

## 1.22.0

- Add key detail route (`/keys/:id`) with locations and related risks
- Add risk detail route (`/risks/:id`) with structured fields and cross-links to hosts and users
- Link risk and key rows across host, user, and list views

## 1.21.0

- Add React dashboard host detail route (`/hosts/:id`) with users and risks sections
- Add user detail route (`/users/:username`) with accounts, keys, sudo rules, and risks
- Link host and user list rows to detail pages; lazy-load Cytoscape graph bundle

## 1.20.0

- Add CI job to build the React dashboard on every push and pull request
- Attach `sshmap-dashboard.tar.gz` (built `dashboard/dist`) to tagged GitHub releases

## 1.19.0

- Extend React dashboard with users, keys, graph (Cytoscape canvas + table), risk detail panel, and graph tools
- Match embedded dashboard coverage for path analysis, blast radius, and exceptions lookup

## 1.18.0

- Add React dashboard under `dashboard/` (Vite + TypeScript) with summary, hosts, risks, and tools views
- Add `--dashboard DIR` to `sshmap serve` to serve a built static bundle with SPA fallback
- Add `serve.dashboard` in YAML config; embedded HTML dashboard remains the default

## 1.17.0

- Add `--identities-only` and `--no-identities-only` to restrict scan auth to `--key` only
- Default to identities-only when `--key` is set without `--agent` (OpenSSH `IdentitiesOnly=yes`)
- Native transport skips agent fallback when identities-only is enabled

## 1.16.0

- Add `--agent` and `--identity-agent` to `scan` for SSH agent authentication on OpenSSH and native transports
- Add `scan.use_agent` and `scan.identity_agent` config keys; scan requires `--key`, `--agent`, or config equivalent
- Extend `sshmap doctor` with optional SSH agent socket connectivity when agent auth is enabled

## 1.15.0

- Add `--proxy-jump` / `-J` to `scan` for OpenSSH ProxyJump chains (`scan.proxy_jump` in YAML)
- Reject `--proxy-jump` with `--transport native` until native jump support lands in 2.x

## 1.14.0

- Extend `sshmap doctor` with known_hosts file writability checks for `yes` and `accept-new` policies
- Config validation in doctor now reports the resolved known_hosts path
- Skips the known_hosts check when `strict-host-key no` is configured

## 1.13.0

- Native transport persists newly accepted host keys to the configured known_hosts file under `accept-new`
- OpenSSH transport passes `UserKnownHostsFile` when `--known-hosts` or config path is set
- Key mismatch still fails under `accept-new`; only unknown hosts are learned

## 1.12.0

- Add benchmark trend comparison against a saved JSON baseline (`--baseline` or `trend` in threshold profile)
- Add `benchmarks/ci-baseline.json` and trend limits to `benchmarks/ci-thresholds.json`
- CI benchmark job now fails on absolute threshold breaches and relative regressions vs baseline

## 1.11.0

- Extend `sshmap doctor` with OpenSSH ControlMaster readiness via `ssh -G`
- Add control socket directory writability check for connection reuse
- Config validation in doctor now reports `scan.transport` and `connection_reuse`

## 1.10.0

- OpenSSH transport reuses one connection per host via ControlMaster (`ControlPath`, `ControlPersist`)
- Add `--no-connection-reuse` to `scan` and `scan.connection_reuse` in YAML config (default: enabled)
- Native transport already reused one session per host; OpenSSH now matches that behavior

## 1.9.0

- Add `--strict-host-key` and `--known-hosts` to `scan` for host key verification on both transports
- Native transport reuses one SSH session per host during collection
- Default host key policy is `accept-new` with `~/.ssh/known_hosts` (unknown keys are accepted for the scan session only)

## 1.8.0

- Implement native SSH transport for `scan --transport native` using in-process russh
- Native transport uses private key auth and default known-hosts verification
- No OpenSSH client binary required when using `--transport native`

## 1.7.0

- Add `--thresholds` to `sshmap bench` for regression checks against JSON limits
- Add `benchmarks/ci-thresholds.json` and a CI benchmark job on release builds

## 1.6.0

- Add `sshmap bench` to measure analyze, report, graph export, and incremental skip timings
- Seed synthetic multi-host workloads with `--seed` for repeatable local performance checks

## 1.5.0

- Add `--transport openssh|native` to `scan` with config override via `scan.transport`
- Introduce `NativeTransport` stub for future in-process SSH support
- Extend `sshmap doctor` with scan transport readiness checks

## 1.4.0

- Add `--incremental` to `analyze` to skip reruns when no new raw evidence exists
- Extend `db stats` with detailed inventory counts, schema version, and `--json` output
- Add migration 008 for analysis metadata tracking

## 1.3.0

- Add `--progress` to `discover` and `scan` for stderr progress reporting
- Add `--max-targets` safety limit for large scope expansion (default 65536)
- Add `sshmap export ssh-config` for CSV and JSON integration output
- Introduce `RemoteTransport` trait as the foundation for future native SSH transport
- Support `runtime.max_targets` in YAML config

## 1.2.2

- Extend `sshmap doctor` with optional `--db`, `--config`, and `--scope` validation
- Add `sshmap export known-hosts` for CSV and JSON integration output
- Tune SQLite pragmas for larger inventories (`cache_size`, `temp_store`)
- Add large CIDR scope expansion regression test

## 1.2.1

- Add macOS aarch64 and x86_64 release binaries
- Add CSV report exports for `known_hosts.csv` and `ssh_client_config.csv`
- Add REST API endpoints for exceptions, known hosts, and SSH client config
- Improve dashboard risk detail view and exception lookup in Tools

## 1.2.0

- Collect `known_hosts` and `ssh_config` during remote scan and local scan
- Add Cytoscape graph export format (`sshmap graph export --format cytoscape`)
- Add interactive graph canvas view to the embedded dashboard
- Improve release workflow with unified checksums and optional GPG signature support

## 1.1.0

- Add integration export commands (`sshmap export summary|risks|hosts`)
- Move HTML report layout to `templates/report.html` and `templates/report.css`
- Add Linux packaging helpers (`packaging/build-packages.sh`, nfpm config, Dockerfile)
- Extend release workflow with x86_64 and aarch64 Linux artifacts
- Add `docs/integrations.md` and `docs/packaging.md`

## 1.0.0

- Stable CLI release with migration 007 for `known_hosts` and SSH client config data
- Add `known_hosts` and `ssh_config` parsers, graph edges, and client-side risk rules
- Add configurable risk policy via `--risk-policy` or `risk_policy` in YAML config
- Add `sshmap db migrate` for explicit schema upgrades
- Add `sshmap import ssh-config` for offline client config evidence
- Add CLI workflow integration tests and complete user/developer documentation
- Bump version to 1.0.0

## 0.9.0

- Add `sshmap serve` read-only REST API and embedded dashboard
- Add offline import framework (`ansible`, `nmap`, `csv`, `known-hosts`, evidence files, JSON)
- Add `local-scan`, `blast-radius`, CSV report export, and graph edge CSV output
- Add YAML configuration via `--config` and `examples/sshmap.yaml`
- Add risk exceptions (`sshmap exceptions list|add|remove`)
- Add shell completion generator (`sshmap completion --shell bash`)
- Add combined and extended SSH risk rules
- Add `analyze --only risks|graph|all`
- Add user documentation under `docs/`

## 0.1.0

- Initial agentless SSH exposure CLI
- Discovery, authenticated scan, analyze, risk engine, graph, baselines, and reports
