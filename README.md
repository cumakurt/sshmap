# SSHMap

SSHMap is an agentless SSH exposure management CLI. It discovers SSH services, collects read-only configuration evidence, analyzes risks, builds a directed access graph, and exposes inventory through a CLI, REST API, and React dashboard.

**Current release:** `2.0.0`

## Features

- TCP SSH discovery and authenticated read-only remote collection (OpenSSH or in-process native russh transport)
- ProxyJump support on both transports (`--proxy-jump` / `-J`)
- Risk engine with YAML policy tuning, baselines, diff, and exceptions
- Access graph export (JSON, DOT, Cytoscape) plus path and blast-radius analysis
- Offline importers, local scan, HTML/JSON/CSV reports, and integration exports
- Read-only REST API, embedded HTML dashboard, and optional React dashboard bundle
- CI benchmark regression profile and tagged release artifacts (binaries + dashboard tarball)

## Safety

Only use SSHMap against systems you own or are explicitly authorized to assess.

SSHMap supports read-only inspection through the system OpenSSH client or the built-in native transport. It does not brute force, exploit, or attempt password login.

## Installation

The repository includes an `install.sh` installer. It detects the operating system and supported package manager, installs missing system dependencies, installs Rust through rustup when `cargo` is missing, builds the release binary, and copies it to `~/.local/bin` by default.

Supported package managers:

```text
apt, dnf, yum, pacman, zypper, apk, brew
```

After installation, verify the binary and optional project files:

```bash
sshmap doctor
sshmap doctor --db sshmap.db --config examples/sshmap.yaml --scope examples/hosts.txt
```

See `docs/doctor.md` for the full check list.

## Quick Start

Initialize a new SQLite database and verify local runtime requirements:

```bash
sshmap init --db sshmap.db
sshmap doctor
sshmap db stats --db sshmap.db
sshmap db migrate --db sshmap.db
```

Run unauthenticated SSH discovery against localhost:

```bash
sshmap discover \
  --targets 127.0.0.1 \
  --ports 22 \
  --timeout 3 \
  --concurrency 10 \
  --db sshmap.db
```

Run analysis and inspect any generated findings:

```bash
sshmap analyze --db sshmap.db
sshmap risks list --db sshmap.db
```

`analyze` parses raw evidence into normalized tables and generates the first risk findings for SSH daemon configuration, unrestricted authorized keys, key reuse, and sudo rules.
It also rebuilds the directed SSH access graph used by graph export and path analysis commands.

Export the access graph and inspect a specific reachability path:

```bash
sshmap graph export \
  --format dot \
  --output sshmap-access-graph.dot \
  --db sshmap.db

sshmap path \
  --from key:SHA256:exampleFingerprint \
  --to host:web01 \
  --db sshmap.db
```

Create a baseline for future drift comparison:

```bash
sshmap baseline create \
  --name initial-audit \
  --db sshmap.db
```

## Configuration

Load shared defaults from YAML:

```bash
sshmap --config examples/sshmap.yaml scan --file hosts.txt --db sshmap.db
```

See `examples/sshmap.yaml` for scan, discover, serve, and database defaults.

## Detailed Usage

### Discovery

Discover SSH services in a CIDR range:

```bash
sshmap discover \
  --targets 10.10.0.0/24 \
  --ports 22 \
  --timeout 3 \
  --concurrency 100 \
  --db sshmap.db
```

Discover multiple SSH ports:

```bash
sshmap discover \
  --targets 10.10.10.5,10.10.10.6 \
  --ports 22,2222,2200 \
  --timeout 5 \
  --concurrency 50 \
  --db sshmap.db
```

Discover hosts from a file:

```bash
sshmap discover \
  --file examples/hosts.txt \
  --ports 22 \
  --db sshmap.db
```

### Authenticated Scan

Run an authenticated read-only scan with an audit key:

```bash
sshmap scan \
  --file examples/hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --timeout 10 \
  --concurrency 20 \
  --transport openssh \
  --strict-host-key accept-new \
  --db sshmap.db
```

OpenSSH reuses one multiplexed connection per host by default. Disable with `--no-connection-reuse` if ControlMaster is blocked on your jump hosts.

Scan through a bastion with ProxyJump (OpenSSH or native transport):

```bash
sshmap scan \
  --file examples/hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --proxy-jump bastion.example.com \
  --transport native \
  --db sshmap.db
```

Use a loaded SSH agent instead of a key file:

```bash
sshmap scan \
  --file examples/hosts.txt \
  --user audituser \
  --agent \
  --transport openssh \
  --db sshmap.db
```

Use the in-process native transport when the OpenSSH client is unavailable:

```bash
sshmap scan \
  --file examples/hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --transport native \
  --db sshmap.db
```

Run an authenticated scan with non-interactive sudo collection enabled:

```bash
sshmap scan \
  --targets 10.10.0.0/24 \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --sudo \
  --timeout 10 \
  --concurrency 20 \
  --db sshmap.db
```

### Local Scan

Run a read-only audit on the local host without SSH:

```bash
sshmap local-scan --db sshmap.db
```

Use `--sudo` when passwordless sudo is configured for the required read-only collection commands:

```bash
sshmap local-scan --sudo --db sshmap.db
```

Private key contents are never collected. Only public keys, permissions, owners, and path metadata are inspected.

### Offline Import

Import host inventory or evidence files without live SSH access:

```bash
sshmap import ansible --file inventory.ini --db sshmap.db
sshmap import nmap --file nmap.xml --db sshmap.db
sshmap import csv --file hosts.csv --db sshmap.db
sshmap import known-hosts --file ~/.ssh/known_hosts --db sshmap.db
```

Import normalized evidence files for offline analysis:

```bash
sshmap import sshd-config --file sshd_config --host web01 --db sshmap.db
sshmap import ssh-config --file config --host workstation01 --db sshmap.db
sshmap import authorized-keys --file authorized_keys --host web01 --user deploy --db sshmap.db
sshmap import sudoers --file sudoers --host web01 --db sshmap.db
sshmap import json --file sshmap-report.json --db sshmap.db
```

Run `sshmap analyze --db sshmap.db` after importing evidence files.

### Analysis

Normalize collected raw evidence and generate findings:

```bash
sshmap analyze --db sshmap.db
sshmap analyze --only risks --db sshmap.db --risk-policy examples/risk-policy.yaml
```

Tune risk severity and thresholds with a YAML policy file. Set `risk_policy` in `examples/sshmap.yaml` or pass `--risk-policy` globally:

```bash
sshmap analyze --db sshmap.db --config examples/sshmap.yaml
```

Run only part of the analysis pipeline:

```bash
sshmap analyze --only risks --db sshmap.db
sshmap analyze --only graph --db sshmap.db
sshmap analyze --incremental --only graph --db sshmap.db
```

Skip analysis when no new evidence was collected since the last successful run.

Check database counts after analysis:

```bash
sshmap db stats --db sshmap.db
sshmap db stats --json --db sshmap.db
```

Measure local analyze and report performance:

```bash
sshmap bench --seed --hosts 25 --iterations 3 --db bench.db
sshmap bench --seed --json --db bench.db
sshmap bench --seed --thresholds benchmarks/ci-thresholds.json --db bench.db
```

See `docs/benchmarks.md` for details.

### Risks

List all findings:

```bash
sshmap risks list --db sshmap.db
```

List only critical findings:

```bash
sshmap risks list \
  --severity critical \
  --db sshmap.db
```

List a specific risk code:

```bash
sshmap risks list \
  --code SSH_PASSWORD_AUTH_ENABLED \
  --db sshmap.db
```

Show a finding with evidence and remediation guidance:

```bash
sshmap risks show 1 --db sshmap.db
```

### Risk Exceptions

Suppress accepted findings during analysis:

```bash
sshmap exceptions add \
  --code SSH_PASSWORD_AUTH_ENABLED \
  --host-id 12 \
  --reason "Accepted legacy jump host" \
  --db sshmap.db

sshmap exceptions list --db sshmap.db
sshmap exceptions remove 1 --db sshmap.db
```

### Shell Completion

```bash
sshmap completion --shell bash > ~/.local/share/bash-completion/completions/sshmap
sshmap completion --shell zsh > ~/.zfunc/_sshmap
```

Export risk results as JSON:

```bash
sshmap risks list \
  --severity high \
  --json \
  --db sshmap.db
```

### Inventory

List discovered and scanned hosts:

```bash
sshmap host list --db sshmap.db
```

Show host details, local users, and host-linked findings:

```bash
sshmap host show web01 --db sshmap.db
```

List normalized SSH users:

```bash
sshmap user list --db sshmap.db
```

Show where a user exists, which keys authorize access, and which sudo rules apply:

```bash
sshmap user show deploy --db sshmap.db
```

List public keys:

```bash
sshmap keys list --db sshmap.db
```

List reused public keys:

```bash
sshmap keys reuse --db sshmap.db
```

Show key locations and key-linked findings:

```bash
sshmap keys show 1 --db sshmap.db
```

### Access Graph

Rebuild the access graph after discovery and authenticated scans:

```bash
sshmap analyze --db sshmap.db
```

Export the graph as JSON for automation pipelines:

```bash
sshmap graph export \
  --format json \
  --output sshmap-access-graph.json \
  --db sshmap.db
```

Export the graph as Graphviz DOT for visualization:

```bash
sshmap graph export \
  --format dot \
  --output sshmap-access-graph.dot \
  --db sshmap.db
```

Export the graph for Cytoscape.js or the embedded dashboard:

```bash
sshmap graph export \
  --format cytoscape \
  --output sshmap-access-graph.cytoscape.json \
  --db sshmap.db
```

The access graph currently models hosts, local users, public keys, and sudo rules. Important edge types include:

```text
HOST_HAS_USER
USER_ON_HOST
PUBLIC_KEY_CAN_LOGIN_TO_USER
PUBLIC_KEY_REUSED_ON_HOST
USER_HAS_SUDO_RULE
SUDO_RULE_APPLIES_TO_HOST
USER_HAS_PASSWORDLESS_SUDO
```

Use `sshmap keys list --db sshmap.db` to get a stable SHA256 fingerprint before running path analysis:

```bash
sshmap keys list --db sshmap.db
```

Find whether a public key can reach a host:

```bash
sshmap path \
  --from key:SHA256:exampleFingerprint \
  --to host:web01 \
  --db sshmap.db
```

Find whether a host-local user has a path to another host:

```bash
sshmap path \
  --from user:deploy@web01 \
  --to host:web02 \
  --db sshmap.db
```

Return path analysis as JSON:

```bash
sshmap path \
  --from user:deploy@web01 \
  --to host:web02 \
  --json \
  --db sshmap.db
```

Measure blast radius for a username across all host-local accounts:

```bash
sshmap blast-radius \
  --user deploy \
  --db sshmap.db
```

Return blast radius analysis as JSON:

```bash
sshmap blast-radius \
  --user deploy \
  --json \
  --db sshmap.db
```

Supported node reference formats:

```text
host:web01
host:10.10.0.15
user:deploy
user:deploy@web01
key:SHA256:exampleFingerprint
key:1
sudo_rule:1
```

Prefer fingerprint-based key references such as `key:SHA256:exampleFingerprint` in repeatable workflows. Numeric key IDs are database-local identifiers and may change after repeated imports or analysis runs.

### Baselines and Diff

Create a named baseline from the current normalized risk state:

```bash
sshmap baseline create \
  --name 2026-q2 \
  --db sshmap.db
```

Create a baseline and return the saved snapshot metadata as JSON:

```bash
sshmap baseline create \
  --name before-remediation \
  --json \
  --db sshmap.db
```

List available baselines:

```bash
sshmap baseline list --db sshmap.db
```

Compare a baseline with the current database state:

```bash
sshmap diff \
  --from 2026-q2 \
  --to latest \
  --db sshmap.db
```

Return the full diff as JSON for automation:

```bash
sshmap diff \
  --from 2026-q2 \
  --to latest \
  --json \
  --db sshmap.db
```

Compare two saved baselines:

```bash
sshmap diff \
  --from before-remediation \
  --to after-remediation \
  --db sshmap.db
```

The diff output reports new risks, resolved risks, and unchanged risk count. `latest` is a reserved reference that means the current `risks` table after the most recent `sshmap analyze` run.

### Reports

Create a machine-readable JSON report:

```bash
sshmap report create \
  --format json \
  --output sshmap-report.json \
  --db sshmap.db
```

Create a single-file HTML report:

```bash
sshmap report create \
  --format html \
  --output sshmap-report.html \
  --db sshmap.db
```

Create CSV exports for automation:

```bash
sshmap report create \
  --format csv \
  --output report-out/ \
  --db sshmap.db
```

This writes `hosts.csv`, `users.csv`, `public_keys.csv`, `key_reuse.csv`, `risks.csv`, `graph_edges.csv`, `known_hosts.csv`, and `ssh_client_config.csv` into the output directory.

### Integration Export

Export compact JSON or monitoring-friendly CSV for automation pipelines:

```bash
sshmap export summary --db sshmap.db --output summary.json
sshmap export risks --format ndjson --severity CRITICAL --db sshmap.db --output critical.ndjson
sshmap export hosts --format csv --db sshmap.db --output hosts-monitoring.csv
sshmap export known-hosts --format csv --db sshmap.db --output known-hosts.csv
sshmap export ssh-config --format json --db sshmap.db --output ssh-config.json
```

See `docs/integrations.md`.

### Packaging

Build release artifacts locally:

```bash
./packaging/build-packages.sh
```

See `docs/packaging.md` for Linux packages, container images, and release notes.

### Read-Only Web Server

Serve the SQLite database through a read-only REST API. By default, `sshmap serve` ships an embedded HTML dashboard; you can also serve the React dashboard built from `dashboard/`.

Embedded dashboard:

```bash
sshmap serve \
  --db sshmap.db \
  --listen 127.0.0.1:8080 \
  --read-only
```

React dashboard (recommended for host/user/key/risk detail views, graph canvas, and filtered inventory lists):

```bash
cd dashboard && npm ci && npm run build
sshmap serve \
  --db sshmap.db \
  --listen 127.0.0.1:8080 \
  --read-only \
  --dashboard dashboard/dist
```

React dashboard routes include `/`, `/hosts`, `/users`, `/keys`, `/risks`, `/graph`, and `/tools`. List filters are reflected in URL query parameters for shareable views.

See `docs/dashboard.md` for local development with the Vite dev server and `docs/api.md` for REST endpoint reference.

Optional API token authentication (required when listening on non-loopback addresses):

```bash
sshmap serve \
  --db sshmap.db \
  --listen 127.0.0.1:8080 \
  --read-only \
  --token "$SSHMAP_TOKEN"
```

When bound to loopback only, the token is optional but strongly recommended outside single-user development setups.

Send the token using the `X-SSHMap-Token` header. The dashboard stores the token in browser local storage when configured from the Tools tab.

Core API endpoints:

```text
GET /api/summary
GET /api/hosts?ssh_open=&source=&q=&limit=
GET /api/hosts/{id}
GET /api/users?q=&min_hosts=&min_risks=&limit=
GET /api/users/{username}
GET /api/keys
GET /api/keys/reuse
GET /api/keys/{target}
GET /api/risks?severity=&code=&limit=
GET /api/risks/{id}
GET /api/graph?limit=
GET /api/path?from=...&to=...
GET /api/blast-radius?user=...
GET /api/baselines
GET /api/exceptions
GET /api/known-hosts
GET /api/ssh-config
```

See `docs/api.md` for query parameters, examples, and response shapes.

See the documentation index:

```text
docs/getting-started.md
docs/scope.md
docs/discovery.md
docs/authenticated-scan.md
docs/local-scan.md
docs/importers.md
docs/reports.md
docs/remediation.md
docs/integrations.md
docs/packaging.md
docs/doctor.md
docs/dashboard.md
docs/api.md
docs/benchmarks.md
docs/architecture.md
docs/development/
```

Start with `docs/getting-started.md` and `docs/architecture.md`.

### End-to-End Example

Run a complete authorized audit workflow:

```bash
sshmap init --db customer.db

sshmap discover \
  --file examples/hosts.txt \
  --ports 22 \
  --concurrency 100 \
  --db customer.db

sshmap scan \
  --file examples/hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --sudo \
  --timeout 10 \
  --concurrency 20 \
  --db customer.db

sshmap analyze --db customer.db

sshmap risks list \
  --severity critical \
  --db customer.db

sshmap keys reuse --db customer.db

sshmap graph export \
  --format dot \
  --output customer-access-graph.dot \
  --db customer.db

sshmap path \
  --from key:SHA256:exampleFingerprint \
  --to host:web01 \
  --db customer.db

sshmap baseline create \
  --name customer-initial \
  --db customer.db

sshmap diff \
  --from customer-initial \
  --to latest \
  --db customer.db

sshmap report create \
  --format html \
  --output customer-sshmap-report.html \
  --db customer.db
```

## Coding Standard

All source code, identifiers, comments, database names, CLI commands, tests, error messages, and log messages must be written in English.
