# SSHMap

SSHMap is an agentless SSH exposure management CLI. It discovers SSH services, collects read-only configuration evidence, analyzes security risks, builds a directed access graph, and exposes inventory through a command-line interface, REST API, and React dashboard.

**Current release:** `2.0.5`  
**License:** [GNU General Public License v3.0 or later](LICENSE) (GPL-3.0-or-later)

## Author

| | |
|---|---|
| **Developer** | Cuma Kurt |
| **Email** | [cumakurt@gmail.com](mailto:cumakurt@gmail.com) |
| **LinkedIn** | [cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/) |
| **GitHub** | [cumakurt/sshmap](https://github.com/cumakurt/sshmap) |

Run `sshmap` or `sshmap --help` for the full command reference. Use `sshmap <command> --help` for detailed flag documentation on any subcommand.

---

## Table of Contents

- [What SSHMap Does](#what-sshmap-does)
- [Feature Reference](#feature-reference)
- [Safety](#safety)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Command Examples](#command-examples)
- [Web Server, API, and Dashboard](#web-server-api-and-dashboard)
- [End-to-End Workflow](#end-to-end-workflow)
- [Documentation Index](#documentation-index)
- [Coding Standard](#coding-standard)
- [License](#license)

---

## What SSHMap Does

SSHMap answers four practical questions for infrastructure and security teams:

1. **Where is SSH exposed?** — TCP discovery finds open SSH ports and banners without authentication.
2. **What SSH-related configuration exists?** — Authenticated scans and imports collect `sshd_config`, `authorized_keys`, sudoers, `known_hosts`, and client `ssh_config` evidence.
3. **What is risky?** — A built-in risk engine flags weak daemon settings, unrestricted keys, key reuse, dangerous sudo rules, and combined escalation paths.
4. **How can access spread?** — A directed graph models users, keys, hosts, and sudo relationships for path and blast-radius analysis.

All findings are stored in a local SQLite database. You can query them from the CLI, export reports, compare baselines over time, or serve them through a read-only API.

---

## Feature Reference

Each section below explains **what a feature does**, **when to use it**, and **what it produces**.

### Database (`init`, `db`)

| Command | Purpose |
|---------|---------|
| `sshmap init` | Creates a new SQLite database with the current schema. Use this at the start of every engagement or customer project. |
| `sshmap db migrate` | Applies pending schema migrations to an existing database. Safe to run after upgrades. |
| `sshmap db stats` | Prints row counts for hosts, users, keys, risks, raw evidence, graph edges, baselines, and exceptions. Use to verify that collection and analysis completed. |

The database is the single source of truth. Discovery, scans, imports, and analysis all write into it; reports, graph tools, and the API read from it.

### Runtime Checks (`doctor`)

`sshmap doctor` validates the local environment before you run discovery or scans:

- OpenSSH client availability and version
- SSH agent socket when `--agent` is configured
- ControlMaster / multiplexing support for connection reuse
- Writable control socket directory
- Known-hosts file permissions when strict host key checking is enabled
- Optional scope file readability

Use doctor in CI, onboarding scripts, or when scan failures suggest a local tooling problem rather than a remote host issue.

### SSH Discovery (`discover`)

**Purpose:** Find which targets expose SSH **without** logging in.

Discovery performs concurrent TCP checks against IP addresses, CIDR ranges, hostnames, or a target file. For each open port it records:

- Target host and port
- Whether SSH appears open
- SSH banner text when available
- Timestamp and source (`discover`)

**When to use:** Network sweeps, asset inventory, or the first phase of an audit before you have credentials.

**Output:** Host rows in the `hosts` table with `ssh_open` and optional `ssh_banner`. No user accounts or keys are collected at this stage.

```bash
sshmap discover --targets 10.10.0.0/24 --ports 22,2222 --concurrency 100 --db sshmap.db
```

### Authenticated Scan (`scan`)

**Purpose:** Collect read-only SSH security evidence from live hosts using an audit SSH key or agent.

After connecting, SSHMap runs a fixed set of remote commands (passwd, groups, authorized_keys, sshd_config, sudoers, known_hosts, ssh client config, hostname, etc.). Evidence is stored as raw text in `raw_evidence` and linked to host rows.

| Option | What it does |
|--------|----------------|
| `--user` / `--key` | SSH identity for authentication |
| `--agent` | Use `SSH_AUTH_SOCK` instead of a key file |
| `--sudo` | Prefix commands that need root-readable paths with non-interactive sudo |
| `--transport openssh` | Use the system `ssh` client (default); supports ControlMaster connection reuse |
| `--transport native` | Use the in-process russh client when OpenSSH is unavailable |
| `--proxy-jump` / `-J` | Reach targets through one or more bastion hops (OpenSSH and native) |
| `--strict-host-key` | Control host key verification (`yes`, `no`, `accept-new`) |
| `--no-connection-reuse` | Disable OpenSSH ControlMaster per-host multiplexing |

**When to use:** Authorized assessments where you have SSH access and want live, complete evidence.

**Output:** Raw evidence rows per host. Run `sshmap analyze` afterward to parse and score findings.

Private key file **contents** are never stored. Sensitive patterns in collected output (private keys, secret assignments) are redacted before persistence.

### Local Scan (`local-scan`)

**Purpose:** Audit the machine where SSHMap runs **without SSH**.

Local scan executes the same read-only collection commands locally. Useful for bastions, CI runners, or air-gapped analysis workstations.

Use `--sudo` when passwordless sudo is required to read `/etc/ssh`, `/etc/sudoers`, and user home directories.

**Output:** Same raw evidence pipeline as remote scan; host source is recorded as a local collection.

### Offline Import (`import`)

**Purpose:** Load inventory or evidence files when live SSH is impossible or undesirable.

| Import type | Input | What it adds |
|-------------|-------|----------------|
| `ansible` | Ansible INI inventory | Hostname/IP rows |
| `nmap` | Nmap XML | Discovered SSH hosts |
| `csv` | Custom CSV mapping | Host inventory |
| `known-hosts` | `known_hosts` file | Client trust relationships |
| `sshd-config` | `sshd_config` snippet | Daemon configuration evidence |
| `ssh-config` | SSH client config | Client jump/forward settings |
| `authorized-keys` | `authorized_keys` file | Key-to-user bindings (requires `--user`) |
| `sudoers` | sudoers fragment | Privilege escalation rules |
| `json` | Prior SSHMap JSON report | Host inventory from export |

Imports create or update host rows and insert raw evidence. IPv6 targets are supported in bracketed form, e.g. `--host [2001:db8::1]:2222`.

**When to use:** Offline forensics, vendor file drops, or combining scanner output with later analysis.

### Analysis (`analyze`)

**Purpose:** Turn raw evidence into structured tables, risk findings, and the access graph.

The analyzer:

1. Parses passwd, groups, authorized_keys, sshd_config, sudoers, known_hosts, and ssh_config
2. Normalizes users, keys, sudo rules, and client config entries
3. Runs the risk engine (with optional YAML policy overrides)
4. Applies stored risk exceptions
5. Rebuilds graph edges between hosts, users, keys, and sudo rules
6. Records analysis timestamp for incremental mode

| Flag | What it does |
|------|----------------|
| `--only risks` | Regenerate risks only (skip graph rebuild) |
| `--only graph` | Rebuild graph only (skip risk regeneration) |
| `--risk-policy` | YAML file to disable rules or change severity thresholds |
| `--incremental --only graph` | Skip graph rebuild when no new evidence since last run |

**When to use:** After every discovery, scan, or import batch.

**Output:** Populated `users`, `public_keys`, `authorized_keys`, `risks`, `graph_edges`, and related tables.

### Risk Engine (`risks`, `exceptions`)

**Purpose:** Surface actionable SSH exposure findings with severity, evidence, and remediation text.

Example risk categories:

- Weak `sshd_config` (password auth, root login, forwarding)
- Unrestricted `authorized_keys` entries
- SSH key reuse across hosts or users
- Dangerous sudo rules (NOPASSWD, broad commands)
- Combined critical paths (reused key plus passwordless sudo)
- Risky SSH client config (`StrictHostKeyChecking no`, `ProxyJump` chains)

| Command | Purpose |
|---------|---------|
| `sshmap risks list` | Filter by severity or risk code |
| `sshmap risks show <id>` | Full detail, evidence, and recommendation |
| `sshmap exceptions add` | Suppress accepted findings (optional expiry, host, user, or key scope) |
| `sshmap exceptions list` | Review active suppressions |
| `sshmap exceptions remove` | Delete an exception |

Exceptions are applied during analysis, not at display time, so suppressed risks do not reappear until the exception expires or is removed.

### Inventory (`host`, `user`, `keys`)

**Purpose:** Browse normalized SSH identity and access data.

| Command | What you get |
|---------|----------------|
| `host list` / `host show` | Hosts with SSH state, user counts, linked risks |
| `user list` / `user show` | Cross-host user presence, authorized keys, sudo rules, risks |
| `keys list` | All public keys with usage counts |
| `keys reuse` | Keys appearing on multiple hosts or users |
| `keys show` | Key fingerprint, locations, and linked risks |

Use inventory commands for triage before diving into graph path analysis.

### Access Graph (`graph`, `path`, `blast-radius`)

**Purpose:** Model and query how SSH access can flow through your estate.

The graph contains nodes for **hosts**, **users**, **public keys**, and **sudo rules**. Edges describe relationships such as:

```text
HOST_HAS_USER
USER_ON_HOST
PUBLIC_KEY_CAN_LOGIN_TO_USER
PUBLIC_KEY_REUSED_ON_HOST
USER_HAS_SUDO_RULE
SUDO_RULE_APPLIES_TO_HOST
USER_HAS_PASSWORDLESS_SUDO
CLIENT_CONFIG_PROXY_JUMP
```

| Command | Purpose |
|---------|---------|
| `graph export` | Export JSON, Graphviz DOT, or Cytoscape JSON for visualization |
| `path --from ... --to ...` | Shortest directed path between two graph nodes |
| `blast-radius --user ...` | All hosts, keys, and passwordless-sudo targets reachable from a username |

Node references use `type:value` syntax, e.g. `host:web01`, `user:deploy@web01`, `key:SHA256:...`.

**When to use:** Lateral movement analysis, key compromise impact, or explaining access chains to stakeholders.

### Baselines and Drift (`baseline`, `diff`)

**Purpose:** Track how risk posture changes over time.

| Command | Purpose |
|---------|---------|
| `baseline create --name <name>` | Snapshot current risks (signatures, severity, targets) |
| `baseline list` | List saved baselines |
| `diff --from <name> --to latest` | New, resolved, and unchanged risks since baseline |
| `diff --from <a> --to <b>` | Compare any two baselines |

Use baselines after initial audit and after remediation sprints to prove progress.

### Reports and Exports (`report`, `export`)

**Purpose:** Deliver findings to humans and automation.

| Command | Output |
|---------|--------|
| `report create --format json` | Single JSON document with hosts, users, keys, risks, graph |
| `report create --format html` | Self-contained HTML report |
| `report create --format csv` | Directory of CSV files per entity type |
| `export summary` | Compact JSON stats for dashboards |
| `export risks` | JSON or NDJSON risk stream |
| `export hosts` / `known-hosts` / `ssh-config` | Filtered CSV or JSON slices |

### Performance Benchmarks (`bench`)

**Purpose:** Measure analyze, report, and graph performance on a seeded database; enforce CI regression thresholds.

```bash
sshmap bench --seed --hosts 25 --iterations 3 --thresholds benchmarks/ci-thresholds.json --db bench.db
```

Use in release pipelines to catch performance regressions.

### Read-Only Server (`serve`)

**Purpose:** Expose the SQLite inventory over HTTP for dashboards and integrations.

- Opens the database in **read-only** mode
- Serves JSON REST endpoints under `/api/*`
- Optional embedded HTML dashboard or React build from `dashboard/dist`
- Optional `--token` authentication (`X-SSHMap-Token` header); required on non-loopback binds

See [Web Server, API, and Dashboard](#web-server-api-and-dashboard) for endpoint list.

### Shell Completion (`completion`)

Generates bash or zsh completion scripts for faster CLI usage:

```bash
sshmap completion --shell bash > ~/.local/share/bash-completion/completions/sshmap
```

---

## Safety

Only use SSHMap against systems you own or are explicitly authorized to assess.

SSHMap supports read-only inspection through the system OpenSSH client or the built-in native transport. It does not brute force, exploit, or attempt password login. An authorization notice is printed before discovery, scan, and local-scan commands.

---

## Installation

The repository includes an `install.sh` installer. It detects the operating system and supported package manager, installs missing system dependencies, installs Rust through rustup when `cargo` is missing, builds the release binary, and copies it to `~/.local/bin` by default.

Supported package managers:

```text
apt, dnf, yum, pacman, zypper, apk, brew
```

After installation:

```bash
sshmap doctor
sshmap doctor --db sshmap.db --config examples/sshmap.yaml --scope examples/hosts.txt
```

See `docs/doctor.md` for the full check list.

---

## Quick Start

```bash
sshmap init --db sshmap.db
sshmap doctor
sshmap db stats --db sshmap.db

sshmap discover --targets 127.0.0.1 --ports 22 --db sshmap.db

sshmap analyze --db sshmap.db
sshmap risks list --db sshmap.db

sshmap graph export --format dot --output graph.dot --db sshmap.db
sshmap baseline create --name initial --db sshmap.db
```

---

## Configuration

Load shared defaults from YAML:

```bash
sshmap --config examples/sshmap.yaml scan --file hosts.txt --db sshmap.db
```

See `examples/sshmap.yaml` for scan, discover, serve, and database defaults.

---

## Command Examples

### Discovery

```bash
sshmap discover --targets 10.10.0.0/24 --ports 22 --concurrency 100 --db sshmap.db
sshmap discover --file examples/hosts.txt --ports 22,2222 --db sshmap.db
```

### Authenticated Scan

```bash
sshmap scan --file examples/hosts.txt --user audituser --key ~/.ssh/audit_ed25519 --db sshmap.db

sshmap scan --file examples/hosts.txt --user audituser --key ~/.ssh/audit_ed25519 \
  --proxy-jump bastion.example.com --transport native --db sshmap.db

sshmap scan --targets 10.10.0.0/24 --user audituser --key ~/.ssh/audit_ed25519 --sudo --db sshmap.db
```

### Offline Import

```bash
sshmap import ansible --file inventory.ini --db sshmap.db
sshmap import sshd-config --file sshd_config --host web01 --db sshmap.db
sshmap import authorized-keys --file authorized_keys --host web01 --user deploy --db sshmap.db
sshmap analyze --db sshmap.db
```

### Analysis and Risks

```bash
sshmap analyze --db sshmap.db --risk-policy examples/risk-policy.yaml
sshmap analyze --only risks --db sshmap.db
sshmap analyze --incremental --only graph --db sshmap.db

sshmap risks list --severity critical --db sshmap.db
sshmap exceptions add --code SSH_PASSWORD_AUTH_ENABLED --host-id 1 --reason "legacy" --db sshmap.db
```

### Graph and Path Analysis

```bash
sshmap keys list --db sshmap.db
sshmap path --from key:SHA256:exampleFingerprint --to host:web01 --db sshmap.db
sshmap blast-radius --user deploy --db sshmap.db
```

### Reports

```bash
sshmap report create --format html --output report.html --db sshmap.db
sshmap export summary --output summary.json --db sshmap.db
```

---

## Web Server, API, and Dashboard

Embedded dashboard:

```bash
sshmap serve --db sshmap.db --listen 127.0.0.1:8080 --read-only
```

React dashboard (detail pages, filters, graph canvas):

```bash
cd dashboard && npm ci && npm run build
sshmap serve --db sshmap.db --listen 127.0.0.1:8080 --read-only --dashboard dashboard/dist
```

API token (required on non-loopback addresses):

```bash
sshmap serve --db sshmap.db --listen 127.0.0.1:8080 --read-only --token "$SSHMAP_TOKEN"
```

Send the token in the `X-SSHMap-Token` header. The React dashboard stores it in browser local storage from the Tools page.

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

See `docs/api.md` and `docs/dashboard.md` for full reference.

---

## End-to-End Workflow

```bash
sshmap init --db customer.db

sshmap discover --file examples/hosts.txt --ports 22 --concurrency 100 --db customer.db

sshmap scan --file examples/hosts.txt --user audituser --key ~/.ssh/audit_ed25519 \
  --sudo --timeout 10 --concurrency 20 --db customer.db

sshmap analyze --db customer.db

sshmap risks list --severity critical --db customer.db
sshmap keys reuse --db customer.db
sshmap graph export --format dot --output customer-graph.dot --db customer.db
sshmap path --from key:SHA256:exampleFingerprint --to host:web01 --db customer.db

sshmap baseline create --name customer-initial --db customer.db
sshmap diff --from customer-initial --to latest --db customer.db

sshmap report create --format html --output customer-report.html --db customer.db
```

---

## Documentation Index

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

---

## Coding Standard

All source code, identifiers, comments, database names, CLI commands, tests, error messages, and log messages must be written in English.

---

## License

SSHMap is free software licensed under the **GNU General Public License v3.0 or later**.

Copyright (C) 2026 Cuma Kurt

You may redistribute and modify SSHMap under the terms of the GPL. See [LICENSE](LICENSE) for the full notice.
