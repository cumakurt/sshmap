//! Centralized help text for the SSHMap CLI.

pub const ROOT_AFTER_HELP: &str = "\
WORKFLOW
  init -> discover/scan/import -> analyze -> risks/graph/report

EXAMPLES
  sshmap -a -t 192.168.0.0/24
  sshmap -a -f /etc/hosts
  sshmap init --db inventory.db
  sshmap discover --file hosts.txt --db inventory.db
  sshmap scan --file hosts.txt --user audit --key ~/.ssh/id_ed25519 --db inventory.db
  sshmap analyze --db inventory.db
  sshmap serve --read-only --db inventory.db --listen 127.0.0.1:8080

DOCUMENTATION
  README.md, docs/getting-started.md, docs/api.md

AUTHORIZATION
  Use SSHMap only on systems you own or are explicitly authorized to assess.
";

pub const INIT_LONG: &str = "\
Create a new SQLite inventory database with the current schema.

Use this once per engagement or project before discovery, scans, or imports.
Existing files are not overwritten; re-running init on an existing database is safe.";

pub const DOCTOR_LONG: &str = "\
Validate the local runtime before discovery or authenticated scans.

Checks OpenSSH availability, SSH agent configuration, ControlMaster support,
control socket directory permissions, known-hosts writability, and optional
scope file readability.";

pub const DB_LONG: &str = "\
Database maintenance and inventory statistics.

  stats    Row counts for hosts, users, keys, risks, evidence, and graph edges
  migrate  Apply pending schema migrations after upgrades";

pub const DISCOVER_LONG: &str = "\
Find SSH services without authenticating.

Performs concurrent TCP checks against IPs, CIDR ranges, hostnames, or a
target file. Records open ports, SSH banners, and host metadata in the database.";

pub const SCAN_LONG: &str = "\
Collect read-only SSH security evidence from live hosts.

Connects with an audit SSH key or agent and runs fixed read-only commands
(passwd, authorized_keys, sshd_config, effective sshd -T, sudoers,
known_hosts, ssh_config, /etc/hosts, /etc/os-release, etc.).
Evidence is stored as raw text for later analysis. Private key contents are
never collected. Use --users-file to repeat collection from multiple SSH user
perspectives with the same configured identity source.";

pub const WORKFLOW_LONG: &str = "\
Run a full SSHMap audit workflow.

The run subcommand chains discovery, authenticated scan, analysis, and optional
DNS enrichment. It is a CLI-first wrapper around existing read-only phases and
can repeat on an interval for lightweight scheduled audits.";

pub const SCAN_RUNS_LONG: &str = "\
Inspect recorded scan, discovery, local-scan, and import runs.

Scan run history includes mode, timestamps, status, operator, sudo flag,
targets, summaries, and audit events.";

pub const LOCAL_SCAN_LONG: &str = "\
Audit the local machine without SSH.

Runs the same read-only collection commands on the host where SSHMap is
executed. Use --sudo when passwordless sudo is required for protected paths.";

pub const ANALYZE_LONG: &str = "\
Parse raw evidence, generate risks, and rebuild the access graph.

Normalizes users, keys, sudo rules, SSH configuration, and host aliases,
applies the risk engine and stored exceptions, refreshes data quality findings,
and updates graph edges. Run after every discovery, scan, or import batch.";

pub const RISKS_LONG: &str = "\
Browse generated SSH exposure findings.

Each risk includes severity, evidence, impact, and remediation guidance.
Filter by severity (CRITICAL, HIGH, MEDIUM, LOW) or exact risk code.";

pub const HOST_LONG: &str = "\
Browse discovered and scanned hosts.

Shows SSH state, source, user counts, and linked risk counts. Host show
includes aliases, local user accounts, and host-scoped risks.";

pub const USER_LONG: &str = "\
Browse normalized SSH user identities across hosts.

User show lists every host account, authorized key locations, sudo rules,
and user-linked risks for a username.";

pub const KEYS_LONG: &str = "\
Browse SSH public keys and reuse patterns.

Reuse highlights keys that appear under multiple users or hosts — a common
lateral movement indicator.";

pub const REPORT_LONG: &str = "\
Generate human-readable or machine-readable assessment reports.

Formats: JSON (automation), HTML (single-file review), CSV (directory of
entity exports).";

pub const BASELINE_LONG: &str = "\
Snapshot and compare risk posture over time.

Baselines store risk signatures from the current database. Use diff to
track new, resolved, and unchanged findings between audits.";

pub const DIFF_LONG: &str = "\
Compare two risk snapshots.

Use --from with a baseline name and --to latest for drift since a saved
baseline, or compare any two saved baselines.";

pub const GRAPH_LONG: &str = "\
Export the SSH access graph for visualization or automation.

Formats: JSON, Graphviz DOT, or Cytoscape.js JSON. The graph models hosts,
users, public keys, sudo rules, and their relationships.";

pub const PATH_LONG: &str = "\
Find the shortest directed access path between two graph nodes.

Node syntax: host:NAME, user:NAME@HOST, key:SHA256:FINGERPRINT,
sudo_rule:ID. Prefer fingerprint-based key references for repeatability.";

pub const BLAST_RADIUS_LONG: &str = "\
Measure lateral reach from a username across the estate.

Traverses the access graph from every host-local account with that username
and reports reachable hosts, keys, and passwordless sudo targets.";

pub const IMPORT_LONG: &str = "\
Load inventory or evidence files without live SSH access.

Supported sources: auto-detected evidence files, evidence bundles, Ansible
inventory, Nmap XML, CSV, known_hosts, /etc/hosts style files, sshd_config,
ssh_config, authorized_keys, sudoers, and prior SSHMap JSON reports.
Run analyze after importing evidence.";

pub const SERVE_LONG: &str = "\
Expose the inventory through an HTTP API and dashboard.

Opens the database in SQLite read-only mode. API routes live under /api/*,
including host aliases, data quality findings, and remediation guidance.
Use --token on non-loopback listeners. Mutating baseline and exception
endpoints require --allow-write-api and a token. Pass --dashboard to serve the
React build from dashboard/dist.";

pub const EXCEPTIONS_LONG: &str = "\
Suppress accepted findings during analysis.

Exceptions match by risk code and optional host, user, or key fingerprint.
Invalid or expired exceptions are ignored. Suppressed risks do not reappear
until the exception is removed or expires.";

pub const EXPORT_LONG: &str = "\
Export compact JSON or CSV slices for monitoring and automation.

Summary exports inventory totals. Other subcommands export risks, hosts,
known_hosts, or ssh client config entries.";

pub const BENCH_LONG: &str = "\
Measure analyze, report, and graph performance on a seeded database.

Use --seed to create benchmark data, --thresholds for CI regression limits,
and --baseline to compare against a previous JSON report.";

pub const COMPLETION_LONG: &str = "\
Generate shell completion scripts for bash or zsh.

Redirect stdout to your shell completion directory, then reload the shell.";
