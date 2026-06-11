# Getting Started with SSHMap

SSHMap is an agentless SSH exposure management CLI. It discovers SSH services, collects read-only configuration evidence, analyzes risks, builds an access graph, and exposes inventory through a CLI, REST API, and optional React dashboard.

**Current release:** `2.0.0`

## Prerequisites

- Linux or macOS host
- OpenSSH client (`ssh`, `ssh-keygen`) when using `--transport openssh` (default)
- Rust toolchain for building from source, or use `install.sh`
- Node.js 20+ only when building the React dashboard from `dashboard/`

## Quick Workflow

```bash
sshmap init --db sshmap.db
sshmap discover --targets 10.10.0.0/24 --db sshmap.db
sshmap scan --file hosts.txt --user audituser --key ~/.ssh/audit_ed25519 --sudo --db sshmap.db
sshmap analyze --db sshmap.db
sshmap risks list --db sshmap.db
sshmap report create --format html --output report.html --db sshmap.db
```

Scan through a jump host with either transport:

```bash
sshmap scan \
  --file hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --proxy-jump bastion.example.com \
  --transport native \
  --db sshmap.db
```

## Local Audit Without Remote SSH

```bash
sshmap local-scan --sudo --db local.db
sshmap analyze --db local.db
```

## Offline Import

```bash
sshmap import ansible --file inventory.ini --db sshmap.db
sshmap import authorized-keys --file authorized_keys --host web01 --user deploy --db sshmap.db
sshmap analyze --db sshmap.db
```

## Read-Only Web UI

Embedded dashboard:

```bash
sshmap serve --db sshmap.db --listen 127.0.0.1:8080 --read-only
```

Open `http://127.0.0.1:8080` in your browser.

React dashboard:

```bash
cd dashboard && npm ci && npm run build
sshmap serve \
  --db sshmap.db \
  --listen 127.0.0.1:8080 \
  --read-only \
  --dashboard dashboard/dist
```

Optional API token protection:

```bash
sshmap serve --db sshmap.db --token "$SSHMAP_TOKEN"
```

Send the token in the `X-SSHMap-Token` request header. See `docs/api.md` for filtered list endpoints and query parameters.

## Database Maintenance

```bash
sshmap db migrate --db sshmap.db
sshmap db stats --db sshmap.db
sshmap db stats --json --db sshmap.db
```

## Risk Policy

```bash
sshmap analyze --risk-policy examples/risk-policy.yaml --db sshmap.db
```

## Documentation

- [scope.md](scope.md)
- [discovery.md](discovery.md)
- [authenticated-scan.md](authenticated-scan.md)
- [local-scan.md](local-scan.md)
- [importers.md](importers.md)
- [reports.md](reports.md)
- [remediation.md](remediation.md)
- [dashboard.md](dashboard.md)
- [api.md](api.md)
- [benchmarks.md](benchmarks.md)
- [architecture.md](architecture.md)
- Developer docs under [development/](development/)

## Safety

Only use SSHMap against systems you own or are explicitly authorized to assess.
