# Discovery

Discovery performs unauthenticated TCP checks to find open SSH services and collect basic banner metadata.

## Basic Usage

```bash
sshmap discover --targets 127.0.0.1 --ports 22 --timeout 3 --concurrency 10 --db sshmap.db
```

## Options

| Flag | Purpose |
|------|---------|
| `--targets` | Inline comma-separated targets or CIDR |
| `--file` | Path to a target file |
| `--ports` | Comma-separated port list, default `22` |
| `--timeout` | Per-target timeout in seconds |
| `--concurrency` | Parallel worker count |
| `--progress` | Print progress updates to stderr |
| `--max-targets` | Maximum expanded endpoint count |
| `--db` | SQLite database path |

YAML config can override defaults through `discover.*` and `runtime.*` keys when `--config` is used.

## What Discovery Collects

- Open TCP ports
- SSH banner text when available
- Host key fingerprints when the server presents them during the TCP probe

Discovery does not attempt password authentication, brute force, or exploit activity.

## Output

After discovery completes, SSHMap prints a summary and stores host records in SQLite. Inspect results with:

```bash
sshmap host list --db sshmap.db
sshmap db stats --db sshmap.db
```

## Next Step

Run authenticated collection against discovered hosts:

```bash
sshmap scan --file examples/hosts.txt --user audituser --key ~/.ssh/audit_ed25519 --db sshmap.db
```

See [authenticated-scan.md](authenticated-scan.md).
