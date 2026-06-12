# Local Scan

Local scan inspects the machine where SSHMap is running without remote SSH connections.

## Basic Usage

```bash
sshmap local-scan --sudo --db local.db
sshmap analyze --db local.db
```

## Options

| Flag | Purpose |
|------|---------|
| `--sudo` | Run privileged collection commands with `sudo` |
| `--db` | SQLite database path |

## What It Collects

Local scan uses the same evidence model as remote scan:

- Local account and group data
- `sshd_config`
- Effective daemon configuration from `sshd -T`
- User `authorized_keys`
- `sudoers` when accessible
- `known_hosts` and user `ssh_config` when accessible
- `/etc/hosts` aliases
- OS metadata from `/etc/os-release` and `uname`
- Public key metadata

The local hostname is recorded as the scanned host.

## When To Use It

- Baseline a jump host or admin workstation
- Audit a single server without SSH loopback
- Collect client-side SSH config from the local user environment when combined with import workflows

## Authorization

Local scan prints the same authorization notice as remote operations. Only run it on systems you are permitted to assess.

## Next Steps

```bash
sshmap analyze --db local.db
sshmap keys reuse --db local.db
sshmap report create --format html --output local-report.html --db local.db
```
