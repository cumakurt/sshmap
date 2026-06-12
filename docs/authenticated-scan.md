# Authenticated Scan

Authenticated scan uses either the system OpenSSH client (`--transport openssh`) or an in-process russh client (`--transport native`).

Both transports honor `--strict-host-key yes|no|accept-new` (default: `accept-new`) and optional `--known-hosts PATH`. Under `accept-new`, unknown host keys are appended to the known_hosts file; changed keys are rejected.

By default, both transports reuse one SSH session per host while collecting evidence. OpenSSH uses ControlMaster multiplexing; pass `--no-connection-reuse` to run a separate SSH connection for each command.

## Basic Usage

```bash
sshmap scan \
  --file examples/hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --sudo \
  --timeout 10 \
  --concurrency 20 \
  --transport openssh \
  --db sshmap.db
```

Native transport example:

```bash
sshmap scan \
  --file examples/hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --transport native \
  --db sshmap.db
```

Native transport through a jump host:

```bash
sshmap scan \
  --file examples/hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --proxy-jump bastion.example.com \
  --transport native \
  --db sshmap.db
```

## Options

| Flag | Purpose |
|------|---------|
| `--file` | Target file |
| `--user` | SSH username for collection |
| `--key` | Private key path used by the local `ssh` binary |
| `--agent` | Authenticate with keys loaded in the local SSH agent |
| `--identity-agent` | SSH agent socket path (default: `SSH_AUTH_SOCK`) |
| `--identities-only` | Restrict authentication to `--key` only (`IdentitiesOnly=yes` on OpenSSH) |
| `--no-identities-only` | Allow agent keys in addition to `--key` when both are configured |
| `--sudo` | Prefix privileged commands with `sudo` when required |
| `--timeout` | Per-host command timeout |
| `--concurrency` | Parallel host workers |
| `--progress` | Print progress updates to stderr |
| `--max-targets` | Maximum expanded endpoint count |
| `--transport` | Remote transport backend (`openssh` default, `native` in-process russh) |
| `--strict-host-key` | Host key policy: `yes`, `no`, or `accept-new` (default) |
| `--known-hosts` | Known hosts file path (default: `~/.ssh/known_hosts`) |
| `--no-connection-reuse` | Disable per-host SSH session reuse (OpenSSH ControlMaster) |
| `--proxy-jump`, `-J` | ProxyJump target; comma-separated for multiple hops (OpenSSH and native transports) |
| `--db` | SQLite database path |

Scan defaults can also come from `scan.*` keys in YAML config.

## Collected Evidence

Remote scan collects metadata only. Private keys and passwords are never stored.

Typical evidence types:

- `passwd` and `group` entries
- `sshd_config`
- Effective daemon configuration from `sshd -T`
- `authorized_keys` for discovered users
- `sudoers` rules when accessible
- `known_hosts` and user `ssh_config` files when accessible
- `/etc/hosts` aliases
- OS metadata from `/etc/os-release` and `uname`
- Public key fingerprints and file permissions

## Safety Model

- Read-only inspection commands
- Sensitive content redaction before storage
- Authorization notice printed before scan starts

## After Scan

Normalize evidence and generate findings:

```bash
sshmap analyze --db sshmap.db
sshmap risks list --severity critical --db sshmap.db
```

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| All hosts failed | Wrong user, key, or network ACL |
| Partial sudo failures | Missing `--sudo` or insufficient sudo policy |
| Timeouts | Increase `--timeout` or reduce `--concurrency` |

Use `sshmap doctor` to verify local `ssh`, `ssh-keygen`, and OpenSSH ControlMaster readiness before scanning.
