# Doctor

`sshmap doctor` validates local runtime requirements before running an audit.

## Basic Usage

```bash
sshmap doctor
```

## Extended Checks

```bash
sshmap doctor \
  --db sshmap.db \
  --config examples/sshmap.yaml \
  --scope examples/hosts.txt
```

## Checks

| Check | Description |
|-------|-------------|
| `ssh` | OpenSSH client availability |
| `ssh-keygen` | Key fingerprint tooling availability |
| Scan transport | OpenSSH backend readiness and in-process native russh client |
| OpenSSH connection reuse | Verifies `ControlMaster=auto` via `ssh -G` (use `--no-connection-reuse` if unsupported) |
| Control socket directory | Ensures the temp directory is writable for ControlPath sockets |
| Known hosts file | Ensures the scan known_hosts path is appendable or creatable for `accept-new` / `yes` |
| SSH agent | When `scan.use_agent` is enabled, verifies the agent socket is reachable |
| SQLite | Embedded database support via rusqlite |
| Templates | `templates/report.html` and `templates/report.css` on disk |
| Config | Optional YAML config parse validation, including transport and connection reuse |
| Scope | Optional target file parse validation |
| Database | Optional SQLite open and schema migration version |

Global `--config` is used when `--config` is not passed to `doctor`.

## Example Output

```text
SSHMap doctor
ssh binary: ok
ssh-keygen binary: ok
scan transport openssh: ok
scan transport native: ok (in-process russh client, requires --key, default strict-host-key accept-new)
openssh connection reuse: ok (ControlMaster auto supported)
control socket directory: ok (/tmp)
known hosts file /home/operator/.ssh/known_hosts: ok (appendable, strict-host-key accept-new)
sqlite storage: embedded rusqlite (WAL mode)
template templates/report.html: ok
template templates/report.css: ok
config examples/sshmap.yaml: ok (transport openssh, connection reuse enabled, strict-host-key accept-new, known_hosts /home/operator/.ssh/known_hosts)
scope file examples/hosts.txt: ok (3 endpoints on port 22)
database sshmap.db: ok (schema version 8)
```

## Troubleshooting

| Status | Action |
|--------|--------|
| `openssh connection reuse: unsupported` | Pass `--no-connection-reuse` to `scan` or upgrade OpenSSH |
| `control socket directory: not writable` | Fix temp directory permissions or disable connection reuse |
| `known hosts file: not writable` | Fix file permissions or pass a writable path via `--known-hosts` |
