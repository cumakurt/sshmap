# SSHMap 1.0.0

SSHMap 1.0.0 is the first stable CLI release for agentless SSH exposure management.

## Highlights

- Single static binary with embedded SQLite storage
- Discovery, authenticated scan, local scan, offline import, analyze, graph, baseline diff, and reporting
- Read-only REST API and embedded dashboard via `sshmap serve`
- Risk engine with YAML policy tuning and exception management
- `known_hosts` and SSH client config parsing with graph integration

## Upgrade Notes

Existing databases are upgraded automatically on the next command that opens the database. To upgrade explicitly:

```bash
sshmap db migrate --db sshmap.db
```

Schema version 7 adds tables for client-side SSH configuration and known host references.

## Configuration

Optional YAML configuration is loaded with `--config`. Risk thresholds and rule toggles can be set in `examples/risk-policy.yaml` or referenced from the main config file:

```yaml
risk_policy: examples/risk-policy.yaml
```

## Safety

SSHMap collects public keys, configuration metadata, and account information only. It does not collect private keys or passwords. Use only on systems you are authorized to assess.
