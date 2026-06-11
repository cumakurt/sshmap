# Importers

SSHMap can ingest inventory and evidence files without live SSH access. Run `sshmap analyze` after importing.

## Host Inventory

```bash
sshmap import ansible --file inventory.ini --db sshmap.db
sshmap import nmap --file scan.xml --db sshmap.db
sshmap import csv --file hosts.csv --db sshmap.db
sshmap import known-hosts --file ~/.ssh/known_hosts --db sshmap.db
sshmap import json --file sshmap-report.json --db sshmap.db
```

## Evidence Files

Evidence imports attach normalized raw content to a named host:

```bash
sshmap import sshd-config --file sshd_config --host web01 --db sshmap.db
sshmap import ssh-config --file config --host workstation01 --db sshmap.db
sshmap import authorized-keys --file authorized_keys --host web01 --user deploy --db sshmap.db
sshmap import sudoers --file sudoers --host web01 --db sshmap.db
```

| Importer | Required flags | Stored evidence type |
|----------|----------------|----------------------|
| `sshd-config` | `--host` | Server SSH daemon config |
| `ssh-config` | `--host` | Client SSH config |
| `authorized-keys` | `--host`, `--user` | User authorized keys |
| `sudoers` | `--host` | Sudo policy file |

## CSV Mapping

Optional mapping files translate column names for CSV import:

```bash
sshmap import csv --file hosts.csv --mapping mapping.yaml --db sshmap.db
```

## Sensitive Content

Import paths run content through the same redaction pipeline used by live collection. Private key material is stripped before storage.

## Workflow

```bash
sshmap init --db offline.db
sshmap import sshd-config --file evidence/sshd_config --host app01 --db offline.db
sshmap import authorized-keys --file evidence/authorized_keys --host app01 --user deploy --db offline.db
sshmap analyze --db offline.db
sshmap report create --format json --output offline-report.json --db offline.db
```

See [getting-started.md](getting-started.md) for the full audit workflow.
