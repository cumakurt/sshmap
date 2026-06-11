# Integrations

SSHMap provides machine-readable export commands for SIEM, monitoring, and automation pipelines.

## Summary Export

Export dashboard-compatible summary metrics:

```bash
sshmap export summary --db sshmap.db --output summary.json
```

Output includes host, user, key, and risk counts plus critical/high risk totals and reused key counts.

## Risk Export

Export findings as JSON or newline-delimited JSON (NDJSON):

```bash
sshmap export risks --format json --db sshmap.db --output risks.json
sshmap export risks --format ndjson --severity CRITICAL --db sshmap.db --output critical.ndjson
```

Filter options:

- `--severity`
- `--code`
- `--limit`

## Host Monitoring Export

Export host inventory with risk counters for monitoring systems:

```bash
sshmap export hosts --format csv --db sshmap.db --output hosts-monitoring.csv
sshmap export hosts --format json --db sshmap.db --output hosts.json
```

CSV columns:

```text
hostname,ip_address,port,ssh_open,critical_risks,high_risks,total_risks,user_count
```

## Suggested Automation Flow

```bash
sshmap scan --file hosts.txt --user audituser --key ~/.ssh/audit_ed25519 --db sshmap.db
sshmap analyze --db sshmap.db
sshmap export summary --db sshmap.db --output /var/lib/sshmap/summary.json
sshmap export risks --format ndjson --db sshmap.db --output /var/lib/sshmap/risks.ndjson
sshmap export hosts --format csv --db sshmap.db --output /var/lib/sshmap/hosts.csv
sshmap export known-hosts --format json --db sshmap.db --output /var/lib/sshmap/known-hosts.json
```

## REST API

For live read-only access, use `sshmap serve` and the REST API documented in `docs/api.md`.
