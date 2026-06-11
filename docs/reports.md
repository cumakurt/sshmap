# Reports

SSHMap can generate JSON, HTML, and CSV reports from analyzed SQLite data.

## JSON

```bash
sshmap report create --format json --output report.json --db sshmap.db
```

Machine-readable full export suitable for automation and re-import.

## HTML

```bash
sshmap report create --format html --output report.html --db sshmap.db
```

Single-file executive summary with hosts, users, keys, reused keys, and top risks.

## CSV

```bash
sshmap report create --format csv --output report-out/ --db sshmap.db
```

Writes:

- `hosts.csv`
- `users.csv`
- `public_keys.csv`
- `key_reuse.csv`
- `risks.csv`
- `graph_edges.csv`
- `known_hosts.csv`
- `ssh_client_config.csv`

## Configuration Defaults

Set a default report format in `sshmap.yaml`:

```yaml
report:
  default_format: html
```

Use `--config examples/sshmap.yaml` to load shared defaults.
