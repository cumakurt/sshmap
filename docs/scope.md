# Target Scope

SSHMap accepts scan and discovery targets through CLI flags or plain-text files.

## Inline Targets

```bash
sshmap discover --targets 10.0.0.1,10.0.0.2 --ports 22 --db sshmap.db
sshmap discover --targets 10.0.0.0/24 --ports 22,2222 --db sshmap.db
```

Supported forms:

- IPv4 addresses
- IPv4 CIDR ranges
- Hostnames and FQDNs
- Comma-separated lists of the above

## Target Files

```bash
sshmap discover --file examples/hosts.txt --ports 22 --db sshmap.db
sshmap scan --file examples/hosts.txt --user audituser --key ~/.ssh/id_ed25519 --db sshmap.db
```

File rules:

- One target per line
- Blank lines and `#` comments are ignored
- The same file format works for `discover` and `scan`

## Port Lists

Ports can be passed as a comma-separated list:

```bash
sshmap discover --targets 10.0.0.0/24 --ports 22,2222,8022 --db sshmap.db
```

When using YAML config, set `discover.ports` or `scan.ports` as a list of integers.

## Validation

Invalid ports, malformed CIDR blocks, empty target sets, and scopes above the configured target limit are rejected before any network activity begins.

Default limit: 65536 endpoints. Override with `--max-targets` or `runtime.max_targets` in config.

```bash
sshmap discover --file large.txt --max-targets 10000 --progress --db sshmap.db
```

## Authorization

Only include systems you own or are explicitly authorized to assess. SSHMap prints an authorization notice before discovery, scan, and local-scan commands.
