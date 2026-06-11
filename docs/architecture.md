# SSHMap Architecture

SSHMap is a single-binary Rust application backed by SQLite.

## Core Layers

```text
CLI -> Discovery / Scan / Import / Local Scan
    -> Raw Evidence Storage
    -> Parser + Normalization
    -> Risk Engine
    -> Graph Engine
    -> Query / Report / Serve API
```

## Storage

- SQLite database with embedded migrations
- Tables for hosts, users, public keys, authorized keys, sshd config, sudo rules, risks, graph edges, baselines
- Raw evidence preserved for auditability

## Analysis Pipeline

1. Collect evidence through discovery, remote scan, local scan, or import
2. Run `sshmap analyze`
3. Parsers normalize evidence into relational tables
4. Risk engine generates findings
5. Graph engine rebuilds directed access edges

## Serve Mode

`sshmap serve` exposes a read-only REST API and embedded dashboard over axum. The server opens the database with SQLite read-only flags and does not run migrations or write queries.

## Coding Standard

All source code, identifiers, database names, CLI commands, logs, errors, and tests must be written in English.
