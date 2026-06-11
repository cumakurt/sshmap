# Architecture (Developer)

SSHMap ships as a single Rust binary with embedded SQLite migrations.

## Module Map

```text
src/main.rs          CLI dispatch
src/cli.rs           clap definitions
src/config.rs        YAML configuration
src/discovery.rs     TCP SSH discovery
src/collector/       Remote and local evidence collection
src/importer/        Offline inventory and evidence import
src/db.rs            SQLite access and migrations
src/parser/          Evidence normalization parsers
src/analyzer.rs      Analysis orchestration
src/risk/            Risk generation and policy
src/exceptions.rs    Risk exception filtering
src/graph.rs         Graph path and blast-radius logic
src/report.rs        JSON, HTML, and CSV reporting
src/server/          Read-only REST API and dashboard
```

## Data Flow

1. Commands write raw evidence, host inventory, or imported files into SQLite.
2. `analyzer::run_analysis` loads raw evidence and builds a `NormalizedAnalysis` in memory.
3. Normalized rows replace analysis tables inside a transaction.
4. The risk engine generates findings, exceptions filter them, and results are persisted.
5. Graph edges are rebuilt from normalized relationships.

## Concurrency Model

- Discovery and remote scan use async Tokio workers with bounded concurrency.
- SQLite writes happen on the main command path; `serve` opens the database read-only.
- Analysis is single-process and batch-oriented.

## Configuration Merge Order

1. CLI flags
2. Optional YAML config from `--config`
3. Built-in defaults in clap argument definitions

Database path resolution follows the same pattern through `config::resolve_database`.

## Extension Points

- Add parsers under `src/parser/` and wire evidence types in `analyzer.rs`
- Add risk rules in `src/risk/mod.rs` and optional policy keys in `src/risk/policy.rs`
- Add graph edge builders in `src/db.rs` inside `rebuild_graph_edges`
- Add importers under `src/importer/` and register them in `ImportKind`
- Add `RemoteTransport` trait in `src/transport/mod.rs` with an OpenSSH implementation today
- Select transport with `scan --transport openssh|native`
- Both transports reuse one SSH session per host during evidence collection; OpenSSH uses ControlMaster (`--no-connection-reuse` disables it)
- OpenSSH scan supports `--proxy-jump` / `-J`; native transport uses russh direct-tcpip chaining for the same hop syntax
- `native` uses an in-process russh client; `openssh` wraps the system SSH binary
- Configure host key checks with `scan --strict-host-key` or `scan.strict_host_key_checking` in YAML config

See also the user-facing overview in [../architecture.md](../architecture.md).
