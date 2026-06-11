# Database

SSHMap stores all state in SQLite with embedded SQL migrations.

## Migration Model

Migrations live in `migrations/` and are registered in `src/db.rs`:

```rust
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/001_init.sql")),
    // ...
];
```

Apply migrations explicitly:

```bash
sshmap db migrate --db sshmap.db
```

Most commands call `initialize_database`, which applies pending migrations automatically.

## Major Table Groups

| Group | Tables | Purpose |
|-------|--------|---------|
| Inventory | `hosts`, `scan_runs` | Discovered and scanned endpoints |
| Raw evidence | `raw_evidence` | Original collected or imported content |
| Normalized | `users`, `groups`, `public_keys`, `authorized_keys`, `sshd_config_entries`, `sudo_rules`, `known_hosts_entries`, `ssh_client_config_entries` | Parsed analysis inputs |
| Findings | `risks`, `risk_exceptions` | Generated and suppressed findings |
| Graph | `graph_edges` | Directed access relationships |
| Baselines | `baselines`, `baseline_risks`, `baseline_diffs` | Snapshot and diff support |
| Metadata | `app_metadata` | Application state such as last analysis timestamp |

Migration 008 adds `app_metadata` for incremental analyze support. The `last_analysis_finished_at` key tracks when analysis last completed successfully.

## Write Paths

- Discovery and scan insert hosts and raw evidence
- Import commands upsert hosts and append evidence rows
- Analyze replaces normalized tables and risks, then rebuilds graph edges
- Baseline commands snapshot risk signatures

## Read-Only Access

`sshmap serve` uses SQLite `OpenFlags::SQLITE_OPEN_READ_ONLY` through helper functions suffixed with `_read_only`. Read-only helpers must never call `initialize_database` in a way that mutates schema during request handling; migration application remains a CLI responsibility.

## Testing Database Code

- Prefer temporary directories in unit tests
- Verify migration stability by opening old fixture databases when schema changes are backward compatible
- Keep destructive cleanup helpers scoped to test-only code paths
