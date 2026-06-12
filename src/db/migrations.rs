use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../../migrations/001_init.sql")),
    (2, include_str!("../../migrations/002_raw_evidence.sql")),
    (3, include_str!("../../migrations/003_normalized_data.sql")),
    (4, include_str!("../../migrations/004_graph_edges.sql")),
    (5, include_str!("../../migrations/005_baselines.sql")),
    (6, include_str!("../../migrations/006_risk_exceptions.sql")),
    (7, include_str!("../../migrations/007_client_data.sql")),
    (8, include_str!("../../migrations/008_app_metadata.sql")),
    (
        9,
        include_str!("../../migrations/009_host_aliases_quality.sql"),
    ),
    (
        10,
        include_str!("../../migrations/010_server_keys_compliance.sql"),
    ),
    (11, include_str!("../../migrations/011_extended_features.sql")),
];

pub fn initialize_database(path: &Path) -> Result<()> {
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    apply_migrations(&connection)?;
    Ok(())
}

pub fn migration_version(path: &Path) -> Result<i64> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .context("failed to read migration version")
}

pub(crate) fn apply_read_only_pragmas(connection: &Connection) -> Result<()> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

pub(crate) fn apply_pragmas(connection: &Connection) -> Result<()> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "cache_size", -64000)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

pub(crate) fn escape_like_pattern(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

pub(crate) fn like_contains_pattern(value: &str) -> String {
    format!("%{}%", escape_like_pattern(value))
}

pub(crate) fn apply_migrations(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );",
    )?;

    for (version, sql) in MIGRATIONS {
        let applied_version = connection
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = ?1",
                params![version],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        if applied_version.is_none() {
            connection.execute_batch(sql)?;
            connection.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![version, Utc::now().to_rfc3339()],
            )?;
        }
    }

    Ok(())
}

const COUNTABLE_TABLES: &[&str] = &[
    "hosts",
    "users",
    "public_keys",
    "risks",
    "raw_evidence",
    "graph_edges",
    "known_hosts_entries",
    "ssh_client_config_entries",
    "host_aliases",
    "data_quality_findings",
    "risk_exceptions",
    "baselines",
];

pub(crate) fn count_rows(connection: &Connection, table_name: &str) -> Result<usize> {
    if !COUNTABLE_TABLES.contains(&table_name) {
        bail!("unsupported table name for count: {table_name}");
    }
    let sql = format!("SELECT COUNT(*) FROM {table_name}");
    let count = connection.query_row(&sql, [], |row| row.get::<_, i64>(0))?;
    Ok(count as usize)
}
