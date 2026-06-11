use crate::baseline;
use crate::discovery::DiscoveryResult;
use crate::models::{
    BaselineDiffRecord, BaselineRecord, BaselineRiskRecord, BaselineSummary, DatabaseStats,
    DetailedDatabaseStats, GeneratedRisk, GraphEdgeRecord, GraphNodeRecord, HostDetailRecord,
    HostQuery, HostRecord, HostScanResult, ImportSummary, ImportedHost, KeyDetailRecord,
    KeyLocationRecord, KeySummaryRecord, KnownHostEntryRecord, NewRiskException,
    NormalizedAnalysis, ParsedAuthorizedKey, ParsedGroup, ParsedPublicKey, ParsedUser,
    RawEvidenceForAnalysis, RawEvidenceRecord, RemoteScanSummary, RiskExceptionRecord, RiskQuery,
    RiskRecord, ScanRunSummary, SshClientConfigEntryRecord, SudoRuleRecord, UserAccountRecord,
    UserDetailRecord, UserQuery, UserSummaryRecord,
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};
use std::path::Path;
use uuid::Uuid;

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/001_init.sql")),
    (2, include_str!("../migrations/002_raw_evidence.sql")),
    (3, include_str!("../migrations/003_normalized_data.sql")),
    (4, include_str!("../migrations/004_graph_edges.sql")),
    (5, include_str!("../migrations/005_baselines.sql")),
    (6, include_str!("../migrations/006_risk_exceptions.sql")),
    (7, include_str!("../migrations/007_client_data.sql")),
    (8, include_str!("../migrations/008_app_metadata.sql")),
];

pub fn initialize_database(path: &Path) -> Result<()> {
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    apply_migrations(&connection)?;
    Ok(())
}

pub fn load_database_stats(path: &Path) -> Result<DatabaseStats> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    load_database_stats_connection(&connection)
}

pub fn load_database_stats_read_only(path: &Path) -> Result<DatabaseStats> {
    with_read_only_connection(path, load_database_stats_connection)
}

fn load_database_stats_connection(connection: &Connection) -> Result<DatabaseStats> {
    Ok(DatabaseStats {
        hosts: count_rows(connection, "hosts")?,
        users: count_rows(connection, "users")?,
        keys: count_rows(connection, "public_keys")?,
        risks: count_rows(connection, "risks")?,
    })
}

pub fn load_detailed_database_stats(path: &Path) -> Result<DetailedDatabaseStats> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    load_detailed_database_stats_connection(&connection)
}

fn load_detailed_database_stats_connection(
    connection: &Connection,
) -> Result<DetailedDatabaseStats> {
    let schema_version = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;

    Ok(DetailedDatabaseStats {
        schema_version,
        hosts: count_rows(connection, "hosts")?,
        users: count_rows(connection, "users")?,
        keys: count_rows(connection, "public_keys")?,
        risks: count_rows(connection, "risks")?,
        raw_evidence: count_rows(connection, "raw_evidence")?,
        graph_edges: count_rows(connection, "graph_edges")?,
        known_hosts_entries: count_rows(connection, "known_hosts_entries")?,
        ssh_client_config_entries: count_rows(connection, "ssh_client_config_entries")?,
        risk_exceptions: count_rows(connection, "risk_exceptions")?,
        baselines: count_rows(connection, "baselines")?,
        last_analysis_finished_at: get_app_metadata_connection(
            connection,
            "last_analysis_finished_at",
        )?,
    })
}

const LAST_ANALYSIS_KEY: &str = "last_analysis_finished_at";

pub fn count_new_raw_evidence_since(path: &Path, since: &str) -> Result<usize> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    connection
        .query_row(
            "SELECT COUNT(*)
             FROM raw_evidence
             WHERE collected_at > ?1
               AND content IS NOT NULL
               AND length(content) > 0",
            params![since],
            |row| row.get(0),
        )
        .context("failed to count new raw evidence")
}

pub fn record_analysis_finished(path: &Path) -> Result<()> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    set_app_metadata_connection(&connection, LAST_ANALYSIS_KEY, &Utc::now().to_rfc3339())
}

pub fn get_last_analysis_timestamp(path: &Path) -> Result<Option<String>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    get_app_metadata_connection(&connection, LAST_ANALYSIS_KEY)
}

fn get_app_metadata_connection(connection: &Connection, key: &str) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT value FROM app_metadata WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .context("failed to read app metadata")
}

fn set_app_metadata_connection(connection: &Connection, key: &str, value: &str) -> Result<()> {
    connection.execute(
        "INSERT INTO app_metadata (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn with_read_only_connection<T, F>(path: &Path, callback: F) -> Result<T>
where
    F: FnOnce(&Connection) -> Result<T>,
{
    if !path.exists() {
        bail!("database not found: {}", path.display());
    }

    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("failed to open database read-only at {}", path.display()))?;
    apply_pragmas(&connection)?;
    callback(&connection)
}

pub fn store_discovery_results(path: &Path, results: &[DiscoveryResult]) -> Result<ScanRunSummary> {
    let mut connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    apply_migrations(&connection)?;

    let started_at = Utc::now();
    let run_uuid = Uuid::new_v4().to_string();
    let targets_json = serde_json::to_string(
        &results
            .iter()
            .map(|result| format!("{}:{}", result.host, result.port))
            .collect::<Vec<_>>(),
    )?;

    connection.execute(
        "INSERT INTO scan_runs (run_uuid, mode, started_at, status, targets_json) VALUES (?1, 'discover', ?2, 'running', ?3)",
        params![run_uuid, started_at.to_rfc3339(), targets_json],
    )?;
    let scan_run_id = connection.last_insert_rowid();

    let tx = connection.transaction()?;
    for result in results {
        upsert_host(&tx, result)?;
    }
    tx.commit()?;

    let summary = ScanRunSummary {
        targets_scanned: results.len(),
        ssh_open: results.iter().filter(|result| result.ssh_open).count(),
        closed_or_unreachable: results.iter().filter(|result| !result.ssh_open).count(),
    };

    let finished_at = Utc::now();
    let summary_json = serde_json::to_string(&summary)?;
    connection.execute(
        "UPDATE scan_runs SET finished_at = ?1, status = 'completed', summary_json = ?2 WHERE id = ?3",
        params![finished_at.to_rfc3339(), summary_json, scan_run_id],
    )?;

    connection.execute(
        "INSERT INTO audit_events (scan_run_id, event_type, message, metadata_json, created_at) VALUES (?1, 'discovery.completed', ?2, ?3, ?4)",
        params![
            scan_run_id,
            "Discovery completed",
            serde_json::to_string(&summary)?,
            finished_at.to_rfc3339()
        ],
    )?;

    Ok(summary)
}

pub fn store_remote_scan_results(
    path: &Path,
    results: &[HostScanResult],
    username: &str,
    sudo_enabled: bool,
) -> Result<RemoteScanSummary> {
    let mut connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    apply_migrations(&connection)?;

    let started_at = Utc::now();
    let run_uuid = Uuid::new_v4().to_string();
    let targets_json = serde_json::to_string(
        &results
            .iter()
            .map(|result| format!("{}:{}", result.host, result.port))
            .collect::<Vec<_>>(),
    )?;

    connection.execute(
        "INSERT INTO scan_runs (
            run_uuid, mode, started_at, status, targets_json, operator, sudo_enabled
        ) VALUES (?1, 'scan', ?2, 'running', ?3, ?4, ?5)",
        params![
            run_uuid,
            started_at.to_rfc3339(),
            targets_json,
            username,
            sudo_enabled as i64
        ],
    )?;
    let scan_run_id = connection.last_insert_rowid();

    let tx = connection.transaction()?;
    let mut evidence_items = 0_usize;
    for result in results {
        let host_id = upsert_scanned_host(&tx, result)?;
        for evidence in &result.evidence {
            insert_raw_evidence(&tx, scan_run_id, host_id, evidence)?;
            evidence_items += 1;
        }
    }
    tx.commit()?;

    let summary = RemoteScanSummary {
        targets_scanned: results.len(),
        hosts_succeeded: results.iter().filter(|result| result.succeeded()).count(),
        hosts_failed: results.iter().filter(|result| !result.succeeded()).count(),
        evidence_items,
    };

    let finished_at = Utc::now();
    let summary_json = serde_json::to_string(&summary)?;
    connection.execute(
        "UPDATE scan_runs SET finished_at = ?1, status = 'completed', summary_json = ?2 WHERE id = ?3",
        params![finished_at.to_rfc3339(), summary_json, scan_run_id],
    )?;

    connection.execute(
        "INSERT INTO audit_events (scan_run_id, event_type, message, metadata_json, created_at) VALUES (?1, 'scan.completed', ?2, ?3, ?4)",
        params![
            scan_run_id,
            "Remote scan completed",
            serde_json::to_string(&summary)?,
            finished_at.to_rfc3339()
        ],
    )?;

    Ok(summary)
}

pub fn store_local_scan_results(
    path: &Path,
    result: &HostScanResult,
    fqdn: Option<&str>,
    sudo_enabled: bool,
) -> Result<RemoteScanSummary> {
    let mut connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    apply_migrations(&connection)?;

    let started_at = Utc::now();
    let run_uuid = Uuid::new_v4().to_string();
    let targets_json = serde_json::to_string(&[format!("{}:{}", result.host, result.port)])?;

    connection.execute(
        "INSERT INTO scan_runs (
            run_uuid, mode, started_at, status, targets_json, operator, sudo_enabled
        ) VALUES (?1, 'local-scan', ?2, 'running', ?3, 'local', ?4)",
        params![
            run_uuid,
            started_at.to_rfc3339(),
            targets_json,
            sudo_enabled as i64
        ],
    )?;
    let scan_run_id = connection.last_insert_rowid();

    let tx = connection.transaction()?;
    let host_id = upsert_scanned_host(&tx, result)?;
    if let Some(fqdn) = fqdn.filter(|value| !value.is_empty()) {
        tx.execute(
            "UPDATE hosts SET hostname = COALESCE(hostname, ?1), fqdn = ?1 WHERE id = ?2",
            params![fqdn, host_id],
        )?;
    }
    let mut evidence_items = 0_usize;
    for evidence in &result.evidence {
        insert_raw_evidence(&tx, scan_run_id, host_id, evidence)?;
        evidence_items += 1;
    }
    tx.commit()?;

    let summary = RemoteScanSummary {
        targets_scanned: 1,
        hosts_succeeded: usize::from(result.succeeded()),
        hosts_failed: usize::from(!result.succeeded()),
        evidence_items,
    };

    let finished_at = Utc::now();
    let summary_json = serde_json::to_string(&summary)?;
    connection.execute(
        "UPDATE scan_runs SET finished_at = ?1, status = 'completed', summary_json = ?2 WHERE id = ?3",
        params![finished_at.to_rfc3339(), summary_json, scan_run_id],
    )?;

    connection.execute(
        "INSERT INTO audit_events (scan_run_id, event_type, message, metadata_json, created_at) VALUES (?1, 'local_scan.completed', ?2, ?3, ?4)",
        params![
            scan_run_id,
            "Local scan completed",
            serde_json::to_string(&summary)?,
            finished_at.to_rfc3339()
        ],
    )?;

    Ok(summary)
}

pub fn update_hostnames_from_evidence(path: &Path) -> Result<usize> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;

    let mut statement = connection.prepare(
        "SELECT host_id, content
         FROM raw_evidence
         WHERE evidence_type = 'hostname' AND exit_code = 0 AND length(content) > 0
         ORDER BY id DESC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;

    let mut updated = 0_usize;
    let mut seen_hosts = std::collections::BTreeSet::new();
    for row in rows {
        let (host_id, content) = row?;
        if !seen_hosts.insert(host_id) {
            continue;
        }
        let hostname = content.lines().next().unwrap_or("").trim();
        if hostname.is_empty() {
            continue;
        }
        connection.execute(
            "UPDATE hosts SET hostname = COALESCE(hostname, ?1), fqdn = ?1 WHERE id = ?2",
            params![hostname, host_id],
        )?;
        updated += 1;
    }

    Ok(updated)
}

pub fn list_user_nodes_by_username(path: &Path, username: &str) -> Result<Vec<GraphNodeRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_user_nodes_by_username_connection(&connection, username)
}

pub fn list_user_nodes_by_username_read_only(
    path: &Path,
    username: &str,
) -> Result<Vec<GraphNodeRecord>> {
    with_read_only_connection(path, |connection| {
        list_user_nodes_by_username_connection(connection, username)
    })
}

fn list_user_nodes_by_username_connection(
    connection: &Connection,
    username: &str,
) -> Result<Vec<GraphNodeRecord>> {
    let mut statement = connection.prepare(
        "SELECT u.id, u.username || '@' || COALESCE(h.hostname, h.ip_address)
         FROM users u
         JOIN hosts h ON h.id = u.host_id
         WHERE u.username = ?1
         ORDER BY h.hostname, h.ip_address",
    )?;
    let rows = statement.query_map(params![username], |row| {
        Ok(GraphNodeRecord {
            node_type: "USER".to_string(),
            node_id: row.get(0)?,
            label: row.get(1)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list user graph nodes")
}

pub fn store_imported_hosts(
    path: &Path,
    source: &str,
    hosts: &[ImportedHost],
) -> Result<ImportSummary> {
    let mut connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    apply_migrations(&connection)?;

    let started_at = Utc::now();
    let run_uuid = Uuid::new_v4().to_string();
    let targets_json = serde_json::to_string(
        &hosts
            .iter()
            .map(|host| format!("{}:{}", host.ip_address, host.port))
            .collect::<Vec<_>>(),
    )?;

    connection.execute(
        "INSERT INTO scan_runs (run_uuid, mode, started_at, status, targets_json, operator)
         VALUES (?1, 'import', ?2, 'running', ?3, ?4)",
        params![run_uuid, started_at.to_rfc3339(), targets_json, source],
    )?;
    let scan_run_id = connection.last_insert_rowid();

    let tx = connection.transaction()?;
    let mut imported = 0_usize;
    for host in hosts {
        upsert_imported_host(&tx, host)?;
        imported += 1;
    }
    tx.commit()?;

    let summary = ImportSummary { imported };
    let finished_at = Utc::now();
    connection.execute(
        "UPDATE scan_runs SET finished_at = ?1, status = 'completed', summary_json = ?2 WHERE id = ?3",
        params![
            finished_at.to_rfc3339(),
            serde_json::to_string(&summary)?,
            scan_run_id
        ],
    )?;
    connection.execute(
        "INSERT INTO audit_events (scan_run_id, event_type, message, metadata_json, created_at)
         VALUES (?1, 'import.completed', ?2, ?3, ?4)",
        params![
            scan_run_id,
            "Import completed",
            serde_json::to_string(&summary)?,
            finished_at.to_rfc3339()
        ],
    )?;

    Ok(summary)
}

pub fn store_imported_evidence(
    path: &Path,
    source: &str,
    host_target: &str,
    evidence: RawEvidenceRecord,
) -> Result<i64> {
    let mut connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    apply_migrations(&connection)?;

    let started_at = Utc::now();
    let run_uuid = Uuid::new_v4().to_string();
    connection.execute(
        "INSERT INTO scan_runs (run_uuid, mode, started_at, status, targets_json, operator)
         VALUES (?1, 'import', ?2, 'running', ?3, ?4)",
        params![
            run_uuid,
            started_at.to_rfc3339(),
            serde_json::to_string(&[host_target.to_string()])?,
            source
        ],
    )?;
    let scan_run_id = connection.last_insert_rowid();

    let tx = connection.transaction()?;
    let host_id = upsert_import_host_by_target(&tx, host_target)?;
    insert_raw_evidence(&tx, scan_run_id, host_id, &evidence)?;
    tx.commit()?;

    let finished_at = Utc::now();
    connection.execute(
        "UPDATE scan_runs SET finished_at = ?1, status = 'completed' WHERE id = ?2",
        params![finished_at.to_rfc3339(), scan_run_id],
    )?;

    Ok(host_id)
}

pub fn load_raw_evidence_for_analysis(path: &Path) -> Result<Vec<RawEvidenceForAnalysis>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;

    let mut statement = connection.prepare(
        "SELECT host_id, evidence_type, source, content, exit_code
         FROM raw_evidence
         WHERE content IS NOT NULL AND length(content) > 0
         ORDER BY id",
    )?;

    let rows = statement.query_map([], |row| {
        Ok(RawEvidenceForAnalysis {
            host_id: row.get(0)?,
            evidence_type: row.get(1)?,
            source: row.get(2)?,
            content: row.get(3)?,
            exit_code: row.get(4)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to load raw evidence for analysis")
}

pub fn replace_normalized_analysis(path: &Path, analysis: &NormalizedAnalysis) -> Result<()> {
    initialize_database(path)?;
    let mut connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;

    let tx = connection.transaction()?;
    clear_normalized_tables(&tx)?;

    for user in &analysis.users {
        upsert_user(&tx, user)?;
    }

    for group in &analysis.groups {
        let group_id = upsert_group(&tx, group)?;
        for member in &group.members {
            let user_id = upsert_minimal_user(&tx, group.host_id, member)?;
            insert_user_group(&tx, group.host_id, user_id, group_id)?;
        }
    }

    for entry in &analysis.sshd_config_entries {
        tx.execute(
            "INSERT INTO sshd_config_entries (
                host_id, key, value, source_file, line_number, effective
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![
                entry.host_id,
                entry.key,
                entry.value,
                entry.source_file,
                entry.line_number
            ],
        )?;
    }

    for authorized_key in &analysis.authorized_keys {
        let user_id = upsert_minimal_user(&tx, authorized_key.host_id, &authorized_key.username)?;
        let public_key_id = upsert_public_key(&tx, &authorized_key.public_key)?;
        insert_authorized_key(&tx, authorized_key, user_id, public_key_id)?;
    }

    for rule in &analysis.sudo_rules {
        tx.execute(
            "INSERT INTO sudo_rules (
                host_id, subject, subject_type, run_as, command, tags, nopasswd,
                source_file, line_number, risk_level
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                rule.host_id,
                rule.subject,
                rule.subject_type,
                rule.run_as,
                rule.command,
                rule.tags,
                rule.nopasswd as i64,
                rule.source_file,
                rule.line_number,
                rule.risk_level
            ],
        )?;
    }

    for entry in &analysis.known_hosts_entries {
        tx.execute(
            "INSERT INTO known_hosts_entries (
                host_id, known_host, known_ip, host_key_type, host_key_fingerprint,
                hashed, source_file, line_number, confidence
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.host_id,
                entry.known_host,
                entry.known_ip,
                entry.host_key_type,
                entry.host_key_fingerprint,
                entry.hashed as i64,
                entry.source_file,
                entry.line_number,
                entry.confidence
            ],
        )?;
    }

    for entry in &analysis.ssh_client_config_entries {
        tx.execute(
            "INSERT INTO ssh_client_config_entries (
                host_id, host_pattern, hostname, ssh_user, port, identity_file,
                proxy_jump, proxy_command, forward_agent, local_forward,
                remote_forward, dynamic_forward, strict_host_key_checking,
                source_file, line_number
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                entry.host_id,
                entry.host_pattern,
                entry.hostname,
                entry.ssh_user,
                entry.port,
                entry.identity_file,
                entry.proxy_jump,
                entry.proxy_command,
                entry.forward_agent,
                entry.local_forward,
                entry.remote_forward,
                entry.dynamic_forward,
                entry.strict_host_key_checking,
                entry.source_file,
                entry.line_number
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

pub fn replace_risks(path: &Path, risks: &[GeneratedRisk]) -> Result<()> {
    initialize_database(path)?;
    let mut connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;

    let tx = connection.transaction()?;
    tx.execute("DELETE FROM risks", [])?;

    for risk in risks {
        insert_generated_risk(&tx, risk)?;
    }

    tx.commit()?;
    Ok(())
}

pub fn list_risks(path: &Path, query: &RiskQuery) -> Result<Vec<RiskRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_risks_connection(&connection, query)
}

pub fn list_risks_read_only(path: &Path, query: &RiskQuery) -> Result<Vec<RiskRecord>> {
    with_read_only_connection(path, |connection| list_risks_connection(connection, query))
}

fn list_risks_connection(connection: &Connection, query: &RiskQuery) -> Result<Vec<RiskRecord>> {
    let mut sql = risk_select_sql();
    let mut conditions = Vec::new();
    if query.severity.is_some() {
        conditions.push("r.severity = ?");
    }
    if query.code.is_some() {
        conditions.push("r.risk_code = ?");
    }
    if !conditions.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
    }
    sql.push_str(
        " ORDER BY
            CASE r.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            r.score DESC,
            r.id ASC
          LIMIT ?",
    );

    let severity = query.severity.as_deref();
    let code = query.code.as_deref();
    let limit = query.limit as i64;
    let records = match (severity, code) {
        (Some(severity), Some(code)) => {
            query_risk_records(connection, &sql, params![severity, code, limit])?
        }
        (Some(severity), None) => query_risk_records(connection, &sql, params![severity, limit])?,
        (None, Some(code)) => query_risk_records(connection, &sql, params![code, limit])?,
        (None, None) => query_risk_records(connection, &sql, params![limit])?,
    };

    Ok(records)
}

pub fn get_risk(path: &Path, risk_id: i64) -> Result<Option<RiskRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    get_risk_connection(&connection, risk_id)
}

pub fn get_risk_read_only(path: &Path, risk_id: i64) -> Result<Option<RiskRecord>> {
    with_read_only_connection(path, |connection| get_risk_connection(connection, risk_id))
}

fn get_risk_connection(connection: &Connection, risk_id: i64) -> Result<Option<RiskRecord>> {
    let mut sql = risk_select_sql();
    sql.push_str(" WHERE r.id = ?");
    let mut statement = connection.prepare(&sql)?;
    statement
        .query_row(params![risk_id], map_risk_record)
        .optional()
        .context("failed to load risk")
}

pub fn list_hosts(path: &Path, limit: usize) -> Result<Vec<HostRecord>> {
    list_hosts_with_query(
        path,
        &HostQuery {
            limit,
            ..HostQuery::default()
        },
    )
}

pub fn list_hosts_with_query(path: &Path, query: &HostQuery) -> Result<Vec<HostRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_hosts_connection(&connection, query)
}

pub fn list_hosts_read_only(path: &Path, limit: usize) -> Result<Vec<HostRecord>> {
    list_hosts_read_only_with_query(
        path,
        &HostQuery {
            limit,
            ..HostQuery::default()
        },
    )
}

pub fn list_hosts_read_only_with_query(path: &Path, query: &HostQuery) -> Result<Vec<HostRecord>> {
    with_read_only_connection(path, |connection| list_hosts_connection(connection, query))
}

fn list_hosts_connection(connection: &Connection, query: &HostQuery) -> Result<Vec<HostRecord>> {
    let mut sql = String::from(
        "SELECT
            h.id, h.hostname, h.fqdn, h.ip_address, h.port, h.ssh_open, h.ssh_banner,
            h.source, h.first_seen, h.last_seen,
            COUNT(DISTINCT u.id) AS user_count,
            COUNT(DISTINCT r.id) AS risk_count
         FROM hosts h
         LEFT JOIN users u ON u.host_id = h.id
         LEFT JOIN risks r ON r.host_id = h.id",
    );
    let mut conditions = Vec::new();
    let mut values = Vec::new();

    if let Some(ssh_open) = query.ssh_open {
        conditions.push("h.ssh_open = ?");
        values.push(rusqlite::types::Value::from(ssh_open));
    }
    if let Some(source) = &query.source {
        conditions.push("h.source = ?");
        values.push(rusqlite::types::Value::from(source.clone()));
    }
    if let Some(search) = &query.search {
        conditions.push("(h.hostname LIKE ? OR h.fqdn LIKE ? OR h.ip_address LIKE ?)");
        let pattern = format!("%{}%", search);
        values.push(rusqlite::types::Value::from(pattern.clone()));
        values.push(rusqlite::types::Value::from(pattern.clone()));
        values.push(rusqlite::types::Value::from(pattern));
    }
    if !conditions.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
    }
    sql.push_str(" GROUP BY h.id ORDER BY h.ip_address, h.port LIMIT ?");
    values.push(rusqlite::types::Value::from(query.limit as i64));

    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(rusqlite::params_from_iter(values), map_host_record)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list hosts")
}

pub fn get_host_detail(path: &Path, target: &str) -> Result<Option<HostDetailRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    get_host_detail_connection(&connection, target)
}

pub fn get_host_detail_read_only(path: &Path, target: &str) -> Result<Option<HostDetailRecord>> {
    with_read_only_connection(path, |connection| {
        get_host_detail_connection(connection, target)
    })
}

fn get_host_detail_connection(
    connection: &Connection,
    target: &str,
) -> Result<Option<HostDetailRecord>> {
    let Some(host) = find_host_record(connection, target)? else {
        return Ok(None);
    };
    let users = list_user_accounts_for_host(connection, host.id)?;
    let risks = list_risks_for_host(connection, host.id)?;

    Ok(Some(HostDetailRecord { host, users, risks }))
}

pub fn list_user_summaries(path: &Path, limit: usize) -> Result<Vec<UserSummaryRecord>> {
    list_user_summaries_with_query(
        path,
        &UserQuery {
            limit,
            ..UserQuery::default()
        },
    )
}

pub fn list_user_summaries_with_query(
    path: &Path,
    query: &UserQuery,
) -> Result<Vec<UserSummaryRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_user_summaries_connection(&connection, query)
}

pub fn list_user_summaries_read_only_with_query(
    path: &Path,
    query: &UserQuery,
) -> Result<Vec<UserSummaryRecord>> {
    with_read_only_connection(path, |connection| {
        list_user_summaries_connection(connection, query)
    })
}

fn list_user_summaries_connection(
    connection: &Connection,
    query: &UserQuery,
) -> Result<Vec<UserSummaryRecord>> {
    let mut sql = String::from(
        "SELECT
            u.username,
            COUNT(DISTINCT u.host_id) AS host_count,
            COUNT(DISTINCT ak.public_key_id) AS key_count,
            COUNT(DISTINCT sr.id) AS sudo_rule_count,
            COUNT(DISTINCT r.id) AS risk_count
         FROM users u
         LEFT JOIN authorized_keys ak ON ak.user_id = u.id
         LEFT JOIN sudo_rules sr
            ON sr.host_id = u.host_id AND sr.subject_type = 'user' AND sr.subject = u.username
         LEFT JOIN risks r ON r.user_id = u.id",
    );
    let mut values = Vec::new();

    if let Some(search) = &query.search {
        sql.push_str(" WHERE u.username LIKE ?");
        values.push(rusqlite::types::Value::from(format!("%{}%", search)));
    }

    sql.push_str(" GROUP BY u.username");

    let mut having_conditions = Vec::new();
    if let Some(min_hosts) = query.min_hosts {
        having_conditions.push("host_count >= ?");
        values.push(rusqlite::types::Value::from(min_hosts as i64));
    }
    if let Some(min_risks) = query.min_risks {
        having_conditions.push("risk_count >= ?");
        values.push(rusqlite::types::Value::from(min_risks as i64));
    }
    if !having_conditions.is_empty() {
        sql.push_str(" HAVING ");
        sql.push_str(&having_conditions.join(" AND "));
    }

    sql.push_str(" ORDER BY host_count DESC, u.username LIMIT ?");
    values.push(rusqlite::types::Value::from(query.limit as i64));

    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(rusqlite::params_from_iter(values), |row| {
        Ok(UserSummaryRecord {
            username: row.get(0)?,
            host_count: i64_to_usize(row.get(1)?),
            key_count: i64_to_usize(row.get(2)?),
            sudo_rule_count: i64_to_usize(row.get(3)?),
            risk_count: i64_to_usize(row.get(4)?),
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list users")
}

pub fn get_user_detail(path: &Path, username: &str) -> Result<Option<UserDetailRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    get_user_detail_connection(&connection, username)
}

pub fn get_user_detail_read_only(path: &Path, username: &str) -> Result<Option<UserDetailRecord>> {
    with_read_only_connection(path, |connection| {
        get_user_detail_connection(connection, username)
    })
}

fn get_user_detail_connection(
    connection: &Connection,
    username: &str,
) -> Result<Option<UserDetailRecord>> {
    let accounts = list_user_accounts_by_username(connection, username)?;
    if accounts.is_empty() {
        return Ok(None);
    }

    Ok(Some(UserDetailRecord {
        username: username.to_string(),
        accounts,
        authorized_keys: list_key_locations_for_username(connection, username)?,
        sudo_rules: list_sudo_rules_for_username(connection, username)?,
        risks: list_risks_for_username(connection, username)?,
    }))
}

pub fn list_keys(path: &Path, limit: usize, reuse_only: bool) -> Result<Vec<KeySummaryRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_keys_connection(&connection, limit, reuse_only)
}

pub fn list_keys_read_only(
    path: &Path,
    limit: usize,
    reuse_only: bool,
) -> Result<Vec<KeySummaryRecord>> {
    with_read_only_connection(path, |connection| {
        list_keys_connection(connection, limit, reuse_only)
    })
}

fn list_keys_connection(
    connection: &Connection,
    limit: usize,
    reuse_only: bool,
) -> Result<Vec<KeySummaryRecord>> {
    let mut sql = key_summary_sql();
    if reuse_only {
        sql.push_str(" HAVING host_count > 1 OR user_count > 1");
    }
    sql.push_str(" ORDER BY host_count DESC, user_count DESC, pk.id LIMIT ?1");

    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params![limit as i64], map_key_summary_record)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list public keys")
}

pub fn get_key_detail(path: &Path, target: &str) -> Result<Option<KeyDetailRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    get_key_detail_connection(&connection, target)
}

pub fn get_key_detail_read_only(path: &Path, target: &str) -> Result<Option<KeyDetailRecord>> {
    with_read_only_connection(path, |connection| {
        get_key_detail_connection(connection, target)
    })
}

fn get_key_detail_connection(
    connection: &Connection,
    target: &str,
) -> Result<Option<KeyDetailRecord>> {
    let Some(key) = find_key_summary(connection, target)? else {
        return Ok(None);
    };
    let locations = list_key_locations_by_public_key_id(connection, key.id)?;
    let risks = list_risks_for_public_key(connection, key.id)?;

    Ok(Some(KeyDetailRecord {
        key,
        locations,
        risks,
    }))
}

pub fn list_risk_exceptions(path: &Path) -> Result<Vec<RiskExceptionRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_risk_exceptions_connection(&connection)
}

fn list_risk_exceptions_connection(connection: &Connection) -> Result<Vec<RiskExceptionRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, risk_code, host_id, username, public_key_fingerprint, reason, created_at, expires_at
         FROM risk_exceptions
         ORDER BY created_at DESC, id DESC",
    )?;
    let rows = statement.query_map([], map_risk_exception_record)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list risk exceptions")
}

pub fn add_risk_exception(
    path: &Path,
    exception: &NewRiskException,
) -> Result<RiskExceptionRecord> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;

    let created_at = Utc::now().to_rfc3339();
    connection.execute(
        "INSERT INTO risk_exceptions (
            risk_code, host_id, username, public_key_fingerprint, reason, created_at, expires_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            exception.risk_code,
            exception.host_id,
            exception.username,
            exception.public_key_fingerprint,
            exception.reason,
            created_at,
            exception.expires_at,
        ],
    )?;
    let id = connection.last_insert_rowid();
    connection
        .query_row(
            "SELECT id, risk_code, host_id, username, public_key_fingerprint, reason, created_at, expires_at
             FROM risk_exceptions WHERE id = ?1",
            params![id],
            map_risk_exception_record,
        )
        .context("failed to load created risk exception")
}

pub fn remove_risk_exception(path: &Path, exception_id: i64) -> Result<bool> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    let deleted = connection.execute(
        "DELETE FROM risk_exceptions WHERE id = ?1",
        params![exception_id],
    )?;
    Ok(deleted > 0)
}

fn map_risk_exception_record(row: &Row<'_>) -> rusqlite::Result<RiskExceptionRecord> {
    Ok(RiskExceptionRecord {
        id: row.get(0)?,
        risk_code: row.get(1)?,
        host_id: row.get(2)?,
        username: row.get(3)?,
        public_key_fingerprint: row.get(4)?,
        reason: row.get(5)?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
    })
}

pub fn create_baseline(path: &Path, name: &str) -> Result<BaselineRecord> {
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!("baseline name cannot be empty");
    }
    if name.eq_ignore_ascii_case("latest") {
        anyhow::bail!("latest is a reserved baseline name");
    }

    initialize_database(path)?;
    let mut connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;

    let summary = load_baseline_summary(&connection)?;
    let risk_snapshots = load_current_risk_snapshots(&connection)?;
    let created_at = Utc::now().to_rfc3339();
    let summary_json = serde_json::to_string(&summary)?;

    let tx = connection.transaction()?;
    tx.execute(
        "INSERT INTO baselines (name, created_at, summary_json) VALUES (?1, ?2, ?3)",
        params![name, created_at, summary_json],
    )
    .with_context(|| format!("failed to create baseline {name}"))?;
    let baseline_id = tx.last_insert_rowid();

    for risk in &risk_snapshots {
        insert_baseline_risk_snapshot(&tx, baseline_id, risk)?;
    }

    tx.commit()?;

    Ok(BaselineRecord {
        id: baseline_id,
        name: name.to_string(),
        created_at,
        summary,
    })
}

pub fn list_baselines(path: &Path) -> Result<Vec<BaselineRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_baselines_connection(&connection)
}

pub fn list_baselines_read_only(path: &Path) -> Result<Vec<BaselineRecord>> {
    with_read_only_connection(path, list_baselines_connection)
}

fn list_baselines_connection(connection: &Connection) -> Result<Vec<BaselineRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, name, created_at, summary_json
         FROM baselines
         ORDER BY created_at DESC, id DESC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(|(id, name, created_at, summary_json)| {
            let summary = serde_json::from_str::<BaselineSummary>(&summary_json)
                .with_context(|| format!("failed to parse summary for baseline {name}"))?;
            Ok(BaselineRecord {
                id,
                name,
                created_at,
                summary,
            })
        })
        .collect()
}

pub fn diff_baselines(path: &Path, from: &str, to: &str) -> Result<BaselineDiffRecord> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;

    let (from_record, from_risks) = load_baseline_snapshot(&connection, from)?;
    let (to_record, to_risks) = load_baseline_snapshot(&connection, to)?;
    let (new_risks, resolved_risks, unchanged_risks) =
        baseline::diff_risk_snapshots(&from_risks, &to_risks);

    Ok(BaselineDiffRecord {
        from: from_record,
        to: to_record,
        new_risks,
        resolved_risks,
        unchanged_risks,
    })
}

pub fn rebuild_graph_edges(path: &Path) -> Result<()> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;

    connection.execute("DELETE FROM graph_edges", [])?;
    insert_host_user_edges(&connection)?;
    insert_public_key_edges(&connection)?;
    insert_sudo_edges(&connection)?;
    insert_client_config_edges(&connection)?;
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

pub fn list_graph_edges(path: &Path) -> Result<Vec<GraphEdgeRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_graph_edges_connection(&connection)
}

pub fn list_graph_edges_read_only(path: &Path) -> Result<Vec<GraphEdgeRecord>> {
    with_read_only_connection(path, list_graph_edges_connection)
}

pub fn list_known_host_entries(path: &Path, limit: usize) -> Result<Vec<KnownHostEntryRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_known_host_entries_connection(&connection, limit)
}

pub fn list_known_host_entries_read_only(
    path: &Path,
    limit: usize,
) -> Result<Vec<KnownHostEntryRecord>> {
    with_read_only_connection(path, |connection| {
        list_known_host_entries_connection(connection, limit)
    })
}

fn list_known_host_entries_connection(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<KnownHostEntryRecord>> {
    let mut statement = connection.prepare(
        "SELECT
            entry.id, entry.host_id, host.hostname, host.ip_address,
            entry.known_host, entry.known_ip, entry.host_key_type,
            entry.host_key_fingerprint, entry.hashed, entry.source_file,
            entry.line_number, entry.confidence
         FROM known_hosts_entries entry
         JOIN hosts host ON host.id = entry.host_id
         ORDER BY entry.id
         LIMIT ?1",
    )?;
    let rows = statement.query_map(params![limit as i64], |row| {
        Ok(KnownHostEntryRecord {
            id: row.get(0)?,
            host_id: row.get(1)?,
            hostname: row.get(2)?,
            ip_address: row.get(3)?,
            known_host: row.get(4)?,
            known_ip: row.get(5)?,
            host_key_type: row.get(6)?,
            host_key_fingerprint: row.get(7)?,
            hashed: row.get::<_, i64>(8)? != 0,
            source_file: row.get(9)?,
            line_number: row.get(10)?,
            confidence: row.get(11)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list known host entries")
}

pub fn list_ssh_client_config_entries(
    path: &Path,
    limit: usize,
) -> Result<Vec<SshClientConfigEntryRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_ssh_client_config_entries_connection(&connection, limit)
}

pub fn list_ssh_client_config_entries_read_only(
    path: &Path,
    limit: usize,
) -> Result<Vec<SshClientConfigEntryRecord>> {
    with_read_only_connection(path, |connection| {
        list_ssh_client_config_entries_connection(connection, limit)
    })
}

fn list_ssh_client_config_entries_connection(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<SshClientConfigEntryRecord>> {
    let mut statement = connection.prepare(
        "SELECT
            cfg.id, cfg.host_id, host.hostname, host.ip_address, cfg.host_pattern,
            cfg.hostname, cfg.ssh_user, cfg.port, cfg.identity_file, cfg.proxy_jump,
            cfg.proxy_command, cfg.forward_agent, cfg.local_forward, cfg.remote_forward,
            cfg.dynamic_forward, cfg.strict_host_key_checking, cfg.source_file, cfg.line_number
         FROM ssh_client_config_entries cfg
         JOIN hosts host ON host.id = cfg.host_id
         ORDER BY cfg.id
         LIMIT ?1",
    )?;
    let rows = statement.query_map(params![limit as i64], |row| {
        Ok(SshClientConfigEntryRecord {
            id: row.get(0)?,
            host_id: row.get(1)?,
            hostname: row.get(2)?,
            ip_address: row.get(3)?,
            host_pattern: row.get(4)?,
            config_hostname: row.get(5)?,
            ssh_user: row.get(6)?,
            port: row.get(7)?,
            identity_file: row.get(8)?,
            proxy_jump: row.get(9)?,
            proxy_command: row.get(10)?,
            forward_agent: row.get(11)?,
            local_forward: row.get(12)?,
            remote_forward: row.get(13)?,
            dynamic_forward: row.get(14)?,
            strict_host_key_checking: row.get(15)?,
            source_file: row.get(16)?,
            line_number: row.get(17)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list ssh client config entries")
}

pub fn list_risk_exceptions_read_only(path: &Path) -> Result<Vec<RiskExceptionRecord>> {
    with_read_only_connection(path, list_risk_exceptions_connection)
}

fn list_graph_edges_connection(connection: &Connection) -> Result<Vec<GraphEdgeRecord>> {
    let mut statement = connection.prepare(
        "SELECT
            id, from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
         FROM graph_edges
         ORDER BY id",
    )?;
    let rows = statement.query_map([], map_graph_edge_record)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list graph edges")
}

pub fn resolve_graph_node_ref(path: &Path, reference: &str) -> Result<Option<GraphNodeRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    resolve_graph_node_ref_connection(&connection, reference)
}

pub fn resolve_graph_node_ref_read_only(
    path: &Path,
    reference: &str,
) -> Result<Option<GraphNodeRecord>> {
    with_read_only_connection(path, |connection| {
        resolve_graph_node_ref_connection(connection, reference)
    })
}

fn resolve_graph_node_ref_connection(
    connection: &Connection,
    reference: &str,
) -> Result<Option<GraphNodeRecord>> {
    let Some((node_type, value)) = reference.split_once(':') else {
        anyhow::bail!("graph node reference must use type:value syntax");
    };

    match node_type {
        "host" => resolve_host_node(connection, value),
        "user" => resolve_user_node(connection, value),
        "key" | "public_key" => resolve_public_key_node(connection, value),
        "sudo_rule" => resolve_sudo_rule_node(connection, value),
        other => anyhow::bail!("unsupported graph node type: {other}"),
    }
}

fn apply_pragmas(connection: &Connection) -> Result<()> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "cache_size", -64000)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

fn apply_migrations(connection: &Connection) -> Result<()> {
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

fn count_rows(connection: &Connection, table_name: &str) -> Result<usize> {
    let sql = format!("SELECT COUNT(*) FROM {table_name}");
    let count = connection.query_row(&sql, [], |row| row.get::<_, i64>(0))?;
    Ok(count as usize)
}

fn count_risks_by_severity(connection: &Connection, severity: &str) -> Result<usize> {
    let count = connection.query_row(
        "SELECT COUNT(*) FROM risks WHERE severity = ?1",
        params![severity],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(i64_to_usize(count))
}

fn load_baseline_summary(connection: &Connection) -> Result<BaselineSummary> {
    Ok(BaselineSummary {
        hosts: count_rows(connection, "hosts")?,
        users: count_rows(connection, "users")?,
        keys: count_rows(connection, "public_keys")?,
        risks: count_rows(connection, "risks")?,
        critical_risks: count_risks_by_severity(connection, "CRITICAL")?,
        high_risks: count_risks_by_severity(connection, "HIGH")?,
    })
}

fn load_current_risk_snapshots(connection: &Connection) -> Result<Vec<BaselineRiskRecord>> {
    let mut sql = risk_select_sql();
    sql.push_str(" ORDER BY r.id");
    let risks = query_risk_records(connection, &sql, [])?;
    Ok(risks.iter().map(baseline::snapshot_risk).collect())
}

fn load_baseline_snapshot(
    connection: &Connection,
    reference: &str,
) -> Result<(BaselineRecord, Vec<BaselineRiskRecord>)> {
    if reference.eq_ignore_ascii_case("latest") {
        return Ok((
            BaselineRecord {
                id: 0,
                name: "latest".to_string(),
                created_at: Utc::now().to_rfc3339(),
                summary: load_baseline_summary(connection)?,
            },
            load_current_risk_snapshots(connection)?,
        ));
    }

    let Some(record) = load_baseline_record(connection, reference)? else {
        anyhow::bail!("baseline {reference} was not found");
    };
    let risks = load_baseline_risk_snapshots(connection, record.id)?;
    Ok((record, risks))
}

fn load_baseline_record(connection: &Connection, name: &str) -> Result<Option<BaselineRecord>> {
    let row = connection
        .query_row(
            "SELECT id, name, created_at, summary_json
             FROM baselines
             WHERE name = ?1",
            params![name],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;

    row.map(|(id, name, created_at, summary_json)| {
        let summary = serde_json::from_str::<BaselineSummary>(&summary_json)
            .with_context(|| format!("failed to parse summary for baseline {name}"))?;
        Ok(BaselineRecord {
            id,
            name,
            created_at,
            summary,
        })
    })
    .transpose()
}

fn load_baseline_risk_snapshots(
    connection: &Connection,
    baseline_id: i64,
) -> Result<Vec<BaselineRiskRecord>> {
    let mut statement = connection.prepare(
        "SELECT signature, risk_code, severity, score, target, title, evidence, status
         FROM baseline_risks
         WHERE baseline_id = ?1
         ORDER BY severity, risk_code, target",
    )?;
    let rows = statement.query_map(params![baseline_id], |row| {
        Ok(BaselineRiskRecord {
            signature: row.get(0)?,
            risk_code: row.get(1)?,
            severity: row.get(2)?,
            score: row.get(3)?,
            target: row.get(4)?,
            title: row.get(5)?,
            evidence: row.get(6)?,
            status: row.get(7)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to load baseline risk snapshots")
}

fn insert_baseline_risk_snapshot(
    connection: &Connection,
    baseline_id: i64,
    risk: &BaselineRiskRecord,
) -> Result<()> {
    connection.execute(
        "INSERT INTO baseline_risks (
            baseline_id, signature, risk_code, severity, score, target, title, evidence, status
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            baseline_id,
            &risk.signature,
            &risk.risk_code,
            &risk.severity,
            risk.score,
            &risk.target,
            &risk.title,
            risk.evidence.as_deref(),
            &risk.status
        ],
    )?;
    Ok(())
}

fn upsert_host(connection: &Connection, result: &DiscoveryResult) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let hostname = result.hostname_hint();
    connection.execute(
        "INSERT INTO hosts (
            hostname, ip_address, port, ssh_open, ssh_banner, first_seen, last_seen, source
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'discover')
        ON CONFLICT(ip_address, port) DO UPDATE SET
            hostname = COALESCE(excluded.hostname, hosts.hostname),
            ssh_open = excluded.ssh_open,
            ssh_banner = excluded.ssh_banner,
            last_seen = excluded.last_seen,
            source = excluded.source",
        params![
            hostname,
            result.host,
            result.port,
            result.ssh_open as i64,
            result.banner,
            now,
            now
        ],
    )?;

    Ok(())
}

fn upsert_scanned_host(connection: &Connection, result: &HostScanResult) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    let hostname = hostname_hint(&result.host);
    connection.execute(
        "INSERT INTO hosts (
            hostname, ip_address, port, ssh_open, first_seen, last_seen, source
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'scan')
        ON CONFLICT(ip_address, port) DO UPDATE SET
            hostname = COALESCE(excluded.hostname, hosts.hostname),
            ssh_open = excluded.ssh_open,
            last_seen = excluded.last_seen,
            source = excluded.source",
        params![
            hostname,
            result.host,
            result.port,
            result.succeeded() as i64,
            now,
            now
        ],
    )?;

    let host_id = connection.query_row(
        "SELECT id FROM hosts WHERE ip_address = ?1 AND port = ?2",
        params![result.host, result.port],
        |row| row.get::<_, i64>(0),
    )?;

    Ok(host_id)
}

fn insert_raw_evidence(
    connection: &Connection,
    scan_run_id: i64,
    host_id: i64,
    evidence: &crate::models::RawEvidenceRecord,
) -> Result<()> {
    connection.execute(
        "INSERT INTO raw_evidence (
            scan_run_id, host_id, evidence_type, source, command, content, stderr,
            exit_code, redacted, collected_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            scan_run_id,
            host_id,
            evidence.evidence_type,
            evidence.source,
            evidence.command,
            evidence.content,
            evidence.stderr,
            evidence.exit_code,
            evidence.redacted as i64,
            Utc::now().to_rfc3339()
        ],
    )?;

    Ok(())
}

fn hostname_hint(value: &str) -> Option<&str> {
    if value.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(value)
    }
}

fn upsert_imported_host(connection: &Connection, host: &ImportedHost) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    connection.execute(
        "INSERT INTO hosts (
            hostname, fqdn, ip_address, port, ssh_open, first_seen, last_seen, source
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'import')
        ON CONFLICT(ip_address, port) DO UPDATE SET
            hostname = COALESCE(excluded.hostname, hosts.hostname),
            fqdn = COALESCE(excluded.fqdn, hosts.fqdn),
            ssh_open = CASE WHEN excluded.ssh_open = 1 THEN 1 ELSE hosts.ssh_open END,
            last_seen = excluded.last_seen,
            source = excluded.source",
        params![
            host.hostname,
            host.fqdn,
            host.ip_address,
            host.port,
            host.ssh_open as i64,
            now,
            now
        ],
    )?;
    Ok(())
}

fn upsert_import_host_by_target(connection: &Connection, target: &str) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    let (ip_address, port, hostname) = parse_host_target(target);
    connection.execute(
        "INSERT INTO hosts (
            hostname, ip_address, port, ssh_open, first_seen, last_seen, source
        ) VALUES (?1, ?2, ?3, 1, ?4, ?5, 'import')
        ON CONFLICT(ip_address, port) DO UPDATE SET
            hostname = COALESCE(excluded.hostname, hosts.hostname),
            last_seen = excluded.last_seen,
            source = excluded.source",
        params![hostname, ip_address, port, now, now],
    )?;
    connection
        .query_row(
            "SELECT id FROM hosts WHERE ip_address = ?1 AND port = ?2",
            params![ip_address, port],
            |row| row.get(0),
        )
        .context("failed to resolve imported host")
}

fn parse_host_target(target: &str) -> (String, i64, Option<String>) {
    if let Some((host, port)) = target.rsplit_once(':')
        && let Ok(port) = port.parse::<i64>()
    {
        let hostname = hostname_hint(host).map(str::to_string);
        return (host.to_string(), port, hostname);
    }

    (
        target.to_string(),
        22,
        hostname_hint(target).map(str::to_string),
    )
}

fn clear_normalized_tables(connection: &Connection) -> Result<()> {
    connection.execute("DELETE FROM risks", [])?;
    connection.execute("DELETE FROM ssh_client_config_entries", [])?;
    connection.execute("DELETE FROM known_hosts_entries", [])?;
    connection.execute("DELETE FROM sudo_rules", [])?;
    connection.execute("DELETE FROM sshd_config_entries", [])?;
    connection.execute("DELETE FROM authorized_keys", [])?;
    connection.execute("DELETE FROM user_groups", [])?;
    connection.execute("DELETE FROM groups", [])?;
    connection.execute("DELETE FROM users", [])?;
    connection.execute("DELETE FROM public_keys", [])?;
    Ok(())
}

fn upsert_user(connection: &Connection, user: &ParsedUser) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    connection.execute(
        "INSERT INTO users (
            host_id, username, uid, gid, home_dir, shell, is_root,
            is_system_account, is_service_account, first_seen, last_seen
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(host_id, username) DO UPDATE SET
            uid = excluded.uid,
            gid = excluded.gid,
            home_dir = excluded.home_dir,
            shell = excluded.shell,
            is_root = excluded.is_root,
            is_system_account = excluded.is_system_account,
            is_service_account = excluded.is_service_account,
            last_seen = excluded.last_seen",
        params![
            user.host_id,
            user.username,
            user.uid,
            user.gid,
            user.home_dir,
            user.shell,
            user.is_root as i64,
            user.is_system_account as i64,
            user.is_service_account as i64,
            now,
            now
        ],
    )?;

    find_user_id(connection, user.host_id, &user.username)
}

fn upsert_minimal_user(connection: &Connection, host_id: i64, username: &str) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    connection.execute(
        "INSERT INTO users (
            host_id, username, is_root, is_system_account, is_service_account, first_seen, last_seen
        ) VALUES (?1, ?2, ?3, 0, 0, ?4, ?5)
        ON CONFLICT(host_id, username) DO UPDATE SET
            last_seen = excluded.last_seen",
        params![host_id, username, (username == "root") as i64, now, now],
    )?;

    find_user_id(connection, host_id, username)
}

fn find_user_id(connection: &Connection, host_id: i64, username: &str) -> Result<i64> {
    connection
        .query_row(
            "SELECT id FROM users WHERE host_id = ?1 AND username = ?2",
            params![host_id, username],
            |row| row.get::<_, i64>(0),
        )
        .context("failed to find normalized user")
}

fn upsert_group(connection: &Connection, group: &ParsedGroup) -> Result<i64> {
    connection.execute(
        "INSERT INTO groups (host_id, group_name, gid) VALUES (?1, ?2, ?3)
        ON CONFLICT(host_id, group_name) DO UPDATE SET gid = excluded.gid",
        params![group.host_id, group.group_name, group.gid],
    )?;

    connection
        .query_row(
            "SELECT id FROM groups WHERE host_id = ?1 AND group_name = ?2",
            params![group.host_id, group.group_name],
            |row| row.get::<_, i64>(0),
        )
        .context("failed to find normalized group")
}

fn insert_user_group(
    connection: &Connection,
    host_id: i64,
    user_id: i64,
    group_id: i64,
) -> Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO user_groups (host_id, user_id, group_id) VALUES (?1, ?2, ?3)",
        params![host_id, user_id, group_id],
    )?;
    Ok(())
}

fn upsert_public_key(connection: &Connection, public_key: &ParsedPublicKey) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    connection.execute(
        "INSERT INTO public_keys (
            key_type, fingerprint_sha256, key_comment, normalized_public_key, first_seen, last_seen
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(fingerprint_sha256) DO UPDATE SET
            key_comment = COALESCE(excluded.key_comment, public_keys.key_comment),
            last_seen = excluded.last_seen",
        params![
            public_key.key_type,
            public_key.fingerprint_sha256,
            public_key.key_comment,
            public_key.normalized_public_key,
            now,
            now
        ],
    )?;

    connection
        .query_row(
            "SELECT id FROM public_keys WHERE fingerprint_sha256 = ?1",
            params![public_key.fingerprint_sha256],
            |row| row.get::<_, i64>(0),
        )
        .context("failed to find normalized public key")
}

fn insert_authorized_key(
    connection: &Connection,
    authorized_key: &ParsedAuthorizedKey,
    user_id: i64,
    public_key_id: i64,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    connection.execute(
        "INSERT OR IGNORE INTO authorized_keys (
            host_id, user_id, public_key_id, source_file, line_number, options,
            has_from_restriction, has_command_restriction, permits_pty,
            permits_port_forwarding, permits_agent_forwarding, permits_x11_forwarding,
            first_seen, last_seen
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            authorized_key.host_id,
            user_id,
            public_key_id,
            authorized_key.source_file,
            authorized_key.line_number,
            authorized_key.options,
            authorized_key.has_from_restriction as i64,
            authorized_key.has_command_restriction as i64,
            authorized_key.permits_pty as i64,
            authorized_key.permits_port_forwarding as i64,
            authorized_key.permits_agent_forwarding as i64,
            authorized_key.permits_x11_forwarding as i64,
            now,
            now
        ],
    )?;

    Ok(())
}

fn insert_generated_risk(connection: &Connection, risk: &GeneratedRisk) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let user_id = find_optional_user_id(connection, risk.host_id, risk.username.as_deref())?;
    let public_key_id =
        find_optional_public_key_id(connection, risk.public_key_fingerprint.as_deref())?;

    connection.execute(
        "INSERT INTO risks (
            host_id, user_id, public_key_id, risk_code, severity, score, confidence,
            title, description, impact, evidence, recommendation, status, first_seen, last_seen
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'open', ?13, ?14)",
        params![
            risk.host_id,
            user_id,
            public_key_id,
            risk.risk_code,
            risk.severity,
            risk.score,
            risk.confidence,
            risk.title,
            risk.description,
            risk.impact,
            risk.evidence,
            risk.recommendation,
            now,
            now
        ],
    )?;

    Ok(())
}

fn find_optional_user_id(
    connection: &Connection,
    host_id: Option<i64>,
    username: Option<&str>,
) -> Result<Option<i64>> {
    let (Some(host_id), Some(username)) = (host_id, username) else {
        return Ok(None);
    };

    connection
        .query_row(
            "SELECT id FROM users WHERE host_id = ?1 AND username = ?2",
            params![host_id, username],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .context("failed to find risk user reference")
}

fn find_optional_public_key_id(
    connection: &Connection,
    fingerprint: Option<&str>,
) -> Result<Option<i64>> {
    let Some(fingerprint) = fingerprint else {
        return Ok(None);
    };

    connection
        .query_row(
            "SELECT id FROM public_keys WHERE fingerprint_sha256 = ?1",
            params![fingerprint],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .context("failed to find risk public key reference")
}

fn risk_select_sql() -> String {
    "SELECT
        r.id,
        r.host_id,
        h.hostname,
        h.ip_address,
        u.username,
        pk.fingerprint_sha256,
        r.risk_code,
        r.severity,
        r.score,
        r.confidence,
        r.title,
        r.description,
        r.impact,
        r.evidence,
        r.recommendation,
        r.status,
        r.first_seen,
        r.last_seen
     FROM risks r
     LEFT JOIN hosts h ON h.id = r.host_id
     LEFT JOIN users u ON u.id = r.user_id
     LEFT JOIN public_keys pk ON pk.id = r.public_key_id"
        .to_string()
}

fn query_risk_records(
    connection: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<RiskRecord>> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map(params, map_risk_record)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to query risks")
}

fn map_risk_record(row: &Row<'_>) -> rusqlite::Result<RiskRecord> {
    Ok(RiskRecord {
        id: row.get(0)?,
        host_id: row.get(1)?,
        hostname: row.get(2)?,
        ip_address: row.get(3)?,
        username: row.get(4)?,
        public_key_fingerprint: row.get(5)?,
        risk_code: row.get(6)?,
        severity: row.get(7)?,
        score: row.get(8)?,
        confidence: row.get(9)?,
        title: row.get(10)?,
        description: row.get(11)?,
        impact: row.get(12)?,
        evidence: row.get(13)?,
        recommendation: row.get(14)?,
        status: row.get(15)?,
        first_seen: row.get(16)?,
        last_seen: row.get(17)?,
    })
}

fn find_host_record(connection: &Connection, target: &str) -> Result<Option<HostRecord>> {
    if let Ok(host_id) = target.parse::<i64>() {
        let mut statement = connection.prepare(
            "SELECT
                h.id, h.hostname, h.fqdn, h.ip_address, h.port, h.ssh_open, h.ssh_banner,
                h.source, h.first_seen, h.last_seen,
                COUNT(DISTINCT u.id) AS user_count,
                COUNT(DISTINCT r.id) AS risk_count
             FROM hosts h
             LEFT JOIN users u ON u.host_id = h.id
             LEFT JOIN risks r ON r.host_id = h.id
             WHERE h.id = ?1
             GROUP BY h.id",
        )?;
        return statement
            .query_row(params![host_id], map_host_record)
            .optional()
            .context("failed to find host by id");
    }

    let mut statement = connection.prepare(
        "SELECT
            h.id, h.hostname, h.fqdn, h.ip_address, h.port, h.ssh_open, h.ssh_banner,
            h.source, h.first_seen, h.last_seen,
            COUNT(DISTINCT u.id) AS user_count,
            COUNT(DISTINCT r.id) AS risk_count
         FROM hosts h
         LEFT JOIN users u ON u.host_id = h.id
         LEFT JOIN risks r ON r.host_id = h.id
         WHERE h.hostname = ?1 OR h.fqdn = ?1 OR h.ip_address = ?1
         GROUP BY h.id
         ORDER BY h.port
         LIMIT 1",
    )?;
    statement
        .query_row(params![target], map_host_record)
        .optional()
        .context("failed to find host")
}

fn map_host_record(row: &Row<'_>) -> rusqlite::Result<HostRecord> {
    Ok(HostRecord {
        id: row.get(0)?,
        hostname: row.get(1)?,
        fqdn: row.get(2)?,
        ip_address: row.get(3)?,
        port: row.get(4)?,
        ssh_open: row.get::<_, i64>(5)? != 0,
        ssh_banner: row.get(6)?,
        source: row.get(7)?,
        first_seen: row.get(8)?,
        last_seen: row.get(9)?,
        user_count: i64_to_usize(row.get(10)?),
        risk_count: i64_to_usize(row.get(11)?),
    })
}

fn list_user_accounts_for_host(
    connection: &Connection,
    host_id: i64,
) -> Result<Vec<UserAccountRecord>> {
    let mut statement = connection.prepare(
        "SELECT
            u.id, u.host_id, h.hostname, h.ip_address, u.username, u.uid, u.gid,
            u.home_dir, u.shell, u.is_root, u.is_system_account, u.is_service_account
         FROM users u
         JOIN hosts h ON h.id = u.host_id
         WHERE u.host_id = ?1
         ORDER BY u.uid, u.username",
    )?;
    let rows = statement.query_map(params![host_id], map_user_account_record)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list host users")
}

fn list_user_accounts_by_username(
    connection: &Connection,
    username: &str,
) -> Result<Vec<UserAccountRecord>> {
    let mut statement = connection.prepare(
        "SELECT
            u.id, u.host_id, h.hostname, h.ip_address, u.username, u.uid, u.gid,
            u.home_dir, u.shell, u.is_root, u.is_system_account, u.is_service_account
         FROM users u
         JOIN hosts h ON h.id = u.host_id
         WHERE u.username = ?1
         ORDER BY h.hostname, h.ip_address",
    )?;
    let rows = statement.query_map(params![username], map_user_account_record)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list user accounts")
}

fn map_user_account_record(row: &Row<'_>) -> rusqlite::Result<UserAccountRecord> {
    Ok(UserAccountRecord {
        id: row.get(0)?,
        host_id: row.get(1)?,
        hostname: row.get(2)?,
        ip_address: row.get(3)?,
        username: row.get(4)?,
        uid: row.get(5)?,
        gid: row.get(6)?,
        home_dir: row.get(7)?,
        shell: row.get(8)?,
        is_root: row.get::<_, i64>(9)? != 0,
        is_system_account: row.get::<_, i64>(10)? != 0,
        is_service_account: row.get::<_, i64>(11)? != 0,
    })
}

fn list_key_locations_for_username(
    connection: &Connection,
    username: &str,
) -> Result<Vec<KeyLocationRecord>> {
    query_key_locations(
        connection,
        "WHERE u.username = ?1 ORDER BY h.hostname, h.ip_address",
        params![username],
    )
}

fn list_key_locations_by_public_key_id(
    connection: &Connection,
    public_key_id: i64,
) -> Result<Vec<KeyLocationRecord>> {
    query_key_locations(
        connection,
        "WHERE pk.id = ?1 ORDER BY h.hostname, h.ip_address, u.username",
        params![public_key_id],
    )
}

fn query_key_locations(
    connection: &Connection,
    where_clause: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<KeyLocationRecord>> {
    let sql = format!(
        "SELECT
            pk.id, pk.key_type, pk.fingerprint_sha256, h.id, h.hostname, h.ip_address,
            u.username, ak.source_file, ak.line_number, ak.options
         FROM authorized_keys ak
         JOIN public_keys pk ON pk.id = ak.public_key_id
         JOIN users u ON u.id = ak.user_id
         JOIN hosts h ON h.id = ak.host_id
         {where_clause}"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params, |row| {
        Ok(KeyLocationRecord {
            public_key_id: row.get(0)?,
            key_type: row.get(1)?,
            fingerprint_sha256: row.get(2)?,
            host_id: row.get(3)?,
            hostname: row.get(4)?,
            ip_address: row.get(5)?,
            username: row.get(6)?,
            source_file: row.get(7)?,
            line_number: row.get(8)?,
            options: row.get(9)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to query key locations")
}

fn list_sudo_rules_for_username(
    connection: &Connection,
    username: &str,
) -> Result<Vec<SudoRuleRecord>> {
    let mut statement = connection.prepare(
        "SELECT
            sr.host_id, h.hostname, h.ip_address, sr.subject, sr.subject_type, sr.run_as,
            sr.command, sr.nopasswd, sr.source_file, sr.line_number, sr.risk_level
         FROM sudo_rules sr
         JOIN hosts h ON h.id = sr.host_id
         WHERE sr.subject_type = 'user' AND sr.subject = ?1
         ORDER BY h.hostname, h.ip_address",
    )?;
    let rows = statement.query_map(params![username], map_sudo_rule_record)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list sudo rules")
}

fn map_sudo_rule_record(row: &Row<'_>) -> rusqlite::Result<SudoRuleRecord> {
    Ok(SudoRuleRecord {
        host_id: row.get(0)?,
        hostname: row.get(1)?,
        ip_address: row.get(2)?,
        subject: row.get(3)?,
        subject_type: row.get(4)?,
        run_as: row.get(5)?,
        command: row.get(6)?,
        nopasswd: row.get::<_, i64>(7)? != 0,
        source_file: row.get(8)?,
        line_number: row.get(9)?,
        risk_level: row.get(10)?,
    })
}

fn list_risks_for_host(connection: &Connection, host_id: i64) -> Result<Vec<RiskRecord>> {
    let mut sql = risk_select_sql();
    sql.push_str(" WHERE r.host_id = ?1 ORDER BY r.score DESC, r.id");
    query_risk_records(connection, &sql, params![host_id])
}

fn list_risks_for_username(connection: &Connection, username: &str) -> Result<Vec<RiskRecord>> {
    let mut sql = risk_select_sql();
    sql.push_str(" WHERE u.username = ?1 ORDER BY r.score DESC, r.id");
    query_risk_records(connection, &sql, params![username])
}

fn list_risks_for_public_key(
    connection: &Connection,
    public_key_id: i64,
) -> Result<Vec<RiskRecord>> {
    let mut sql = risk_select_sql();
    sql.push_str(" WHERE pk.id = ?1 ORDER BY r.score DESC, r.id");
    query_risk_records(connection, &sql, params![public_key_id])
}

fn key_summary_sql() -> String {
    "SELECT
        pk.id,
        pk.key_type,
        pk.fingerprint_sha256,
        pk.key_comment,
        COUNT(DISTINCT ak.host_id) AS host_count,
        COUNT(DISTINCT u.username) AS user_count,
        SUM(CASE WHEN u.username = 'root' THEN 1 ELSE 0 END) AS root_usage_count,
        COUNT(DISTINCT r.id) AS risk_count
     FROM public_keys pk
     LEFT JOIN authorized_keys ak ON ak.public_key_id = pk.id
     LEFT JOIN users u ON u.id = ak.user_id
     LEFT JOIN risks r ON r.public_key_id = pk.id
     GROUP BY pk.id"
        .to_string()
}

fn find_key_summary(connection: &Connection, target: &str) -> Result<Option<KeySummaryRecord>> {
    if let Ok(public_key_id) = target.parse::<i64>() {
        let mut sql = key_summary_sql();
        sql = sql.replacen(" GROUP BY pk.id", " WHERE pk.id = ?1 GROUP BY pk.id", 1);
        let mut statement = connection.prepare(&sql)?;
        return statement
            .query_row(params![public_key_id], map_key_summary_record)
            .optional()
            .context("failed to find public key by id");
    }

    let mut sql = key_summary_sql();
    sql = sql.replacen(
        " GROUP BY pk.id",
        " WHERE pk.fingerprint_sha256 = ?1 GROUP BY pk.id",
        1,
    );
    let mut statement = connection.prepare(&sql)?;
    statement
        .query_row(params![target], map_key_summary_record)
        .optional()
        .context("failed to find public key")
}

fn map_key_summary_record(row: &Row<'_>) -> rusqlite::Result<KeySummaryRecord> {
    Ok(KeySummaryRecord {
        id: row.get(0)?,
        key_type: row.get(1)?,
        fingerprint_sha256: row.get(2)?,
        key_comment: row.get(3)?,
        host_count: i64_to_usize(row.get(4)?),
        user_count: i64_to_usize(row.get(5)?),
        root_usage_count: i64_to_usize(row.get(6)?),
        risk_count: i64_to_usize(row.get(7)?),
    })
}

fn i64_to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or_default()
}

fn insert_host_user_edges(connection: &Connection) -> Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'HOST',
            h.id,
            COALESCE(h.hostname, h.ip_address),
            'USER',
            u.id,
            u.username || '@' || COALESCE(h.hostname, h.ip_address),
            'HOST_HAS_USER',
            1,
            'HIGH',
            'User account exists on host'
        FROM hosts h
        JOIN users u ON u.host_id = h.id",
        [],
    )?;

    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'USER',
            u.id,
            u.username || '@' || COALESCE(h.hostname, h.ip_address),
            'HOST',
            h.id,
            COALESCE(h.hostname, h.ip_address),
            'USER_ON_HOST',
            1,
            'HIGH',
            'User account exists on host'
        FROM users u
        JOIN hosts h ON h.id = u.host_id",
        [],
    )?;

    Ok(())
}

fn insert_public_key_edges(connection: &Connection) -> Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'PUBLIC_KEY',
            pk.id,
            pk.fingerprint_sha256,
            'USER',
            u.id,
            u.username || '@' || COALESCE(h.hostname, h.ip_address),
            'PUBLIC_KEY_CAN_LOGIN_TO_USER',
            1,
            'HIGH',
            COALESCE(ak.source_file, 'authorized_keys') || ':' || COALESCE(ak.line_number, 0)
        FROM authorized_keys ak
        JOIN public_keys pk ON pk.id = ak.public_key_id
        JOIN users u ON u.id = ak.user_id
        JOIN hosts h ON h.id = ak.host_id",
        [],
    )?;

    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'PUBLIC_KEY',
            pk.id,
            pk.fingerprint_sha256,
            'HOST',
            h.id,
            COALESCE(h.hostname, h.ip_address),
            'PUBLIC_KEY_REUSED_ON_HOST',
            2,
            'HIGH',
            'Public key appears in authorized_keys on host'
        FROM authorized_keys ak
        JOIN public_keys pk ON pk.id = ak.public_key_id
        JOIN hosts h ON h.id = ak.host_id",
        [],
    )?;

    Ok(())
}

fn insert_sudo_edges(connection: &Connection) -> Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'USER',
            u.id,
            u.username || '@' || COALESCE(h.hostname, h.ip_address),
            'SUDO_RULE',
            sr.id,
            sr.subject || ' ' || COALESCE(sr.command, '-'),
            'USER_HAS_SUDO_RULE',
            1,
            'HIGH',
            COALESCE(sr.source_file, 'sudoers') || ':' || COALESCE(sr.line_number, 0)
        FROM sudo_rules sr
        JOIN users u ON u.host_id = sr.host_id AND sr.subject_type = 'user' AND sr.subject = u.username
        JOIN hosts h ON h.id = sr.host_id",
        [],
    )?;

    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'SUDO_RULE',
            sr.id,
            sr.subject || ' ' || COALESCE(sr.command, '-'),
            'HOST',
            h.id,
            COALESCE(h.hostname, h.ip_address),
            'SUDO_RULE_APPLIES_TO_HOST',
            1,
            'HIGH',
            COALESCE(sr.source_file, 'sudoers') || ':' || COALESCE(sr.line_number, 0)
        FROM sudo_rules sr
        JOIN hosts h ON h.id = sr.host_id",
        [],
    )?;

    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'USER',
            u.id,
            u.username || '@' || COALESCE(h.hostname, h.ip_address),
            'HOST',
            h.id,
            COALESCE(h.hostname, h.ip_address),
            'USER_HAS_PASSWORDLESS_SUDO',
            1,
            'HIGH',
            COALESCE(sr.source_file, 'sudoers') || ':' || COALESCE(sr.line_number, 0)
        FROM sudo_rules sr
        JOIN users u ON u.host_id = sr.host_id AND sr.subject_type = 'user' AND sr.subject = u.username
        JOIN hosts h ON h.id = sr.host_id
        WHERE sr.nopasswd = 1",
        [],
    )?;

    Ok(())
}

fn insert_client_config_edges(connection: &Connection) -> Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'HOST',
            source.id,
            COALESCE(source.hostname, source.ip_address),
            'HOST',
            target.id,
            COALESCE(target.hostname, target.ip_address),
            'CLIENT_CONFIG_PROXY_JUMP',
            2,
            'MEDIUM',
            COALESCE(cfg.source_file, 'ssh_config') || ':' || COALESCE(cfg.line_number, 0)
        FROM ssh_client_config_entries cfg
        JOIN hosts source ON source.id = cfg.host_id
        JOIN hosts target
            ON target.hostname = cfg.proxy_jump
            OR target.fqdn = cfg.proxy_jump
            OR target.ip_address = cfg.proxy_jump
        WHERE cfg.proxy_jump IS NOT NULL",
        [],
    )?;

    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'HOST',
            source.id,
            COALESCE(source.hostname, source.ip_address),
            'HOST',
            target.id,
            COALESCE(target.hostname, target.ip_address),
            'KNOWN_HOSTS_REFERENCE',
            1,
            entry.confidence,
            COALESCE(entry.source_file, 'known_hosts') || ':' || COALESCE(entry.line_number, 0)
        FROM known_hosts_entries entry
        JOIN hosts source ON source.id = entry.host_id
        JOIN hosts target
            ON target.hostname = entry.known_host
            OR target.fqdn = entry.known_host
            OR target.ip_address = entry.known_ip
        WHERE entry.known_host IS NOT NULL OR entry.known_ip IS NOT NULL",
        [],
    )?;

    Ok(())
}

fn map_graph_edge_record(row: &Row<'_>) -> rusqlite::Result<GraphEdgeRecord> {
    Ok(GraphEdgeRecord {
        id: row.get(0)?,
        from_type: row.get(1)?,
        from_id: row.get(2)?,
        from_label: row.get(3)?,
        to_type: row.get(4)?,
        to_id: row.get(5)?,
        to_label: row.get(6)?,
        edge_type: row.get(7)?,
        weight: row.get(8)?,
        confidence: row.get(9)?,
        evidence: row.get(10)?,
    })
}

fn resolve_host_node(connection: &Connection, value: &str) -> Result<Option<GraphNodeRecord>> {
    if let Ok(host_id) = value.parse::<i64>() {
        return connection
            .query_row(
                "SELECT id, COALESCE(hostname, ip_address) FROM hosts WHERE id = ?1",
                params![host_id],
                |row| {
                    Ok(GraphNodeRecord {
                        node_type: "HOST".to_string(),
                        node_id: row.get(0)?,
                        label: row.get(1)?,
                    })
                },
            )
            .optional()
            .context("failed to resolve host graph node");
    }

    connection
        .query_row(
            "SELECT id, COALESCE(hostname, ip_address)
             FROM hosts
             WHERE hostname = ?1 OR fqdn = ?1 OR ip_address = ?1
             ORDER BY port
             LIMIT 1",
            params![value],
            |row| {
                Ok(GraphNodeRecord {
                    node_type: "HOST".to_string(),
                    node_id: row.get(0)?,
                    label: row.get(1)?,
                })
            },
        )
        .optional()
        .context("failed to resolve host graph node")
}

fn resolve_user_node(connection: &Connection, value: &str) -> Result<Option<GraphNodeRecord>> {
    if let Ok(user_id) = value.parse::<i64>() {
        return connection
            .query_row(
                "SELECT u.id, u.username || '@' || COALESCE(h.hostname, h.ip_address)
                 FROM users u
                 JOIN hosts h ON h.id = u.host_id
                 WHERE u.id = ?1",
                params![user_id],
                |row| {
                    Ok(GraphNodeRecord {
                        node_type: "USER".to_string(),
                        node_id: row.get(0)?,
                        label: row.get(1)?,
                    })
                },
            )
            .optional()
            .context("failed to resolve user graph node");
    }

    if let Some((username, host)) = value.split_once('@') {
        return connection
            .query_row(
                "SELECT u.id, u.username || '@' || COALESCE(h.hostname, h.ip_address)
                 FROM users u
                 JOIN hosts h ON h.id = u.host_id
                 WHERE u.username = ?1 AND (h.hostname = ?2 OR h.fqdn = ?2 OR h.ip_address = ?2)
                 LIMIT 1",
                params![username, host],
                |row| {
                    Ok(GraphNodeRecord {
                        node_type: "USER".to_string(),
                        node_id: row.get(0)?,
                        label: row.get(1)?,
                    })
                },
            )
            .optional()
            .context("failed to resolve user graph node");
    }

    connection
        .query_row(
            "SELECT u.id, u.username || '@' || COALESCE(h.hostname, h.ip_address)
             FROM users u
             JOIN hosts h ON h.id = u.host_id
             WHERE u.username = ?1
             ORDER BY h.hostname, h.ip_address
             LIMIT 1",
            params![value],
            |row| {
                Ok(GraphNodeRecord {
                    node_type: "USER".to_string(),
                    node_id: row.get(0)?,
                    label: row.get(1)?,
                })
            },
        )
        .optional()
        .context("failed to resolve user graph node")
}

fn resolve_public_key_node(
    connection: &Connection,
    value: &str,
) -> Result<Option<GraphNodeRecord>> {
    if let Ok(public_key_id) = value.parse::<i64>() {
        return connection
            .query_row(
                "SELECT id, fingerprint_sha256 FROM public_keys WHERE id = ?1",
                params![public_key_id],
                |row| {
                    Ok(GraphNodeRecord {
                        node_type: "PUBLIC_KEY".to_string(),
                        node_id: row.get(0)?,
                        label: row.get(1)?,
                    })
                },
            )
            .optional()
            .context("failed to resolve public key graph node");
    }

    connection
        .query_row(
            "SELECT id, fingerprint_sha256 FROM public_keys WHERE fingerprint_sha256 = ?1",
            params![value],
            |row| {
                Ok(GraphNodeRecord {
                    node_type: "PUBLIC_KEY".to_string(),
                    node_id: row.get(0)?,
                    label: row.get(1)?,
                })
            },
        )
        .optional()
        .context("failed to resolve public key graph node")
}

fn resolve_sudo_rule_node(connection: &Connection, value: &str) -> Result<Option<GraphNodeRecord>> {
    let rule_id = value
        .parse::<i64>()
        .context("sudo_rule reference must use an integer id")?;
    connection
        .query_row(
            "SELECT id, subject || ' ' || COALESCE(command, '-') FROM sudo_rules WHERE id = ?1",
            params![rule_id],
            |row| {
                Ok(GraphNodeRecord {
                    node_type: "SUDO_RULE".to_string(),
                    node_id: row.get(0)?,
                    label: row.get(1)?,
                })
            },
        )
        .optional()
        .context("failed to resolve sudo rule graph node")
}
