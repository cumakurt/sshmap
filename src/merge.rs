use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct MergeSummary {
    pub source_databases: usize,
    pub hosts_imported: usize,
    pub risks_imported: usize,
    pub graph_edges_imported: usize,
}

pub fn merge_databases(sources: &[&Path], output: &Path) -> Result<MergeSummary> {
    if sources.is_empty() {
        anyhow::bail!("at least one source database is required");
    }

    if output.exists() {
        std::fs::remove_file(output)
            .with_context(|| format!("failed to remove existing output {}", output.display()))?;
    }

    crate::db::initialize_database(output)?;
    let destination = Connection::open(output)
        .with_context(|| format!("failed to open output database {}", output.display()))?;

    let mut summary = MergeSummary {
        source_databases: sources.len(),
        hosts_imported: 0,
        risks_imported: 0,
        graph_edges_imported: 0,
    };

    for source_path in sources {
        let source = Connection::open(source_path).with_context(|| {
            format!("failed to open source database {}", source_path.display())
        })?;
        summary.hosts_imported += copy_hosts(&source, &destination)?;
        summary.risks_imported += copy_risks(&source, &destination)?;
        summary.graph_edges_imported += copy_graph_edges(&source, &destination)?;
    }

    Ok(summary)
}

fn copy_hosts(source: &Connection, destination: &Connection) -> Result<usize> {
    let mut statement = source.prepare(
        "SELECT hostname, fqdn, ip_address, port, os_family, os_version, environment, criticality,
                ssh_open, ssh_banner, openssh_version, first_seen, last_seen, source
         FROM hosts",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, Option<String>>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, String>(12)?,
            row.get::<_, String>(13)?,
        ))
    })?;

    let mut imported = 0usize;
    for row in rows {
        let row = row?;
        destination.execute(
            "INSERT INTO hosts (
                hostname, fqdn, ip_address, port, os_family, os_version, environment, criticality,
                ssh_open, ssh_banner, openssh_version, first_seen, last_seen, source
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            ON CONFLICT(ip_address, port) DO UPDATE SET
                hostname = COALESCE(excluded.hostname, hosts.hostname),
                fqdn = COALESCE(excluded.fqdn, hosts.fqdn),
                os_family = COALESCE(excluded.os_family, hosts.os_family),
                os_version = COALESCE(excluded.os_version, hosts.os_version),
                environment = COALESCE(excluded.environment, hosts.environment),
                criticality = COALESCE(excluded.criticality, hosts.criticality),
                ssh_open = MAX(hosts.ssh_open, excluded.ssh_open),
                ssh_banner = COALESCE(excluded.ssh_banner, hosts.ssh_banner),
                openssh_version = COALESCE(excluded.openssh_version, hosts.openssh_version),
                last_seen = excluded.last_seen,
                source = excluded.source",
            params![
                row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9, row.10, row.11,
                row.12, row.13
            ],
        )?;
        imported += 1;
    }

    Ok(imported)
}

fn copy_risks(source: &Connection, destination: &Connection) -> Result<usize> {
    let mut statement = source.prepare(
        "SELECT h.ip_address, h.port, r.username, r.public_key_fingerprint, r.risk_code, r.severity,
                r.score, r.confidence, r.title, r.description, r.impact, r.evidence, r.recommendation,
                r.status, r.first_seen, r.last_seen
         FROM risks r
         LEFT JOIN hosts h ON h.id = r.host_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, Option<i64>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, Option<String>>(10)?,
            row.get::<_, Option<String>>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, String>(13)?,
            row.get::<_, String>(14)?,
            row.get::<_, String>(15)?,
        ))
    })?;

    let mut imported = 0usize;
    for row in rows {
        let row = row?;
        let host_id = match (row.0.as_deref(), row.1) {
            (Some(ip), Some(port)) => destination
                .query_row(
                    "SELECT id FROM hosts WHERE ip_address = ?1 AND port = ?2",
                    params![ip, port],
                    |row| row.get::<_, i64>(0),
                )
                .ok(),
            _ => None,
        };

        destination.execute(
            "INSERT INTO risks (
                host_id, username, public_key_fingerprint, risk_code, severity, score, confidence,
                title, description, impact, evidence, recommendation, status, first_seen, last_seen
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                host_id, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9, row.10, row.11, row.12,
                row.13, row.14, row.15
            ],
        )?;
        imported += 1;
    }

    Ok(imported)
}

fn copy_graph_edges(source: &Connection, destination: &Connection) -> Result<usize> {
    let mut statement = source.prepare(
        "SELECT from_type, from_id, from_label, to_type, to_id, to_label, edge_type, weight,
                confidence, evidence
         FROM graph_edges",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;

    let mut imported = 0usize;
    for row in rows {
        let row = row?;
        destination.execute(
            "INSERT INTO graph_edges (
                from_type, from_id, from_label, to_type, to_id, to_label, edge_type, weight,
                confidence, evidence
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9
            ],
        )?;
        imported += 1;
    }

    Ok(imported)
}
