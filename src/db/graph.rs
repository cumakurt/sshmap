use crate::db::migrations::{apply_pragmas, count_rows, initialize_database};
use crate::db::pool::ReadOnlyDbAccess;
use crate::models::{GraphEdgeRecord, GraphNodeRecord};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::path::Path;

pub fn list_user_nodes_by_username(path: &Path, username: &str) -> Result<Vec<GraphNodeRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_user_nodes_by_username_connection(&connection, username)
}

pub fn list_user_nodes_by_username_read_only(
    source: &(impl ReadOnlyDbAccess + ?Sized),
    username: &str,
) -> Result<Vec<GraphNodeRecord>> {
    source.with_read_connection(|connection| {
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

pub fn list_public_key_nodes_by_fingerprint(
    path: &Path,
    fingerprint: &str,
) -> Result<Vec<GraphNodeRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_public_key_nodes_by_fingerprint_connection(&connection, fingerprint)
}

pub fn list_public_key_nodes_by_fingerprint_read_only(
    source: &(impl ReadOnlyDbAccess + ?Sized),
    fingerprint: &str,
) -> Result<Vec<GraphNodeRecord>> {
    source.with_read_connection(|connection| {
        list_public_key_nodes_by_fingerprint_connection(connection, fingerprint)
    })
}

fn list_public_key_nodes_by_fingerprint_connection(
    connection: &Connection,
    fingerprint: &str,
) -> Result<Vec<GraphNodeRecord>> {
    let normalized = fingerprint.strip_prefix("key:").unwrap_or(fingerprint);
    let mut statement = connection
        .prepare("SELECT id, fingerprint_sha256 FROM public_keys WHERE fingerprint_sha256 = ?1")?;
    let rows = statement.query_map(params![normalized], |row| {
        Ok(GraphNodeRecord {
            node_type: "PUBLIC_KEY".to_string(),
            node_id: row.get(0)?,
            label: row.get(1)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list public key graph nodes")
}

pub fn rebuild_graph_edges(path: &Path) -> Result<()> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;

    connection.execute("DELETE FROM graph_edges", [])?;
    insert_host_user_edges(&connection)?;
    insert_public_key_edges(&connection)?;
    insert_certificate_authority_edges(&connection)?;
    insert_sudo_edges(&connection)?;
    insert_client_config_edges(&connection)?;
    insert_bastion_reachability_edges(&connection)?;
    Ok(())
}

pub fn list_graph_edges(path: &Path) -> Result<Vec<GraphEdgeRecord>> {
    initialize_database(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;
    apply_pragmas(&connection)?;
    list_graph_edges_connection(&connection, None)
}

pub const GRAPH_DEFAULT_ANALYSIS_EDGE_LIMIT: usize = 10_000;
pub const GRAPH_FULL_ANALYSIS_EDGE_LIMIT: usize = 100_000;
#[allow(dead_code)]
pub const GRAPH_API_ANALYSIS_EDGE_LIMIT: usize = GRAPH_DEFAULT_ANALYSIS_EDGE_LIMIT;

pub fn resolve_graph_analysis_edge_limit(full_graph: bool) -> usize {
    if full_graph {
        GRAPH_FULL_ANALYSIS_EDGE_LIMIT
    } else {
        GRAPH_DEFAULT_ANALYSIS_EDGE_LIMIT
    }
}

pub fn graph_analysis_edge_limit_from_env() -> Option<usize> {
    std::env::var("SSHMAP_GRAPH_EDGE_LIMIT")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|limit| *limit > 0)
}

fn effective_graph_edge_limit(requested: usize) -> usize {
    graph_analysis_edge_limit_from_env().unwrap_or(requested)
}

pub fn list_graph_edges_read_only_limited(
    source: &(impl ReadOnlyDbAccess + ?Sized),
    limit: usize,
) -> Result<Vec<GraphEdgeRecord>> {
    source.with_read_connection(|connection| list_graph_edges_connection(connection, Some(limit)))
}

pub fn load_graph_edges_for_analysis(
    source: &(impl ReadOnlyDbAccess + ?Sized),
    full_graph: bool,
) -> Result<GraphEdgeSlice> {
    let limit = effective_graph_edge_limit(resolve_graph_analysis_edge_limit(full_graph));
    load_graph_edges_read_only(source, limit)
}

#[derive(Debug, Clone)]
pub struct GraphEdgeSlice {
    pub edges: Vec<GraphEdgeRecord>,
    pub truncated: bool,
    pub total_edges: usize,
    pub edge_limit: usize,
}

pub fn count_graph_edges_read_only(
    source: &(impl ReadOnlyDbAccess + ?Sized),
) -> Result<usize> {
    source.with_read_connection(|connection| count_rows(connection, "graph_edges"))
}

pub fn load_graph_edges_read_only(
    source: &(impl ReadOnlyDbAccess + ?Sized),
    limit: usize,
) -> Result<GraphEdgeSlice> {
    let total_edges = count_graph_edges_read_only(source)?;
    let edges = list_graph_edges_read_only_limited(source, limit)?;
    Ok(GraphEdgeSlice {
        truncated: total_edges > limit,
        total_edges,
        edge_limit: limit,
        edges,
    })
}

pub fn load_graph_edges_for_api_analysis(
    source: &(impl ReadOnlyDbAccess + ?Sized),
) -> Result<GraphEdgeSlice> {
    load_graph_edges_read_only(
        source,
        effective_graph_edge_limit(GRAPH_DEFAULT_ANALYSIS_EDGE_LIMIT),
    )
}

fn list_graph_edges_connection(
    connection: &Connection,
    limit: Option<usize>,
) -> Result<Vec<GraphEdgeRecord>> {
    let sql = match limit {
        Some(_) => {
            "SELECT
                id, from_type, from_id, from_label, to_type, to_id, to_label,
                edge_type, weight, confidence, evidence
             FROM graph_edges
             ORDER BY id
             LIMIT ?1"
        }
        None => {
            "SELECT
                id, from_type, from_id, from_label, to_type, to_id, to_label,
                edge_type, weight, confidence, evidence
             FROM graph_edges
             ORDER BY id"
        }
    };
    let mut statement = connection.prepare(sql)?;
    let rows = match limit {
        Some(limit) => statement.query_map(params![limit as i64], map_graph_edge_record)?,
        None => statement.query_map([], map_graph_edge_record)?,
    };
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
    source: &(impl ReadOnlyDbAccess + ?Sized),
    reference: &str,
) -> Result<Option<GraphNodeRecord>> {
    source
        .with_read_connection(|connection| resolve_graph_node_ref_connection(connection, reference))
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

fn insert_certificate_authority_edges(connection: &Connection) -> Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'SSH_CA',
            MIN(pk.id),
            pk.certificate_signing_ca,
            'PUBLIC_KEY',
            pk.id,
            pk.fingerprint_sha256,
            'SSH_CA_SIGNED_PUBLIC_KEY',
            1,
            'HIGH',
            'Certificate-based authorized key'
        FROM public_keys pk
        WHERE pk.key_type LIKE '%-cert-%'
          AND pk.certificate_signing_ca IS NOT NULL
        GROUP BY pk.certificate_signing_ca, pk.id, pk.fingerprint_sha256",
        [],
    )?;

    connection.execute(
        "INSERT OR IGNORE INTO graph_edges (
            from_type, from_id, from_label, to_type, to_id, to_label,
            edge_type, weight, confidence, evidence
        )
        SELECT
            'SSH_CA',
            MIN(pk.id),
            pk.certificate_signing_ca,
            'USER',
            u.id,
            u.username || '@' || COALESCE(h.hostname, h.ip_address),
            'SSH_CA_GRANTS_USER_ACCESS',
            2,
            'HIGH',
            COALESCE(ak.source_file, 'authorized_keys')
        FROM authorized_keys ak
        JOIN public_keys pk ON pk.id = ak.public_key_id
        JOIN users u ON u.id = ak.user_id
        JOIN hosts h ON h.id = ak.host_id
        WHERE pk.key_type LIKE '%-cert-%'
          AND pk.certificate_signing_ca IS NOT NULL
        GROUP BY pk.certificate_signing_ca, u.id, h.hostname, h.ip_address, ak.source_file",
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

fn insert_bastion_reachability_edges(connection: &Connection) -> Result<()> {
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
            bastion.id,
            COALESCE(bastion.hostname, bastion.ip_address),
            'BASTION_REACHABILITY',
            2,
            'HIGH',
            'scan via ProxyJump'
        FROM bastion_reachability br
        JOIN hosts source ON source.id = br.host_id
        JOIN hosts bastion ON bastion.id = br.bastion_host_id",
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::pool::ReadOnlyPool;

    #[test]
    fn resolve_graph_analysis_edge_limit_respects_full_graph_flag() {
        assert_eq!(
            resolve_graph_analysis_edge_limit(false),
            GRAPH_DEFAULT_ANALYSIS_EDGE_LIMIT
        );
        assert_eq!(
            resolve_graph_analysis_edge_limit(true),
            GRAPH_FULL_ANALYSIS_EDGE_LIMIT
        );
    }

    #[test]
    fn graph_edge_slice_reports_truncation() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("graph.db");
        initialize_database(&db_path).expect("initialize");
        let pool = ReadOnlyPool::open(&db_path).expect("pool");

        let slice = load_graph_edges_read_only(&pool, 1).expect("graph slice");
        assert!(!slice.truncated);
        assert_eq!(slice.total_edges, 0);
        assert!(slice.edges.is_empty());
    }
}
