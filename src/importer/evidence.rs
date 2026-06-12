use crate::collector::redact_sensitive_content;
use crate::db;
use crate::importer::store_hosts;
use crate::models::{ImportedHost, RawEvidenceRecord};
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;

pub fn import_file_evidence(
    source: &str,
    evidence_type: &str,
    path: &Path,
    host: &str,
    username: Option<&str>,
    db_path: &Path,
) -> Result<crate::models::ImportSummary> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read import file {}", path.display()))?;
    let (content, redacted) = redact_sensitive_content(&content);
    if evidence_type == "authorized_keys" && username.is_none() {
        bail!("--user is required when importing authorized_keys files");
    }

    let mut import_content = content;
    if evidence_type == "authorized_keys" {
        let username = username.unwrap_or("unknown");
        let source_file = authorized_keys_source_path(username);
        import_content = format!("\n--- SSHMAP_FILE:{source_file} ---\n{import_content}");
    }

    db::store_imported_evidence(
        db_path,
        source,
        host,
        RawEvidenceRecord {
            evidence_type: evidence_type.to_string(),
            source: source.to_string(),
            command: format!("import {}", path.display()),
            content: import_content,
            stderr: String::new(),
            exit_code: Some(0),
            redacted,
        },
    )?;

    Ok(crate::models::ImportSummary { imported: 1 })
}

pub fn import_json_report(path: &Path, db_path: &Path) -> Result<crate::models::ImportSummary> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read json report {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse json report {}", path.display()))?;
    let Some(hosts) = value.get("hosts").and_then(|hosts| hosts.as_array()) else {
        bail!("json report does not contain a hosts array");
    };

    let imported_hosts = hosts
        .iter()
        .filter_map(|host| {
            let ip_address = host
                .get("ip_address")
                .and_then(|value| value.as_str())
                .map(str::to_string)?;
            Some(ImportedHost {
                hostname: host
                    .get("hostname")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                fqdn: host
                    .get("fqdn")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                ip_address,
                port: host
                    .get("port")
                    .and_then(|value| value.as_i64())
                    .unwrap_or(22),
                ssh_open: host
                    .get("ssh_open")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(true),
            })
        })
        .collect::<Vec<_>>();

    store_hosts(db_path, "json", &imported_hosts)
}

pub fn import_auto(
    path: &Path,
    host: Option<&str>,
    username: Option<&str>,
    db_path: &Path,
) -> Result<crate::models::ImportSummary> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read import file {}", path.display()))?;
    let Some(kind) = crate::parser::registry::detect_parser(path, &content) else {
        bail!("could not auto-detect parser for {}", path.display());
    };

    import_detected_file(kind, path, host, username, db_path)
}

pub fn import_bundle(
    dir: &Path,
    host: Option<&str>,
    username: Option<&str>,
    db_path: &Path,
) -> Result<crate::models::ImportSummary> {
    if !dir.is_dir() {
        bail!("bundle directory not found: {}", dir.display());
    }

    let mut imported = 0_usize;
    for path in list_files_recursive(dir)? {
        match import_auto(&path, host, username, db_path) {
            Ok(summary) => imported += summary.imported,
            Err(error) if error.to_string().contains("could not auto-detect parser") => {}
            Err(error) => return Err(error),
        }
    }

    Ok(crate::models::ImportSummary { imported })
}

fn import_detected_file(
    kind: crate::parser::registry::ParserKind,
    path: &Path,
    host: Option<&str>,
    username: Option<&str>,
    db_path: &Path,
) -> Result<crate::models::ImportSummary> {
    if kind == crate::parser::registry::ParserKind::HostsFile {
        return crate::importer::hosts_file::import_hosts_file(path, db_path);
    }
    if kind == crate::parser::registry::ParserKind::KnownHosts {
        return crate::importer::known_hosts::import_known_hosts(path, db_path);
    }

    let host = host.ok_or_else(|| {
        anyhow::anyhow!(
            "--host is required when auto-importing {} evidence",
            kind.evidence_type()
        )
    })?;

    let username = if kind.requires_user() {
        username
            .map(str::to_string)
            .or_else(|| infer_username_from_path(path))
            .ok_or_else(|| anyhow::anyhow!("--user is required for authorized_keys evidence"))?
            .into()
    } else {
        None
    };

    import_file_evidence(
        kind.source(),
        kind.evidence_type(),
        path,
        host,
        username.as_deref(),
        db_path,
    )
}

fn infer_username_from_path(path: &Path) -> Option<String> {
    crate::parser::authorized_keys::username_from_authorized_keys_path(&path.to_string_lossy())
}

fn list_files_recursive(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            files.extend(list_files_recursive(&path)?);
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(files)
}

fn authorized_keys_source_path(username: &str) -> String {
    if username == "root" {
        "/root/.ssh/authorized_keys".to_string()
    } else {
        format!("/home/{username}/.ssh/authorized_keys")
    }
}

#[cfg(test)]
mod import_tests {
    use super::*;

    #[test]
    fn root_authorized_keys_use_root_home_path() {
        assert_eq!(
            authorized_keys_source_path("root"),
            "/root/.ssh/authorized_keys"
        );
    }

    #[test]
    fn regular_user_authorized_keys_use_home_path() {
        assert_eq!(
            authorized_keys_source_path("deploy"),
            "/home/deploy/.ssh/authorized_keys"
        );
    }

    #[test]
    fn auto_import_detects_hosts_file() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let hosts_path = temp_dir.path().join("hosts");
        std::fs::write(&hosts_path, "10.0.0.10 web01 web01.internal\n").expect("hosts");
        let db_path = temp_dir.path().join("auto.db");
        crate::db::initialize_database(&db_path).expect("db");

        let summary = import_auto(&hosts_path, None, None, &db_path).expect("auto import");

        assert_eq!(summary.imported, 1);
    }
}
