use crate::collector::redact_sensitive_content;
use crate::db;
use crate::importer::store_hosts;
use crate::models::{ImportedHost, RawEvidenceRecord};
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_BUNDLE_DEPTH: usize = 32;
const MAX_BUNDLE_FILES: usize = 10_000;

pub fn import_file_evidence(
    source: &str,
    evidence_type: &str,
    path: &Path,
    host: &str,
    username: Option<&str>,
    db_path: &Path,
) -> Result<crate::models::ImportSummary> {
    crate::security::validate_import_host_identifier(host)?;
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read import file {}", path.display()))?;
    let (content, redacted) = redact_sensitive_content(&content);
    if evidence_type == "authorized_keys" && username.is_none() {
        bail!("--user is required when importing authorized_keys files");
    }

    let mut import_content = content;
    if evidence_type == "authorized_keys" {
        let username = username.unwrap_or("unknown");
        crate::transport::auth::validate_ssh_username(username)
            .map_err(|error| anyhow::anyhow!(error))?;
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

    let mut imported_hosts = Vec::new();
    for host in hosts {
        let Some(ip_address) = host
            .get("ip_address")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        crate::security::validate_import_host_identifier(ip_address)?;
        imported_hosts.push(ImportedHost {
            hostname: host
                .get("hostname")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            fqdn: host
                .get("fqdn")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            ip_address: ip_address.to_string(),
            port: host
                .get("port")
                .and_then(|value| value.as_i64())
                .unwrap_or(22),
            os_family: host
                .get("os_family")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            os_version: host
                .get("os_version")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            environment: host
                .get("environment")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            criticality: host
                .get("criticality")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            ssh_open: host
                .get("ssh_open")
                .and_then(|value| value.as_bool())
                .unwrap_or(true),
        });
    }

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
    for path in list_files_recursive(dir, 0)? {
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
    crate::security::validate_import_host_identifier(host)?;

    let username = if kind.requires_user() {
        let username = username
            .map(str::to_string)
            .or_else(|| infer_username_from_path(path))
            .ok_or_else(|| anyhow::anyhow!("--user is required for authorized_keys evidence"))?;
        crate::transport::auth::validate_ssh_username(&username)
            .map_err(|error| anyhow::anyhow!(error))?;
        Some(username)
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

fn list_files_recursive(dir: &Path, depth: usize) -> Result<Vec<PathBuf>> {
    if depth > MAX_BUNDLE_DEPTH {
        bail!(
            "bundle directory exceeds maximum depth of {MAX_BUNDLE_DEPTH}: {}",
            dir.display()
        );
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            files.extend(list_files_recursive(&path, depth + 1)?);
        } else if file_type.is_file() {
            files.push(path);
        }
        if files.len() > MAX_BUNDLE_FILES {
            bail!("bundle directory exceeds maximum file count of {MAX_BUNDLE_FILES}");
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
    fn rejects_invalid_host_identifier_on_auto_import() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let sshd_path = temp_dir.path().join("sshd_config");
        std::fs::write(&sshd_path, "PermitRootLogin no\n").expect("sshd_config");
        let db_path = temp_dir.path().join("invalid-host.db");
        crate::db::initialize_database(&db_path).expect("db");

        let error =
            import_auto(&sshd_path, Some("bad host"), None, &db_path).expect_err("invalid host");
        assert!(error.to_string().contains("invalid host identifier"));
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

    #[cfg(unix)]
    #[test]
    fn bundle_import_skips_symlinked_files() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let bundle_dir = temp_dir.path().join("bundle");
        std::fs::create_dir(&bundle_dir).expect("bundle dir");
        let outside_hosts = temp_dir.path().join("outside-hosts");
        std::fs::write(&outside_hosts, "10.0.0.10 web01 web01.internal\n").expect("hosts");
        std::os::unix::fs::symlink(&outside_hosts, bundle_dir.join("hosts")).expect("symlink");
        let db_path = temp_dir.path().join("bundle.db");
        crate::db::initialize_database(&db_path).expect("db");

        let summary = import_bundle(&bundle_dir, None, None, &db_path).expect("bundle import");

        assert_eq!(summary.imported, 0);
    }
}
