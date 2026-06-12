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
}
