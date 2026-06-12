use crate::db;
use crate::models::ImportSummary;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct SshAuditReport {
    #[serde(default)]
    failures: Vec<SshAuditFinding>,
    #[serde(default)]
    recommendations: Vec<SshAuditFinding>,
}

#[derive(Debug, Deserialize)]
struct SshAuditFinding {
    #[serde(alias = "id")]
    code: Option<String>,
    level: Option<String>,
    #[serde(alias = "txt")]
    description: Option<String>,
}

pub fn import_ssh_audit_report(
    path: &Path,
    db_path: &Path,
    host: Option<&str>,
) -> Result<ImportSummary> {
    if let Some(host) = host {
        crate::security::validate_import_host_identifier(host)?;
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read ssh-audit report {}", path.display()))?;
    let report: SshAuditReport = serde_json::from_str(&content)?;
    let host_id = host
        .map(|value| db::resolve_host_id(db_path, value))
        .transpose()?
        .flatten();

    let mut imported = 0_usize;
    for finding in report.failures.into_iter().chain(report.recommendations) {
        let title = finding
            .description
            .clone()
            .unwrap_or_else(|| "ssh-audit finding".to_string());
        db::insert_external_finding(
            db_path,
            host_id,
            "ssh-audit",
            &finding
                .code
                .unwrap_or_else(|| "SSH_AUDIT_FINDING".to_string()),
            &finding.level.unwrap_or_else(|| "MEDIUM".to_string()),
            &title,
            finding.description.as_deref(),
            None,
        )?;
        imported += 1;
    }

    Ok(ImportSummary { imported })
}
