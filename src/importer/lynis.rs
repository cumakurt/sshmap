use crate::db;
use crate::models::ImportSummary;
use anyhow::{Context, Result};
use std::path::Path;

pub fn import_lynis_report(
    path: &Path,
    db_path: &Path,
    host: Option<&str>,
) -> Result<ImportSummary> {
    if let Some(host) = host {
        crate::security::validate_import_host_identifier(host)?;
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read Lynis report {}", path.display()))?;
    let host_id = host
        .map(|value| db::resolve_host_id(db_path, value))
        .transpose()?
        .flatten();

    let mut imported = 0_usize;
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("warning[]=") && !trimmed.starts_with("suggestion[]=") {
            continue;
        }
        let (kind, text) = trimmed
            .split_once('=')
            .map(|(left, right)| (left.trim_end_matches("[]"), right))
            .unwrap_or(("finding", trimmed));
        let severity = if kind == "warning" { "HIGH" } else { "MEDIUM" };
        let finding_id = format!("LYNIS_{}", kind.to_ascii_uppercase());
        db::insert_external_finding(
            db_path,
            host_id,
            "lynis",
            &finding_id,
            severity,
            text,
            Some(text),
            None,
        )?;
        imported += 1;
    }

    Ok(ImportSummary { imported })
}
