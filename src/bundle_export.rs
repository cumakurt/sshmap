use crate::db;
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use zip::{ZipWriter, write::SimpleFileOptions};

pub struct EvidenceBundleOptions<'a> {
    pub db_path: &'a Path,
    pub output: &'a Path,
    pub host: Option<&'a str>,
    pub include_raw_evidence: bool,
}

pub fn export_evidence_bundle(options: EvidenceBundleOptions<'_>) -> Result<PathBuf> {
    db::initialize_database(options.db_path)?;
    if let Some(parent) = options.output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let summary = crate::server::build_api_summary(options.db_path)?;
    let risks = db::list_risks(
        options.db_path,
        &crate::models::RiskQuery {
            severity: None,
            code: None,
            limit: 10_000,
        },
    )?;
    let hosts = db::list_hosts(options.db_path, 10_000)?;
    let manifest = serde_json::json!({
        "tool": "sshmap",
        "version": env!("CARGO_PKG_VERSION"),
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "host_filter": options.host,
        "summary": summary,
        "risk_count": risks.len(),
        "host_count": hosts.len(),
    });

    let file = File::create(options.output)
        .with_context(|| format!("failed to create {}", options.output.display()))?;
    let mut zip = ZipWriter::new(file);
    let options_zip =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("manifest.json", options_zip)?;
    zip.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;

    zip.start_file("risks.json", options_zip)?;
    zip.write_all(serde_json::to_string_pretty(&risks)?.as_bytes())?;

    zip.start_file("hosts.json", options_zip)?;
    zip.write_all(serde_json::to_string_pretty(&hosts)?.as_bytes())?;

    if options.include_raw_evidence {
        let evidence = db::list_raw_evidence_for_bundle(options.db_path, options.host)?;
        zip.start_file("raw_evidence.json", options_zip)?;
        zip.write_all(serde_json::to_string_pretty(&evidence)?.as_bytes())?;
    }

    zip.finish()?;
    Ok(options.output.to_path_buf())
}
