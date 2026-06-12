use crate::models::{HostRecord, ImportSummary};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct CloudTagFile {
    pub hosts: Vec<CloudHostTags>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct CloudHostTags {
    pub match_host: String,
    pub provider: Option<String>,
    pub region: Option<String>,
    pub account_id: Option<String>,
    pub instance_id: Option<String>,
    pub environment: Option<String>,
    pub criticality: Option<String>,
    pub tags: Option<BTreeMap<String, String>>,
}

pub fn enrich_from_tags_file(db_path: &Path, tags_file: &Path) -> Result<ImportSummary> {
    let content = std::fs::read_to_string(tags_file)
        .with_context(|| format!("failed to read cloud tags file {}", tags_file.display()))?;
    let payload: CloudTagFile = if tags_file.extension().is_some_and(|ext| ext == "yaml" || ext == "yml") {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let hosts = crate::db::list_hosts(db_path, 10_000)?;
    let mut updated = 0_usize;

    for entry in payload.hosts {
        let Some(host) = find_matching_host(&hosts, &entry.match_host) else {
            continue;
        };
        let tags_json = serde_json::to_string(&entry)?;
        crate::db::update_host_cloud_metadata(
            db_path,
            host.id,
            entry.environment.as_deref(),
            entry.criticality.as_deref(),
            &tags_json,
        )?;
        updated += 1;
    }

    Ok(ImportSummary { imported: updated })
}

fn find_matching_host<'a>(hosts: &'a [HostRecord], needle: &str) -> Option<&'a HostRecord> {
    hosts.iter().find(|host| {
        host.ip_address == needle
            || host.hostname.as_deref() == Some(needle)
            || host.fqdn.as_deref() == Some(needle)
    })
}
