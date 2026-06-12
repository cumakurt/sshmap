use crate::importer::store_hosts;
use crate::models::ImportedHost;
use anyhow::Result;
use std::path::Path;

pub fn import_known_hosts(path: &Path, db_path: &Path) -> Result<crate::models::ImportSummary> {
    let content = crate::security::read_text_file_limited(
        path,
        crate::security::MAX_IMPORT_FILE_BYTES,
        "known_hosts",
    )?;
    let mut hosts = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(hostnames) = line.split_whitespace().next() else {
            continue;
        };
        for hostname in hostnames.split(',') {
            if hostname.starts_with('|') || hostname.starts_with('[') {
                continue;
            }
            let ip_address = hostname.to_string();
            hosts.push(ImportedHost {
                hostname: Some(hostname.to_string()),
                fqdn: Some(hostname.to_string()),
                ip_address,
                port: 22,
                os_family: None,
                os_version: None,
                environment: None,
                criticality: None,
                ssh_open: true,
            });
        }
    }

    store_hosts(db_path, "known_hosts", &hosts)
}
