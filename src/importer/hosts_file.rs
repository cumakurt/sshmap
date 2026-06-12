use crate::models::{ImportSummary, ImportedHost};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub fn import_hosts_file(path: &Path, db_path: &Path) -> Result<ImportSummary> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read hosts file {}", path.display()))?;
    let aliases =
        crate::parser::hosts_file::parse_hosts_file(&content, 0, &path.display().to_string());
    let mut by_ip = BTreeMap::<String, ImportedHost>::new();

    for alias in aliases.iter().filter(|alias| alias.confidence != "LOW") {
        let entry = by_ip
            .entry(alias.ip_address.clone())
            .or_insert(ImportedHost {
                hostname: None,
                fqdn: None,
                ip_address: alias.ip_address.clone(),
                port: 22,
                os_family: None,
                os_version: None,
                environment: None,
                criticality: None,
                ssh_open: false,
            });

        if alias.alias_kind == "canonical" && entry.hostname.is_none() {
            entry.hostname = Some(alias.alias.clone());
        } else if alias.alias.contains('.') && entry.fqdn.is_none() {
            entry.fqdn = Some(alias.alias.clone());
        }
    }

    let hosts = by_ip.into_values().collect::<Vec<_>>();
    let summary = crate::db::store_imported_hosts(db_path, "hosts_file", &hosts)?;
    crate::db::store_host_aliases(db_path, &aliases)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_hosts_file_inventory() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let hosts_path = temp_dir.path().join("hosts");
        std::fs::write(&hosts_path, "10.0.0.10 web01 web01.internal\n").expect("hosts");
        let db_path = temp_dir.path().join("hosts.db");
        crate::db::initialize_database(&db_path).expect("db");

        let summary = import_hosts_file(&hosts_path, &db_path).expect("import hosts");

        assert_eq!(summary.imported, 1);
    }
}
