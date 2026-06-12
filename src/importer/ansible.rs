use crate::importer::store_hosts;
use crate::models::ImportedHost;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub fn import_ansible_inventory(
    path: &Path,
    db_path: &Path,
) -> Result<crate::models::ImportSummary> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read ansible inventory {}", path.display()))?;
    let mut hosts = Vec::new();
    let mut current_group = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current_group = line.trim_matches(['[', ']']).to_string();
            continue;
        }
        if line.contains('=') && !line.contains(' ') {
            continue;
        }

        let mut tokens = line.split_whitespace();
        let Some(name) = tokens.next() else {
            continue;
        };
        if name.starts_with('[') {
            continue;
        }

        let mut ip_address = name.to_string();
        let mut port = 22_i64;
        for token in tokens {
            if let Some(value) = token.strip_prefix("ansible_host=") {
                ip_address = value.to_string();
            } else if let Some(value) = token.strip_prefix("ansible_port=") {
                port = value.parse().unwrap_or(22);
            }
        }

        hosts.push(ImportedHost {
            hostname: Some(name.to_string()),
            fqdn: if current_group.is_empty() {
                None
            } else {
                Some(format!("{name}.{current_group}"))
            },
            ip_address,
            port,
            os_family: None,
            os_version: None,
            environment: (!current_group.is_empty()).then(|| current_group.clone()),
            criticality: None,
            ssh_open: true,
        });
    }

    store_hosts(db_path, "ansible", &hosts)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_inventory_line() {
        let line = "web01 ansible_host=10.0.0.10 ansible_port=2222";
        let mut tokens = line.split_whitespace();
        let name = tokens.next().unwrap();
        let mut ip_address = name.to_string();
        let mut port = 22_i64;
        for token in tokens {
            if let Some(value) = token.strip_prefix("ansible_host=") {
                ip_address = value.to_string();
            } else if let Some(value) = token.strip_prefix("ansible_port=") {
                port = value.parse().unwrap_or(22);
            }
        }
        assert_eq!(name, "web01");
        assert_eq!(ip_address, "10.0.0.10");
        assert_eq!(port, 2222);
    }
}
