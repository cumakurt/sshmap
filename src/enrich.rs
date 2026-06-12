use crate::models::{ImportSummary, ParsedHostAlias};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::net::ToSocketAddrs;
use std::path::Path;

pub fn enrich_dns(db_path: &Path, limit: usize, reverse: bool) -> Result<ImportSummary> {
    crate::db::initialize_database(db_path)?;
    let hosts = crate::db::list_hosts(db_path, limit)?;
    let aliases = crate::db::list_host_aliases_read_only(db_path, limit)?;
    let mut names = BTreeSet::new();

    for host in &hosts {
        if let Some(hostname) = host.hostname.as_deref().filter(|value| !value.is_empty()) {
            names.insert(hostname.to_string());
        }
        if let Some(fqdn) = host.fqdn.as_deref().filter(|value| !value.is_empty()) {
            names.insert(fqdn.to_string());
        }
    }
    for alias in aliases {
        if alias.confidence != "LOW" {
            names.insert(alias.alias);
        }
    }

    let mut parsed_aliases = Vec::new();
    for name in names.into_iter().take(limit) {
        for address in resolve_name(&name)? {
            parsed_aliases.push(ParsedHostAlias {
                host_id: 0,
                ip_address: address,
                alias: name.clone(),
                alias_kind: "dns".to_string(),
                source: "dns".to_string(),
                source_file: "resolver".to_string(),
                line_number: 0,
                confidence: "MEDIUM".to_string(),
            });
        }
    }

    if reverse {
        for host in hosts.iter().take(limit) {
            if let Some(name) = reverse_lookup(&host.ip_address) {
                parsed_aliases.push(ParsedHostAlias {
                    host_id: host.id,
                    ip_address: host.ip_address.clone(),
                    alias: name,
                    alias_kind: "reverse_dns".to_string(),
                    source: "dns".to_string(),
                    source_file: "getent hosts".to_string(),
                    line_number: 0,
                    confidence: "MEDIUM".to_string(),
                });
            }
        }
    }

    let summary = crate::db::store_host_aliases(db_path, &parsed_aliases)?;
    crate::db::refresh_data_quality_findings(db_path)?;
    Ok(summary)
}

fn resolve_name(name: &str) -> Result<Vec<String>> {
    let mut addresses = BTreeSet::new();
    let socket_addrs = (name, 22)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {name}"))?;
    for address in socket_addrs {
        addresses.insert(address.ip().to_string());
    }
    Ok(addresses.into_iter().collect())
}

fn reverse_lookup(ip_address: &str) -> Option<String> {
    let output = std::process::Command::new("getent")
        .args(["hosts", ip_address])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.split_whitespace().nth(1).map(str::to_string)
}
