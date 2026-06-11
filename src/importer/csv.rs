use crate::importer::store_hosts;
use crate::models::ImportedHost;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub fn import_csv_inventory(
    path: &Path,
    mapping_path: Option<&Path>,
    db_path: &Path,
) -> Result<crate::models::ImportSummary> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read csv inventory {}", path.display()))?;
    let mapping = load_mapping(mapping_path)?;
    let mut lines = content.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("csv inventory is empty"))?;
    let columns = parse_csv_line(header);
    let column_index = |name: &str| -> Result<usize> {
        columns
            .iter()
            .position(|column| column.eq_ignore_ascii_case(name))
            .ok_or_else(|| anyhow::anyhow!("csv header is missing required column: {name}"))
    };

    let hostname_idx = mapping
        .get("hostname")
        .and_then(|value| columns.iter().position(|column| column == value))
        .or_else(|| {
            columns
                .iter()
                .position(|column| column.eq_ignore_ascii_case("hostname"))
        });
    let ip_idx = mapping
        .get("ip_address")
        .and_then(|value| columns.iter().position(|column| column == value))
        .unwrap_or_else(|| column_index("ip_address").unwrap_or(0));
    let port_idx = mapping
        .get("port")
        .and_then(|value| columns.iter().position(|column| column == value))
        .or_else(|| {
            columns
                .iter()
                .position(|column| column.eq_ignore_ascii_case("port"))
        });

    let mut hosts = Vec::new();
    for line in lines {
        let fields = parse_csv_line(line);
        if fields.is_empty() {
            continue;
        }
        let ip_address = fields
            .get(ip_idx)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("csv row is missing ip_address"))?
            .to_string();
        let hostname = hostname_idx.and_then(|index| fields.get(index)).cloned();
        let port = port_idx
            .and_then(|index| fields.get(index))
            .and_then(|value| value.parse().ok())
            .unwrap_or(22);

        hosts.push(ImportedHost {
            hostname: hostname.clone(),
            fqdn: hostname,
            ip_address,
            port,
            ssh_open: true,
        });
    }

    store_hosts(db_path, "csv", &hosts)
}

fn load_mapping(path: Option<&Path>) -> Result<BTreeMap<String, String>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read csv mapping {}", path.display()))?;
    let mut mapping = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            bail!("invalid mapping line: {line}");
        };
        mapping.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(mapping)
}

fn parse_csv_line(line: &str) -> Vec<String> {
    line.split(',')
        .map(|field| field.trim().trim_matches('"').to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_csv_line() {
        assert_eq!(
            parse_csv_line("web01,10.0.0.10,22"),
            vec!["web01", "10.0.0.10", "22"]
        );
    }
}
