use crate::importer::store_hosts;
use crate::models::ImportedHost;
use anyhow::Result;
use std::path::Path;

pub fn import_nmap_xml(path: &Path, db_path: &Path) -> Result<crate::models::ImportSummary> {
    let content = crate::security::read_text_file_limited(
        path,
        crate::security::MAX_IMPORT_FILE_BYTES,
        "nmap xml",
    )?;
    let mut hosts = Vec::new();

    for host_block in content.split("<host ") {
        let Some(end) = host_block.find("</host>") else {
            continue;
        };
        let block = &host_block[..end];
        let ip = extract_attribute(block, "address", "addr");
        let Some(ip_address) = ip else {
            continue;
        };
        if !block.contains("addrtype=\"ipv4\"") && !block.contains("addrtype=\"ipv6\"") {
            continue;
        }
        if !block.contains("portid=\"22\"") || !block.contains("state=\"open\"") {
            continue;
        }

        let hostname = extract_hostname(block);
        hosts.push(ImportedHost {
            hostname: hostname.clone(),
            fqdn: hostname,
            ip_address,
            port: 22,
            os_family: None,
            os_version: None,
            environment: None,
            criticality: None,
            ssh_open: true,
        });
    }

    store_hosts(db_path, "nmap", &hosts)
}

fn extract_hostname(block: &str) -> Option<String> {
    for line in block.lines() {
        if line.contains("<hostname") {
            return extract_attribute(line, "hostname", "name");
        }
    }
    None
}

fn extract_attribute(text: &str, _tag: &str, attribute: &str) -> Option<String> {
    let needle = format!("{attribute}=\"");
    let start = text.find(&needle)? + needle.len();
    let end = text[start..].find('"')? + start;
    Some(text[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ipv4_ssh_host() {
        let block = r#"<address addr="10.0.0.5" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
        <hostnames><hostname name="web01" type="PTR"/></hostnames>"#;
        assert_eq!(extract_hostname(block), Some("web01".to_string()));
    }
}
