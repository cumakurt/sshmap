use crate::models::ParsedHostAlias;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn parse_hosts_file(content: &str, host_id: i64, source_file: &str) -> Vec<ParsedHostAlias> {
    let mut aliases = Vec::new();

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = (index + 1) as i64;
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(ip_value) = parts.next() else {
            continue;
        };
        let Ok(ip_address) = ip_value.parse::<IpAddr>() else {
            continue;
        };

        for (alias_index, alias) in parts.enumerate() {
            if !is_valid_hosts_alias(alias) {
                continue;
            }
            aliases.push(ParsedHostAlias {
                host_id,
                ip_address: ip_address.to_string(),
                alias: alias.to_string(),
                alias_kind: if alias_index == 0 {
                    "canonical".to_string()
                } else {
                    "alias".to_string()
                },
                source: "hosts_file".to_string(),
                source_file: source_file.to_string(),
                line_number,
                confidence: hosts_file_confidence(ip_address).to_string(),
            });
        }
    }

    aliases
}

fn is_valid_hosts_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.'))
}

fn hosts_file_confidence(ip_address: IpAddr) -> &'static str {
    match ip_address {
        IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST || ip.is_unspecified() => "LOW",
        IpAddr::V4(ip) if ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() => "LOW",
        IpAddr::V6(ip) if ip == Ipv6Addr::LOCALHOST || ip.is_unspecified() => "LOW",
        IpAddr::V6(ip) if ip.is_loopback() || ip.is_multicast() => "LOW",
        _ => "MEDIUM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_file_aliases() {
        let aliases = parse_hosts_file(
            "127.0.0.1 localhost\n10.0.0.10 web01 web01.internal # comment\n",
            7,
            "/etc/hosts",
        );

        assert_eq!(aliases.len(), 3);
        assert_eq!(aliases[1].alias, "web01");
        assert_eq!(aliases[1].alias_kind, "canonical");
        assert_eq!(aliases[2].alias, "web01.internal");
    }
}
