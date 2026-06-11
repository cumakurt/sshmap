use crate::models::ParsedKnownHostEntry;

pub fn parse_known_hosts(
    content: &str,
    host_id: i64,
    source_file: &str,
) -> Vec<ParsedKnownHostEntry> {
    let mut entries = Vec::new();

    for (index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(hostnames) = parts.next() else {
            continue;
        };
        let Some(key_type) = parts.next() else {
            continue;
        };
        let key_material = parts.next().unwrap_or_default();
        let hashed = hostnames.starts_with('|');
        let fingerprint = if hashed {
            None
        } else {
            Some(format!("{key_type}:{key_material}"))
        };

        for host in hostnames.split(',') {
            let (known_host, known_ip) = if host.parse::<std::net::IpAddr>().is_ok() {
                (None, Some(host.to_string()))
            } else if hashed {
                (None, None)
            } else {
                (Some(host.to_string()), None)
            };

            entries.push(ParsedKnownHostEntry {
                host_id,
                known_host,
                known_ip,
                host_key_type: key_type.to_string(),
                host_key_fingerprint: fingerprint.clone(),
                hashed,
                source_file: source_file.to_string(),
                line_number: (index + 1) as i64,
                confidence: if hashed { "LOW" } else { "MEDIUM" }.to_string(),
            });
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_known_host_line() {
        let entries = parse_known_hosts(
            "db01.example.com,10.0.0.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample",
            1,
            "/home/user/.ssh/known_hosts",
        );

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].known_host.as_deref(), Some("db01.example.com"));
        assert_eq!(entries[1].known_ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn parses_hashed_known_host_line() {
        let entries = parse_known_hosts(
            "|1|abc|def ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHashed",
            1,
            "/home/user/.ssh/known_hosts",
        );

        assert_eq!(entries.len(), 1);
        assert!(entries[0].hashed);
        assert!(entries[0].host_key_fingerprint.is_none());
    }
}
