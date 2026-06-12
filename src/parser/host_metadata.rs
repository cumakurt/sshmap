use crate::models::ParsedHostMetadata;
use std::collections::BTreeMap;

pub fn parse_host_metadata(content: &str, host_id: i64) -> Option<ParsedHostMetadata> {
    let values = parse_key_values(content);
    let os_family = values
        .get("ID")
        .cloned()
        .or_else(|| {
            values
                .get("ID_LIKE")
                .and_then(|value| value.split_whitespace().next())
                .map(str::to_string)
        })
        .or_else(|| parse_uname(content));
    let os_version = values
        .get("PRETTY_NAME")
        .cloned()
        .or_else(|| values.get("VERSION_ID").cloned());

    if os_family.is_none() && os_version.is_none() {
        return None;
    }

    Some(ParsedHostMetadata {
        host_id,
        os_family,
        os_version,
    })
}

fn parse_key_values(content: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_string(), unquote(value.trim()));
    }
    values
}

fn unquote(value: &str) -> String {
    value
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn parse_uname(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.trim().strip_prefix("SSHMAP_UNAME="))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.split_whitespace().next())
        .map(|value| value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_os_release_metadata() {
        let metadata = parse_host_metadata(
            "ID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\nSSHMAP_UNAME=Linux x86_64",
            7,
        )
        .expect("metadata");

        assert_eq!(metadata.host_id, 7);
        assert_eq!(metadata.os_family.as_deref(), Some("ubuntu"));
        assert_eq!(metadata.os_version.as_deref(), Some("Ubuntu 24.04 LTS"));
    }
}
