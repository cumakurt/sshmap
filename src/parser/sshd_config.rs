use crate::models::ParsedSshdConfigEntry;
use crate::parser::common::strip_inline_comment;

pub fn parse_sshd_config(
    content: &str,
    host_id: i64,
    source_file: &str,
) -> Vec<ParsedSshdConfigEntry> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| parse_config_line(line, host_id, source_file, index + 1))
        .collect()
}

fn parse_config_line(
    line: &str,
    host_id: i64,
    source_file: &str,
    line_number: usize,
) -> Option<ParsedSshdConfigEntry> {
    let trimmed = strip_inline_comment(line).trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let key = parts.next()?;
    let value = parts.collect::<Vec<_>>().join(" ");

    Some(ParsedSshdConfigEntry {
        host_id,
        key: key.to_string(),
        value: if value.is_empty() { None } else { Some(value) },
        source_file: source_file.to_string(),
        line_number: line_number as i64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config_entries_and_ignores_comments() {
        let entries = parse_sshd_config(
            "PermitRootLogin yes # risky\n# ignored\nPasswordAuthentication no",
            1,
            "/etc/ssh/sshd_config",
        );

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "PermitRootLogin");
        assert_eq!(entries[0].value.as_deref(), Some("yes"));
    }
}
