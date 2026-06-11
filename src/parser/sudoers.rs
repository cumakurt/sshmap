use crate::models::ParsedSudoRule;
use crate::parser::common::strip_inline_comment;

const DANGEROUS_BINARIES: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "vim",
    "vi",
    "less",
    "more",
    "find",
    "tar",
    "rsync",
    "python",
    "python3",
    "perl",
    "ruby",
    "awk",
    "sed",
    "scp",
    "ssh",
    "systemctl",
    "docker",
    "kubectl",
    "mysql",
    "psql",
];

pub fn parse_sudoers(content: &str, host_id: i64, source_file: &str) -> Vec<ParsedSudoRule> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| parse_sudoers_line(line, host_id, source_file, index + 1))
        .collect()
}

fn parse_sudoers_line(
    line: &str,
    host_id: i64,
    source_file: &str,
    line_number: usize,
) -> Option<ParsedSudoRule> {
    let trimmed = strip_inline_comment(line).trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("Defaults")
        || trimmed.starts_with("Cmnd_Alias")
        || trimmed.starts_with("User_Alias")
    {
        return None;
    }

    let subject = trimmed.split_whitespace().next()?;
    let subject_type = if subject.starts_with('%') {
        "group"
    } else {
        "user"
    };
    let run_as = extract_between(trimmed, '(', ')');
    let nopasswd = trimmed.contains("NOPASSWD");
    let command = extract_command(trimmed);
    let risk_level = classify_sudo_risk(nopasswd, command.as_deref());

    Some(ParsedSudoRule {
        host_id,
        subject: subject.trim_start_matches('%').to_string(),
        subject_type: subject_type.to_string(),
        run_as,
        command,
        tags: extract_tags(trimmed),
        nopasswd,
        source_file: source_file.to_string(),
        line_number: line_number as i64,
        risk_level,
    })
}

fn extract_between(line: &str, start: char, end: char) -> Option<String> {
    let start_index = line.find(start)?;
    let remaining = &line[start_index + 1..];
    let end_index = remaining.find(end)?;
    Some(remaining[..end_index].trim().to_string()).filter(|value| !value.is_empty())
}

fn extract_command(line: &str) -> Option<String> {
    line.rsplit_once(':')
        .map(|(_, command)| command.trim().to_string())
        .filter(|command| !command.is_empty())
}

fn extract_tags(line: &str) -> Option<String> {
    line.contains("NOPASSWD").then(|| "NOPASSWD".to_string())
}

fn classify_sudo_risk(nopasswd: bool, command: Option<&str>) -> Option<String> {
    let command = command?;
    if nopasswd && command == "ALL" {
        return Some("CRITICAL".to_string());
    }

    if nopasswd
        && DANGEROUS_BINARIES.iter().any(|binary| {
            command.split('/').any(|part| part == *binary) || command.contains(binary)
        })
    {
        return Some("HIGH".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nopasswd_all() {
        let rules = parse_sudoers("deploy ALL=(ALL) NOPASSWD:ALL", 3, "/etc/sudoers");

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].subject, "deploy");
        assert!(rules[0].nopasswd);
        assert_eq!(rules[0].risk_level.as_deref(), Some("CRITICAL"));
    }

    #[test]
    fn parses_group_subject() {
        let rules = parse_sudoers("%admin ALL=(ALL) ALL", 3, "/etc/sudoers");

        assert_eq!(rules[0].subject_type, "group");
        assert_eq!(rules[0].subject, "admin");
    }
}
