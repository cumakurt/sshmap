#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileSection {
    pub source_file: String,
    pub content: String,
}

pub fn split_file_sections(content: &str, default_source_file: &str) -> Vec<FileSection> {
    let mut sections = Vec::new();
    let mut current_source = default_source_file.to_string();
    let mut current_lines = Vec::new();

    for line in content.lines() {
        if let Some(source_file) = parse_source_marker(line) {
            push_section(&mut sections, &current_source, &current_lines);
            current_source = source_file;
            current_lines.clear();
        } else {
            current_lines.push(line.to_string());
        }
    }

    push_section(&mut sections, &current_source, &current_lines);
    sections
}

pub fn strip_inline_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..index],
            _ => {}
        }
    }
    line
}

fn parse_source_marker(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let prefix = "--- SSHMAP_FILE:";
    let suffix = " ---";

    trimmed
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn push_section(sections: &mut Vec<FileSection>, source_file: &str, lines: &[String]) {
    let content = lines.join("\n");
    if content.trim().is_empty() {
        return;
    }

    sections.push(FileSection {
        source_file: source_file.to_string(),
        content,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_marked_file_sections() {
        let sections = split_file_sections(
            "first\n--- SSHMAP_FILE:/etc/example.conf ---\nsecond\n",
            "default",
        );

        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].source_file, "default");
        assert_eq!(sections[1].source_file, "/etc/example.conf");
    }

    #[test]
    fn strips_comments_outside_quotes() {
        assert_eq!(
            strip_inline_comment("PermitRootLogin yes # comment"),
            "PermitRootLogin yes "
        );
        assert_eq!(
            strip_inline_comment("Command \"#keep\" # drop"),
            "Command \"#keep\" "
        );
    }
}
