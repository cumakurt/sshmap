use crate::models::ParsedSshdMatchBlock;
use crate::parser::common::strip_inline_comment;

pub fn parse_sshd_match_blocks(
    content: &str,
    host_id: i64,
    source_file: &str,
) -> Vec<ParsedSshdMatchBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<ParsedSshdMatchBlock> = None;

    for (index, line) in content.lines().enumerate() {
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("match ") {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(ParsedSshdMatchBlock {
                host_id,
                source_file: source_file.to_string(),
                line_number: index as i64 + 1,
                criteria: trimmed[6..].trim().to_string(),
                directives: Vec::new(),
            });
            continue;
        }

        if let Some(block) = current.as_mut() {
            let mut parts = trimmed.split_whitespace();
            let key = parts.next().unwrap_or_default().to_string();
            let value = parts.collect::<Vec<_>>().join(" ");
            block.directives.push((key, value));
        }
    }

    if let Some(block) = current {
        blocks.push(block);
    }

    blocks
}
