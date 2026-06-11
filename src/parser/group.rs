use crate::models::ParsedGroup;

pub fn parse_group(content: &str, host_id: i64) -> Vec<ParsedGroup> {
    content
        .lines()
        .filter_map(|line| parse_group_line(line, host_id))
        .collect()
}

fn parse_group_line(line: &str, host_id: i64) -> Option<ParsedGroup> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let fields = trimmed.split(':').collect::<Vec<_>>();
    if fields.len() < 4 || fields[0].is_empty() {
        return None;
    }

    let members = fields[3]
        .split(',')
        .map(str::trim)
        .filter(|member| !member.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    Some(ParsedGroup {
        host_id,
        group_name: fields[0].to_string(),
        gid: fields[2].parse::<i64>().ok(),
        members,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_group_members() {
        let groups = parse_group("sudo:x:27:alice,bob", 2);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].members, vec!["alice", "bob"]);
    }
}
