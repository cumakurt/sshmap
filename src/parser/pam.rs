use crate::models::ParsedPamEntry;

pub fn parse_pam_config(content: &str, host_id: i64, source_file: &str) -> Vec<ParsedPamEntry> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| parse_pam_line(line, host_id, source_file, index + 1))
        .collect()
}

pub fn parse_nsswitch(content: &str, host_id: i64, source_file: &str) -> Vec<ParsedPamEntry> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut parts = trimmed.split_whitespace();
            let service = parts.next()?.to_string();
            let backends = parts.collect::<Vec<_>>().join(" ");
            Some(ParsedPamEntry {
                host_id,
                source_file: source_file.to_string(),
                line_number: index as i64 + 1,
                service,
                module_type: "nsswitch".to_string(),
                control: backends.clone(),
                module_path: backends,
            })
        })
        .collect()
}

fn parse_pam_line(
    line: &str,
    host_id: i64,
    source_file: &str,
    line_number: usize,
) -> Option<ParsedPamEntry> {
    let trimmed = line.split('#').next().unwrap_or("").trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let service = parts.next()?.to_string();
    let module_type = parts.next()?.to_string();
    let control = parts.next()?.to_string();
    let module_path = parts.collect::<Vec<_>>().join(" ");
    Some(ParsedPamEntry {
        host_id,
        source_file: source_file.to_string(),
        line_number: line_number as i64,
        service,
        module_type,
        control,
        module_path,
    })
}
