use crate::models::ParsedSshClientConfigEntry;
use crate::parser::common::strip_inline_comment;

pub fn parse_ssh_config(
    content: &str,
    host_id: i64,
    source_file: &str,
) -> Vec<ParsedSshClientConfigEntry> {
    let mut entries = Vec::new();
    let mut current_host = "*".to_string();

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = (index + 1) as i64;
        let line = strip_inline_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = line.split_once([' ', '\t']) else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('"').to_string();

        if key == "host" {
            current_host = value;
            continue;
        }

        let entry = ParsedSshClientConfigEntry {
            host_id,
            host_pattern: current_host.clone(),
            hostname: None,
            ssh_user: None,
            port: None,
            identity_file: None,
            proxy_jump: None,
            proxy_command: None,
            forward_agent: None,
            local_forward: None,
            remote_forward: None,
            dynamic_forward: None,
            strict_host_key_checking: None,
            include_file: None,
            source_file: source_file.to_string(),
            line_number,
        };

        let mut entry = entry;
        match key.as_str() {
            "hostname" => entry.hostname = Some(value),
            "user" => entry.ssh_user = Some(value),
            "port" => entry.port = value.parse().ok(),
            "identityfile" => entry.identity_file = Some(value),
            "proxyjump" => entry.proxy_jump = Some(value),
            "proxycommand" => entry.proxy_command = Some(value),
            "forwardagent" => entry.forward_agent = Some(value),
            "localforward" => entry.local_forward = Some(value),
            "remoteforward" => entry.remote_forward = Some(value),
            "dynamicforward" => entry.dynamic_forward = Some(value),
            "stricthostkeychecking" => entry.strict_host_key_checking = Some(value),
            "include" => entry.include_file = Some(value),
            _ => continue,
        };
        entries.push(entry);
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_jump_and_forward_agent() {
        let entries = parse_ssh_config(
            "Host *\n  ForwardAgent yes\nHost db01\n  HostName db01.internal\n  ProxyJump bastion\n",
            1,
            "/home/user/.ssh/config",
        );

        assert!(
            entries
                .iter()
                .any(|entry| entry.forward_agent.as_deref() == Some("yes"))
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.proxy_jump.as_deref() == Some("bastion"))
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.hostname.as_deref() == Some("db01.internal"))
        );
    }

    #[test]
    fn records_include_directives() {
        let entries = parse_ssh_config(
            "Include ~/.ssh/conf.d/*.conf\n",
            1,
            "/home/user/.ssh/config",
        );

        assert_eq!(
            entries[0].include_file.as_deref(),
            Some("~/.ssh/conf.d/*.conf")
        );
    }
}
