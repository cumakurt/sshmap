use crate::models::{ParsedAuthorizedKey, ParsedPublicKey};
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use sha2::{Digest, Sha256};

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

pub fn parse_authorized_keys(
    content: &str,
    host_id: i64,
    username: &str,
    source_file: &str,
) -> Vec<ParsedAuthorizedKey> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            parse_authorized_key_line(line, host_id, username, source_file, index + 1).ok()
        })
        .collect()
}

pub fn username_from_authorized_keys_path(source_file: &str) -> Option<String> {
    if source_file == "/root/.ssh/authorized_keys" {
        return Some("root".to_string());
    }

    let parts = source_file.split('/').collect::<Vec<_>>();
    parts
        .windows(3)
        .find(|window| window[0] == "home" && window[2] == ".ssh")
        .map(|window| window[1].to_string())
}

fn parse_authorized_key_line(
    line: &str,
    host_id: i64,
    username: &str,
    source_file: &str,
    line_number: usize,
) -> Result<ParsedAuthorizedKey> {
    let trimmed = line.trim();
    anyhow::ensure!(
        !trimmed.is_empty() && !trimmed.starts_with('#'),
        "ignored line"
    );

    let tokens = split_authorized_key_tokens(trimmed);
    let key_index = tokens
        .iter()
        .position(|token| KEY_TYPES.contains(&token.as_str()))
        .ok_or_else(|| anyhow::anyhow!("missing key type"))?;
    let key_type = tokens[key_index].clone();
    let key_blob = tokens
        .get(key_index + 1)
        .ok_or_else(|| anyhow::anyhow!("missing key blob"))?
        .clone();
    let key_bytes = STANDARD.decode(&key_blob)?;
    let fingerprint_sha256 = format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(&key_bytes))
    );
    let comment = tokens
        .get(key_index + 2..)
        .map(|values| values.join(" "))
        .filter(|value| !value.is_empty());
    let options = if key_index == 0 {
        None
    } else {
        Some(tokens[..key_index].join(" "))
    };
    let option_value = options.as_deref().unwrap_or_default();
    let has_from_restriction = option_value.contains("from=");
    let has_command_restriction = option_value.contains("command=");
    let permits_pty = !option_value.contains("no-pty");
    let permits_port_forwarding = !option_value.contains("no-port-forwarding");
    let permits_agent_forwarding = !option_value.contains("no-agent-forwarding");
    let permits_x11_forwarding = !option_value.contains("no-X11-forwarding");

    Ok(ParsedAuthorizedKey {
        host_id,
        username: username.to_string(),
        public_key: ParsedPublicKey {
            key_type: key_type.clone(),
            fingerprint_sha256,
            key_comment: comment,
            normalized_public_key: format!("{key_type} {key_blob}"),
        },
        source_file: source_file.to_string(),
        line_number: line_number as i64,
        options,
        has_from_restriction,
        has_command_restriction,
        permits_pty,
        permits_port_forwarding,
        permits_agent_forwarding,
        permits_x11_forwarding,
    })
}

fn split_authorized_key_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for character in line.chars() {
        match character {
            '"' => {
                in_quotes = !in_quotes;
                current.push(character);
            }
            value if value.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            value => current.push(value),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKLr9KYUQzyPewIhS54TEK6cOP7th7NeGj1Z5VfK6LhN user@example";

    #[test]
    fn parses_restricted_authorized_key() {
        let keys = parse_authorized_keys(
            &format!("from=\"10.0.0.0/8\",no-pty {ED25519_KEY}"),
            1,
            "deploy",
            "/home/deploy/.ssh/authorized_keys",
        );

        assert_eq!(keys.len(), 1);
        assert!(keys[0].has_from_restriction);
        assert!(!keys[0].permits_pty);
        assert_eq!(keys[0].public_key.key_type, "ssh-ed25519");
    }

    #[test]
    fn extracts_username_from_home_path() {
        assert_eq!(
            username_from_authorized_keys_path("/home/deploy/.ssh/authorized_keys"),
            Some("deploy".to_string())
        );
    }
}
