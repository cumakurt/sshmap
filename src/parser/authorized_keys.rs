use crate::models::{ParsedAuthorizedKey, ParsedPublicKey};
use anyhow::Result;
use std::collections::BTreeMap;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use sha2::{Digest, Sha256};

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-ed25519-cert-v01@openssh.com",
    "ssh-rsa",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss",
    "ssh-dss-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
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

    let (certificate_signing_ca, certificate_valid_after, certificate_valid_before) =
        if key_type.ends_with("-cert-v01@openssh.com") {
            let metadata = parse_certificate_metadata(&key_bytes);
            (
                metadata.signing_ca_fingerprint,
                Some(metadata.valid_after as i64),
                Some(metadata.valid_before as i64),
            )
        } else {
            (None, None, None)
        };

    Ok(ParsedAuthorizedKey {
        host_id,
        username: username.to_string(),
        public_key: ParsedPublicKey {
            key_type: key_type.clone(),
            fingerprint_sha256,
            key_bits: key_bits(&key_type, &key_bytes),
            key_comment: comment,
            normalized_public_key: format!("{key_type} {key_blob}"),
            certificate_signing_ca,
            certificate_valid_after,
            certificate_valid_before,
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

struct CertificateMetadata {
    signing_ca_fingerprint: Option<String>,
    valid_after: u64,
    valid_before: u64,
}

fn parse_certificate_metadata(cert_bytes: &[u8]) -> CertificateMetadata {
    let mut cursor = KeyBlobCursor::new(cert_bytes);
    let mut metadata = CertificateMetadata {
        signing_ca_fingerprint: None,
        valid_after: 0,
        valid_before: 0,
    };
    if cursor.read_string().is_err() {
        return metadata;
    }
    if cursor.read_string().is_err() {
        return metadata;
    }
    metadata.valid_after = cursor.read_u64().unwrap_or(0);
    if cursor.read_u32().is_err() {
        return metadata;
    }
    if cursor.read_string().is_err() {
        return metadata;
    }
    if cursor.read_string_list().is_err() {
        return metadata;
    }
    metadata.valid_before = cursor.read_u64().unwrap_or(0);
    let _ = cursor.read_u64();
    let _ = cursor.read_options();
    let _ = cursor.read_options();
    let _ = cursor.read_string();
    if let Ok(signing_key_bytes) = cursor.read_bytes() {
        if !signing_key_bytes.is_empty() {
            metadata.signing_ca_fingerprint = Some(format!(
                "SHA256:{}",
                STANDARD_NO_PAD.encode(Sha256::digest(signing_key_bytes))
            ));
        }
    }
    metadata
}

fn key_bits(key_type: &str, key_bytes: &[u8]) -> Option<i64> {
    let mut cursor = KeyBlobCursor::new(key_bytes);
    let blob_key_type = cursor.read_string().ok()?;
    if blob_key_type != key_type {
        return None;
    }

    match key_type {
        "ssh-rsa" => {
            cursor.read_mpint().ok()?;
            cursor.read_mpint().ok().map(mpint_bits)
        }
        "ssh-dss" => cursor.read_mpint().ok().map(mpint_bits),
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => Some(256),
        "ecdsa-sha2-nistp256" | "sk-ecdsa-sha2-nistp256@openssh.com" => Some(256),
        "ecdsa-sha2-nistp384" => Some(384),
        "ecdsa-sha2-nistp521" => Some(521),
        _ if key_type.ends_with("-cert-v01@openssh.com") => None,
        _ => None,
    }
}

struct KeyBlobCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> KeyBlobCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    fn read_mpint(&mut self) -> Result<&'a [u8]> {
        self.read_bytes()
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_bytes()?;
        let mut value = [0_u8; 8];
        let start = 8usize.saturating_sub(bytes.len());
        value[start..].copy_from_slice(bytes);
        Ok(u64::from_be_bytes(value))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes()?;
        let mut value = [0_u8; 4];
        let start = 4usize.saturating_sub(bytes.len());
        value[start..].copy_from_slice(bytes);
        Ok(u32::from_be_bytes(value))
    }

    fn read_string_list(&mut self) -> Result<Vec<String>> {
        let count = self.read_u32()? as usize;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.read_string()?);
        }
        Ok(values)
    }

    fn read_options(&mut self) -> Result<BTreeMap<String, String>> {
        let count = self.read_u32()? as usize;
        let mut options = BTreeMap::new();
        for _ in 0..count {
            let key = self.read_string()?;
            let value = self.read_string()?;
            options.insert(key, value);
        }
        Ok(options)
    }

    fn read_bytes(&mut self) -> Result<&'a [u8]> {
        anyhow::ensure!(self.offset + 4 <= self.bytes.len(), "truncated key blob");
        let len = u32::from_be_bytes(
            self.bytes[self.offset..self.offset + 4]
                .try_into()
                .map_err(|_| anyhow::anyhow!("truncated key blob length"))?,
        ) as usize;
        self.offset += 4;
        anyhow::ensure!(
            self.offset + len <= self.bytes.len(),
            "truncated key blob field"
        );
        let value = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(value)
    }
}

fn mpint_bits(value: &[u8]) -> i64 {
    let value = value
        .iter()
        .skip_while(|byte| **byte == 0)
        .copied()
        .collect::<Vec<_>>();
    let Some(first) = value.first() else {
        return 0;
    };
    ((value.len() - 1) * 8 + (8 - first.leading_zeros() as usize)) as i64
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
