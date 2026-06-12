use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScannedServerHostKey {
    pub key_type: String,
    pub fingerprint_sha256: String,
    pub public_key: String,
}

pub async fn scan_server_host_keys(
    host: &str,
    port: u16,
    timeout_duration: Duration,
) -> Vec<ScannedServerHostKey> {
    let address = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut command = Command::new("ssh-keyscan");
    command
        .arg("-p")
        .arg(port.to_string())
        .arg("-T")
        .arg("3")
        .arg("-t")
        .arg("rsa,ecdsa,ed25519")
        .arg(&address)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let output = match timeout(timeout_duration, command.output()).await {
        Ok(Ok(output)) => output,
        _ => return Vec::new(),
    };

    if !output.status.success() {
        return Vec::new();
    }

    parse_ssh_keyscan_output(&String::from_utf8_lossy(&output.stdout))
}

pub fn parse_ssh_keyscan_output(content: &str) -> Vec<ScannedServerHostKey> {
    let mut keys = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((_, key_type, public_key)) = parse_ssh_keyscan_line(trimmed) else {
            continue;
        };
        let fingerprint_sha256 = fingerprint_public_key(&public_key);
        keys.push(ScannedServerHostKey {
            key_type,
            fingerprint_sha256,
            public_key,
        });
    }
    keys
}

fn parse_ssh_keyscan_line(line: &str) -> Option<(String, String, String)> {
    let mut parts = line.split_whitespace();
    let host = parts.next()?.to_string();
    let key_type = parts.next()?.to_string();
    let public_key = parts.collect::<Vec<_>>().join(" ");
    if public_key.is_empty() {
        return None;
    }
    Some((host, key_type, public_key))
}

fn fingerprint_public_key(public_key: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use sha2::{Digest, Sha256};
    let blob = public_key.split_whitespace().nth(1).unwrap_or(public_key);
    let bytes = STANDARD.decode(blob).unwrap_or_default();
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(bytes))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_keyscan_line() {
        let keys = parse_ssh_keyscan_output(
            "[127.0.0.1]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIComment\n",
        );
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert!(keys[0].fingerprint_sha256.starts_with("SHA256:"));
    }
}
