pub mod commands;
pub mod local;
pub mod remote;

pub fn redact_sensitive_content(content: &str) -> (String, bool) {
    const PRIVATE_KEY_MARKERS: &[&str] = &[
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ];

    if PRIVATE_KEY_MARKERS
        .iter()
        .any(|marker| content.contains(marker))
    {
        return ("[redacted private key material]\n".to_string(), true);
    }

    let mut redacted = false;
    let mut output = String::new();
    for line in content.lines() {
        if line_looks_like_secret_assignment(line) {
            output.push_str("[redacted sensitive value]\n");
            redacted = true;
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }

    if redacted {
        return (output, true);
    }

    (content.to_string(), false)
}

fn line_looks_like_secret_assignment(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("passwordauthentication")
        || lower.contains("challengeresponseauthentication")
        || lower.contains("permitrootlogin")
    {
        return false;
    }

    const SECRET_KEYS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "api-key",
        "access_key",
        "private_key",
        "token",
    ];

    SECRET_KEYS.iter().any(|key| {
        lower.contains(&format!("{key}="))
            || lower.contains(&format!("{key}:"))
            || lower.contains(&format!("{key} "))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_private_key_material() {
        let (content, redacted) =
            redact_sensitive_content("prefix\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret");

        assert!(redacted);
        assert_eq!(content, "[redacted private key material]\n");
    }

    #[test]
    fn redacts_secret_assignments_without_touching_sshd_directives() {
        let (content, redacted) = redact_sensitive_content(
            "PasswordAuthentication yes\nAPI_KEY=super-secret\nPermitRootLogin no\n",
        );

        assert!(redacted);
        assert!(content.contains("PasswordAuthentication yes"));
        assert!(content.contains("[redacted sensitive value]"));
        assert!(content.contains("PermitRootLogin no"));
        assert!(!content.contains("super-secret"));
    }
}
