pub mod commands;
pub mod local;
pub mod remote;

pub fn redact_sensitive_content(content: &str) -> (String, bool) {
    const PRIVATE_KEY_MARKERS: &[&str] = &[
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ];

    if PRIVATE_KEY_MARKERS
        .iter()
        .any(|marker| content.contains(marker))
    {
        return ("[redacted private key material]\n".to_string(), true);
    }

    (content.to_string(), false)
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
}
