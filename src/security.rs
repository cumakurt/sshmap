use anyhow::{Context, Result, bail};
use std::net::IpAddr;

const MAX_FINGERPRINT_BYTES: usize = 256;

pub fn validate_webhook_url(url: &str) -> Result<()> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        bail!("webhook URL cannot be empty");
    }
    if trimmed.contains(char::is_whitespace) {
        bail!("webhook URL cannot contain whitespace");
    }

    let (scheme, authority) = if let Some(rest) = trimmed.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        ("http", rest)
    } else {
        bail!("webhook URL must use https:// (or http:// for localhost only)");
    };

    let host = extract_url_host(authority)?;
    if scheme == "http" {
        if !is_localhost_hostname(&host) {
            bail!("http webhook URLs are only allowed for localhost");
        }
        return Ok(());
    }

    if is_blocked_webhook_host(&host) {
        bail!("webhook URL host is not allowed");
    }

    Ok(())
}

pub fn validate_exception_username(username: Option<&str>) -> Result<()> {
    let Some(username) = username else {
        return Ok(());
    };
    let username = username.trim();
    if username.is_empty() {
        bail!("exception username cannot be empty");
    }
    crate::transport::auth::validate_ssh_username(username)
        .map_err(|error| anyhow::anyhow!(error))
}

pub fn validate_exception_fingerprint(fingerprint: Option<&str>) -> Result<()> {
    let Some(fingerprint) = fingerprint else {
        return Ok(());
    };
    let fingerprint = fingerprint.trim();
    if fingerprint.is_empty() {
        bail!("exception fingerprint cannot be empty");
    }
    if fingerprint.len() > MAX_FINGERPRINT_BYTES {
        bail!("exception fingerprint is too long");
    }
    if fingerprint.chars().any(char::is_control) {
        bail!("exception fingerprint cannot contain control characters");
    }
    Ok(())
}

pub fn validate_exception_expires_at(expires_at: Option<&str>) -> Result<()> {
    let Some(expires_at) = expires_at else {
        return Ok(());
    };
    let expires_at = expires_at.trim();
    if expires_at.is_empty() {
        return Ok(());
    }
    chrono::DateTime::parse_from_rfc3339(expires_at)
        .with_context(|| format!("expires_at must be RFC3339: {expires_at}"))?;
    Ok(())
}

pub fn validate_import_host_identifier(host: &str) -> Result<()> {
    let host = host.trim();
    if host.is_empty() {
        bail!("host identifier cannot be empty");
    }
    let (hostname, _) = crate::target::parse_host_port(host)?;
    if hostname.parse::<IpAddr>().is_ok() || crate::target::is_valid_connection_host(&hostname) {
        return Ok(());
    }
    bail!("invalid host identifier: {host}");
}

fn extract_url_host(authority: &str) -> Result<String> {
    let authority = authority.split('/').next().unwrap_or(authority);
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host_port)| host_port)
        .unwrap_or(authority);
    let host = authority
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|_| host))
        .unwrap_or(authority);
    let host = host.trim_matches(|character| character == '[' || character == ']');
    if host.is_empty() {
        bail!("webhook URL host is missing");
    }
    Ok(host.to_ascii_lowercase())
}

fn is_localhost_hostname(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_blocked_webhook_host(host: &str) -> bool {
    if is_localhost_hostname(host) {
        return true;
    }
    if host == "metadata.google.internal" || host.ends_with(".internal") {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_non_public_ip(ip);
    }
    false
}

fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_unspecified()
                || ipv4.is_broadcast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1])) // CGNAT
                || (octets[0] == 169 && octets[1] == 254) // link-local / metadata
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00 // unique local
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80 // link-local
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_https_webhook() {
        validate_webhook_url("https://hooks.example.com/sshmap").unwrap();
    }

    #[test]
    fn rejects_metadata_ssrf_target() {
        assert!(validate_webhook_url("https://169.254.169.254/latest/meta-data").is_err());
    }

    #[test]
    fn rejects_private_ip_webhook() {
        assert!(validate_webhook_url("https://10.0.0.5/hook").is_err());
    }

    #[test]
    fn allows_localhost_http_webhook() {
        validate_webhook_url("http://127.0.0.1:8080/hook").unwrap();
    }

    #[test]
    fn validates_import_host_identifier() {
        validate_import_host_identifier("web01.example.com").unwrap();
        validate_import_host_identifier("[2001:db8::1]:2222").unwrap();
        assert!(validate_import_host_identifier("bad host").is_err());
    }
}
