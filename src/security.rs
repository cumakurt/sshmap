use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::path::Path;

const MAX_FINGERPRINT_BYTES: usize = 256;
const MAX_RISK_CODE_BYTES: usize = 256;
const MAX_EXCEPTION_REASON_BYTES: usize = 512;

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

pub fn validate_risk_code(code: &str) -> Result<()> {
    let code = code.trim();
    if code.is_empty() {
        bail!("risk code cannot be empty");
    }
    if code.len() > MAX_RISK_CODE_BYTES {
        bail!("risk code is too long");
    }
    if !code.chars().all(|character| {
        character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
    }) {
        bail!("risk code must contain only A-Z, 0-9, and underscore");
    }
    Ok(())
}

pub fn validate_exception_reason(reason: &str) -> Result<()> {
    let reason = reason.trim();
    if reason.is_empty() {
        bail!("exception reason cannot be empty");
    }
    if reason.len() > MAX_EXCEPTION_REASON_BYTES {
        bail!("exception reason is too long");
    }
    if reason.chars().any(char::is_control) {
        bail!("exception reason cannot contain control characters");
    }
    Ok(())
}

pub fn validate_new_risk_exception(exception: &crate::models::NewRiskException) -> Result<()> {
    validate_risk_code(&exception.risk_code)?;
    validate_exception_reason(&exception.reason)?;
    validate_exception_username(exception.username.as_deref())?;
    validate_exception_fingerprint(exception.public_key_fingerprint.as_deref())?;
    validate_exception_expires_at(exception.expires_at.as_deref())?;
    Ok(())
}

pub fn webhook_database_label(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("sshmap.db")
        .to_string()
}

pub fn validate_exception_username(username: Option<&str>) -> Result<()> {
    let Some(username) = username else {
        return Ok(());
    };
    let username = username.trim();
    if username.is_empty() {
        bail!("exception username cannot be empty");
    }
    crate::transport::auth::validate_ssh_username(username).map_err(|error| anyhow::anyhow!(error))
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
    if is_localhost_hostname(host) || host == "0.0.0.0" {
        return true;
    }
    if host == "metadata.google.internal"
        || host.ends_with(".internal")
        || host == "metadata.azure.com"
        || host.ends_with(".metadata.azure.com")
    {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_non_public_ip(ip);
    }
    false
}

#[derive(Debug, Clone)]
pub struct WebhookEndpoint {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub allow_localhost_only: bool,
}

pub fn parse_webhook_endpoint(url: &str) -> Result<WebhookEndpoint> {
    validate_webhook_url(url)?;
    let trimmed = url.trim();
    let (scheme, authority) = if let Some(rest) = trimmed.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        ("http", rest)
    } else {
        bail!("webhook URL must use https:// (or http:// for localhost only)");
    };

    let host = extract_url_host(authority)?;
    let port = extract_url_port(authority, scheme == "https")?;
    let path_and_query = authority
        .split_once('/')
        .map(|(_, remainder)| remainder)
        .unwrap_or("");
    let request_url = build_webhook_request_url(scheme, &host, port, path_and_query);
    Ok(WebhookEndpoint {
        url: request_url,
        host,
        port,
        allow_localhost_only: scheme == "http",
    })
}

fn build_webhook_request_url(scheme: &str, host: &str, port: u16, path_and_query: &str) -> String {
    let default_port = if scheme == "https" { 443 } else { 80 };
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let authority = if port == default_port {
        authority
    } else {
        format!("{authority}:{port}")
    };
    if path_and_query.is_empty() {
        format!("{scheme}://{authority}")
    } else {
        format!("{scheme}://{authority}/{path_and_query}")
    }
}

pub async fn resolve_webhook_addresses(
    endpoint: &WebhookEndpoint,
) -> Result<Vec<std::net::SocketAddr>> {
    let lookup = format!("{}:{}", endpoint.host, endpoint.port);
    let mut addresses = tokio::net::lookup_host(&lookup)
        .await
        .with_context(|| format!("failed to resolve webhook host {}", endpoint.host))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        bail!("webhook host did not resolve to any address");
    }

    for address in &addresses {
        let ip = address.ip();
        if endpoint.allow_localhost_only {
            if !is_loopback_ip(ip) {
                bail!("http webhook host must resolve to loopback addresses only");
            }
        } else if is_non_public_ip(ip) {
            bail!("webhook host resolves to non-public address");
        }
    }

    addresses.sort_by_key(|address| address.ip());
    addresses.dedup_by(|left, right| left.ip() == right.ip() && left.port() == right.port());
    Ok(addresses)
}

fn extract_url_port(authority: &str, is_https: bool) -> Result<u16> {
    let authority = authority.split('/').next().unwrap_or(authority);
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, value)| value)
        .unwrap_or(authority);
    if let Some((host, port)) = host_port.rsplit_once(':')
        && port.parse::<u16>().is_ok()
        && (host.starts_with('[') || !host.contains(':'))
    {
        return port
            .parse()
            .with_context(|| format!("invalid webhook port: {port}"));
    }
    Ok(if is_https { 443 } else { 80 })
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

pub fn is_non_public_ip(ip: IpAddr) -> bool {
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

    #[test]
    fn validates_risk_exception_fields() {
        validate_new_risk_exception(&crate::models::NewRiskException {
            risk_code: "SSH_PASSWORD_AUTH_ENABLED".to_string(),
            host_id: None,
            username: Some("deploy".to_string()),
            public_key_fingerprint: None,
            reason: "accepted risk".to_string(),
            expires_at: None,
        })
        .unwrap();
        assert!(
            validate_new_risk_exception(&crate::models::NewRiskException {
                risk_code: "bad code".to_string(),
                host_id: None,
                username: None,
                public_key_fingerprint: None,
                reason: "accepted".to_string(),
                expires_at: None,
            })
            .is_err()
        );
    }

    #[test]
    fn webhook_database_label_uses_basename_only() {
        assert_eq!(
            webhook_database_label(Path::new("/var/lib/sshmap/prod.db")),
            "prod.db"
        );
    }

    #[test]
    fn rejects_zero_ipv4_webhook_target() {
        assert!(validate_webhook_url("https://0.0.0.0/hook").is_err());
    }

    #[test]
    fn parses_webhook_endpoint_port() {
        let endpoint = parse_webhook_endpoint("https://hooks.example.com:8443/sshmap").unwrap();
        assert_eq!(endpoint.host, "hooks.example.com");
        assert_eq!(endpoint.port, 8443);
        assert_eq!(endpoint.url, "https://hooks.example.com:8443/sshmap");
        assert!(!endpoint.allow_localhost_only);
    }

    #[test]
    fn strips_webhook_url_credentials_from_request_url() {
        let endpoint =
            parse_webhook_endpoint("https://user:secret@hooks.example.com/sshmap").unwrap();
        assert_eq!(endpoint.url, "https://hooks.example.com/sshmap");
        assert!(!endpoint.url.contains("secret"));
        assert!(!endpoint.url.contains('@'));
    }

    #[tokio::test]
    async fn resolves_localhost_http_webhook_to_loopback() {
        let endpoint = parse_webhook_endpoint("http://127.0.0.1:9/hook").unwrap();
        let addresses = resolve_webhook_addresses(&endpoint).await.unwrap();
        assert!(addresses.iter().all(|address| is_loopback_ip(address.ip())));
    }
}
