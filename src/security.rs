use anyhow::{Context, Result, bail};
use reqwest::Url;
use std::net::IpAddr;
use std::path::Path;

const MAX_FINGERPRINT_BYTES: usize = 256;
const MAX_RISK_CODE_BYTES: usize = 256;
const MAX_EXCEPTION_REASON_BYTES: usize = 512;
const MAX_COMPLIANCE_FRAMEWORK_BYTES: usize = 32;
const MAX_BASELINE_NAME_BYTES: usize = 128;
const MAX_GRAPH_NODE_REFERENCE_BYTES: usize = 512;
const GRAPH_NODE_TYPES: &[&str] = &["host", "user", "key", "public_key", "sudo_rule"];
pub(crate) const MAX_CONFIG_FILE_BYTES: u64 = 1_048_576;
pub(crate) const MAX_TARGET_FILE_BYTES: u64 = 16 * 1_048_576;
pub(crate) const MAX_IMPORT_FILE_BYTES: u64 = 64 * 1_048_576;
pub(crate) const MAX_BUNDLE_TOTAL_BYTES: u64 = 512 * 1_048_576;
pub(crate) const MAX_BENCHMARK_FILE_BYTES: u64 = 16 * 1_048_576;

pub(crate) fn read_text_file_limited(
    path: &Path,
    max_bytes: u64,
    description: &str,
) -> Result<String> {
    validate_regular_file_size(path, max_bytes, description)?;
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {description} {}", path.display()))?;
    if content.len() as u64 > max_bytes {
        bail!(
            "{description} {} exceeds maximum size of {max_bytes} bytes",
            path.display()
        );
    }
    Ok(content)
}

pub(crate) fn validate_regular_file_size(
    path: &Path,
    max_bytes: u64,
    description: &str,
) -> Result<u64> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect {description} {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{description} is not a regular file: {}", path.display());
    }
    let size = metadata.len();
    if size > max_bytes {
        bail!(
            "{description} {} exceeds maximum size of {max_bytes} bytes",
            path.display()
        );
    }
    Ok(size)
}

pub fn validate_webhook_url(url: &str) -> Result<()> {
    let parsed = parse_webhook_url(url)?;

    if parsed.scheme == "http" {
        if !is_localhost_hostname(&parsed.host) {
            bail!("http webhook URLs are only allowed for localhost");
        }
        return Ok(());
    }

    if is_blocked_webhook_host(&parsed.host) {
        bail!("webhook URL host is not allowed");
    }

    Ok(())
}

pub fn validate_baseline_name(name: &str, allow_latest: bool) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        bail!("baseline name cannot be empty");
    }
    if name.len() > MAX_BASELINE_NAME_BYTES {
        bail!("baseline name is too long");
    }
    if name.chars().any(char::is_control) {
        bail!("baseline name cannot contain control characters");
    }
    if name.eq_ignore_ascii_case("latest") {
        if allow_latest {
            return Ok(());
        }
        bail!("latest is a reserved baseline name");
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        bail!(
            "baseline name must contain only ASCII letters, digits, hyphen, underscore, or period"
        );
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

pub fn validate_compliance_framework(framework: &str) -> Result<()> {
    let framework = framework.trim();
    if framework.is_empty() {
        return Ok(());
    }
    if framework.len() > MAX_COMPLIANCE_FRAMEWORK_BYTES {
        bail!("compliance framework parameter is too long");
    }
    if !framework
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
    {
        bail!("compliance framework parameter contains invalid characters");
    }
    Ok(())
}

pub fn validate_graph_node_reference(reference: &str) -> Result<()> {
    let reference = reference.trim();
    if reference.is_empty() {
        bail!("graph node reference cannot be empty");
    }
    if reference.len() > MAX_GRAPH_NODE_REFERENCE_BYTES {
        bail!("graph node reference is too long");
    }
    if reference.chars().any(char::is_control) {
        bail!("graph node reference cannot contain control characters");
    }

    let Some((node_type, value)) = reference.split_once(':') else {
        bail!("graph node reference must use type:value syntax");
    };
    if !GRAPH_NODE_TYPES.contains(&node_type) {
        bail!("unsupported graph node type: {node_type}");
    }

    let value = value.trim();
    if value.is_empty() {
        bail!("graph node value cannot be empty");
    }

    match node_type {
        "user" => {
            if let Some((username, host)) = value.split_once('@') {
                crate::transport::auth::validate_ssh_username(username.trim())
                    .map_err(|error| anyhow::anyhow!(error))?;
                if host.trim().is_empty() {
                    bail!("graph user reference host cannot be empty");
                }
            } else {
                crate::transport::auth::validate_ssh_username(value)
                    .map_err(|error| anyhow::anyhow!(error))?;
            }
        }
        "host" => {
            if value.parse::<i64>().is_err() {
                validate_import_host_identifier(value)?;
            }
        }
        "key" | "public_key" => validate_exception_fingerprint(Some(value))?,
        "sudo_rule" => {
            if value.parse::<i64>().is_err() && value.len() > MAX_FINGERPRINT_BYTES {
                bail!("sudo_rule reference is too long");
            }
        }
        _ => {}
    }

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

struct ParsedWebhookUrl {
    url: Url,
    scheme: String,
    host: String,
    port: u16,
}

fn parse_webhook_url(url: &str) -> Result<ParsedWebhookUrl> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        bail!("webhook URL cannot be empty");
    }
    if trimmed.contains(char::is_whitespace) {
        bail!("webhook URL cannot contain whitespace");
    }

    let parsed = Url::parse(trimmed).context("invalid webhook URL")?;
    let scheme = parsed.scheme().to_string();
    if scheme != "https" && scheme != "http" {
        bail!("webhook URL must use https:// (or http:// for localhost only)");
    }
    if parsed.cannot_be_a_base() {
        bail!("webhook URL must include an authority");
    }

    let host = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| anyhow::anyhow!("webhook URL host is missing"))?
        .trim_matches(|character| character == '[' || character == ']')
        .to_ascii_lowercase();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("webhook URL port is missing"))?;

    Ok(ParsedWebhookUrl {
        url: parsed,
        scheme,
        host,
        port,
    })
}

pub fn parse_webhook_endpoint(url: &str) -> Result<WebhookEndpoint> {
    validate_webhook_url(url)?;
    let parsed = parse_webhook_url(url)?;
    let mut request_url = parsed.url.clone();
    let _ = request_url.set_username("");
    let _ = request_url.set_password(None);
    request_url.set_fragment(None);
    Ok(WebhookEndpoint {
        url: request_url.to_string(),
        host: parsed.host,
        port: parsed.port,
        allow_localhost_only: parsed.scheme == "http",
    })
}

pub async fn resolve_webhook_addresses(
    endpoint: &WebhookEndpoint,
) -> Result<Vec<std::net::SocketAddr>> {
    let mut addresses = tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
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
    fn validates_compliance_framework_parameter() {
        validate_compliance_framework("CIS").unwrap();
        validate_compliance_framework("all").unwrap();
        assert!(validate_compliance_framework("bad framework").is_err());
        assert!(validate_compliance_framework(&"x".repeat(64)).is_err());
    }

    #[test]
    fn validates_import_host_identifier() {
        validate_import_host_identifier("web01.example.com").unwrap();
        validate_import_host_identifier("[2001:db8::1]:2222").unwrap();
        assert!(validate_import_host_identifier("bad host").is_err());
    }

    #[test]
    fn validates_graph_node_references() {
        validate_graph_node_reference("host:10.0.0.1").unwrap();
        validate_graph_node_reference("user:deploy@web01.example.com").unwrap();
        validate_graph_node_reference("key:SHA256:abcdef").unwrap();
        assert!(validate_graph_node_reference("bad").is_err());
        assert!(validate_graph_node_reference("host:").is_err());
        assert!(validate_graph_node_reference("unknown:1").is_err());
        assert!(validate_graph_node_reference("user:bad user@host").is_err());
    }

    #[test]
    fn validates_baseline_names() {
        validate_baseline_name("2026-q1-audit", false).unwrap();
        validate_baseline_name("latest", true).unwrap();
        assert!(validate_baseline_name("latest", false).is_err());
        assert!(validate_baseline_name("bad name", false).is_err());
        assert!(validate_baseline_name(&"x".repeat(256), false).is_err());
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
    fn limited_text_reader_rejects_oversized_regular_files() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("oversized.txt");
        let file = std::fs::File::create(&path).expect("file");
        file.set_len(MAX_CONFIG_FILE_BYTES + 1)
            .expect("set sparse file length");

        let error = read_text_file_limited(&path, MAX_CONFIG_FILE_BYTES, "config file")
            .expect_err("oversized file");

        assert!(error.to_string().contains("exceeds maximum size"));
    }

    #[test]
    fn rejects_zero_ipv4_webhook_target() {
        assert!(validate_webhook_url("https://0.0.0.0/hook").is_err());
    }

    #[test]
    fn rejects_invalid_webhook_port() {
        assert!(validate_webhook_url("https://hooks.example.com:99999/hook").is_err());
    }

    #[test]
    fn rejects_loopback_ipv6_webhook_target() {
        assert!(validate_webhook_url("https://[::1]/hook").is_err());
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
            parse_webhook_endpoint("https://user:secret@hooks.example.com/sshmap?x=1").unwrap();
        assert_eq!(endpoint.url, "https://hooks.example.com/sshmap?x=1");
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
