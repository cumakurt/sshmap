use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SshMapConfig {
    pub database: Option<PathBuf>,
    pub runtime: Option<RuntimeConfig>,
    pub scan: Option<ScanConfig>,
    pub discover: Option<DiscoverConfig>,
    pub serve: Option<ServeConfig>,
    pub report: Option<ReportConfig>,
    pub risk_policy: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuntimeConfig {
    pub concurrency: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub max_targets: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScanConfig {
    pub user: Option<String>,
    pub key: Option<PathBuf>,
    pub sudo: Option<bool>,
    pub ports: Option<Vec<u16>>,
    pub concurrency: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub transport: Option<String>,
    pub strict_host_key_checking: Option<String>,
    pub known_hosts: Option<PathBuf>,
    pub connection_reuse: Option<bool>,
    pub proxy_jump: Option<String>,
    pub use_agent: Option<bool>,
    pub identity_agent: Option<PathBuf>,
    pub identities_only: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DiscoverConfig {
    pub ports: Option<Vec<u16>>,
    pub concurrency: Option<usize>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServeConfig {
    pub listen: Option<String>,
    pub read_only: Option<bool>,
    pub allow_write_api: Option<bool>,
    pub token: Option<String>,
    pub read_token: Option<String>,
    pub write_token: Option<String>,
    pub dashboard: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportConfig {
    pub default_format: Option<String>,
}

pub fn load_optional(path: Option<&Path>) -> Result<SshMapConfig> {
    let Some(path) = path else {
        return Ok(SshMapConfig::default());
    };

    let content = crate::security::read_text_file_limited(
        path,
        crate::security::MAX_CONFIG_FILE_BYTES,
        "config file",
    )?;
    serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse config file {}", path.display()))
}

pub fn discover_config(config: &SshMapConfig) -> DiscoverConfig {
    config.discover.clone().unwrap_or_default()
}

pub fn scan_config(config: &SshMapConfig) -> ScanConfig {
    config.scan.clone().unwrap_or_default()
}

pub fn serve_config(config: &SshMapConfig) -> ServeConfig {
    config.serve.clone().unwrap_or_default()
}

pub fn resolve_dashboard_dir(config: &SshMapConfig, cli_path: Option<&Path>) -> Option<PathBuf> {
    cli_path.map(Path::to_path_buf).or_else(|| {
        config
            .serve
            .as_ref()
            .and_then(|serve| serve.dashboard.clone())
    })
}

pub fn report_config(config: &SshMapConfig) -> ReportConfig {
    config.report.clone().unwrap_or_default()
}

pub fn runtime_config(config: &SshMapConfig) -> RuntimeConfig {
    config.runtime.clone().unwrap_or_default()
}

pub fn risk_policy_path(config: &SshMapConfig) -> Option<PathBuf> {
    config.risk_policy.clone()
}

pub fn resolve_database(config: &SshMapConfig, cli_value: &Path) -> PathBuf {
    config
        .database
        .clone()
        .unwrap_or_else(|| cli_value.to_path_buf())
}

pub fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

pub fn resolve_max_targets(config: &SshMapConfig, cli_value: Option<usize>) -> usize {
    cli_value
        .or_else(|| {
            config
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.max_targets)
        })
        .unwrap_or(crate::scope::DEFAULT_MAX_TARGETS)
}

pub fn resolve_scan_transport(
    config: &SshMapConfig,
    cli_value: Option<&str>,
) -> anyhow::Result<crate::transport::TransportKind> {
    if let Some(value) = cli_value {
        return crate::transport::TransportKind::parse(value);
    }

    if let Some(value) = config
        .scan
        .as_ref()
        .and_then(|scan| scan.transport.as_deref())
    {
        return crate::transport::TransportKind::parse(value);
    }

    Ok(crate::transport::TransportKind::OpenSsh)
}

pub fn resolve_strict_host_key_policy(
    config: &SshMapConfig,
    cli_strict: Option<&str>,
    cli_known_hosts: Option<&Path>,
) -> anyhow::Result<crate::transport::StrictHostKeyPolicy> {
    let scan = config.scan.as_ref();
    let known_hosts_file = crate::transport::resolve_known_hosts_file(
        scan.and_then(|scan| scan.known_hosts.as_deref()),
        cli_known_hosts,
    );
    crate::transport::resolve_strict_host_key_policy(
        scan.and_then(|scan| scan.strict_host_key_checking.as_deref()),
        cli_strict,
        known_hosts_file,
    )
}

pub fn resolve_connection_reuse(config: &SshMapConfig, disable_cli_flag: bool) -> bool {
    if disable_cli_flag {
        return false;
    }

    config
        .scan
        .as_ref()
        .and_then(|scan| scan.connection_reuse)
        .unwrap_or(true)
}

pub fn resolve_proxy_jump(
    config: &SshMapConfig,
    cli_value: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let value = cli_value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            config
                .scan
                .as_ref()
                .and_then(|scan| scan.proxy_jump.as_deref())
        })
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(value) = value {
        validate_proxy_jump(value)?;
        Ok(Some(value.to_string()))
    } else {
        Ok(None)
    }
}

pub fn validate_proxy_jump(value: &str) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > 512 {
        anyhow::bail!("proxy jump value must be between 1 and 512 characters");
    }

    crate::transport::proxy_jump::parse_proxy_jump_chain(value, "sshmap")?;

    Ok(())
}

pub fn resolve_scan_auth(
    config: &SshMapConfig,
    cli_key: Option<PathBuf>,
    cli_use_agent: bool,
    cli_identity_agent: Option<&Path>,
    cli_identities_only: Option<bool>,
) -> anyhow::Result<crate::transport::ScanAuth> {
    let scan = config.scan.as_ref();
    let use_agent = cli_use_agent || scan.and_then(|scan| scan.use_agent).unwrap_or(false);
    let identity_file = cli_key.or_else(|| scan.and_then(|scan| scan.key.clone()));
    let agent_socket = cli_identity_agent
        .map(Path::to_path_buf)
        .or_else(|| scan.and_then(|scan| scan.identity_agent.clone()));

    let identities_only = resolve_identities_only(
        config,
        cli_identities_only,
        identity_file.is_some(),
        use_agent,
    );

    if identities_only && identity_file.is_none() {
        anyhow::bail!("--identities-only requires --key or scan.key in config");
    }

    let auth = crate::transport::ScanAuth {
        identity_file,
        use_agent,
        agent_socket,
        identities_only,
    };

    if !auth.has_identity_source() {
        anyhow::bail!(
            "scan requires an identity source; set --key, --agent, scan.key, or scan.use_agent in config"
        );
    }

    Ok(auth)
}

pub fn resolve_identities_only(
    config: &SshMapConfig,
    cli_value: Option<bool>,
    has_identity_file: bool,
    use_agent: bool,
) -> bool {
    if let Some(value) = cli_value {
        return value;
    }

    if let Some(value) = config.scan.as_ref().and_then(|scan| scan.identities_only) {
        return value;
    }

    has_identity_file && !use_agent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let config = load_optional(Some(Path::new("examples/sshmap.yaml"))).unwrap();
        assert_eq!(config.database.as_deref(), Some(Path::new("sshmap.db")));
        assert_eq!(
            config.scan.as_ref().unwrap().user.as_deref(),
            Some("audituser")
        );
    }

    #[test]
    fn formats_port_list() {
        assert_eq!(format_ports(&[22, 2222]), "22,2222");
    }

    #[test]
    fn connection_reuse_defaults_to_enabled() {
        let config = load_optional(Some(Path::new("examples/sshmap.yaml"))).unwrap();
        assert_eq!(
            resolve_connection_reuse(&config, false),
            config.scan.as_ref().unwrap().connection_reuse.unwrap()
        );
        assert!(!resolve_connection_reuse(&config, true));
    }

    #[test]
    fn validates_proxy_jump_chain() {
        validate_proxy_jump("bastion.example.com").unwrap();
        validate_proxy_jump("jump1.example.com,jump2.example.com").unwrap();
        assert!(validate_proxy_jump("").is_err());
        assert!(validate_proxy_jump("bad hop").is_err());
        assert!(validate_proxy_jump(":22").is_err());
        assert!(validate_proxy_jump("bad user@bastion.example.com").is_err());
    }

    #[test]
    fn resolves_scan_auth_from_agent_flag() {
        let auth = resolve_scan_auth(&SshMapConfig::default(), None, true, None, None).unwrap();
        assert!(auth.use_agent);
        assert!(auth.identity_file.is_none());
        assert!(!auth.identities_only);
    }

    #[test]
    fn identities_only_defaults_when_key_without_agent() {
        let auth = resolve_scan_auth(
            &SshMapConfig::default(),
            Some(PathBuf::from("/tmp/audit.key")),
            false,
            None,
            None,
        )
        .unwrap();
        assert!(auth.identities_only);
    }

    #[test]
    fn identities_only_disabled_when_agent_enabled() {
        let auth = resolve_scan_auth(
            &SshMapConfig::default(),
            Some(PathBuf::from("/tmp/audit.key")),
            true,
            None,
            None,
        )
        .unwrap();
        assert!(!auth.identities_only);
    }
}
