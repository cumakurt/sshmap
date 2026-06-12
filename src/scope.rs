use crate::error::SshMapError;
use crate::target::normalize_scope_target;
use anyhow::{Context, Result};
use ipnet::IpNet;
use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub const DEFAULT_MAX_TARGETS: usize = 65_536;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct TargetEndpoint {
    pub host: String,
    pub port: u16,
}

pub fn load_target_endpoints(
    inline_targets: Option<&str>,
    file_path: Option<&Path>,
    ports: &str,
) -> Result<Vec<TargetEndpoint>> {
    let ports = parse_ports(ports)?;
    let mut target_values = Vec::new();

    if let Some(value) = inline_targets {
        target_values.extend(parse_inline_targets(value));
    }

    if let Some(path) = file_path {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read target file {}", path.display()))?;
        target_values.extend(parse_target_file_content(&content));
    }

    if target_values.is_empty() {
        return Err(SshMapError::NoTargets.into());
    }

    expand_targets(&target_values, &ports)
}

pub fn enforce_max_targets(
    endpoints: Vec<TargetEndpoint>,
    max_targets: usize,
) -> Result<Vec<TargetEndpoint>> {
    if endpoints.len() > max_targets {
        return Err(SshMapError::TooManyTargets {
            count: endpoints.len(),
            max: max_targets,
        }
        .into());
    }

    Ok(endpoints)
}

pub fn parse_ports(value: &str) -> Result<Vec<u16>> {
    let mut ports = BTreeSet::new();

    for raw_part in value.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }

        let port = part
            .parse::<u16>()
            .map_err(|_| SshMapError::InvalidPort(part.to_string()))?;
        ports.insert(port);
    }

    if ports.is_empty() {
        return Err(SshMapError::InvalidPort(value.to_string()).into());
    }

    Ok(ports.into_iter().collect())
}

fn parse_inline_targets(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_target_file_content(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| line.split('#').next())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn expand_targets(targets: &[String], ports: &[u16]) -> Result<Vec<TargetEndpoint>> {
    let mut endpoints = BTreeSet::new();

    for target in targets {
        let hosts = expand_target(target)?;
        for host in hosts {
            for port in ports {
                endpoints.insert(TargetEndpoint {
                    host: host.clone(),
                    port: *port,
                });
            }
        }
    }

    Ok(endpoints.into_iter().collect())
}

fn expand_target(target: &str) -> Result<Vec<String>> {
    let normalized = normalize_scope_target(target)?;

    if let Ok(ip_net) = normalized.parse::<IpNet>() {
        return Ok(ip_net.hosts().map(|ip| ip.to_string()).collect());
    }

    if normalized.parse::<IpAddr>().is_ok() {
        return Ok(vec![normalized]);
    }

    if is_valid_hostname_like_value(&normalized) {
        return Ok(vec![normalized]);
    }

    Err(SshMapError::InvalidTarget(target.to_string()).into())
}

fn is_valid_hostname_like_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comma_separated_ports() {
        assert_eq!(parse_ports("22,2222, 2200").unwrap(), vec![22, 2200, 2222]);
    }

    #[test]
    fn rejects_invalid_ports() {
        assert!(parse_ports("22,not-a-port").is_err());
    }

    #[test]
    fn parses_target_file_content_with_comments() {
        let targets = parse_target_file_content(
            "
            # comment
            10.0.0.1
            web01.local # inline comment
            ",
        );

        assert_eq!(targets, vec!["10.0.0.1", "web01.local"]);
    }

    #[test]
    fn expands_cidr_targets() {
        let endpoints = load_target_endpoints(Some("192.0.2.0/30"), None, "22").unwrap();
        let hosts = endpoints
            .iter()
            .map(|endpoint| endpoint.host.as_str())
            .collect::<Vec<_>>();

        assert_eq!(hosts, vec!["192.0.2.1", "192.0.2.2"]);
    }

    #[test]
    fn expands_multiple_ports() {
        let endpoints = load_target_endpoints(Some("web01.local"), None, "22,2222").unwrap();

        assert_eq!(
            endpoints,
            vec![
                TargetEndpoint {
                    host: "web01.local".to_string(),
                    port: 22,
                },
                TargetEndpoint {
                    host: "web01.local".to_string(),
                    port: 2222,
                },
            ]
        );
    }

    #[test]
    fn expands_large_target_sets_without_error() {
        let endpoints = load_target_endpoints(Some("10.0.0.0/22"), None, "22").unwrap();
        assert!(endpoints.len() >= 1000);
    }

    #[test]
    fn rejects_overly_large_target_sets() {
        let endpoints = (0..3)
            .map(|index| TargetEndpoint {
                host: format!("10.0.0.{index}"),
                port: 22,
            })
            .collect::<Vec<_>>();

        assert!(enforce_max_targets(endpoints, 2).is_err());
    }

    #[test]
    fn expands_bracketed_ipv6_targets() {
        let endpoints = load_target_endpoints(Some("[2001:db8::1]"), None, "22").unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].host, "2001:db8::1");
    }
}
