use crate::error::SshMapError;
use crate::target::normalize_scope_target;
use anyhow::{Context, Result};
use ipnet::IpNet;
use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
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
    content.lines().flat_map(parse_target_file_line).collect()
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
    if let Some(hosts) = expand_ipv4_range_target(target)? {
        return Ok(hosts);
    }

    if let Some(hosts) = expand_ipv4_wildcard_target(target)? {
        return Ok(hosts);
    }

    let normalized = normalize_scope_target(target)?;

    if let Ok(ip_net) = normalized.parse::<IpNet>() {
        return Ok(ip_net.hosts().map(|ip| ip.to_string()).collect());
    }

    if normalized.parse::<IpAddr>().is_ok() {
        return Ok(vec![normalized]);
    }

    if crate::target::is_valid_connection_host(&normalized) {
        return Ok(vec![normalized]);
    }

    Err(SshMapError::InvalidTarget(target.to_string()).into())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TargetCandidateSource {
    Plain,
    Extracted,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TargetCandidate {
    value: String,
    source: TargetCandidateSource,
}

fn parse_target_file_line(line: &str) -> Vec<String> {
    let line = line.split('#').next().map(str::trim).unwrap_or_default();
    if line.is_empty() {
        return Vec::new();
    }

    let tokens = split_target_line_tokens(line);
    if tokens.is_empty() {
        return Vec::new();
    }

    if let Some(hosts_entry) = parse_hosts_file_alias_line(&tokens) {
        return vec![hosts_entry];
    }

    let single_token_line = tokens.len() == 1;
    let mut targets = Vec::new();
    for token in tokens {
        for candidate in target_candidates_from_token(&token) {
            if !is_supported_file_target(&candidate, single_token_line) {
                continue;
            }
            if !targets.contains(&candidate.value) {
                targets.push(candidate.value);
            }
            break;
        }
    }

    targets
}

fn split_target_line_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0usize;

    for character in line.chars() {
        match character {
            '[' => {
                bracket_depth += 1;
                current.push(character);
            }
            ']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                current.push(character);
            }
            ',' | ';' if bracket_depth == 0 => push_target_token(&mut tokens, &mut current),
            character if character.is_whitespace() && bracket_depth == 0 => {
                push_target_token(&mut tokens, &mut current);
            }
            character => current.push(character),
        }
    }

    push_target_token(&mut tokens, &mut current);
    tokens
}

fn push_target_token(tokens: &mut Vec<String>, current: &mut String) {
    let token = current.trim();
    if !token.is_empty() {
        tokens.push(token.to_string());
    }
    current.clear();
}

fn parse_hosts_file_alias_line(tokens: &[String]) -> Option<String> {
    if tokens.len() < 2 {
        return None;
    }

    let first = target_candidates_from_token(&tokens[0])
        .into_iter()
        .find(|candidate| candidate_is_ip_literal(&candidate.value))?;

    if tokens[1..]
        .iter()
        .all(|token| token_is_plain_hostname_alias(token))
    {
        Some(first.value)
    } else {
        None
    }
}

fn token_is_plain_hostname_alias(token: &str) -> bool {
    let value = clean_target_token(token);
    !value.is_empty()
        && !value.contains([':', '/', '@', '='])
        && value.parse::<IpAddr>().is_err()
        && crate::target::is_valid_connection_host(&value)
}

fn target_candidates_from_token(token: &str) -> Vec<TargetCandidate> {
    let value = clean_target_token(token);
    if value.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    if let Some(host) = extract_uri_host_candidate(&value) {
        push_candidate(&mut candidates, host, TargetCandidateSource::Extracted);
    }
    if let Some((_key, raw_value)) = value.rsplit_once('=') {
        push_candidate(
            &mut candidates,
            clean_target_token(raw_value),
            TargetCandidateSource::Extracted,
        );
    }
    if let Some(raw_value) = extract_labeled_target_value(&value) {
        push_candidate(&mut candidates, raw_value, TargetCandidateSource::Extracted);
    }

    push_candidate(&mut candidates, value, TargetCandidateSource::Plain);
    candidates
}

fn push_candidate(
    candidates: &mut Vec<TargetCandidate>,
    value: String,
    source: TargetCandidateSource,
) {
    let value = clean_target_token(&value);
    if value.is_empty() || candidates.iter().any(|candidate| candidate.value == value) {
        return;
    }

    candidates.push(TargetCandidate { value, source });
}

fn clean_target_token(token: &str) -> String {
    let mut value = token.trim().trim_matches(['"', '\'', '`', ','].as_ref());

    loop {
        let trimmed = value
            .trim_start_matches(['(', '{', '<'].as_ref())
            .trim_end_matches([')', '}', '>', ',', ';'].as_ref());
        if trimmed.len() == value.len() {
            value = trimmed;
            break;
        }
        value = trimmed.trim();
    }

    value.trim_end_matches([',', ';'].as_ref()).to_string()
}

fn extract_uri_host_candidate(value: &str) -> Option<String> {
    let (_scheme, rest) = value.split_once("://")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    if authority.is_empty() {
        return None;
    }

    let host_port = authority
        .rsplit_once('@')
        .map(|(_user_info, host_port)| host_port)
        .unwrap_or(authority);

    extract_host_from_host_port(host_port)
}

fn extract_labeled_target_value(value: &str) -> Option<String> {
    let (label, raw_value) = value.split_once(':')?;
    if label.is_empty()
        || raw_value.is_empty()
        || !label.chars().all(|character| {
            character.is_ascii_alphabetic() || character == '_' || character == '-'
        })
    {
        return None;
    }

    let value = clean_target_token(raw_value);
    if target_looks_network_like(&value)
        || value.contains('.')
        || value.chars().any(|character| character.is_ascii_digit())
    {
        Some(value)
    } else {
        None
    }
}

fn extract_host_from_host_port(value: &str) -> Option<String> {
    let value = clean_target_token(value);
    if value.is_empty() {
        return None;
    }

    if value.starts_with('[') {
        let end = value.find(']')?;
        return Some(value[1..end].to_string());
    }

    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && port.parse::<u16>().is_ok()
    {
        return Some(host.to_string());
    }

    Some(value)
}

fn is_supported_file_target(candidate: &TargetCandidate, single_token_line: bool) -> bool {
    if target_looks_network_like(&candidate.value) {
        return true;
    }

    if normalize_scope_target(&candidate.value).is_err() {
        return false;
    }

    candidate.source == TargetCandidateSource::Extracted
        || single_token_line
        || candidate.value.contains('.')
        || candidate.value.contains('-')
        || candidate
            .value
            .chars()
            .any(|character| character.is_ascii_digit())
}

fn target_looks_network_like(value: &str) -> bool {
    candidate_is_ip_literal(value)
        || value.parse::<IpNet>().is_ok()
        || parse_ipv4_range_bounds(value).is_some()
        || parse_ipv4_wildcard_ranges(value).is_some()
}

fn candidate_is_ip_literal(value: &str) -> bool {
    normalize_scope_target(value)
        .ok()
        .and_then(|target| target.parse::<IpAddr>().ok())
        .is_some()
}

fn expand_ipv4_range_target(target: &str) -> Result<Option<Vec<String>>> {
    let Some((start, end)) = parse_ipv4_range_bounds(target) else {
        return Ok(None);
    };

    let start = u32::from(start);
    let end = u32::from(end);
    if end < start {
        return Err(SshMapError::InvalidTarget(target.to_string()).into());
    }

    let count = u64::from(end - start) + 1;
    if count > DEFAULT_MAX_TARGETS as u64 {
        return Err(SshMapError::TooManyTargets {
            count: usize::try_from(count).unwrap_or(usize::MAX),
            max: DEFAULT_MAX_TARGETS,
        }
        .into());
    }

    Ok(Some(
        (start..=end)
            .map(|value| Ipv4Addr::from(value).to_string())
            .collect(),
    ))
}

fn parse_ipv4_range_bounds(value: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let value = value.trim();
    let (start, end) = value.split_once("..").or_else(|| value.split_once('-'))?;
    let start = start.parse::<Ipv4Addr>().ok()?;
    let end = if end.contains('.') {
        end.parse::<Ipv4Addr>().ok()?
    } else {
        let last_octet = end.parse::<u8>().ok()?;
        let mut octets = start.octets();
        octets[3] = last_octet;
        Ipv4Addr::from(octets)
    };

    Some((start, end))
}

fn expand_ipv4_wildcard_target(target: &str) -> Result<Option<Vec<String>>> {
    let Some(ranges) = parse_ipv4_wildcard_ranges(target) else {
        return Ok(None);
    };

    let count = ranges
        .iter()
        .try_fold(1u64, |accumulator, (start, end)| {
            accumulator.checked_mul(u64::from(end - start) + 1)
        })
        .unwrap_or(u64::MAX);
    if count > DEFAULT_MAX_TARGETS as u64 {
        return Err(SshMapError::TooManyTargets {
            count: usize::try_from(count).unwrap_or(usize::MAX),
            max: DEFAULT_MAX_TARGETS,
        }
        .into());
    }

    let count = usize::try_from(count).unwrap_or(usize::MAX);
    let mut hosts = Vec::with_capacity(count);
    for first in ranges[0].0..=ranges[0].1 {
        for second in ranges[1].0..=ranges[1].1 {
            for third in ranges[2].0..=ranges[2].1 {
                for fourth in ranges[3].0..=ranges[3].1 {
                    hosts.push(Ipv4Addr::new(first, second, third, fourth).to_string());
                }
            }
        }
    }

    Ok(Some(hosts))
}

fn parse_ipv4_wildcard_ranges(value: &str) -> Option<[(u8, u8); 4]> {
    let value = value.trim();
    if !value.contains('*') {
        return None;
    }

    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 4 {
        return None;
    }

    let mut ranges = [(0u8, 0u8); 4];
    for (index, part) in parts.iter().enumerate() {
        ranges[index] = if *part == "*" {
            (0, 255)
        } else {
            let value = part.parse::<u8>().ok()?;
            (value, value)
        };
    }

    Some(ranges)
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
    fn parses_etc_hosts_style_target_file_content() {
        let targets = parse_target_file_content(
            "
            127.0.0.1 localhost
            192.0.2.10 web01 web01.internal # comment
            ",
        );

        assert_eq!(targets, vec!["127.0.0.1", "192.0.2.10"]);
    }

    #[test]
    fn parses_mixed_target_file_content() {
        let targets = parse_target_file_content(
            "
            target=192.0.2.10:2222, ssh://audit@192.0.2.11:22
            Host: 192.0.2.12 () Ports: 22/open/tcp//ssh///
            [2001:db8::10]:2222; 192.0.2.0/31
            192.0.2.20-22
            192.0.2.*
            127.0.0.1 localhost
            ",
        );

        assert_eq!(
            targets,
            vec![
                "192.0.2.10:2222",
                "192.0.2.11",
                "192.0.2.12",
                "[2001:db8::10]:2222",
                "192.0.2.0/31",
                "192.0.2.20-22",
                "192.0.2.*",
                "127.0.0.1",
            ]
        );
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
    fn expands_ipv4_range_targets() {
        let endpoints = load_target_endpoints(Some("192.0.2.10-12"), None, "22").unwrap();
        let hosts = endpoints
            .iter()
            .map(|endpoint| endpoint.host.as_str())
            .collect::<Vec<_>>();

        assert_eq!(hosts, vec!["192.0.2.10", "192.0.2.11", "192.0.2.12"]);
    }

    #[test]
    fn expands_ipv4_wildcard_targets() {
        let endpoints = load_target_endpoints(Some("192.0.2.*"), None, "22").unwrap();
        let hosts = endpoints
            .iter()
            .map(|endpoint| endpoint.host.as_str())
            .collect::<Vec<_>>();

        assert_eq!(endpoints.len(), 256);
        assert!(hosts.contains(&"192.0.2.0"));
        assert!(hosts.contains(&"192.0.2.255"));
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
    fn rejects_overly_large_ipv4_range_targets() {
        assert!(load_target_endpoints(Some("0.0.0.0-255.255.255.255"), None, "22").is_err());
        assert!(load_target_endpoints(Some("*.*.*.*"), None, "22").is_err());
    }

    #[test]
    fn expands_bracketed_ipv6_targets() {
        let endpoints = load_target_endpoints(Some("[2001:db8::1]"), None, "22").unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].host, "2001:db8::1");
    }
}
