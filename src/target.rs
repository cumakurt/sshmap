use anyhow::{Context, Result, bail};

pub const DEFAULT_SSH_PORT: u16 = 22;

pub fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        bail!("host target is empty");
    }

    if value.starts_with('[') {
        let end = value
            .find(']')
            .with_context(|| format!("invalid bracketed host target: {value}"))?;
        let host = value[1..end].to_string();
        let port = if value.len() > end + 1 {
            let rest = &value[end + 1..];
            if !rest.starts_with(':') {
                bail!("invalid bracketed host target: {value}");
            }
            rest[1..]
                .parse::<u16>()
                .with_context(|| format!("invalid port in host target: {value}"))?
        } else {
            DEFAULT_SSH_PORT
        };
        return Ok((host, port));
    }

    if let Some((host_part, port_str)) = value.rsplit_once(':')
        && !host_part.contains(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return Ok((host_part.to_string(), port));
    }

    Ok((value.to_string(), DEFAULT_SSH_PORT))
}

pub fn parse_host_target(value: &str) -> Result<(String, i64, Option<String>)> {
    let (host, port) = parse_host_port(value)?;
    Ok((
        host.clone(),
        i64::from(port),
        hostname_hint(&host).map(str::to_string),
    ))
}

pub fn normalize_scope_target(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("target is empty");
    }

    if trimmed.parse::<ipnet::IpNet>().is_ok() {
        return Ok(trimmed.to_string());
    }

    if trimmed.starts_with('[') {
        let end = trimmed
            .find(']')
            .with_context(|| format!("invalid bracketed target: {trimmed}"))?;
        let host = &trimmed[1..end];
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Ok(host.to_string());
        }
    }

    if let Ok((host, _port)) = parse_host_port(trimmed)
        && (host.parse::<std::net::IpAddr>().is_ok() || is_valid_hostname_like_value(&host))
    {
        return Ok(host);
    }

    if trimmed.parse::<std::net::IpAddr>().is_ok() || is_valid_hostname_like_value(trimmed) {
        return Ok(trimmed.to_string());
    }

    bail!("invalid target: {trimmed}");
}

pub fn hostname_hint(value: &str) -> Option<&str> {
    if value.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(value)
    }
}

pub fn is_ip_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
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
    fn parses_ipv4_with_port() {
        let (host, port) = parse_host_port("10.0.0.1:2222").unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 2222);
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let (host, port) = parse_host_port("[2001:db8::1]:2222").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 2222);
    }

    #[test]
    fn treats_unbracketed_ipv6_as_host_without_port() {
        let (host, port) = parse_host_port("2001:db8::1").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 22);
    }

    #[test]
    fn parse_host_target_rejects_empty_input() {
        assert!(parse_host_target("").is_err());
    }

    #[test]
    fn normalizes_bracketed_ipv6_scope_target() {
        assert_eq!(
            normalize_scope_target("[2001:db8::1]").unwrap(),
            "2001:db8::1"
        );
    }
}
