use crate::transport::SshTarget;
use anyhow::{Context, Result, bail};

pub fn parse_proxy_jump_hop(hop: &str, default_username: &str) -> Result<SshTarget> {
    let hop = hop.trim();
    if hop.is_empty() {
        bail!("proxy jump chain contains an empty hop");
    }

    let (user_host, port) = if let Some((host_part, port_str)) = hop.rsplit_once(':') {
        if host_part.is_empty() {
            bail!("invalid proxy jump hop: {hop}");
        }
        let port = port_str
            .parse::<u16>()
            .with_context(|| format!("invalid proxy jump port in hop: {hop}"))?;
        (host_part, port)
    } else {
        (hop, 22)
    };

    let (username, host) = if let Some((username, host)) = user_host.rsplit_once('@') {
        if username.is_empty() || host.is_empty() {
            bail!("invalid proxy jump hop: {hop}");
        }
        (username.to_string(), host.to_string())
    } else {
        (default_username.to_string(), user_host.to_string())
    };

    Ok(SshTarget {
        host,
        port,
        username,
    })
}

pub fn parse_proxy_jump_chain(chain: &str, default_username: &str) -> Result<Vec<SshTarget>> {
    chain
        .split(',')
        .map(|hop| parse_proxy_jump_hop(hop, default_username))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_hop() {
        let hop = parse_proxy_jump_hop("bastion.example.com", "audit").unwrap();
        assert_eq!(hop.host, "bastion.example.com");
        assert_eq!(hop.port, 22);
        assert_eq!(hop.username, "audit");
    }

    #[test]
    fn parses_hop_with_port_and_user() {
        let hop = parse_proxy_jump_hop("jump@bastion.example.com:2222", "audit").unwrap();
        assert_eq!(hop.host, "bastion.example.com");
        assert_eq!(hop.port, 2222);
        assert_eq!(hop.username, "jump");
    }

    #[test]
    fn parses_proxy_jump_chain() {
        let hops = parse_proxy_jump_chain("jump1.example.com,jump@jump2:2222", "audit").unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].host, "jump1.example.com");
        assert_eq!(hops[1].port, 2222);
        assert_eq!(hops[1].username, "jump");
    }
}
