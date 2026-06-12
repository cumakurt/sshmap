use crate::target::parse_host_port;
use crate::transport::SshTarget;
use anyhow::{Result, bail};

pub fn parse_proxy_jump_hop(hop: &str, default_username: &str) -> Result<SshTarget> {
    let hop = hop.trim();
    if hop.is_empty() {
        bail!("proxy jump chain contains an empty hop");
    }

    let (username, host_port) = match hop.split_once('@') {
        Some((username, host_port)) if !username.is_empty() && !host_port.is_empty() => {
            (username.to_string(), host_port)
        }
        None => (default_username.to_string(), hop),
        _ => bail!("invalid proxy jump hop: {hop}"),
    };

    let (host, port) = parse_host_port(host_port)?;

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

    #[test]
    fn parses_bracketed_ipv6_hop_with_port() {
        let hop = parse_proxy_jump_hop("[2001:db8::1]:2222", "audit").unwrap();
        assert_eq!(hop.host, "2001:db8::1");
        assert_eq!(hop.port, 2222);
        assert_eq!(hop.username, "audit");
    }

    #[test]
    fn parses_user_with_bracketed_ipv6_hop() {
        let hop = parse_proxy_jump_hop("jump@[2001:db8::1]:2222", "audit").unwrap();
        assert_eq!(hop.host, "2001:db8::1");
        assert_eq!(hop.port, 2222);
        assert_eq!(hop.username, "jump");
    }

    #[test]
    fn treats_unbracketed_ipv6_as_host_without_port() {
        let hop = parse_proxy_jump_hop("2001:db8::1", "audit").unwrap();
        assert_eq!(hop.host, "2001:db8::1");
        assert_eq!(hop.port, 22);
    }
}
