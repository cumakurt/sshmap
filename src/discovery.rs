use crate::db;
use crate::host_key_scan::{ScannedServerHostKey, scan_server_host_keys};
use crate::models::ScanRunSummary;
use crate::scope::TargetEndpoint;
use crate::ssh_version::parse_openssh_banner;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryResult {
    pub host: String,
    pub port: u16,
    pub ssh_open: bool,
    pub banner: Option<String>,
    pub openssh_version: Option<String>,
    pub server_keys: Vec<ScannedServerHostKey>,
    pub error: Option<String>,
}

impl DiscoveryResult {
    pub fn hostname_hint(&self) -> Option<&str> {
        if self.host.parse::<IpAddr>().is_ok() {
            None
        } else {
            Some(&self.host)
        }
    }
}

pub async fn run_discovery(
    targets: Vec<TargetEndpoint>,
    concurrency: usize,
    timeout_duration: Duration,
    db_path: &Path,
    show_progress: bool,
) -> Result<ScanRunSummary> {
    let concurrency = concurrency.max(1);
    let total = targets.len();
    let progress = std::sync::Arc::new(crate::progress::ProgressReporter::new(
        "discover",
        total,
        show_progress,
    ));

    let results = stream::iter(targets)
        .map(|target| {
            let progress = std::sync::Arc::clone(&progress);
            async move {
                let detail = format!("{}:{}", target.host, target.port);
                let result = scan_target(target, timeout_duration).await;
                progress.tick_with_detail(Some(&detail));
                result
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

    progress.finish();
    db::store_discovery_results(db_path, &results)
}

async fn scan_target(target: TargetEndpoint, timeout_duration: Duration) -> DiscoveryResult {
    let address = socket_address(&target.host, target.port);
    match timeout(timeout_duration, TcpStream::connect(&address)).await {
        Ok(Ok(mut stream)) => match read_ssh_banner(&mut stream, timeout_duration).await {
            Ok(banner) => {
                let ssh_open = banner
                    .as_deref()
                    .map(|value| value.starts_with("SSH-"))
                    .unwrap_or(true);
                let openssh_version =
                    parse_openssh_banner(banner.as_deref()).map(|version| version.raw);
                let server_keys = if ssh_open {
                    scan_server_host_keys(&target.host, target.port, timeout_duration).await
                } else {
                    Vec::new()
                };
                DiscoveryResult {
                    host: target.host,
                    port: target.port,
                    ssh_open,
                    banner,
                    openssh_version,
                    server_keys,
                    error: None,
                }
            }
            Err(error) => DiscoveryResult {
                host: target.host,
                port: target.port,
                ssh_open: true,
                banner: None,
                openssh_version: None,
                server_keys: Vec::new(),
                error: Some(error.to_string()),
            },
        },
        Ok(Err(error)) => DiscoveryResult {
            host: target.host,
            port: target.port,
            ssh_open: false,
            banner: None,
            openssh_version: None,
            server_keys: Vec::new(),
            error: Some(error.to_string()),
        },
        Err(_) => DiscoveryResult {
            host: target.host,
            port: target.port,
            ssh_open: false,
            banner: None,
            openssh_version: None,
            server_keys: Vec::new(),
            error: Some("connection timed out".to_string()),
        },
    }
}

async fn read_ssh_banner(
    stream: &mut TcpStream,
    timeout_duration: Duration,
) -> Result<Option<String>> {
    let mut buffer = [0_u8; 512];
    let bytes_read = timeout(timeout_duration, stream.read(&mut buffer)).await??;
    if bytes_read == 0 {
        return Ok(None);
    }

    let banner = String::from_utf8_lossy(&buffer[..bytes_read])
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned);

    Ok(banner)
}

fn socket_address(host: &str, port: u16) -> String {
    if host.parse::<IpAddr>().is_ok() && host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_hint_is_none_for_ip_addresses() {
        let result = DiscoveryResult {
            host: "127.0.0.1".to_string(),
            port: 22,
            ssh_open: true,
            banner: None,
            openssh_version: None,
            server_keys: Vec::new(),
            error: None,
        };

        assert_eq!(result.hostname_hint(), None);
    }

    #[test]
    fn hostname_hint_is_hostname_for_names() {
        let result = DiscoveryResult {
            host: "web01.local".to_string(),
            port: 22,
            ssh_open: true,
            banner: None,
            openssh_version: None,
            server_keys: Vec::new(),
            error: None,
        };

        assert_eq!(result.hostname_hint(), Some("web01.local"));
    }

    #[test]
    fn socket_address_brackets_ipv6_targets() {
        assert_eq!(socket_address("2001:db8::1", 22), "[2001:db8::1]:22");
        assert_eq!(socket_address("192.0.2.10", 2222), "192.0.2.10:2222");
        assert_eq!(
            socket_address("web01.example.com", 22),
            "web01.example.com:22"
        );
    }
}
