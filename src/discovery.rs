use crate::db;
use crate::models::ScanRunSummary;
use crate::scope::TargetEndpoint;
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
                let result = scan_target(target, timeout_duration).await;
                progress.tick();
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
    let address = format!("{}:{}", target.host, target.port);
    match timeout(timeout_duration, TcpStream::connect(&address)).await {
        Ok(Ok(mut stream)) => match read_ssh_banner(&mut stream, timeout_duration).await {
            Ok(banner) => DiscoveryResult {
                host: target.host,
                port: target.port,
                ssh_open: banner
                    .as_deref()
                    .map(|value| value.starts_with("SSH-"))
                    .unwrap_or(true),
                banner,
                error: None,
            },
            Err(error) => DiscoveryResult {
                host: target.host,
                port: target.port,
                ssh_open: true,
                banner: None,
                error: Some(error.to_string()),
            },
        },
        Ok(Err(error)) => DiscoveryResult {
            host: target.host,
            port: target.port,
            ssh_open: false,
            banner: None,
            error: Some(error.to_string()),
        },
        Err(_) => DiscoveryResult {
            host: target.host,
            port: target.port,
            ssh_open: false,
            banner: None,
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
            error: None,
        };

        assert_eq!(result.hostname_hint(), Some("web01.local"));
    }
}
