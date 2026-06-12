use crate::collector::commands::default_remote_commands;
use crate::db;
use crate::models::{HostScanResult, RemoteScanSummary};
use crate::scope::TargetEndpoint;
use crate::transport::auth::validate_ssh_username;
use crate::transport::{ScanAuth, ScanTransport, SshTarget, TransportKind};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::path::PathBuf;
use std::time::Duration;

pub struct RemoteScanRequest {
    pub targets: Vec<TargetEndpoint>,
    pub username: String,
    pub auth: ScanAuth,
    pub use_sudo: bool,
    pub concurrency: usize,
    pub timeout: Duration,
    pub db_path: PathBuf,
    pub show_progress: bool,
    pub transport: TransportKind,
    pub host_key_policy: crate::transport::StrictHostKeyPolicy,
    pub connection_reuse: bool,
    pub proxy_jump: Option<String>,
}

pub async fn run_remote_scan(request: RemoteScanRequest) -> Result<RemoteScanSummary> {
    validate_ssh_username(&request.username)?;

    let concurrency = request.concurrency.max(1);
    let transport = ScanTransport::new(
        request.transport,
        request.auth.clone(),
        request.timeout,
        request.host_key_policy.clone(),
        request.connection_reuse,
        request.proxy_jump.clone(),
    );
    let commands = default_remote_commands();
    let total = request.targets.len();
    let progress = std::sync::Arc::new(crate::progress::ProgressReporter::new(
        "scan",
        total,
        request.show_progress,
    ));

    let results = stream::iter(request.targets.clone())
        .map(|target| {
            let transport = transport.clone();
            let username = request.username.clone();
            let commands = commands.clone();
            let use_sudo = request.use_sudo;
            let progress = std::sync::Arc::clone(&progress);

            async move {
                let ssh_target = SshTarget {
                    host: target.host.clone(),
                    port: target.port,
                    username,
                };
                let result =
                    scan_single_host(target, ssh_target, &transport, &commands, use_sudo).await;
                progress.tick();
                result
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

    progress.finish();

    db::store_remote_scan_results(
        &request.db_path,
        &results,
        &request.username,
        request.use_sudo,
    )
}

async fn scan_single_host(
    target: TargetEndpoint,
    ssh_target: SshTarget,
    transport: &ScanTransport,
    commands: &[crate::collector::commands::RemoteCommand],
    use_sudo: bool,
) -> HostScanResult {
    let evidence = match transport {
        ScanTransport::Native(native) => {
            native
                .collect_host_evidence(&ssh_target, commands, use_sudo)
                .await
        }
        ScanTransport::OpenSsh(openssh) => {
            openssh
                .collect_host_evidence(&ssh_target, commands, use_sudo)
                .await
        }
    };

    HostScanResult {
        host: target.host,
        port: target.port,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_ssh_usernames() {
        validate_ssh_username("audit-user_01").unwrap();
    }

    #[test]
    fn rejects_usernames_with_at_sign() {
        assert!(validate_ssh_username("audit@example").is_err());
    }

    #[tokio::test]
    async fn accepts_proxy_jump_with_native_transport() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("scan.db");

        let result = run_remote_scan(RemoteScanRequest {
            targets: vec![],
            username: "audit".to_string(),
            auth: ScanAuth {
                identity_file: None,
                use_agent: false,
                agent_socket: None,
                identities_only: false,
            },
            use_sudo: false,
            concurrency: 1,
            timeout: Duration::from_secs(1),
            db_path,
            show_progress: false,
            transport: TransportKind::Native,
            host_key_policy: crate::transport::StrictHostKeyPolicy::No,
            connection_reuse: false,
            proxy_jump: Some("bastion.example.com".to_string()),
        })
        .await;

        assert!(result.is_ok());
    }
}
