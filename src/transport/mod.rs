pub mod auth;
pub mod host_key;
pub mod native;
pub mod openssh;
pub mod proxy_jump;

pub use auth::ScanAuth;
pub use host_key::{StrictHostKeyPolicy, resolve_known_hosts_file, resolve_strict_host_key_policy};
pub use native::NativeTransport;
pub use openssh::{CommandOutput, OpenSshTransport, SshTarget};

use anyhow::{Result, bail};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TransportKind {
    OpenSsh,
    Native,
}

impl TransportKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "openssh" | "ssh" => Ok(Self::OpenSsh),
            "native" => Ok(Self::Native),
            other => bail!("unsupported transport: {other}"),
        }
    }
}

#[derive(Clone)]
pub enum ScanTransport {
    OpenSsh(OpenSshTransport),
    Native(NativeTransport),
}

impl ScanTransport {
    pub fn new(
        kind: TransportKind,
        auth: ScanAuth,
        timeout: Duration,
        host_key_policy: StrictHostKeyPolicy,
        connection_reuse: bool,
        proxy_jump: Option<String>,
    ) -> Self {
        match kind {
            TransportKind::OpenSsh => Self::OpenSsh(OpenSshTransport::new(
                auth,
                timeout,
                host_key_policy,
                connection_reuse,
                proxy_jump,
            )),
            TransportKind::Native => Self::Native(NativeTransport::new(
                auth,
                timeout,
                host_key_policy,
                proxy_jump,
            )),
        }
    }
}

#[allow(dead_code)]
pub trait RemoteTransport {
    fn run_command<'a>(
        &'a self,
        target: &'a SshTarget,
        remote_command: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>>;
}

impl RemoteTransport for ScanTransport {
    fn run_command<'a>(
        &'a self,
        target: &'a SshTarget,
        remote_command: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
        match self {
            Self::OpenSsh(transport) => Box::pin(OpenSshTransport::run_command(
                transport,
                target,
                remote_command,
            )),
            Self::Native(transport) => Box::pin(NativeTransport::run_command(
                transport,
                target,
                remote_command,
            )),
        }
    }
}

impl RemoteTransport for OpenSshTransport {
    fn run_command<'a>(
        &'a self,
        target: &'a SshTarget,
        remote_command: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
        Box::pin(OpenSshTransport::run_command(self, target, remote_command))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_transport_kinds() {
        assert_eq!(
            TransportKind::parse("openssh").unwrap(),
            TransportKind::OpenSsh
        );
        assert_eq!(TransportKind::parse("SSH").unwrap(), TransportKind::OpenSsh);
        assert_eq!(
            TransportKind::parse("native").unwrap(),
            TransportKind::Native
        );
        assert!(TransportKind::parse("telnet").is_err());
    }
}
