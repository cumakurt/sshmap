use crate::collector::commands::RemoteCommand;
use crate::collector::redact_sensitive_content;
use crate::models::RawEvidenceRecord;
use crate::transport::auth::ScanAuth;
use crate::transport::host_key::StrictHostKeyPolicy;
use crate::transport::proxy_jump::parse_proxy_jump_chain;
use crate::transport::{CommandOutput, SshTarget};
use anyhow::{Context, Result, bail};
use russh::keys::agent::AgentIdentity;
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::{ChannelMsg, Disconnect, client};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

type ClientHandle = client::Handle<NativeClientHandler>;

async fn disconnect_sessions(sessions: impl IntoIterator<Item = ClientHandle>) {
    for session in sessions {
        session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
            .ok();
    }
}

#[derive(Debug, Clone)]
pub struct NativeTransport {
    auth: ScanAuth,
    timeout: Duration,
    host_key_policy: StrictHostKeyPolicy,
    proxy_jump: Option<String>,
}

struct NativeSession {
    session: ClientHandle,
    jump_sessions: Vec<ClientHandle>,
}

struct NativeClientHandler {
    host: String,
    port: u16,
    host_key_policy: StrictHostKeyPolicy,
}

impl client::Handler for NativeClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        self.host_key_policy
            .verify_host_key(&self.host, self.port, server_public_key)
    }
}

impl NativeTransport {
    pub fn new(
        auth: ScanAuth,
        timeout: Duration,
        host_key_policy: StrictHostKeyPolicy,
        proxy_jump: Option<String>,
    ) -> Self {
        Self {
            auth,
            timeout,
            host_key_policy,
            proxy_jump,
        }
    }

    pub async fn collect_host_evidence(
        &self,
        target: &SshTarget,
        commands: &[RemoteCommand],
        use_sudo: bool,
    ) -> Vec<RawEvidenceRecord> {
        let mut evidence = Vec::new();
        let mut native_session = match connect_session(
            &self.auth,
            target,
            self.timeout,
            self.host_key_policy.clone(),
            self.proxy_jump.as_deref(),
        )
        .await
        {
            Ok(session) => session,
            Err(error) => {
                evidence.push(RawEvidenceRecord {
                    evidence_type: "transport".to_string(),
                    source: "native".to_string(),
                    command: "connect".to_string(),
                    content: String::new(),
                    stderr: error.to_string(),
                    exit_code: None,
                    redacted: false,
                });
                return evidence;
            }
        };

        for command in commands {
            let Some(rendered_command) = command.render(use_sudo) else {
                continue;
            };

            let output = match timeout(
                self.timeout,
                exec_on_session(&mut native_session.session, &rendered_command),
            )
            .await
            {
                Ok(Ok(output)) => output,
                Ok(Err(error)) => CommandOutput {
                    stdout: String::new(),
                    stderr: error.to_string(),
                    exit_code: None,
                },
                Err(_) => CommandOutput {
                    stdout: String::new(),
                    stderr: format!(
                        "native SSH command timed out after {} seconds",
                        self.timeout.as_secs()
                    ),
                    exit_code: None,
                },
            };
            let (content, content_redacted) = redact_sensitive_content(&output.stdout);
            let (stderr, stderr_redacted) = redact_sensitive_content(&output.stderr);

            evidence.push(RawEvidenceRecord {
                evidence_type: command.evidence_type.to_string(),
                source: command.name.to_string(),
                command: rendered_command,
                content,
                stderr,
                exit_code: output.exit_code,
                redacted: content_redacted || stderr_redacted,
            });
        }

        native_session
            .session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
            .ok();
        disconnect_sessions(native_session.jump_sessions).await;

        evidence
    }

    #[allow(dead_code)]
    pub async fn run_command(
        &self,
        target: &SshTarget,
        remote_command: &str,
    ) -> Result<CommandOutput> {
        let operation = async {
            let mut native_session = connect_session(
                &self.auth,
                target,
                self.timeout,
                self.host_key_policy.clone(),
                self.proxy_jump.as_deref(),
            )
            .await?;
            let output = exec_on_session(&mut native_session.session, remote_command).await?;
            native_session
                .session
                .disconnect(Disconnect::ByApplication, "", "English")
                .await
                .ok();
            disconnect_sessions(native_session.jump_sessions).await;
            Ok(output)
        };

        match timeout(self.timeout, operation).await {
            Ok(result) => result,
            Err(_) => bail!(
                "native SSH command timed out after {} seconds",
                self.timeout.as_secs()
            ),
        }
    }
}

async fn exec_on_session(
    session: &mut ClientHandle,
    remote_command: &str,
) -> Result<CommandOutput> {
    let mut channel = session
        .channel_open_session()
        .await
        .context("native SSH session channel open failed")?;
    channel
        .exec(true, remote_command)
        .await
        .context("native SSH exec request failed")?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = None;

    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.push_str(&String::from_utf8_lossy(&data)),
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                stderr.push_str(&String::from_utf8_lossy(&data));
            }
            ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status as i32),
            _ => {}
        }
    }

    Ok(CommandOutput {
        stdout,
        stderr,
        exit_code,
    })
}

async fn connect_session(
    auth: &ScanAuth,
    target: &SshTarget,
    inactivity_timeout: Duration,
    host_key_policy: StrictHostKeyPolicy,
    proxy_jump: Option<&str>,
) -> Result<NativeSession> {
    if let Some(chain) = proxy_jump {
        return connect_through_proxy_jump(
            auth,
            target,
            chain,
            inactivity_timeout,
            host_key_policy,
        )
        .await;
    }

    let session = connect_direct_session(auth, target, inactivity_timeout, host_key_policy).await?;
    Ok(NativeSession {
        session,
        jump_sessions: Vec::new(),
    })
}

async fn connect_direct_session(
    auth: &ScanAuth,
    target: &SshTarget,
    inactivity_timeout: Duration,
    host_key_policy: StrictHostKeyPolicy,
) -> Result<ClientHandle> {
    let config = client_config(inactivity_timeout);
    let handler = NativeClientHandler {
        host: target.host.clone(),
        port: target.port,
        host_key_policy,
    };

    let mut session = client::connect(config, (target.host.as_str(), target.port), handler)
        .await
        .with_context(|| {
            format!(
                "native SSH connect failed for {}@{}:{}",
                target.username, target.host, target.port
            )
        })?;

    authenticate_session(&mut session, &target.username, auth).await?;
    Ok(session)
}

async fn connect_through_proxy_jump(
    auth: &ScanAuth,
    target: &SshTarget,
    proxy_jump: &str,
    inactivity_timeout: Duration,
    host_key_policy: StrictHostKeyPolicy,
) -> Result<NativeSession> {
    let hops = parse_proxy_jump_chain(proxy_jump, &target.username)?;
    if hops.is_empty() {
        bail!("proxy jump chain is empty");
    }

    let config = client_config(inactivity_timeout);
    let mut jump_sessions = Vec::new();
    let mut parent =
        connect_direct_session(auth, &hops[0], inactivity_timeout, host_key_policy.clone()).await?;

    for hop in hops.iter().skip(1) {
        let previous = parent;
        parent = match connect_over_direct_tcpip(
            &previous,
            hop,
            auth,
            config.clone(),
            host_key_policy.clone(),
        )
        .await
        {
            Ok(next) => next,
            Err(error) => {
                disconnect_sessions(std::iter::once(previous).chain(jump_sessions)).await;
                return Err(error);
            }
        };
        jump_sessions.push(previous);
    }

    let previous = parent;
    let session =
        match connect_over_direct_tcpip(&previous, target, auth, config, host_key_policy).await {
            Ok(session) => session,
            Err(error) => {
                disconnect_sessions(std::iter::once(previous).chain(jump_sessions)).await;
                return Err(error);
            }
        };
    jump_sessions.push(previous);

    Ok(NativeSession {
        session,
        jump_sessions,
    })
}

async fn connect_over_direct_tcpip(
    parent: &ClientHandle,
    target: &SshTarget,
    auth: &ScanAuth,
    config: std::sync::Arc<client::Config>,
    host_key_policy: StrictHostKeyPolicy,
) -> Result<ClientHandle> {
    let channel = parent
        .channel_open_direct_tcpip(&target.host, u32::from(target.port), "127.0.0.1", 0)
        .await
        .with_context(|| {
            format!(
                "native SSH direct-tcpip failed for {}@{}:{}",
                target.username, target.host, target.port
            )
        })?;
    let stream = channel.into_stream();
    let handler = NativeClientHandler {
        host: target.host.clone(),
        port: target.port,
        host_key_policy,
    };

    let mut session = client::connect_stream(config, stream, handler)
        .await
        .with_context(|| {
            format!(
                "native SSH connect over proxy channel failed for {}@{}:{}",
                target.username, target.host, target.port
            )
        })?;
    authenticate_session(&mut session, &target.username, auth).await?;
    Ok(session)
}

fn client_config(inactivity_timeout: Duration) -> std::sync::Arc<client::Config> {
    std::sync::Arc::new(client::Config {
        inactivity_timeout: Some(inactivity_timeout),
        ..Default::default()
    })
}

async fn authenticate_session(
    session: &mut ClientHandle,
    username: &str,
    auth: &ScanAuth,
) -> Result<()> {
    if let Some(identity_file) = &auth.identity_file {
        if !identity_file.exists() {
            bail!("identity file not found: {}", identity_file.display());
        }

        let key_pair = load_secret_key(identity_file, None).with_context(|| {
            format!(
                "failed to load native transport identity file {}",
                identity_file.display()
            )
        })?;

        let auth_result = session
            .authenticate_publickey(
                username,
                PrivateKeyWithHashAlg::new(
                    Arc::new(key_pair),
                    session.best_supported_rsa_hash().await?.flatten(),
                ),
            )
            .await
            .context("native SSH public key authentication failed")?;

        if auth_result.success() {
            return Ok(());
        }

        if auth.identities_only || !auth.use_agent {
            bail!(
                "native SSH authentication failed for {} using {}",
                username,
                identity_file.display()
            );
        }
    }

    if auth.use_agent {
        return authenticate_with_agent(session, username, auth.agent_socket.as_deref()).await;
    }

    bail!("native transport requires --key, --agent, or scan.key / scan.use_agent in config");
}

async fn authenticate_with_agent(
    session: &mut ClientHandle,
    username: &str,
    agent_socket: Option<&Path>,
) -> Result<()> {
    #[cfg(unix)]
    {
        use russh::keys::agent::client::AgentClient;

        let mut agent = if let Some(path) = agent_socket {
            AgentClient::connect_uds(path)
                .await
                .with_context(|| format!("failed to connect to SSH agent at {}", path.display()))?
        } else {
            AgentClient::connect_env()
                .await
                .context("failed to connect to SSH agent from SSH_AUTH_SOCK")?
        };

        let identities = agent
            .request_identities()
            .await
            .context("failed to list SSH agent identities")?;
        if identities.is_empty() {
            bail!("SSH agent has no loaded identities");
        }

        let hash_alg = session.best_supported_rsa_hash().await?.flatten();
        for identity in identities {
            let auth_result = match identity {
                AgentIdentity::PublicKey { ref key, .. } => {
                    session
                        .authenticate_publickey_with(username, key.clone(), hash_alg, &mut agent)
                        .await
                }
                AgentIdentity::Certificate {
                    ref certificate, ..
                } => {
                    session
                        .authenticate_certificate_with(
                            username,
                            certificate.clone(),
                            hash_alg,
                            &mut agent,
                        )
                        .await
                }
            };

            match auth_result {
                Ok(result) if result.success() => return Ok(()),
                Ok(_) => continue,
                Err(error) => {
                    return Err(error).context("native SSH agent authentication failed");
                }
            }
        }

        bail!("native SSH agent authentication failed for all loaded identities");
    }

    #[cfg(not(unix))]
    {
        let _ = (session, username, agent_socket);
        bail!("native SSH agent authentication is only supported on Unix");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::host_key::StrictHostKeyPolicy;
    use std::path::PathBuf;

    #[tokio::test]
    async fn requires_identity_source() {
        let transport = NativeTransport::new(
            ScanAuth {
                identity_file: None,
                use_agent: false,
                agent_socket: None,
                identities_only: false,
            },
            Duration::from_secs(5),
            StrictHostKeyPolicy::No,
            None,
        );
        let target = SshTarget {
            host: "127.0.0.1".to_string(),
            port: 22,
            username: "audit".to_string(),
        };

        let error = transport
            .run_command(&target, "echo test")
            .await
            .expect_err("native transport should require an identity source");

        assert!(error.to_string().contains("requires --key, --agent"));
    }

    #[tokio::test]
    async fn rejects_missing_identity_path() {
        let transport = NativeTransport::new(
            ScanAuth {
                identity_file: Some(PathBuf::from("/tmp/sshmap-missing-native-key")),
                use_agent: false,
                agent_socket: None,
                identities_only: true,
            },
            Duration::from_secs(5),
            StrictHostKeyPolicy::No,
            None,
        );
        let target = SshTarget {
            host: "127.0.0.1".to_string(),
            port: 22,
            username: "audit".to_string(),
        };

        let error = transport
            .run_command(&target, "echo test")
            .await
            .expect_err("missing key path should fail");

        assert!(error.to_string().contains("identity file not found"));
    }
}
