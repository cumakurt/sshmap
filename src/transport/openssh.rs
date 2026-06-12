use crate::collector::commands::RemoteCommand;
use crate::collector::redact_sensitive_content;
use crate::models::RawEvidenceRecord;
use crate::transport::ScanAuth;
use crate::transport::StrictHostKeyPolicy;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct OpenSshTransport {
    auth: ScanAuth,
    timeout: Duration,
    host_key_policy: StrictHostKeyPolicy,
    connection_reuse: bool,
    proxy_jump: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

impl OpenSshTransport {
    pub fn new(
        auth: ScanAuth,
        timeout: Duration,
        host_key_policy: StrictHostKeyPolicy,
        connection_reuse: bool,
        proxy_jump: Option<String>,
    ) -> Self {
        Self {
            auth,
            timeout,
            host_key_policy,
            connection_reuse,
            proxy_jump,
        }
    }

    pub async fn collect_host_evidence(
        &self,
        target: &SshTarget,
        commands: &[RemoteCommand],
        use_sudo: bool,
    ) -> Vec<RawEvidenceRecord> {
        if !self.connection_reuse {
            return self
                .collect_host_evidence_sequential(target, commands, use_sudo)
                .await;
        }

        let control_path = control_socket_path(target);
        let mut evidence = Vec::new();

        for command in commands {
            let Some(rendered_command) = command.render(use_sudo) else {
                continue;
            };

            let output = self
                .run_multiplexed_command(target, &rendered_command, &control_path)
                .await
                .unwrap_or_else(|error| CommandOutput {
                    stdout: String::new(),
                    stderr: error.to_string(),
                    exit_code: None,
                });
            evidence.push(build_evidence_record(command, rendered_command, output));
        }

        self.close_control_master(target, &control_path).await;
        evidence
    }

    pub async fn run_command(
        &self,
        target: &SshTarget,
        remote_command: &str,
    ) -> Result<CommandOutput> {
        self.run_ssh_command(target, remote_command, None).await
    }

    async fn collect_host_evidence_sequential(
        &self,
        target: &SshTarget,
        commands: &[RemoteCommand],
        use_sudo: bool,
    ) -> Vec<RawEvidenceRecord> {
        let mut evidence = Vec::new();

        for command in commands {
            let Some(rendered_command) = command.render(use_sudo) else {
                continue;
            };

            let output = self
                .run_command(target, &rendered_command)
                .await
                .unwrap_or_else(|error| CommandOutput {
                    stdout: String::new(),
                    stderr: error.to_string(),
                    exit_code: None,
                });
            evidence.push(build_evidence_record(command, rendered_command, output));
        }

        evidence
    }

    async fn run_multiplexed_command(
        &self,
        target: &SshTarget,
        remote_command: &str,
        control_path: &Path,
    ) -> Result<CommandOutput> {
        self.run_ssh_command(target, remote_command, Some(control_path))
            .await
    }

    async fn run_ssh_command(
        &self,
        target: &SshTarget,
        remote_command: &str,
        control_path: Option<&Path>,
    ) -> Result<CommandOutput> {
        let mut command = self.build_ssh_command(target, control_path);
        command
            .arg("--")
            .arg(format!("{}@{}", target.username, target.host))
            .arg(remote_command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = match timeout(self.timeout, command.output()).await {
            Ok(output) => output.context("failed to run ssh command")?,
            Err(_) => bail!(
                "ssh command timed out after {} seconds",
                self.timeout.as_secs()
            ),
        };

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code(),
        })
    }

    fn build_ssh_command(&self, target: &SshTarget, control_path: Option<&Path>) -> Command {
        let mut command = Command::new("ssh");
        command
            .kill_on_drop(true)
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("NumberOfPasswordPrompts=0")
            .arg("-o")
            .arg("PasswordAuthentication=no")
            .arg("-o")
            .arg("KbdInteractiveAuthentication=no")
            .arg("-o")
            .arg(format!("ConnectTimeout={}", self.timeout.as_secs().max(1)));

        if let Some(value) = self.host_key_policy.openssh_option() {
            command
                .arg("-o")
                .arg(format!("StrictHostKeyChecking={value}"));
        }

        if let Some(path) = self.host_key_policy.known_hosts_path() {
            command
                .arg("-o")
                .arg(format!("UserKnownHostsFile={}", path.display()));
        }

        if let Some(proxy_jump) = self.proxy_jump.as_deref() {
            command.arg("-J").arg(proxy_jump);
        }

        if let Some(control_path) = control_path {
            command
                .arg("-o")
                .arg("ControlMaster=auto")
                .arg("-o")
                .arg(format!("ControlPath={}", control_path.display()))
                .arg("-o")
                .arg(format!("ControlPersist={}", self.timeout.as_secs().max(1)));
        }

        command.arg("-p").arg(target.port.to_string());

        if let Some(path) = self.auth.agent_socket.as_deref() {
            command
                .arg("-o")
                .arg(format!("IdentityAgent={}", path.display()));
        }

        if let Some(identity_file) = &self.auth.identity_file {
            command.arg("-i").arg(identity_file);
        }

        if self.auth.identities_only {
            command.arg("-o").arg("IdentitiesOnly=yes");
        }

        command
    }

    async fn close_control_master(&self, target: &SshTarget, control_path: &Path) {
        if !control_path.exists() {
            return;
        }

        let mut command = self.build_ssh_command(target, Some(control_path));
        command
            .arg("-O")
            .arg("exit")
            .arg("--")
            .arg(format!("{}@{}", target.username, target.host))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let _ = timeout(Duration::from_secs(5), command.status()).await;
        let _ = std::fs::remove_file(control_path);
    }
}

fn build_evidence_record(
    command: &RemoteCommand,
    rendered_command: String,
    output: CommandOutput,
) -> RawEvidenceRecord {
    let (content, content_redacted) = redact_sensitive_content(&output.stdout);
    let (stderr, stderr_redacted) = redact_sensitive_content(&output.stderr);

    RawEvidenceRecord {
        evidence_type: command.evidence_type.to_string(),
        source: command.name.to_string(),
        command: rendered_command,
        content,
        stderr,
        exit_code: output.exit_code,
        redacted: content_redacted || stderr_redacted,
    }
}

fn control_socket_path(target: &SshTarget) -> PathBuf {
    let socket_name = format!(
        "sshmap-{}-{}-{}-{}-{}.sock",
        sanitize_path_component(&target.username),
        sanitize_path_component(&target.host),
        target.port,
        std::process::id(),
        Uuid::new_v4()
    );
    std::env::temp_dir().join(socket_name)
}

fn sanitize_path_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_socket_path_is_unique_per_target() {
        let target = SshTarget {
            host: "web01.example.com".to_string(),
            port: 22,
            username: "audit".to_string(),
        };

        let path = control_socket_path(&target);
        assert!(
            path.to_string_lossy()
                .contains("sshmap-audit-web01.example.com-22")
        );
    }

    #[test]
    fn sanitizes_hostnames_for_control_path() {
        assert_eq!(sanitize_path_component("host/name"), "host_name");
    }
}
