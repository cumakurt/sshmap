use crate::collector::commands::default_local_commands;
use crate::collector::redact_sensitive_content;
use crate::db;
use crate::models::{HostScanResult, RawEvidenceRecord, RemoteScanSummary};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;

pub struct LocalScanRequest {
    pub use_sudo: bool,
    pub db_path: PathBuf,
    pub show_progress: bool,
}

pub fn run_local_scan(request: LocalScanRequest) -> Result<RemoteScanSummary> {
    let (host, hostname, port) = detect_local_identity()?;
    let commands = default_local_commands();
    let runnable_commands = commands
        .iter()
        .filter(|command| command.render(request.use_sudo).is_some())
        .count();
    let progress = crate::progress::ProgressReporter::new(
        "local-scan",
        runnable_commands.max(1),
        request.show_progress,
    );
    let mut evidence = Vec::new();

    for command in &commands {
        let Some(rendered_command) = command.render(request.use_sudo) else {
            continue;
        };

        if request.show_progress {
            progress.message(&format!("collecting {}", command.evidence_type));
        }

        let output = run_shell_command(&rendered_command);
        let (content, stderr, exit_code) = match output {
            Ok(output) => (output.stdout, output.stderr, output.exit_code),
            Err(error) => (String::new(), error.to_string(), None),
        };
        let (content, content_redacted) = redact_sensitive_content(&content);
        let (stderr, stderr_redacted) = redact_sensitive_content(&stderr);

        evidence.push(RawEvidenceRecord {
            evidence_type: command.evidence_type.to_string(),
            source: command.name.to_string(),
            command: rendered_command,
            content,
            stderr,
            exit_code,
            redacted: content_redacted || stderr_redacted,
        });
        progress.tick_with_detail(Some(command.evidence_type));
    }

    progress.finish();

    let result = HostScanResult {
        host: host.clone(),
        port,
        evidence,
    };

    db::store_local_scan_results(
        &request.db_path,
        &result,
        hostname.as_deref(),
        request.use_sudo,
    )
}

struct CommandOutput {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

fn run_shell_command(command: &str) -> Result<CommandOutput> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .with_context(|| format!("failed to run local command: {command}"))?;

    Ok(CommandOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: Some(output.status.code().unwrap_or(-1)),
    })
}

fn detect_local_identity() -> Result<(String, Option<String>, u16)> {
    let hostname = run_shell_command("hostname -f 2>/dev/null || hostname")
        .ok()
        .and_then(|output| {
            let value = output.stdout.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        });

    let ip = run_shell_command("hostname -I 2>/dev/null | awk '{print $1}'")
        .ok()
        .and_then(|output| {
            let value = output.stdout.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        })
        .unwrap_or_else(|| "127.0.0.1".to_string());

    Ok((ip, hostname, 22))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_local_identity() {
        let result = detect_local_identity();
        assert!(result.is_ok());
        let (host, _, port) = result.unwrap();
        assert!(!host.is_empty());
        assert_eq!(port, 22);
    }
}
