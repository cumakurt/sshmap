use serde::Serialize;
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event: String,
    pub database: String,
    pub summary: WebhookSummary,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookSummary {
    pub critical_risks: usize,
    pub high_risks: usize,
    pub new_risks: usize,
    pub resolved_risks: usize,
    pub hosts: usize,
}

pub async fn send_webhook(url: &str, payload: &WebhookPayload) -> anyhow::Result<()> {
    let body = serde_json::to_string(payload)?;
    let output = timeout(
        Duration::from_secs(15),
        Command::new("curl")
            .arg("-fsS")
            .arg("-X")
            .arg("POST")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(body)
            .arg(url)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output(),
    )
    .await??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("webhook request failed: {stderr}");
    }
    Ok(())
}

pub fn build_alert_payload(
    event: &str,
    database: &str,
    critical: usize,
    high: usize,
    new_risks: usize,
    resolved_risks: usize,
    hosts: usize,
    details: Option<serde_json::Value>,
) -> WebhookPayload {
    WebhookPayload {
        event: event.to_string(),
        database: database.to_string(),
        summary: WebhookSummary {
            critical_risks: critical,
            high_risks: high,
            new_risks,
            resolved_risks,
            hosts,
        },
        details,
    }
}
