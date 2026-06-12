use serde::Serialize;
use std::net::SocketAddr;
use std::time::Duration;

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
    let endpoint = crate::security::parse_webhook_endpoint(url)?;
    let addresses = crate::security::resolve_webhook_addresses(&endpoint).await?;
    let body = serde_json::to_string(payload)?;

    let mut client_builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15));
    for address in addresses {
        client_builder =
            client_builder.resolve(&endpoint.host, SocketAddr::new(address.ip(), endpoint.port));
    }

    let client = client_builder.build()?;
    let response = client
        .post(endpoint.url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!(
            "webhook request failed with HTTP {}",
            response.status().as_u16()
        );
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
