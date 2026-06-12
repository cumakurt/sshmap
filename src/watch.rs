use crate::webhook::{build_alert_payload, send_webhook};
use anyhow::Result;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

pub struct WatchConfig {
    pub db_path: std::path::PathBuf,
    pub interval_seconds: u64,
    pub webhook_url: Option<String>,
    pub baseline_name: Option<String>,
}

pub async fn run_watch<F, Fut>(config: WatchConfig, mut run_cycle: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    loop {
        run_cycle().await?;
        if let Some(url) = &config.webhook_url
            && let Err(error) =
                notify_webhook(url, &config.db_path, config.baseline_name.as_deref()).await
        {
            tracing::warn!(
                error = %error,
                "webhook notification failed; continuing watch loop"
            );
        }
        sleep(Duration::from_secs(config.interval_seconds.max(60))).await;
    }
}

pub async fn notify_webhook(url: &str, db_path: &Path, baseline_name: Option<&str>) -> Result<()> {
    let read_pool = crate::db::ReadOnlyPool::open(db_path)?;
    let summary = crate::server::build_api_summary(&read_pool)?;
    let (new_risks, resolved_risks) = if let Some(name) = baseline_name {
        let diff = crate::db::diff_baselines(db_path, name, "latest")?;
        (diff.new_risks.len(), diff.resolved_risks.len())
    } else {
        (0, 0)
    };

    let payload = build_alert_payload(
        "sshmap.watch.completed",
        &crate::security::webhook_database_label(db_path),
        summary.critical_risks,
        summary.high_risks,
        new_risks,
        resolved_risks,
        summary.stats.hosts,
        None,
    );
    send_webhook(url, &payload).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[tokio::test]
    async fn notify_webhook_rejects_private_target() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("watch.db");
        db::initialize_database(&db_path).expect("initialize");

        let error = notify_webhook("https://10.0.0.5/hook", &db_path, None)
            .await
            .expect_err("private webhook");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn webhook_database_label_uses_basename_only() {
        let label = crate::security::webhook_database_label(Path::new("/tmp/sshmap/prod.db"));
        assert_eq!(label, "prod.db");
    }
}
