mod api;

use crate::models::ApiSummary;
use anyhow::{Context, Result, bail};
use axum::{Router, middleware, routing::get};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub db_path: PathBuf,
    pub listen: SocketAddr,
    pub read_only: bool,
    pub token: Option<String>,
    pub dashboard_dir: Option<PathBuf>,
}

#[derive(Clone)]
pub struct AppState {
    pub db_path: PathBuf,
    pub token: Option<String>,
}

pub async fn run_server(config: ServerConfig) -> Result<()> {
    if !config.db_path.exists() {
        bail!("database not found: {}", config.db_path.display());
    }

    if !config.read_only {
        bail!("sshmap serve currently supports read-only mode only; pass --read-only");
    }

    if let Some(dashboard_dir) = config.dashboard_dir.as_deref() {
        validate_dashboard_dir(dashboard_dir)?;
    }

    let token = normalize_api_token(config.token)?;

    if token.is_none() {
        if !config.listen.ip().is_loopback() {
            bail!(
                "--token is required when listening on a non-loopback address ({})",
                config.listen.ip()
            );
        }
        eprintln!(
            "Warning: API token authentication is disabled; use only on trusted loopback interfaces."
        );
    }

    let state = AppState {
        db_path: config.db_path.clone(),
        token: token.clone(),
    };

    let app = build_app(state, config.dashboard_dir.clone());

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind to {}", config.listen))?;

    println!(
        "SSHMap read-only server listening on http://{}",
        config.listen
    );
    println!("Database: {}", config.db_path.display());
    if let Some(dashboard_dir) = &config.dashboard_dir {
        println!("Dashboard: {}", dashboard_dir.display());
    } else {
        println!("Dashboard: embedded HTML");
    }
    if token.is_some() {
        println!("API token authentication: enabled");
    }

    axum::serve(listener, app)
        .await
        .context("sshmap server terminated with error")?;

    Ok(())
}

fn normalize_api_token(token: Option<String>) -> Result<Option<String>> {
    let Some(token) = token else {
        return Ok(None);
    };

    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("API token cannot be empty or whitespace");
    }
    if token.chars().any(char::is_control) {
        bail!("API token cannot contain control characters");
    }

    Ok(Some(token))
}

pub fn build_app(state: AppState, dashboard_dir: Option<PathBuf>) -> Router {
    let protected = Router::new()
        .route("/api/summary", get(api::summary))
        .route("/api/hosts", get(api::list_hosts))
        .route("/api/hosts/{id}", get(api::get_host))
        .route("/api/users", get(api::list_users))
        .route("/api/users/{username}", get(api::get_user))
        .route("/api/keys", get(api::list_keys))
        .route("/api/keys/reuse", get(api::list_reused_keys))
        .route("/api/keys/{target}", get(api::get_key))
        .route("/api/risks", get(api::list_risks))
        .route("/api/risks/{id}", get(api::get_risk))
        .route("/api/graph", get(api::list_graph))
        .route("/api/path", get(api::find_path))
        .route("/api/blast-radius", get(api::blast_radius))
        .route("/api/baselines", get(api::list_baselines))
        .route("/api/exceptions", get(api::list_exceptions))
        .route("/api/known-hosts", get(api::list_known_hosts))
        .route("/api/ssh-config", get(api::list_ssh_config))
        .route("/api/host-aliases", get(api::list_host_aliases))
        .route("/api/data-quality", get(api::list_data_quality))
        .route("/api/remediation/{code}", get(api::get_remediation))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::auth_middleware,
        ))
        .with_state(state.clone());

    let mut app = Router::new()
        .merge(protected)
        .route("/health", get(api::health));

    if let Some(dashboard_dir) = dashboard_dir {
        let index = dashboard_dir.join("index.html");
        app = app.fallback_service(
            ServeDir::new(dashboard_dir).not_found_service(ServeFile::new(index)),
        );
    } else {
        app = app.route("/", get(api::dashboard));
    }

    app.layer(TraceLayer::new_for_http()).with_state(state)
}

fn validate_dashboard_dir(path: &Path) -> Result<()> {
    if !path.is_dir() {
        bail!("dashboard directory not found: {}", path.display());
    }
    if !path.join("index.html").is_file() {
        bail!(
            "dashboard directory {} is missing index.html; run npm run build in dashboard/",
            path.display()
        );
    }
    Ok(())
}

pub fn build_api_summary(db_path: &std::path::Path) -> Result<ApiSummary> {
    let stats = crate::db::load_database_stats_read_only(db_path)?;
    let hosts = crate::db::list_hosts_read_only(db_path, 10_000)?;
    let reused_keys = crate::db::list_keys_read_only(db_path, 10_000, true)?;
    let (critical_risks, high_risks) = crate::db::count_open_risks_by_severity_read_only(db_path)?;

    Ok(ApiSummary {
        ssh_open_hosts: hosts.iter().filter(|host| host.ssh_open).count(),
        critical_risks,
        high_risks,
        reused_keys: reused_keys.len(),
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer;
    use crate::bench::seed_benchmark_database;
    use crate::models::AnalyzeScope;
    use crate::risk::RiskPolicy;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::path::Path;
    use tower::ServiceExt;

    fn seed_api_test_database(path: &Path) -> anyhow::Result<()> {
        crate::db::initialize_database(path)?;
        seed_benchmark_database(path, 5)?;
        analyzer::run_analysis(path, AnalyzeScope::All, &RiskPolicy::default(), false)?;
        Ok(())
    }

    async fn api_response(app: &Router, uri: &str, token: Option<&str>) -> (StatusCode, String) {
        let mut request = Request::builder().uri(uri);
        if let Some(token) = token {
            request = request.header("X-SSHMap-Token", token);
        }

        let response = app
            .clone()
            .oneshot(
                request
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("request failed");

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("failed to read body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[test]
    fn rejects_missing_dashboard_index() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let error = validate_dashboard_dir(temp_dir.path()).expect_err("missing index");
        assert!(error.to_string().contains("index.html"));
    }

    #[test]
    fn rejects_empty_api_token() {
        let error = normalize_api_token(Some("  ".to_string())).expect_err("empty token");
        assert!(error.to_string().contains("cannot be empty"));
    }

    #[tokio::test]
    async fn summary_and_filtered_list_endpoints_return_json() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("api-test.db");
        seed_api_test_database(&db_path).expect("seed database");

        let app = build_app(
            AppState {
                db_path: db_path.clone(),
                token: Some("secret-token".to_string()),
            },
            None,
        );

        let (status, body) = api_response(&app, "/api/summary", Some("secret-token")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"stats\""));
        assert!(body.contains("\"critical_risks\""));

        let (status, _body) = api_response(&app, "/api/summary", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, all_hosts) =
            api_response(&app, "/api/hosts?limit=1000", Some("secret-token")).await;
        assert_eq!(status, StatusCode::OK);
        let all_hosts_json: serde_json::Value =
            serde_json::from_str(&all_hosts).expect("hosts json");
        let all_host_rows = all_hosts_json.as_array().expect("hosts array");
        assert!(!all_host_rows.is_empty());

        let (status, open_hosts) = api_response(
            &app,
            "/api/hosts?ssh_open=true&limit=1000",
            Some("secret-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let open_hosts_json: serde_json::Value =
            serde_json::from_str(&open_hosts).expect("open hosts json");
        for host in open_hosts_json.as_array().expect("open hosts array") {
            assert_eq!(host["ssh_open"].as_bool(), Some(true));
        }

        let (status, risks) =
            api_response(&app, "/api/risks?limit=1000", Some("secret-token")).await;
        assert_eq!(status, StatusCode::OK);
        let risks_json: serde_json::Value = serde_json::from_str(&risks).expect("risks json");
        assert!(!risks_json.as_array().expect("risks array").is_empty());

        if let Some(first_risk) = risks_json.as_array().and_then(|rows| rows.first()) {
            let severity = first_risk["severity"]
                .as_str()
                .expect("risk severity")
                .to_string();
            let (status, filtered) = api_response(
                &app,
                &format!("/api/risks?severity={severity}&limit=1000"),
                Some("secret-token"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let filtered_json: serde_json::Value =
                serde_json::from_str(&filtered).expect("filtered risks json");
            for risk in filtered_json.as_array().expect("filtered risks array") {
                assert_eq!(risk["severity"].as_str(), Some(severity.as_str()));
            }
        }

        let (status, users) = api_response(
            &app,
            "/api/users?min_hosts=1&limit=1000",
            Some("secret-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let users_json: serde_json::Value = serde_json::from_str(&users).expect("users json");
        for user in users_json.as_array().expect("users array") {
            assert!(user["host_count"].as_u64().unwrap_or(0) >= 1);
        }

        let (status, _) = api_response(&app, "/api/hosts/missing-host", Some("secret-token")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        assert!(all_host_rows.len() >= open_hosts_json.as_array().map_or(0, |rows| rows.len()));
    }
}
