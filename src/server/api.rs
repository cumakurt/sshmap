use crate::graph;
use crate::models::RiskQuery;
use crate::server::{AppState, build_api_summary};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;

const API_LIMIT: usize = 10_000;
const API_FILTER_PARAM_MAX_BYTES: usize = 256;
const API_REF_PARAM_MAX_BYTES: usize = 512;
const VALID_RISK_SEVERITIES: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW"];

pub async fn health() -> &'static str {
    "ok"
}

pub async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());

    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }

    diff == 0
}

pub async fn read_auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !authorize_request(&state, &request, false) {
        return (StatusCode::UNAUTHORIZED, "invalid or missing API token").into_response();
    }
    next.run(request).await
}

pub async fn write_auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !authorize_request(&state, &request, true) {
        return (
            StatusCode::UNAUTHORIZED,
            "invalid or missing write API token",
        )
            .into_response();
    }
    next.run(request).await
}

fn authorize_request(
    state: &AppState,
    request: &Request<axum::body::Body>,
    require_write: bool,
) -> bool {
    if state.read_token.is_none() && state.write_token.is_none() {
        return true;
    }
    let Some(provided) = request
        .headers()
        .get("X-SSHMap-Token")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    if require_write {
        return state
            .write_token
            .as_deref()
            .is_some_and(|expected| constant_time_eq(provided, expected));
    }
    state
        .read_token
        .as_deref()
        .is_some_and(|expected| constant_time_eq(provided, expected))
        || state
            .write_token
            .as_deref()
            .is_some_and(|expected| constant_time_eq(provided, expected))
}

pub async fn summary(
    State(state): State<AppState>,
) -> Result<Json<crate::models::ApiSummary>, ApiError> {
    Ok(Json(build_api_summary(&state.read_pool)?))
}

pub async fn list_hosts(
    State(state): State<AppState>,
    Query(query): Query<HostListQuery>,
) -> Result<Json<Vec<crate::models::HostRecord>>, ApiError> {
    let source = optional_param(query.source, "source", API_FILTER_PARAM_MAX_BYTES)?
        .map(|value| value.to_ascii_lowercase());
    let search = optional_param(query.q, "q", API_FILTER_PARAM_MAX_BYTES)?;

    Ok(Json(crate::db::list_hosts_read_only_with_query(
        &state.read_pool,
        &crate::models::HostQuery {
            ssh_open: query.ssh_open,
            source,
            search,
            limit: query.limit.unwrap_or(1000).min(API_LIMIT),
        },
    )?))
}

#[derive(Debug, Deserialize)]
pub struct HostListQuery {
    pub ssh_open: Option<bool>,
    pub source: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
}

pub async fn get_host(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<crate::models::HostDetailRecord>, ApiError> {
    let id = required_param(&id, "host id", API_REF_PARAM_MAX_BYTES)?;
    let Some(host) = crate::db::get_host_detail_read_only(&state.read_pool, id)? else {
        return Err(ApiError::not_found("host not found"));
    };
    Ok(Json(host))
}

pub async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<UserListQuery>,
) -> Result<Json<Vec<crate::models::UserSummaryRecord>>, ApiError> {
    let search = optional_param(query.q, "q", API_FILTER_PARAM_MAX_BYTES)?;

    Ok(Json(crate::db::list_user_summaries_read_only_with_query(
        &state.read_pool,
        &crate::models::UserQuery {
            search,
            min_hosts: query.min_hosts,
            min_risks: query.min_risks,
            limit: query.limit.unwrap_or(500).min(API_LIMIT),
        },
    )?))
}

#[derive(Debug, Deserialize)]
pub struct UserListQuery {
    pub q: Option<String>,
    pub min_hosts: Option<usize>,
    pub min_risks: Option<usize>,
    pub limit: Option<usize>,
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<crate::models::UserDetailRecord>, ApiError> {
    let username = required_param(&username, "username", API_FILTER_PARAM_MAX_BYTES)?;
    let Some(user) = crate::db::get_user_detail_read_only(&state.read_pool, username)? else {
        return Err(ApiError::not_found("user not found"));
    };
    Ok(Json(user))
}

pub async fn list_keys(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::KeySummaryRecord>>, ApiError> {
    Ok(Json(crate::db::list_keys_read_only(
        &state.read_pool,
        API_LIMIT,
        false,
    )?))
}

pub async fn list_reused_keys(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::KeySummaryRecord>>, ApiError> {
    Ok(Json(crate::db::list_keys_read_only(
        &state.read_pool,
        API_LIMIT,
        true,
    )?))
}

pub async fn get_key(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> Result<Json<crate::models::KeyDetailRecord>, ApiError> {
    let target = required_param(&target, "key", API_REF_PARAM_MAX_BYTES)?;
    let Some(key) = crate::db::get_key_detail_read_only(&state.read_pool, target)? else {
        return Err(ApiError::not_found("key not found"));
    };
    Ok(Json(key))
}

#[derive(Debug, Deserialize)]
pub struct RiskListQuery {
    pub severity: Option<String>,
    pub code: Option<String>,
    pub limit: Option<usize>,
}

pub async fn list_risks(
    State(state): State<AppState>,
    Query(query): Query<RiskListQuery>,
) -> Result<Json<Vec<crate::models::RiskRecord>>, ApiError> {
    let severity = optional_param(query.severity, "severity", API_FILTER_PARAM_MAX_BYTES)?
        .map(|value| value.to_ascii_uppercase());
    if let Some(severity) = &severity
        && !VALID_RISK_SEVERITIES.contains(&severity.as_str())
    {
        return Err(ApiError::bad_request(
            "severity must be one of CRITICAL, HIGH, MEDIUM, or LOW",
        ));
    }

    Ok(Json(crate::db::list_risks_read_only(
        &state.read_pool,
        &RiskQuery {
            severity,
            code: optional_param(query.code, "code", API_FILTER_PARAM_MAX_BYTES)?
                .map(|value| value.to_ascii_uppercase()),
            limit: query.limit.unwrap_or(100).min(API_LIMIT),
        },
    )?))
}

pub async fn get_risk(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<crate::models::RiskRecord>, ApiError> {
    let Some(risk) = crate::db::get_risk_read_only(&state.read_pool, id)? else {
        return Err(ApiError::not_found("risk not found"));
    };
    Ok(Json(risk))
}

#[derive(Debug, Deserialize)]
pub struct GraphListQuery {
    pub limit: Option<usize>,
}

pub async fn list_graph(
    State(state): State<AppState>,
    Query(query): Query<GraphListQuery>,
) -> Result<Json<Vec<crate::models::GraphEdgeRecord>>, ApiError> {
    Ok(Json(crate::db::list_graph_edges_read_only_limited(
        &state.read_pool,
        query.limit.unwrap_or(1000).min(API_LIMIT),
    )?))
}

#[derive(Debug, Deserialize)]
pub struct PathQuery {
    pub from: String,
    pub to: String,
}

pub async fn find_path(
    State(state): State<AppState>,
    Query(query): Query<PathQuery>,
) -> Result<Json<crate::models::GraphPathRecord>, ApiError> {
    let from = required_param(&query.from, "from", API_REF_PARAM_MAX_BYTES)?;
    let to = required_param(&query.to, "to", API_REF_PARAM_MAX_BYTES)?;

    let Some(start) = crate::db::resolve_graph_node_ref_read_only(&state.read_pool, from)? else {
        return Err(ApiError::not_found("source graph node not found"));
    };
    let Some(end) = crate::db::resolve_graph_node_ref_read_only(&state.read_pool, to)? else {
        return Err(ApiError::not_found("destination graph node not found"));
    };
    let edges = crate::db::list_graph_edges_for_api_analysis(&state.read_pool)?;
    Ok(Json(graph::find_path(&edges, start, end)))
}

#[derive(Debug, Deserialize)]
pub struct BlastRadiusQuery {
    pub user: String,
}

pub async fn blast_radius(
    State(state): State<AppState>,
    Query(query): Query<BlastRadiusQuery>,
) -> Result<Json<crate::models::BlastRadiusRecord>, ApiError> {
    let username = required_param(&query.user, "user", API_FILTER_PARAM_MAX_BYTES)?;

    let entry_points =
        crate::db::list_user_nodes_by_username_read_only(&state.read_pool, username)?;
    if entry_points.is_empty() {
        return Err(ApiError::not_found("user not found"));
    }
    let edges = crate::db::list_graph_edges_for_api_analysis(&state.read_pool)?;
    Ok(Json(graph::compute_blast_radius(
        &edges,
        &entry_points,
        username,
    )))
}

#[derive(Debug, Deserialize)]
pub struct ScanRunListQuery {
    pub limit: Option<usize>,
}

pub async fn list_scan_runs(
    State(state): State<AppState>,
    Query(query): Query<ScanRunListQuery>,
) -> Result<Json<Vec<crate::models::ScanRunRecord>>, ApiError> {
    Ok(Json(crate::db::list_scan_runs_read_only(
        &state.read_pool,
        query.limit.unwrap_or(50).min(API_LIMIT),
    )?))
}

pub async fn get_scan_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<crate::models::ScanRunDetailRecord>, ApiError> {
    let id = required_param(&id, "scan run id", API_REF_PARAM_MAX_BYTES)?;
    let Some(run) = crate::db::get_scan_run_read_only(&state.read_pool, id)? else {
        return Err(ApiError::not_found("scan run not found"));
    };
    Ok(Json(run))
}

pub async fn list_baselines(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::BaselineRecord>>, ApiError> {
    Ok(Json(crate::db::list_baselines_read_only(&state.read_pool)?))
}

#[derive(Debug, Deserialize)]
pub struct CreateBaselineRequest {
    pub name: String,
}

pub async fn create_baseline(
    State(state): State<AppState>,
    Json(request): Json<CreateBaselineRequest>,
) -> Result<Json<crate::models::BaselineRecord>, ApiError> {
    ensure_write_enabled(&state)?;
    let name = required_param(&request.name, "baseline name", API_FILTER_PARAM_MAX_BYTES)?;
    Ok(Json(crate::db::create_baseline(&state.db_path, name)?))
}

#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    pub from: String,
    pub to: Option<String>,
}

pub async fn diff_baselines(
    State(state): State<AppState>,
    Query(query): Query<DiffQuery>,
) -> Result<Json<crate::models::BaselineDiffRecord>, ApiError> {
    let from = required_param(&query.from, "from", API_FILTER_PARAM_MAX_BYTES)?;
    let to = query.to.as_deref().unwrap_or("latest");
    let to = required_param(to, "to", API_FILTER_PARAM_MAX_BYTES)?;
    Ok(Json(crate::db::diff_baselines(&state.db_path, from, to)?))
}

pub async fn list_exceptions(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::RiskExceptionRecord>>, ApiError> {
    Ok(Json(crate::db::list_risk_exceptions_read_only(
        &state.read_pool,
    )?))
}

#[derive(Debug, Deserialize)]
pub struct AddExceptionRequest {
    pub code: String,
    pub reason: String,
    pub host_id: Option<i64>,
    pub username: Option<String>,
    pub fingerprint: Option<String>,
    pub expires_at: Option<String>,
}

pub async fn add_exception(
    State(state): State<AppState>,
    Json(request): Json<AddExceptionRequest>,
) -> Result<Json<crate::models::RiskExceptionRecord>, ApiError> {
    ensure_write_enabled(&state)?;
    let code = required_param(&request.code, "code", API_FILTER_PARAM_MAX_BYTES)?;
    let reason = required_param(&request.reason, "reason", API_REF_PARAM_MAX_BYTES)?;
    let exception = crate::models::NewRiskException {
        risk_code: code.to_ascii_uppercase(),
        host_id: request.host_id,
        username: request.username,
        public_key_fingerprint: request.fingerprint,
        reason: reason.to_string(),
        expires_at: request.expires_at,
    };
    crate::security::validate_new_risk_exception(&exception)
        .map_err(ApiError::bad_request_from_anyhow)?;
    Ok(Json(crate::db::add_risk_exception(
        &state.db_path,
        &exception,
    )?))
}

pub async fn remove_exception(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_write_enabled(&state)?;
    if !crate::db::remove_risk_exception(&state.db_path, id)? {
        return Err(ApiError::not_found("exception not found"));
    }
    Ok(Json(serde_json::json!({ "removed": true, "id": id })))
}

pub async fn list_known_hosts(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::KnownHostEntryRecord>>, ApiError> {
    Ok(Json(crate::db::list_known_host_entries_read_only(
        &state.read_pool,
        API_LIMIT,
    )?))
}

pub async fn list_ssh_config(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::SshClientConfigEntryRecord>>, ApiError> {
    Ok(Json(crate::db::list_ssh_client_config_entries_read_only(
        &state.read_pool,
        API_LIMIT,
    )?))
}

pub async fn list_host_aliases(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::HostAliasRecord>>, ApiError> {
    Ok(Json(crate::db::list_host_aliases_read_only(
        &state.read_pool,
        API_LIMIT,
    )?))
}

pub async fn list_data_quality(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::DataQualityFindingRecord>>, ApiError> {
    Ok(Json(crate::db::list_data_quality_findings_read_only(
        &state.read_pool,
        API_LIMIT,
    )?))
}

pub async fn get_remediation(
    Path(code): Path<String>,
) -> Result<Json<crate::models::RemediationRecord>, ApiError> {
    let code = required_param(&code, "code", API_FILTER_PARAM_MAX_BYTES)?;
    let Some(record) = crate::risk::remediation_for_code(code) else {
        return Err(ApiError::not_found("remediation not found"));
    };
    Ok(Json(record))
}

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn not_found(message: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.to_string(),
        }
    }

    fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    fn forbidden(message: &str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.to_string(),
        }
    }

    fn bad_request_from_anyhow(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }
}

fn ensure_write_enabled(state: &AppState) -> Result<(), ApiError> {
    if state.allow_write_api {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "write API is disabled; restart serve with --allow-write-api",
        ))
    }
}

#[derive(Debug, Deserialize)]
pub struct ComplianceQuery {
    pub framework: Option<String>,
}

pub async fn compliance_report(
    State(state): State<AppState>,
    Query(query): Query<ComplianceQuery>,
) -> Result<Json<crate::compliance::ComplianceReport>, ApiError> {
    let framework = optional_param(query.framework, "framework", API_FILTER_PARAM_MAX_BYTES)?
        .unwrap_or_else(|| "all".to_string());
    crate::security::validate_compliance_framework(&framework)
        .map_err(ApiError::bad_request_from_anyhow)?;
    let risk_codes = crate::db::list_active_risk_codes_read_only(&state.read_pool)?;
    Ok(Json(crate::compliance::build_compliance_report(
        &framework,
        &risk_codes,
    )))
}

pub async fn operations_metrics(
    State(state): State<AppState>,
) -> Result<Json<crate::models::OperationsMetricsRecord>, ApiError> {
    Ok(Json(crate::db::load_operations_metrics_read_only(
        &state.read_pool,
    )?))
}

pub async fn hardening_report(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::hardening::HostHardeningScore>>, ApiError> {
    let hosts = crate::db::list_hosts_read_only(&state.read_pool, API_LIMIT)?;
    let risks = crate::db::list_risks_read_only(
        &state.read_pool,
        &RiskQuery {
            severity: None,
            code: None,
            limit: API_LIMIT,
        },
    )?;
    Ok(Json(crate::hardening::compute_inventory_hardening(
        &hosts, &risks,
    )))
}

#[derive(Debug, Deserialize)]
pub struct PathsQuery {
    pub from: String,
    pub to: String,
    pub limit: Option<usize>,
}

pub async fn find_paths(
    State(state): State<AppState>,
    Query(query): Query<PathsQuery>,
) -> Result<Json<crate::models::GraphPathsRecord>, ApiError> {
    let from = required_param(&query.from, "from", API_REF_PARAM_MAX_BYTES)?;
    let to = required_param(&query.to, "to", API_REF_PARAM_MAX_BYTES)?;
    let Some(start) = crate::db::resolve_graph_node_ref_read_only(&state.read_pool, from)? else {
        return Err(ApiError::not_found("source graph node not found"));
    };
    let Some(end) = crate::db::resolve_graph_node_ref_read_only(&state.read_pool, to)? else {
        return Err(ApiError::not_found("destination graph node not found"));
    };
    let edges = crate::db::list_graph_edges_for_api_analysis(&state.read_pool)?;
    Ok(Json(graph::find_all_paths(
        &edges,
        start,
        end,
        query.limit.unwrap_or(10).min(100),
    )))
}

#[derive(Debug, Deserialize)]
pub struct KeyBlastRadiusQuery {
    pub fingerprint: String,
}

pub async fn key_blast_radius(
    State(state): State<AppState>,
    Query(query): Query<KeyBlastRadiusQuery>,
) -> Result<Json<crate::models::KeyCompromiseBlastRadiusRecord>, ApiError> {
    let fingerprint = required_param(&query.fingerprint, "fingerprint", API_REF_PARAM_MAX_BYTES)?;
    let normalized = fingerprint.strip_prefix("key:").unwrap_or(fingerprint);
    let entry_points =
        crate::db::list_public_key_nodes_by_fingerprint_read_only(&state.read_pool, normalized)?;
    if entry_points.is_empty() {
        return Err(ApiError::not_found("public key not found"));
    }
    let edges = crate::db::list_graph_edges_for_api_analysis(&state.read_pool)?;
    Ok(Json(graph::compute_key_compromise_blast_radius(
        &edges,
        normalized,
        &entry_points,
    )))
}

fn optional_param(
    value: Option<String>,
    name: &str,
    max_bytes: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };

    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > max_bytes {
        return Err(ApiError::bad_request(&format!(
            "{name} parameter must be at most {max_bytes} bytes"
        )));
    }

    Ok(Some(value.to_string()))
}

fn required_param<'a>(value: &'a str, name: &str, max_bytes: usize) -> Result<&'a str, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ApiError::bad_request(&format!(
            "{name} parameter is required"
        )));
    }
    if value.len() > max_bytes {
        return Err(ApiError::bad_request(&format!(
            "{name} parameter must be at most {max_bytes} bytes"
        )));
    }

    Ok(value)
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        tracing::debug!(error = %error, "api request failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_html_is_embedded() {
        let html = include_str!("dashboard.html");
        assert!(html.contains("SSHMap Dashboard"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq("short", "longer-value"));
    }

    #[test]
    fn rejects_invalid_exception_username() {
        let error = crate::security::validate_exception_username(Some("bad user"))
            .expect_err("invalid username");
        assert!(error.to_string().contains("username"));
    }

    #[test]
    fn constant_time_eq_accepts_matching_values() {
        assert!(constant_time_eq("secret-token", "secret-token"));
    }

    #[test]
    fn rejects_invalid_compliance_framework() {
        let error = crate::security::validate_compliance_framework("bad framework")
            .expect_err("invalid framework");
        assert!(error.to_string().contains("invalid characters"));
    }

    #[test]
    fn rejects_oversized_query_params() {
        let value = "x".repeat(API_FILTER_PARAM_MAX_BYTES + 1);
        let error = optional_param(Some(value), "q", API_FILTER_PARAM_MAX_BYTES)
            .expect_err("oversized param");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }
}
