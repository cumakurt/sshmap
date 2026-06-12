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
use tracing::error;

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

pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Some(expected) = &state.token {
        let authorized = request
            .headers()
            .get("X-SSHMap-Token")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| constant_time_eq(value, expected));
        if !authorized {
            return (StatusCode::UNAUTHORIZED, "invalid or missing API token").into_response();
        }
    }

    next.run(request).await
}

pub async fn summary(
    State(state): State<AppState>,
) -> Result<Json<crate::models::ApiSummary>, ApiError> {
    Ok(Json(build_api_summary(&state.db_path)?))
}

pub async fn list_hosts(
    State(state): State<AppState>,
    Query(query): Query<HostListQuery>,
) -> Result<Json<Vec<crate::models::HostRecord>>, ApiError> {
    let source = optional_param(query.source, "source", API_FILTER_PARAM_MAX_BYTES)?
        .map(|value| value.to_ascii_lowercase());
    let search = optional_param(query.q, "q", API_FILTER_PARAM_MAX_BYTES)?;

    Ok(Json(crate::db::list_hosts_read_only_with_query(
        &state.db_path,
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
    let Some(host) = crate::db::get_host_detail_read_only(&state.db_path, id)? else {
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
        &state.db_path,
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
    let Some(user) = crate::db::get_user_detail_read_only(&state.db_path, username)? else {
        return Err(ApiError::not_found("user not found"));
    };
    Ok(Json(user))
}

pub async fn list_keys(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::KeySummaryRecord>>, ApiError> {
    Ok(Json(crate::db::list_keys_read_only(
        &state.db_path,
        API_LIMIT,
        false,
    )?))
}

pub async fn list_reused_keys(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::KeySummaryRecord>>, ApiError> {
    Ok(Json(crate::db::list_keys_read_only(
        &state.db_path,
        API_LIMIT,
        true,
    )?))
}

pub async fn get_key(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> Result<Json<crate::models::KeyDetailRecord>, ApiError> {
    let target = required_param(&target, "key", API_REF_PARAM_MAX_BYTES)?;
    let Some(key) = crate::db::get_key_detail_read_only(&state.db_path, target)? else {
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
        &state.db_path,
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
    let Some(risk) = crate::db::get_risk_read_only(&state.db_path, id)? else {
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
        &state.db_path,
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

    let Some(start) = crate::db::resolve_graph_node_ref_read_only(&state.db_path, from)? else {
        return Err(ApiError::not_found("source graph node not found"));
    };
    let Some(end) = crate::db::resolve_graph_node_ref_read_only(&state.db_path, to)? else {
        return Err(ApiError::not_found("destination graph node not found"));
    };
    let edges = crate::db::list_graph_edges_for_analysis(&state.db_path)?;
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

    let entry_points = crate::db::list_user_nodes_by_username_read_only(&state.db_path, username)?;
    if entry_points.is_empty() {
        return Err(ApiError::not_found("user not found"));
    }
    let edges = crate::db::list_graph_edges_for_analysis(&state.db_path)?;
    Ok(Json(graph::compute_blast_radius(
        &edges,
        &entry_points,
        username,
    )))
}

pub async fn list_baselines(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::BaselineRecord>>, ApiError> {
    Ok(Json(crate::db::list_baselines_read_only(&state.db_path)?))
}

pub async fn list_exceptions(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::RiskExceptionRecord>>, ApiError> {
    Ok(Json(crate::db::list_risk_exceptions_read_only(
        &state.db_path,
    )?))
}

pub async fn list_known_hosts(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::KnownHostEntryRecord>>, ApiError> {
    Ok(Json(crate::db::list_known_host_entries_read_only(
        &state.db_path,
        API_LIMIT,
    )?))
}

pub async fn list_ssh_config(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::SshClientConfigEntryRecord>>, ApiError> {
    Ok(Json(crate::db::list_ssh_client_config_entries_read_only(
        &state.db_path,
        API_LIMIT,
    )?))
}

pub async fn list_host_aliases(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::HostAliasRecord>>, ApiError> {
    Ok(Json(crate::db::list_host_aliases_read_only(
        &state.db_path,
        API_LIMIT,
    )?))
}

pub async fn list_data_quality(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::DataQualityFindingRecord>>, ApiError> {
    Ok(Json(crate::db::list_data_quality_findings_read_only(
        &state.db_path,
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
        error!(error = ?error, "api request failed");
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
    fn constant_time_eq_accepts_matching_values() {
        assert!(constant_time_eq("secret-token", "secret-token"));
    }

    #[test]
    fn rejects_oversized_query_params() {
        let value = "x".repeat(API_FILTER_PARAM_MAX_BYTES + 1);
        let error = optional_param(Some(value), "q", API_FILTER_PARAM_MAX_BYTES)
            .expect_err("oversized param");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }
}
