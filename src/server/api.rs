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

pub async fn health() -> &'static str {
    "ok"
}

pub async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
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
            .is_some_and(|value| value == expected);
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
    Ok(Json(crate::db::list_hosts_read_only_with_query(
        &state.db_path,
        &crate::models::HostQuery {
            ssh_open: query.ssh_open,
            source: query.source.map(|value| value.to_ascii_lowercase()),
            search: query
                .q
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
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
    let Some(host) = crate::db::get_host_detail_read_only(&state.db_path, &id)? else {
        return Err(ApiError::not_found("host not found"));
    };
    Ok(Json(host))
}

pub async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<UserListQuery>,
) -> Result<Json<Vec<crate::models::UserSummaryRecord>>, ApiError> {
    Ok(Json(crate::db::list_user_summaries_read_only_with_query(
        &state.db_path,
        &crate::models::UserQuery {
            search: query
                .q
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
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
    let Some(user) = crate::db::get_user_detail_read_only(&state.db_path, &username)? else {
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
    let Some(key) = crate::db::get_key_detail_read_only(&state.db_path, &target)? else {
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
    Ok(Json(crate::db::list_risks_read_only(
        &state.db_path,
        &RiskQuery {
            severity: query.severity.map(|value| value.to_ascii_uppercase()),
            code: query.code.map(|value| value.to_ascii_uppercase()),
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

pub async fn list_graph(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::GraphEdgeRecord>>, ApiError> {
    Ok(Json(crate::db::list_graph_edges_read_only(&state.db_path)?))
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
    let Some(start) = crate::db::resolve_graph_node_ref_read_only(&state.db_path, &query.from)?
    else {
        return Err(ApiError::not_found("source graph node not found"));
    };
    let Some(end) = crate::db::resolve_graph_node_ref_read_only(&state.db_path, &query.to)? else {
        return Err(ApiError::not_found("destination graph node not found"));
    };
    let edges = crate::db::list_graph_edges_read_only(&state.db_path)?;
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
    let entry_points =
        crate::db::list_user_nodes_by_username_read_only(&state.db_path, &query.user)?;
    if entry_points.is_empty() {
        return Err(ApiError::not_found("user not found"));
    }
    let edges = crate::db::list_graph_edges_read_only(&state.db_path)?;
    Ok(Json(graph::compute_blast_radius(
        &edges,
        &entry_points,
        &query.user,
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
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
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
    #[test]
    fn dashboard_html_is_embedded() {
        let html = include_str!("dashboard.html");
        assert!(html.contains("SSHMap Dashboard"));
    }
}
