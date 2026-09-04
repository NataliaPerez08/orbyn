//! HTTP API (axum).
//!
//! Versioned endpoints live under `/api/v1`. This is the boundary for
//! CLI/UI/automation clients.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

use crate::domain::Asset;
use crate::store::traits::Store;

#[derive(Debug, Clone)]
pub struct AppState<S> {
    pub store: S,
}

/// Build the axum router for the current store backend.
pub fn router<S>(store: S) -> Router
where
    S: Store + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/assets", get(list_assets))
        .route("/api/v1/discovery/jobs", post(create_job))
        .with_state(AppState { store })
}

async fn healthz() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn list_assets<S>(State(state): State<AppState<S>>) -> Result<Json<Vec<Asset>>, StatusCode>
where
    S: Store,
{
    state
        .store
        .list_assets()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        .map(Json)
}

async fn create_job() -> StatusCode {
    // TODO(v0.1): wire discovery job creation once the job queue exists.
    StatusCode::NOT_IMPLEMENTED
}
