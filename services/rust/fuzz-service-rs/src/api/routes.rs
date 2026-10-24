use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post},
};

use crate::AppState;
use super::handlers;

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health check
        .route("/health", get(handlers::health))
        
        // Legacy v1 endpoints (Python compatibility)
        .route("/scan", post(handlers::start_scan))
        .route("/wordlists", get(handlers::list_wordlists))
        .route("/logs/:scan_id", get(handlers::get_results))
        .route("/scan/monitor/:scan_id", get(handlers::stream_scan))
        
        // New v2 endpoints
        .route("/api/v2/scan", post(handlers::start_scan))
        .route("/api/v2/wordlists", get(handlers::list_wordlists))
        .route("/api/v2/scans/:scan_id/results", get(handlers::get_results))
        .route("/api/v2/scans/:scan_id/status", get(handlers::get_scan_status))
        .route("/api/v2/scans/:scan_id/stream", get(handlers::stream_scan))
        
        .with_state(state)
}
