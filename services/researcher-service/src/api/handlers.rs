//! API Handler'ları

use axum::{
    extract::{Path, State, WebSocketUpgrade},
    response::Response,
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use std::collections::HashMap;

use crate::AppState;
use crate::models::{ResearchScan, ScanRequest, ScanStatus, ScanDepth};
use crate::analyzer::ResearchEngine;

// Aktif taramalar (bellek içi)
lazy_static::lazy_static! {
    pub static ref ACTIVE_SCANS: RwLock<HashMap<String, ResearchScan>> = RwLock::new(HashMap::new());
    // Canlı log yayını için kanallar (JSON string taşır)
    pub static ref SCAN_CHANNELS: RwLock<HashMap<String, broadcast::Sender<String>>> = RwLock::new(HashMap::new());
    // İptal edilebilmesi için çalışan task handle'ları
    pub static ref ACTIVE_TASKS: RwLock<HashMap<String, tokio::task::AbortHandle>> = RwLock::new(HashMap::new());
}

/// API yanıt wrapper'ı
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

/// Health check endpoint
pub async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "researcher-service",
        "version": "1.0.0",
        "capabilities": [
            "tech_detection",
            "js_analysis",
            "headless_browser",
            "smart_fuzzing"
        ]
    }))
}

/// Yeni tarama başlat
pub async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> Json<ApiResponse<ScanStartResponse>> {
    // URL validation
    if let Err(e) = url::Url::parse(&request.url) {
        return Json(ApiResponse::error(format!("Geçersiz URL: {}", e)));
    }
    
    // Scan ID oluştur
    let scan_id = uuid::Uuid::new_v4().to_string();
    
    // Modüller belirle
    let modules = if request.modules.is_empty() {
        default_modules_for_depth(&request.depth)
    } else {
        request.modules.clone()
    };
    
    // Tarama kaydı oluştur
    let scan = ResearchScan::new(
        scan_id.clone(),
        request.url.clone(),
        request.depth.clone(),
        modules.clone(),
    );
    
    // Aktif taramalara ekle
    {
        let mut scans = ACTIVE_SCANS.write().await;
        scans.insert(scan_id.clone(), scan);
    }
    
    // Kanal oluştur
    let (tx, _) = broadcast::channel(100);
    {
        let mut channels = SCAN_CHANNELS.write().await;
        channels.insert(scan_id.clone(), tx);
    }
    
    // Arka planda taramayı başlat
    let scan_id_clone = scan_id.clone();
    let state_clone = state.clone();
    
    let handle = tokio::spawn(async move {
        run_scan(state_clone, scan_id_clone).await;
    });
    
    // Task handle'ı kaydet
    ACTIVE_TASKS.write().await.insert(scan_id.clone(), handle.abort_handle());
    
    Json(ApiResponse::success(ScanStartResponse {
        scan_id,
        status: "pending".to_string(),
        message: "Tarama başlatıldı".to_string(),
    }))
}

/// Tarama durumu sorgula
pub async fn get_scan_status(
    Path(scan_id): Path<String>,
) -> Json<ApiResponse<ScanStatusResponse>> {
    let scans = ACTIVE_SCANS.read().await;
    
    match scans.get(&scan_id) {
        Some(scan) => {
            Json(ApiResponse::success(ScanStatusResponse {
                id: scan.id.clone(),
                status: scan.status.clone(),
                target_url: scan.target_url.clone(),
                domain: scan.domain.clone(),
                technologies: scan.technologies.clone(),
                findings: scan.findings.clone(),
                secrets: scan.secrets.clone(),
                discovered_endpoints: scan.discovered_endpoints.clone(),
                logs: scan.logs.iter().rev().take(50).cloned().collect(),
                risk_score: scan.risk_score,
                started_at: scan.started_at.to_rfc3339(),
                completed_at: scan.completed_at.map(|t| t.to_rfc3339()),
                error: scan.error.clone(),
            }))
        }
        None => Json(ApiResponse::error("Tarama bulunamadı")),
    }
}

/// Taramayı durdur
pub async fn stop_scan(
    Path(scan_id): Path<String>,
) -> Json<ApiResponse<String>> {
    let mut scans = ACTIVE_SCANS.write().await;
    
    if let Some(scan) = scans.get_mut(&scan_id) {
        if scan.status == ScanStatus::Running || scan.status == ScanStatus::Pending {
            scan.status = ScanStatus::Cancelled;
            scan.add_log("warn", "core", "Tarama kullanıcı tarafından durduruldu");
            
            // Task'ı abort et ve sil
            {
                let mut tasks = ACTIVE_TASKS.write().await;
                if let Some(handle) = tasks.remove(&scan_id) {
                    handle.abort();
                }
            }
            // Logu kanala gönder (websocket'ten düşsün)
            let channels = SCAN_CHANNELS.read().await;
            if let Some(tx) = channels.get(&scan_id) {
                 let _ = tx.send(serde_json::json!({
                    "type": "log",
                     "data": scan.logs.last().unwrap()
                 }).to_string());
                 
                 let _ = tx.send(serde_json::json!({
                    "type": "complete",
                    "status": "cancelled",
                    "risk_score": scan.risk_score
                 }).to_string());
            }

            return Json(ApiResponse::success("Tarama durduruldu".to_string()));
        }
    }
    
    Json(ApiResponse::error("Tarama durdurulamadı"))
}

/// WebSocket handler (canlı log stream)
pub async fn websocket_handler(
    Path(scan_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_websocket(socket, scan_id))
}

async fn handle_websocket(
    mut socket: axum::extract::ws::WebSocket,
    scan_id: String,
) {
    use axum::extract::ws::Message;
    
    // Kanala abone ol
    let mut rx = {
        let channels = SCAN_CHANNELS.read().await;
        match channels.get(&scan_id) {
            Some(tx) => tx.subscribe(),
            None => {
                let _ = socket.send(Message::Text(serde_json::json!({
                    "type": "error",
                    "message": "Tarama kanalı bulunamadı"
                }).to_string())).await;
                return;
            }
        }
    };
    
    // Mevcut logları gönder (geçmiş)
    {
        let scans = ACTIVE_SCANS.read().await;
        if let Some(scan) = scans.get(&scan_id) {
            for log in &scan.logs {
                let msg = serde_json::json!({
                    "type": "log",
                    "data": log
                });
                if socket.send(Message::Text(msg.to_string())).await.is_err() {
                    return;
                }
            }
            
            // Eğer tarama zaten bittiyse durumu gönder
            if scan.status != ScanStatus::Running && scan.status != ScanStatus::Pending {
                let msg = serde_json::json!({
                    "type": "complete",
                    "status": scan.status,
                    "risk_score": scan.risk_score
                });
                let _ = socket.send(Message::Text(msg.to_string())).await;
                return;
            }
        }
    }
    
    // Canlı akışı dinle
    while let Ok(msg) = rx.recv().await {
        if socket.send(Message::Text(msg)).await.is_err() {
            break;
        }
    }
}

/// Tarama çalıştır
async fn run_scan(state: Arc<AppState>, scan_id: String) {
    // Status'u running yap
    {
        let mut scans = ACTIVE_SCANS.write().await;
        if let Some(scan) = scans.get_mut(&scan_id) {
            scan.status = ScanStatus::Running;
            scan.add_log("info", "core", "🔬 Tarama başlıyor...");
        }
    }
    
    // Research engine oluştur
    let engine = ResearchEngine::new(state);
    
    // Taramayı çalıştır
    match engine.run(&scan_id).await {
        Ok(_) => {
            let mut scans = ACTIVE_SCANS.write().await;
            if let Some(scan) = scans.get_mut(&scan_id) {
                if scan.status == ScanStatus::Running {
                    scan.status = ScanStatus::Completed;
                    scan.completed_at = Some(chrono::Utc::now());
                    scan.add_log("info", "core", "✅ Tarama tamamlandı");
                    
                    // Risk skoru hesapla
                    scan.risk_score = Some(calculate_risk_score(scan));
                    
                    // Bitiş mesajını kanala gönder
                    let channels = SCAN_CHANNELS.read().await;
                    if let Some(tx) = channels.get(&scan_id) {
                        let msg = serde_json::json!({
                            "type": "complete",
                            "status": scan.status,
                            "risk_score": scan.risk_score
                        });
                        let _ = tx.send(msg.to_string());
                    }
                }
            }
        }
        Err(e) => {
            let mut scans = ACTIVE_SCANS.write().await;
            if let Some(scan) = scans.get_mut(&scan_id) {
                scan.status = ScanStatus::Failed;
                scan.error = Some(e.to_string());
                scan.add_log("error", "core", &format!("❌ Tarama hatası: {}", e));
                
                // Hata mesajını kanala gönder
                let channels = SCAN_CHANNELS.read().await;
                if let Some(tx) = channels.get(&scan_id) {
                    let msg = serde_json::json!({
                        "type": "complete",
                        "status": scan.status,
                        "error": scan.error
                    });
                    let _ = tx.send(msg.to_string());
                }
            }
        }
    }
    
    // Handle'ı temizle
    ACTIVE_TASKS.write().await.remove(&scan_id);
    
    // Kanalı temizle (biraz bekleyip?)
    // SCAN_CHANNELS.write().await.remove(&scan_id);
}
    


/// Derinliğe göre varsayılan modüller
fn default_modules_for_depth(depth: &ScanDepth) -> Vec<String> {
    match depth {
        ScanDepth::Quick => vec!["fingerprint".to_string()],
        ScanDepth::Standard => vec![
            "fingerprint".to_string(),
            "js_analysis".to_string(),
        ],
        ScanDepth::Deep => vec![
            "fingerprint".to_string(),
            "js_analysis".to_string(),
            "cve_scan".to_string(),
            "fuzzing".to_string(),
        ],
        ScanDepth::Aggressive => vec![
            "fingerprint".to_string(),
            "js_analysis".to_string(),
            "cve_scan".to_string(),
            "browser".to_string(),
            "fuzzing".to_string(),
        ],
    }
}

/// Risk skoru hesapla
fn calculate_risk_score(scan: &ResearchScan) -> u8 {
    use crate::models::Severity;
    
    let mut score: u32 = 0;
    
    for finding in &scan.findings {
        score += match finding.severity {
            Severity::Critical => 30,
            Severity::High => 20,
            Severity::Medium => 10,
            Severity::Low => 5,
            Severity::Info => 1,
        };
    }
    
    // Secret başına +15
    score += (scan.secrets.len() as u32) * 15;
    
    // 100'ü geçmemeli
    score.min(100) as u8
}

// Response types
#[derive(Debug, Serialize)]
pub struct ScanStartResponse {
    pub scan_id: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ScanStatusResponse {
    pub id: String,
    pub status: ScanStatus,
    pub target_url: String,
    pub domain: String,
    pub technologies: Vec<crate::models::DetectedTechnology>,
    pub findings: Vec<crate::models::Finding>,
    pub secrets: Vec<crate::models::SecretFinding>,
    pub discovered_endpoints: Vec<String>,
    pub logs: Vec<crate::models::ScanLog>,
    pub risk_score: Option<u8>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}
