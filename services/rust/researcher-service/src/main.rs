//! # Kadim Güvenlik - Zero-Day Research Service
//! 
//! Modern web framework zafiyetlerini tespit eden gelişmiş güvenlik analiz motoru.
//! 
//! ## Özellikler
//! - Teknoloji Tespiti (recon-service entegrasyonu)
//! - JavaScript Bundle Analizi (secrets, hidden endpoints)
//! - Headless Browser DOM Analizi (XSS, Hydration)
//! - Smart API Fuzzing (IDOR, Rate Limit)
//! - CVE Tarama (nuclei-service entegrasyonu)

mod config;
mod models;
mod api;
mod analyzer;
mod services;

use axum::{
    Router,
    routing::{get, post},
    http::Method,
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::AppConfig;

/// Uygulama durumu - Tüm handler'lar tarafından paylaşılır
pub struct AppState {
    pub config: AppConfig,
    pub http_client: reqwest::Client,
    pub db: Option<mongodb::Database>,
}

#[tokio::main]
async fn main() {
    // Tracing başlat
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "researcher_service=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("🔬 Zero-Day Researcher Service başlatılıyor...");

    // Konfigürasyon yükle
    let config = AppConfig::from_env();
    let port = config.port;

    // HTTP client oluştur
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("Kadim-Researcher/1.0")
        .danger_accept_invalid_certs(true) // Test için
        .build()
        .expect("HTTP client oluşturulamadı");

    // MongoDB bağlantısı
    let db = connect_mongodb(&config).await;

    // Shared state
    let state = Arc::new(AppState {
        config,
        http_client,
        db,
    });

    // CORS ayarları
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    // Router oluştur
    let app = Router::new()
        // Health check
        .route("/health", get(api::health_check))
        // Scan endpoints
        .route("/scan", post(api::start_scan))
        .route("/scan/:id", get(api::get_scan_status))
        .route("/scan/:id/stop", post(api::stop_scan))
        // WebSocket for live logs
        .route("/ws/:scan_id", get(api::websocket_handler))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Server başlat
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("🚀 Server dinleniyor: http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// MongoDB bağlantısı (retry ile)
async fn connect_mongodb(config: &AppConfig) -> Option<mongodb::Database> {
    for attempt in 1..=3 {
        tracing::info!("MongoDB bağlantı denemesi {}/3...", attempt);
        
        match mongodb::Client::with_uri_str(&config.mongodb_uri).await {
            Ok(client) => {
                // Ping test
                if client.database("admin").run_command(mongodb::bson::doc! {"ping": 1}, None).await.is_ok() {
                    tracing::info!("✅ MongoDB bağlantısı başarılı");
                    return Some(client.database(&config.mongodb_database));
                }
            }
            Err(e) => {
                tracing::warn!("MongoDB bağlantı hatası: {}", e);
            }
        }
        
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    
    tracing::warn!("⚠️ MongoDB bağlantısı kurulamadı, servis DB'siz çalışacak");
    None
}
