//! # Kadim Güvenlik - OSINT Intelligence Service
//! 
//! Maltego benzeri OSINT (Open Source Intelligence) yetenekleri sunan
//! yüksek performanslı Rust servisi.
//! 
//! ## Özellikler
//! - Domain Intelligence (DNS, WHOIS, SSL)
//! - IP Intelligence (Geolocation, ASN, Reputation)
//! - Email Intelligence (MX, SPF/DKIM/DMARC)
//! - Technology Fingerprinting
//! - Graph görselleştirme için entity-relationship modeli
//! - MongoDB'de tarihsel kayıt tutma
//! 
//! ## Güvenlik
//! - Input validation her katmanda
//! - Rate limiting external API çağrıları için
//! - Audit logging tüm işlemler için

mod config;
mod db;
mod api;
mod osint;
mod models;
mod graph;
mod integrations;  // External API entegrasyonları (Shodan, VirusTotal, AbuseIPDB)
// mod utils;

use axum::{
    Router,
    routing::{get, post, delete},
    http::{Method, HeaderValue},
    middleware,
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::AppConfig;
use crate::db::Database;
use crate::integrations::IntegrationManager;

/// Uygulama durumu - Tüm handler'lar tarafından paylaşılır
pub struct AppState {
    pub db: Database,
    pub config: AppConfig,
    /// Türkçe: Threat Intelligence entegrasyonları (Shodan, VirusTotal, AbuseIPDB)
    pub integrations: IntegrationManager,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Türkçe: Tracing/logging yapılandırması
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "osint_service=info,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("🚀 Kadim OSINT Service başlatılıyor...");

    // Türkçe: Konfigürasyonu yükle
    let config = AppConfig::from_env();
    tracing::info!("📝 Konfigürasyon yüklendi");

    // Türkçe: Veritabanı bağlantılarını kur
    let db = Database::connect(&config).await?;
    tracing::info!("🗄️ MongoDB ve Redis bağlantıları kuruldu");

    // Türkçe: Uygulama durumunu oluştur
    let integrations = IntegrationManager::new();
    tracing::info!("🔌 Threat Intelligence entegrasyonları yüklendi (Shodan: {}, VirusTotal: {}, AbuseIPDB: {})", 
        integrations.shodan.is_available(),
        integrations.virustotal.is_available(),
        integrations.abuseipdb.is_available()
    );
    
    let state = Arc::new(AppState { db, config: config.clone(), integrations });

    // Türkçe: CORS yapılandırması (sadece internal network)
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    // Protected Routes (Require JWT)
    let protected_routes = Router::new()
        // Investigation endpoints - OSINT araştırma
        .route("/investigate", post(api::handlers::start_investigation))
        .route("/investigate/:id", get(api::handlers::get_investigation))
        .route("/investigate/:id", delete(api::handlers::cancel_investigation))
        
        // Entity operations - Varlık işlemleri
        .route("/entities", get(api::handlers::list_entities))
        .route("/entities/:id", get(api::handlers::get_entity))
        .route("/entities/:id/transform", post(api::handlers::transform_entity))
        .route("/entities/:id/relationships", get(api::handlers::get_entity_relationships))
        
        // Graph operations - Graf işlemleri
        .route("/graph/:domain", get(api::handlers::get_domain_graph))
        
        // History & Reporting - Geçmiş ve raporlama
        .route("/history", get(api::handlers::list_history))
        .route("/history/:domain", get(api::handlers::get_domain_history))
        .route("/reports", post(api::handlers::create_report))
        .route("/reports/:id", get(api::handlers::get_report))
        
        // Domain management - Şirket domain yönetimi
        .route("/domains", get(api::handlers::list_domains))
        .route("/domains", post(api::handlers::add_domain))
        .route("/domains/:id", delete(api::handlers::remove_domain))
        .route("/domains/:id/scan", post(api::handlers::scan_domain))
        
        // Quick OSINT lookups - Hızlı OSINT sorguları
        .route("/lookup/dns", post(api::handlers::dns_lookup))
        .route("/lookup/whois", post(api::handlers::whois_lookup))
        .route("/lookup/ssl", post(api::handlers::ssl_lookup))
        .route("/lookup/subdomains", post(api::handlers::subdomain_lookup))
        .route("/lookup/ip", post(api::handlers::ip_lookup))
        .route("/lookup/tech", post(api::handlers::tech_lookup))
        
        // Türkçe: External Threat Intelligence API'leri
        .route("/lookup/shodan", post(api::handlers::shodan_lookup))
        .route("/lookup/virustotal", post(api::handlers::virustotal_lookup))
        .route("/lookup/abuseipdb", post(api::handlers::abuseipdb_lookup))
        .route("/lookup/reputation", post(api::handlers::reputation_lookup))
        
        // Internal callbacks - Diğer servislerden gelen sonuçlar
        .route("/internal/nmap-result", post(api::handlers::receive_nmap_result))
        .route("/internal/nikto-result", post(api::handlers::receive_nikto_result))
        .route("/internal/nuclei-result", post(api::handlers::receive_nuclei_result))
        
        // Stats - İstatistikler
        .route("/stats", get(api::handlers::get_stats))

        // Domain Profile (Aggregated Endpoint)
        .route("/profile/:target", get(api::handlers::get_domain_profile))
        
        .layer(middleware::from_fn(crate::api::middleware::auth_middleware));


    // Türkçe: Router'ı oluştur
    let app = Router::new()
        // Health check (Public)
        .route("/health", get(api::handlers::health_check))
        .merge(protected_routes)
        
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state);

    // Türkçe: Sunucuyu başlat
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("🌐 Sunucu {} adresinde dinliyor", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
