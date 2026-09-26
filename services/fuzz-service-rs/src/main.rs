use std::sync::Arc;
use std::net::SocketAddr;
use axum::http::{Method, HeaderValue};
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod models;
mod services;
mod db;
mod api;

use config::Config;
use db::FuzzRepository;
use services::FeroxScanner;

pub struct AppState {
    pub db: Arc<FuzzRepository>,
    pub scanner: Arc<FeroxScanner>,
    pub config: Config,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tracing init
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "fuzz_service_rs=info,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Starting Fuzz Service (Rust + Feroxbuster)...");

    // Load config
    let config = Config::from_env();
    
    // Verify feroxbuster is available
    match FeroxScanner::version().await {
        Ok(version) => tracing::info!("Feroxbuster version: {}", version),
        Err(e) => {
            tracing::error!("Feroxbuster not found: {}. Please install feroxbuster.", e);
            return Err(anyhow::anyhow!("Feroxbuster not installed"));
        }
    }

    // Connect to MongoDB
    let db = FuzzRepository::connect(&config).await?;
    
    // Create scanner
    let scanner = FeroxScanner::new(config.wordlist_path.clone());

    let state = Arc::new(AppState {
        db: Arc::new(db),
        scanner: Arc::new(scanner),
        config: config.clone(),
    });

    // CORS
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:5173".parse::<HeaderValue>().unwrap(),
            "http://localhost:5566".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ]);

    // Build router
    let app = api::create_router(state)
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
