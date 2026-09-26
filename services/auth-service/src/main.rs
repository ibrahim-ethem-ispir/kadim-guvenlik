use axum::{
    Router,
    routing::{get, post, put, delete},
    http::{Method, HeaderValue},
    middleware,
};
use tower_http::cors::CorsLayer;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod db;
mod models;
mod auth;
mod handlers;
#[path = "middleware.rs"]
mod custom_middleware;

use config::Config;
use db::Database;

pub struct AppState {
    pub db: Database,
    pub config: Config,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tracing init
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "auth_service=info,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Starting Auth Service...");

    // Load Config
    let config = Config::from_env();
    
    // Connect DB
    let db = Database::connect(&config).await?;
    tracing::info!("Connected to MongoDB");

    let state = Arc::new(AppState {
        db,
        config: config.clone(),
    });

    // CORS - Türkçe: Güvenli CORS yapılandırması
    // Sadece belirtilen originlere izin ver
    let allowed_origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect();

    tracing::info!("CORS allowed origins: {:?}", config.allowed_origins);

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(false);

    // Türkçe: Protected routes (admin yetkisi gerekli)
    let protected_routes = Router::new()
        .route("/users", get(handlers::list_users))
        .route("/users/:id", put(handlers::update_user))
        .route("/users/:id", delete(handlers::delete_user))
        .route("/users/:id/password", put(handlers::change_password))
        .layer(middleware::from_fn(custom_middleware::admin_only_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            custom_middleware::auth_middleware,
        ));

    // Routes - Türkçe: Public ve protected route'ları birleştir
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/login", post(handlers::login))
        .route("/register", post(handlers::register))
        .merge(protected_routes)
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

