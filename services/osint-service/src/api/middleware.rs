use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::env;
use crate::api::responses::ApiResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}

pub async fn auth_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, Json<ApiResponse<()>>)> {
    // 1. Get Authorization Header
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            &header[7..]
        }
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::error("Missing or invalid Authorization header")),
            ));
        }
    };

    // 2. Refresh Secret from Env
    // Ideally passed via State, but env var is simpler for middleware signature
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "super_secret_kadim_key_123!".to_string());

    // 3. Verify Token
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true; // Validate expiration

    match decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_bytes()), &validation) {
        Ok(_) => {
            // Token valid, proceed
             Ok(next.run(req).await)
        }
        Err(err) => {
            tracing::warn!("JWT Validation failed: {}", err);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::error("Invalid or expired token")),
            ))
        }
    }
}
