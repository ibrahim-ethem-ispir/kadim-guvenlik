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
    // JWT_SECRET ZORUNLU — bilinen varsayılan anahtarla doğrulama YAPILMAZ (fail-closed).
    let secret = match env::var("JWT_SECRET") {
        Ok(s) if s.len() >= 32 => s,
        _ => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("JWT_SECRET yapılandırması eksik veya çok kısa (min 32)")),
            ));
        }
    };

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
