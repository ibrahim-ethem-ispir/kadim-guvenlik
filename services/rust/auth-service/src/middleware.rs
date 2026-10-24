use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde_json::json;
use std::sync::Arc;
use crate::{AppState, auth::Claims};

// Türkçe: JWT token'ı doğrula ve kullanıcı bilgilerini al
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Authorization header'ı al
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Token bulunamadı" })),
            )
                .into_response())
        }
    };

    // Token'ı doğrula
    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data,
        Err(err) => {
            tracing::warn!("JWT validation failed: {:?}", err);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Geçersiz veya süresi dolmuş token" })),
            )
                .into_response());
        }
    };

    // Kullanıcı bilgilerini request extension'a ekle
    request.extensions_mut().insert(token_data.claims);

    Ok(next.run(request).await)
}

// Türkçe: Sadece admin yetkisi kontrolü
pub async fn admin_only_middleware(
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Extension'dan claims'i al
    let claims = request.extensions().get::<Claims>().cloned();

    match claims {
        Some(claims) if claims.role == "admin" => Ok(next.run(request).await),
        Some(_) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Bu işlem için admin yetkisi gereklidir" })),
        )
            .into_response()),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Yetkilendirme hatası" })),
        )
            .into_response()),
    }
}
