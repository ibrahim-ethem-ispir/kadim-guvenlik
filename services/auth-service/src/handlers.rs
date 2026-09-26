use axum::{
    extract::{State, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use mongodb::bson::{doc, oid::ObjectId};
use std::sync::Arc;
use serde_json::json;
use futures::stream::StreamExt;
use crate::{AppState, models::{LoginRequest, LoginResponse, RegisterRequest, UpdateUserRequest, ChangePasswordRequest, User, UserResponse}, auth};

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let collection = state.db.db.collection::<User>("users");
    
    // Find user by username
    let user = match collection.find_one(doc! {"username": &payload.username}, None).await {
        Ok(Some(user)) => user,
        Ok(None) => return (StatusCode::UNAUTHORIZED, Json(json!({
            "error": "Geçersiz kullanıcı adı veya şifre"
        }))).into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Veritabanı hatası"
        }))).into_response(),
    };
    
    // Türkçe: Kullanıcı aktif mi kontrol et
    if !user.is_active {
        return (StatusCode::FORBIDDEN, Json(json!({
            "error": "Hesabınız henüz aktif değil. Admin onayı bekleniyor."
        }))).into_response();
    }
    
    // Verify password
    if !auth::verify_password(&payload.password, &user.password_hash) {
        return (StatusCode::UNAUTHORIZED, Json(json!({
            "error": "Geçersiz kullanıcı adı veya şifre"
        }))).into_response();
    }
    
    // Generate Token
    let token = match auth::create_jwt(&user.username, &user.role, &state.config) {
        Ok(token) => token,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Token oluşturma hatası"
        }))).into_response(),
    };
    
    // Update last login
    let _ = collection.update_one(
        doc! {"username": &user.username},
        doc! {"$set": {"last_login": mongodb::bson::DateTime::from(chrono::Utc::now())}},
        None
    ).await;

    let response = LoginResponse {
        token,
        username: user.username,
        role: user.role,
    };

    (StatusCode::OK, Json(response)).into_response()
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Check if registration is enabled
    if !state.config.register_enabled {
         return (StatusCode::FORBIDDEN, Json(json!({
             "error": "Kayıt işlemi devre dışı"
         }))).into_response();
    }

    // Türkçe: Şifre validasyonu
    if payload.password.len() < 6 {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "Şifre en az 6 karakter olmalıdır"
        }))).into_response();
    }

    // Türkçe: Kullanıcı adı validasyonu (alfanumerik ve bazı özel karakterler)
    if payload.username.len() < 3 {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "Kullanıcı adı en az 3 karakter olmalıdır"
        }))).into_response();
    }

    if !payload.username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "Kullanıcı adı sadece harf, rakam, tire ve alt çizgi içerebilir"
        }))).into_response();
    }

    let collection = state.db.db.collection::<User>("users");

    // Check if user exists
    match collection.find_one(doc! {"username": &payload.username}, None).await {
        Ok(Some(_)) => return (StatusCode::CONFLICT, Json(json!({
            "error": "Bu kullanıcı adı zaten kullanılıyor"
        }))).into_response(),
        Err(e) => {
            tracing::error!("Database error during find_one: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                "error": "Veritabanı hatası"
            }))).into_response()
        },
        _ => {}
    };

    // Hash password
    let password_hash = match auth::hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Password hashing error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                "error": "Şifre işleme hatası"
            }))).into_response()
        },
    };

    // Türkçe: auto_activate_users ayarına göre kullanıcı aktifliğini belirle
    let new_user = User {
        id: None,
        username: payload.username.clone(),
        password_hash,
        role: "viewer".to_string(), // Default role
        is_active: state.config.auto_activate_users,
        created_at: chrono::Utc::now(),
        last_login: None,
    };

    match collection.insert_one(new_user, None).await {
        Ok(_) => {
            if state.config.auto_activate_users {
                (StatusCode::CREATED, Json(json!({
                    "message": "Kayıt başarılı! Şimdi giriş yapabilirsiniz."
                }))).into_response()
            } else {
                (StatusCode::CREATED, Json(json!({
                    "message": "Kayıt başarılı! Admin onayı bekleniyor."
                }))).into_response()
            }
        },
        Err(e) => {
            tracing::error!("Database error during insert_one: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                "error": "Kullanıcı oluşturulamadı"
            }))).into_response()
        },
    }
}

// Türkçe: Tüm kullanıcıları listele (Admin endpoint)
pub async fn list_users(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let collection = state.db.db.collection::<User>("users");
    
    let mut cursor = match collection.find(None, None).await {
        Ok(cursor) => cursor,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Kullanıcılar getirilemedi"
        }))).into_response(),
    };

    let mut users: Vec<UserResponse> = Vec::new();
    
    while let Some(result) = cursor.next().await {
        if let Ok(user) = result {
            users.push(UserResponse {
                id: user.id.map(|id| id.to_hex()).unwrap_or_default(),
                username: user.username,
                role: user.role,
                is_active: user.is_active,
                created_at: user.created_at,
                last_login: user.last_login,
            });
        }
    }

    (StatusCode::OK, Json(json!({ "users": users }))).into_response()
}

// Türkçe: Kullanıcı güncelle (role, is_active)
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    let collection = state.db.db.collection::<User>("users");
    
    let object_id = match ObjectId::parse_str(&user_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "Geçersiz kullanıcı ID"
        }))).into_response(),
    };

    let mut update_doc = doc! {};
    
    if let Some(role) = &payload.role {
        update_doc.insert("role", role);
    }
    
    if let Some(is_active) = payload.is_active {
        update_doc.insert("is_active", is_active);
    }

    if update_doc.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "Güncelleme için en az bir alan gerekli"
        }))).into_response();
    }

    match collection.update_one(
        doc! {"_id": object_id},
        doc! {"$set": update_doc},
        None
    ).await {
        Ok(result) => {
            if result.matched_count == 0 {
                (StatusCode::NOT_FOUND, Json(json!({
                    "error": "Kullanıcı bulunamadı"
                }))).into_response()
            } else {
                (StatusCode::OK, Json(json!({
                    "message": "Kullanıcı güncellendi"
                }))).into_response()
            }
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Güncelleme hatası"
        }))).into_response(),
    }
}

// Türkçe: Kullanıcı sil
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let collection = state.db.db.collection::<User>("users");
    
    let object_id = match ObjectId::parse_str(&user_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "Geçersiz kullanıcı ID"
        }))).into_response(),
    };

    match collection.delete_one(doc! {"_id": object_id}, None).await {
        Ok(result) => {
            if result.deleted_count == 0 {
                (StatusCode::NOT_FOUND, Json(json!({
                    "error": "Kullanıcı bulunamadı"
                }))).into_response()
            } else {
                (StatusCode::OK, Json(json!({
                    "message": "Kullanıcı silindi"
                }))).into_response()
            }
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Silme hatası"
        }))).into_response(),
    }
}

// Türkçe: Kullanıcı şifresini değiştir (Admin)
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let collection = state.db.db.collection::<User>("users");
    
    // Türkçe: Şifre validasyonu
    if payload.new_password.len() < 6 {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "Şifre en az 6 karakter olmalıdır"
        }))).into_response();
    }
    
    let object_id = match ObjectId::parse_str(&user_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "Geçersiz kullanıcı ID"
        }))).into_response(),
    };

    // Türkçe: Yeni şifreyi hashle
    let password_hash = match auth::hash_password(&payload.new_password) {
        Ok(hash) => hash,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Şifre işleme hatası"
        }))).into_response(),
    };

    match collection.update_one(
        doc! {"_id": object_id},
        doc! {"$set": {"password_hash": password_hash}},
        None
    ).await {
        Ok(result) => {
            if result.matched_count == 0 {
                (StatusCode::NOT_FOUND, Json(json!({
                    "error": "Kullanıcı bulunamadı"
                }))).into_response()
            } else {
                (StatusCode::OK, Json(json!({
                    "message": "Şifre başarıyla değiştirildi"
                }))).into_response()
            }
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Şifre güncelleme hatası"
        }))).into_response(),
    }
}


