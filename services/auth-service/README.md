# Auth Service - Kimlik Doğrulama ve Yetkilendirme Servisi

Kadim Güvenlik Sistemi için güvenli authentication ve user management servisi.

## 🔐 Özellikler

- ✅ JWT tabanlı kimlik doğrulama
- ✅ Argon2 ile güvenli şifre hashleme
- ✅ Role-based access control (Admin/Viewer)
- ✅ User activation system
- ✅ Güvenli CORS yapılandırması
- ✅ Input validation
- ✅ MongoDB ile kullanıcı yönetimi

## 🚀 Kurulum

### Environment Variables

`.env` dosyası oluşturun:

```env
# Server
PORT=8007

# Database
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=kadim_security

# Security (ÇOK ÖNEMLİ: En az 32 karakter!)
JWT_SECRET=your-super-secret-jwt-key-min-32-chars-please-change-this

# Features
REGISTER_ENABLED=false
AUTO_ACTIVATE_USERS=false

# CORS (virgülle ayrılmış)
ALLOWED_ORIGINS=http://localhost:5173,https://app.example.com

# Logging
RUST_LOG=info,auth_service=debug
```

### Docker ile Çalıştırma

```bash
docker-compose up -d auth-service
```

### Geliştirme (Yerel)

```bash
cargo build --release
cargo run
```

## 📡 API Endpoints

### Public Endpoints

#### Health Check
```http
GET /health
```

#### Login
```http
POST /login
Content-Type: application/json

{
  "username": "admin",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJ...",
  "username": "admin",
  "role": "admin"
}
```

#### Register
```http
POST /register
Content-Type: application/json

{
  "username": "newuser",
  "password": "password123"
}
```

**Note:** `REGISTER_ENABLED=true` olmalı

---

### Protected Endpoints (Admin Only)

**Authentication Required:** `Authorization: Bearer <token>`

**Role Required:** `admin`

#### List Users
```http
GET /users
Authorization: Bearer <token>
```

#### Update User
```http
PUT /users/{id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "role": "viewer",
  "is_active": true
}
```

#### Delete User
```http
DELETE /users/{id}
Authorization: Bearer <token>
```

#### Change Password
```http
PUT /users/{id}/password
Authorization: Bearer <token>
Content-Type: application/json

{
  "new_password": "newpassword123"
}
```

## 🔒 Güvenlik

### Authentication Flow

```
1. User -> POST /login -> Auth Service
2. Auth Service -> Verify credentials -> MongoDB
3. Auth Service -> Generate JWT -> User
4. User -> Request with JWT -> Protected Endpoint
5. Middleware -> Validate JWT -> Allow/Deny
```

### Authorization Layers

```
Request
  ↓
CORS Layer (Origin check)
  ↓
Auth Middleware (JWT validation)
  ↓
Admin Middleware (Role check)
  ↓
Handler (Business logic)
```

### Güvenlik Özellikleri

1. **Password Hashing**: Argon2 (industry standard)
2. **JWT Tokens**: 24 saat geçerlilik
3. **CORS**: Sadece izin verilen originler
4. **Input Validation**:
   - Şifre min. 6 karakter
   - Kullanıcı adı min. 3 karakter, alfanumerik
5. **Role-Based Access**: Admin vs Viewer
6. **User Activation**: Manuel veya otomatik

## 🛠️ Development

### Test

```bash
cargo test
```

### Linting

```bash
cargo clippy
```

### Format

```bash
cargo fmt
```

### Security Audit

```bash
cargo audit
```

## 📊 Logging

Structured JSON logging kullanılır:

```bash
# Log seviyelerini ayarla
RUST_LOG=debug cargo run

# Sadece auth_service logları
RUST_LOG=auth_service=debug cargo run
```

## 🔧 Yapılandırma

### CORS

Development:
```env
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000
```

Production:
```env
ALLOWED_ORIGINS=https://app.example.com,https://app.domain.com
```

### User Registration

Kayıt açık:
```env
REGISTER_ENABLED=true
AUTO_ACTIVATE_USERS=true  # Otomatik aktif
```

Kayıt kapalı (production):
```env
REGISTER_ENABLED=false
AUTO_ACTIVATE_USERS=false  # Manuel onay gerekli
```

## 📝 Database Schema

### Users Collection

```json
{
  "_id": ObjectId("..."),
  "username": "admin",
  "password_hash": "$argon2id$v=19$m=...",
  "role": "admin",
  "is_active": true,
  "created_at": "2024-01-08T10:00:00Z",
  "last_login": "2024-01-08T15:30:00Z"
}
```

**Indexes:**
- `username`: unique

**Roles:**
- `admin`: Tüm yetkilere sahip
- `viewer`: Sadece okuma yetkisi

## 🚨 Troubleshooting

### JWT Secret Hatası
```
JWT_SECRET must be at least 32 characters long for security
```
**Çözüm:** `.env` dosyasında `JWT_SECRET` değerini en az 32 karaktere çıkarın.

### CORS Hatası
```
Access to fetch blocked by CORS policy
```
**Çözüm:** `ALLOWED_ORIGINS` içine frontend URL'ini ekleyin.

### 401 Unauthorized
- Token süresi dolmuş olabilir (24 saat)
- Token yanlış veya eksik
- Authorization header formatı: `Bearer <token>`

### 403 Forbidden
- Kullanıcı admin değil
- Endpoint sadece admin erişimine açık

## 📚 Daha Fazla Bilgi

- [SECURITY.md](./SECURITY.md) - Güvenlik dokümantasyonu
- [../../../DEGISIKLIK_RAPORU.md](../../../DEGISIKLIK_RAPORU.md) - Değişiklik raporu

## 📄 License

[License bilgisi]

---

**Version:** 0.1.0
**Last Updated:** 2026-01-08
