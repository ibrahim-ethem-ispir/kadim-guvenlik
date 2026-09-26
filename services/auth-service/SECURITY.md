# Auth Service - Güvenlik Dokümantasyonu

## Yapılan Güvenlik İyileştirmeleri

### 1. Authentication & Authorization

#### JWT Middleware
- Tüm admin endpoint'leri JWT middleware ile korunmaktadır
- Token doğrulama: `auth_middleware`
- Admin yetki kontrolü: `admin_only_middleware`

#### Korunan Endpoint'ler
- `GET /users` - Kullanıcı listesi (Admin)
- `PUT /users/:id` - Kullanıcı güncelleme (Admin)
- `DELETE /users/:id` - Kullanıcı silme (Admin)
- `PUT /users/:id/password` - Şifre değiştirme (Admin)

#### Public Endpoint'ler
- `GET /health` - Sağlık kontrolü
- `POST /login` - Giriş yapma
- `POST /register` - Kayıt olma (REGISTER_ENABLED=true ise)

### 2. CORS Güvenliği

#### Önceki Durum (GÜVENSİZ!)
```rust
let cors = CorsLayer::new()
    .allow_origin(Any)  // ❌ TÜM ORIGINLERE İZİN!
    .allow_methods([...])
    .allow_headers(Any);
```

#### Yeni Durum (GÜVENLİ!)
```rust
let cors = CorsLayer::new()
    .allow_origin(allowed_origins)  // ✅ SADECE BELİRTİLEN ORIGINLER
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
    .allow_headers([CONTENT_TYPE, AUTHORIZATION])
    .allow_credentials(false);
```

#### Yapılandırma
`.env` dosyasında:
```env
ALLOWED_ORIGINS=http://localhost:5173,https://dev.example-corp.com
```

### 3. Input Validation

#### Şifre Validasyonu
- Minimum 6 karakter
- Kayıt ve şifre değiştirmede kontrol edilir

#### Kullanıcı Adı Validasyonu
- Minimum 3 karakter
- Sadece alfanumerik karakterler, tire (-) ve alt çizgi (_)
- SQL injection ve XSS koruması

### 4. JWT Secret Güvenliği
- JWT secret minimum 32 karakter olmalı
- Uygulama başlarken kontrol edilir
- Yetersiz uzunlukta secret ile uygulama başlamaz

### 5. Password Hashing
- Argon2 algoritması kullanılır (endüstri standardı)
- Salt otomatik oluşturulur
- Rainbow table saldırılarına karşı korumalı

### 6. MongoDB Güvenliği
- Username alanı unique index
- Duplicate key hatalarına karşı korumalı

### 7. Error Handling
- Detaylı hata mesajları loglarda
- Kullanıcıya genel hata mesajları
- Sensitive bilgi sızıntısı yok

## Güvenlik Kontrol Listesi

### Deployment Öncesi
- [ ] JWT_SECRET en az 32 karakter ve güçlü
- [ ] ALLOWED_ORIGINS production domain'i içeriyor
- [ ] REGISTER_ENABLED production'da false
- [ ] AUTO_ACTIVATE_USERS production'da false
- [ ] MongoDB connection string güvenli
- [ ] HTTPS kullanılıyor (production)

### Düzenli Kontroller
- [ ] Dependency güncellemeleri (cargo audit)
- [ ] JWT token'ların süresi uygun (24 saat)
- [ ] Log dosyalarında sensitive data yok
- [ ] Rate limiting (gelecekte eklenecek)

## Bilinen Limitasyonlar

### İyileştirme Gereken Alanlar
1. **Rate Limiting**: Brute force saldırılarına karşı endpoint bazlı rate limiting eklenebilir
2. **Token Refresh**: Refresh token mekanizması eklenebilir
3. **Account Lockout**: Başarısız giriş denemelerinde hesap kilitleme
4. **IP Whitelist**: Kritik işlemler için IP kontrolü
5. **2FA**: İki faktörlü kimlik doğrulama
6. **Audit Logging**: Tüm admin işlemleri için detaylı log

## Önerilen Environment Variables

```env
# Zorunlu
PORT=8007
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=kadim_security
JWT_SECRET=<32+ karakter güçlü secret>
ALLOWED_ORIGINS=http://localhost:5173,https://dev.example-corp.com

# Opsiyonel
REGISTER_ENABLED=false
AUTO_ACTIVATE_USERS=false
RUST_LOG=info,auth_service=debug
```

## Güvenlik İletişimi
Güvenlik açığı bildirimleri için: [güvenlik ekibi iletişim bilgisi]

---

**Son Güncelleme**: 2026-01-08
**Versiyon**: 0.1.0
