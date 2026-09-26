use std::env;
use dotenv::dotenv;

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub mongodb_uri: String,
    pub mongodb_database: String,
    pub jwt_secret: String,
    pub register_enabled: bool,
    // Türkçe: Yeni kayıt olan kullanıcılar otomatik olarak aktif mi olsun?
    // true = Hemen giriş yapabilir, false = Admin onayı gerekir
    pub auto_activate_users: bool,
    // Türkçe: CORS için izin verilen originler (virgülle ayrılmış)
    pub allowed_origins: Vec<String>,
}

impl Config {
    pub fn from_env() -> Self {
        dotenv().ok();

        let port = env::var("PORT")
            .unwrap_or_else(|_| "8007".to_string())
            .parse()
            .expect("PORT must be a number");

        let mongodb_uri = env::var("MONGODB_URI")
            .unwrap_or_else(|_| "mongodb://localhost:27017".to_string());

        let mongodb_database = env::var("MONGODB_DATABASE")
            .unwrap_or_else(|_| "kadim_security".to_string());

        let jwt_secret = env::var("JWT_SECRET")
            .expect("JWT_SECRET must be set");
            
        let register_enabled = env::var("REGISTER_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        // Türkçe: Yeni kullanıcılar otomatik aktif olsun mu?
        // true = Kayıt anında aktif (hemen giriş yapabilir)
        // false = Pasif başlar (admin onayı gerekir)
        let auto_activate_users = env::var("AUTO_ACTIVATE_USERS")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        // Türkçe: CORS için izin verilen originler
        // Örnek: "http://localhost:3000,https://dev.example-corp.com"
        let allowed_origins_str = env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:5173,https://dev.example-corp.com".to_string());

        let allowed_origins: Vec<String> = allowed_origins_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // JWT secret validation
        if jwt_secret.len() < 32 {
            panic!("JWT_SECRET must be at least 32 characters long for security");
        }

        Config {
            port,
            mongodb_uri,
            mongodb_database,
            jwt_secret,
            register_enabled,
            auto_activate_users,
            allowed_origins,
        }
    }
}

