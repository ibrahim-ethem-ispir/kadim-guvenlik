//! Konfigürasyon modülü

use std::env;

/// Uygulama konfigürasyonu
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub port: u16,
    pub mongodb_uri: String,
    pub mongodb_database: String,
    
    // Servis URL'leri
    pub recon_service_url: String,
    pub osint_service_url: String,
    pub nuclei_service_url: String,
    
    // Analiz ayarları
    pub scan_timeout_secs: u64,
    pub max_js_file_size: usize,
    pub headless_browser_enabled: bool,
}

impl AppConfig {
    /// Environment variable'lardan konfigürasyon yükle
    pub fn from_env() -> Self {
        Self {
            port: env::var("PORT")
                .unwrap_or_else(|_| "8008".to_string())
                .parse()
                .expect("PORT geçerli bir sayı olmalı"),
            
            mongodb_uri: env::var("MONGODB_URI")
                .unwrap_or_else(|_| "mongodb://kadim:kadim_secure_2024@mongodb:27017".to_string()),
            
            mongodb_database: env::var("MONGODB_DATABASE")
                .unwrap_or_else(|_| "kadim_security".to_string()),
            
            // Mevcut servislerin URL'leri
            recon_service_url: env::var("RECON_SERVICE_URL")
                .unwrap_or_else(|_| "http://recon-service:8004".to_string()),
            
            osint_service_url: env::var("OSINT_SERVICE_URL")
                .unwrap_or_else(|_| "http://osint-service:8005".to_string()),
            
            nuclei_service_url: env::var("NUCLEI_SERVICE_URL")
                .unwrap_or_else(|_| "http://nuclei-service:8003".to_string()),
            
            // Analiz limitleri
            scan_timeout_secs: env::var("SCAN_TIMEOUT_SECS")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .unwrap_or(300),
            
            max_js_file_size: env::var("MAX_JS_FILE_SIZE")
                .unwrap_or_else(|_| "5242880".to_string()) // 5MB default
                .parse()
                .unwrap_or(5242880),
            
            headless_browser_enabled: env::var("HEADLESS_BROWSER_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        }
    }
}
