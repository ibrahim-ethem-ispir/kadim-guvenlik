//! # Konfigürasyon Modülü
//! 
//! Türkçe: Environment variable'lardan konfigürasyon yükleme.
//! Docker container içinde çalışacağından tüm ayarlar env'den gelir.

use std::env;

/// Uygulama konfigürasyonu
#[derive(Clone, Debug)]
pub struct AppConfig {
    /// Türkçe: Sunucunun dinleyeceği port
    pub port: u16,
    
    /// Türkçe: MongoDB bağlantı URI'si
    pub mongodb_uri: String,
    
    /// Türkçe: MongoDB veritabanı adı
    pub mongodb_database: String,
    

    
    /// Türkçe: Orchestrator servisi URL'si
    pub orchestrator_url: String,
    
    /// Türkçe: Nmap servisi URL'si (entegrasyon için)
    pub nmap_service_url: String,
    
    /// Türkçe: Subfinder servisi URL'si (entegrasyon için)
    pub subfinder_service_url: String,
    
    /// Türkçe: Nuclei servisi URL'si (entegrasyon için)
    pub nuclei_service_url: String,
    
    // External API Keys - Opsiyonel
    /// Türkçe: Shodan API anahtarı (IP intelligence için)
    pub shodan_api_key: Option<String>,
    
    /// Türkçe: VirusTotal API anahtarı (reputation check için)
    pub virustotal_api_key: Option<String>,
    
    /// Türkçe: SecurityTrails API anahtarı (subdomain discovery için)
    pub securitytrails_api_key: Option<String>,
    
    /// Türkçe: Rate limit - dakikadaki maksimum istek sayısı
    pub rate_limit_per_minute: u32,
    
    /// Türkçe: OSINT sorgularında timeout (saniye)
    pub osint_timeout_secs: u64,
}

impl AppConfig {
    /// Environment variable'lardan konfigürasyon yükle
    pub fn from_env() -> Self {
        Self {
            port: env::var("PORT")
                .unwrap_or_else(|_| "8010".to_string())
                .parse()
                .expect("PORT geçerli bir sayı olmalı"),
            
            mongodb_uri: env::var("MONGODB_URI")
                .unwrap_or_else(|_| "mongodb://mongodb:27017".to_string()),
            
            mongodb_database: env::var("MONGODB_DATABASE")
                .unwrap_or_else(|_| "kadim_osint".to_string()),
            

            
            orchestrator_url: env::var("ORCHESTRATOR_URL")
                .unwrap_or_else(|_| "http://orchestrator:8000".to_string()),
            
            nmap_service_url: env::var("NMAP_SERVICE_URL")
                .unwrap_or_else(|_| "http://nmap-service:8001".to_string()),
            
            subfinder_service_url: env::var("SUBFINDER_SERVICE_URL")
                .unwrap_or_else(|_| "http://subfinder-service:8010".to_string()),
            
            nuclei_service_url: env::var("NUCLEI_SERVICE_URL")
                .unwrap_or_else(|_| "http://nuclei-service:8003".to_string()),
            
            shodan_api_key: env::var("SHODAN_API_KEY").ok().filter(|s| !s.is_empty()),
            virustotal_api_key: env::var("VIRUSTOTAL_API_KEY").ok().filter(|s| !s.is_empty()),
            securitytrails_api_key: env::var("SECURITYTRAILS_API_KEY").ok().filter(|s| !s.is_empty()),
            
            rate_limit_per_minute: env::var("RATE_LIMIT_PER_MINUTE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
            
            osint_timeout_secs: env::var("OSINT_TIMEOUT_SECS")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
        }
    }
}
