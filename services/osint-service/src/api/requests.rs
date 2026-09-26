//! # API Request Modelleri
//! 
//! Türkçe: HTTP istekleri için veri modelleri ve validasyon.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Türkçe: Araştırma başlatma isteği
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct InvestigateRequest {
    /// Hedef (domain, IP, email)
    #[validate(length(min = 1, max = 255))]
    pub target: String,
    
    /// Çalıştırılacak modüller (boş ise otomatik tespit)
    #[serde(default)]
    pub modules: Vec<String>,
    
    /// Araştırma derinliği (1-3)
    #[serde(default = "default_depth")]
    #[validate(range(min = 1, max = 3))]
    pub depth: u8,
    
    /// Maksimum entity limiti
    #[serde(default = "default_max_entities")]
    #[validate(range(min = 1, max = 5000))]
    pub max_entities: u32,
}

fn default_depth() -> u8 { 2 }
fn default_max_entities() -> u32 { 500 }

/// Türkçe: DNS sorgu isteği
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DnsLookupRequest {
    /// Domain adı
    #[validate(length(min = 1, max = 255))]
    pub domain: String,
    
    /// Sorgulanacak kayıt tipleri (boş ise tümü)
    #[serde(default)]
    pub record_types: Vec<String>,
}

/// Türkçe: WHOIS sorgu isteği
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct WhoisLookupRequest {
    /// Domain adı
    #[validate(length(min = 1, max = 255))]
    pub domain: String,
}

/// Türkçe: SSL sertifika sorgu isteği
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SslLookupRequest {
    /// Domain adı (port dahil olabilir: example.com:443)
    #[validate(length(min = 1, max = 255))]
    pub host: String,
    
    /// Port (varsayılan 443)
    #[serde(default = "default_ssl_port")]
    pub port: u16,
}

fn default_ssl_port() -> u16 { 443 }

/// Türkçe: Subdomain keşfi isteği
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SubdomainLookupRequest {
    /// Ana domain
    #[validate(length(min = 1, max = 255))]
    pub domain: String,
    
    /// Brute-force modu (varsayılan passive)
    #[serde(default)]
    pub bruteforce: bool,
    
    /// Özel wordlist (brute-force için)
    #[serde(default)]
    pub wordlist: Option<String>,
    
    /// Maksimum sonuç sayısı
    #[serde(default = "default_max_subdomains")]
    #[validate(range(min = 1, max = 10000))]
    pub max_results: u32,
}

fn default_max_subdomains() -> u32 { 1000 }

/// Türkçe: IP intelligence isteği
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct IpLookupRequest {
    /// IP adresi
    #[validate(length(min = 7, max = 45))]  // IPv4 min: 0.0.0.0, IPv6 max
    pub ip: String,
}

/// Türkçe: Teknoloji tespiti isteği
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TechLookupRequest {
    /// URL veya domain
    #[validate(length(min = 1, max = 2048))]
    pub target: String,
}

/// Türkçe: Transform isteği (entity genişletme)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformRequest {
    /// Transform tipi
    pub transform_type: String,
    
    /// Ek parametreler
    #[serde(default)]
    pub params: serde_json::Value,
}

/// Türkçe: Şirket domain ekleme isteği
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AddDomainRequest {
    /// Domain adı
    #[validate(length(min = 1, max = 255))]
    pub domain: String,
    
    /// Organizasyon adı
    #[validate(length(min = 1, max = 255))]
    pub organization: String,
    
    /// Tarama planı
    #[serde(default = "default_schedule")]
    pub scan_schedule: String,
    
    /// Alarm ayarları
    #[serde(default)]
    pub alert_settings: Option<AlertSettings>,
}

fn default_schedule() -> String { "manual".to_string() }

/// Türkçe: Alarm ayarları
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSettings {
    pub new_subdomain: bool,
    pub ssl_expiry: bool,
    pub new_vulnerability: bool,
}

impl Default for AlertSettings {
    fn default() -> Self {
        Self {
            new_subdomain: true,
            ssl_expiry: true,
            new_vulnerability: true,
        }
    }
}

/// Türkçe: Rapor oluşturma isteği
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateReportRequest {
    /// Hedef domain
    #[validate(length(min = 1, max = 255))]
    pub target: String,
    
    /// Rapor başlığı
    #[serde(default)]
    pub title: Option<String>,
    
    /// Format (json, pdf, html, markdown)
    #[serde(default = "default_format")]
    pub format: String,
    
    /// Dahil edilecek tarama ID'leri
    #[serde(default)]
    pub scan_ids: Vec<String>,
}

fn default_format() -> String { "json".to_string() }

/// Türkçe: Entity listeleme için filtre
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityFilter {
    /// Entity tipi filtresi
    pub entity_type: Option<String>,
    
    /// Sayfalama - limit
    #[serde(default = "default_limit")]
    pub limit: i64,
    
    /// Sayfalama - skip
    #[serde(default)]
    pub skip: u64,
    
    /// Arama terimi
    pub search: Option<String>,
    
    /// Tag filtresi
    pub tags: Option<Vec<String>>,
}

fn default_limit() -> i64 { 50 }

/// Türkçe: Geçmiş listeleme için filtre
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryFilter {
    /// Domain filtresi
    pub domain: Option<String>,
    
    /// Başlangıç tarihi
    pub from_date: Option<String>,
    
    /// Bitiş tarihi
    pub to_date: Option<String>,
    
    /// Limit
    #[serde(default = "default_limit")]
    pub limit: i64,
}

/// Türkçe: Nmap sonuç callback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapResultCallback {
    pub scan_id: String,
    pub target: String,
    pub ports: Vec<PortResult>,
    pub os_detection: Option<serde_json::Value>,
    pub raw_output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

/// Türkçe: Nikto sonuç callback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NiktoResultCallback {
    pub scan_id: String,
    pub target: String,
    pub vulnerabilities: Vec<VulnResult>,
    pub server_info: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnResult {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub url: Option<String>,
    pub method: Option<String>,
    pub references: Vec<String>,
}

/// Türkçe: Nuclei sonuç callback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiResultCallback {
    pub scan_id: String,
    pub target: String,
    pub findings: Vec<NucleiFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiFinding {
    pub template_id: String,
    pub name: String,
    pub severity: String,
    pub matched_at: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub reference: Vec<String>,
    pub extracted_results: Option<Vec<String>>,
}

/// Türkçe: Genel hedef lookup isteği (IP veya domain için)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TargetLookupRequest {
    /// Hedef (IP veya domain)
    #[validate(length(min = 1, max = 255))]
    pub target: String,
}
