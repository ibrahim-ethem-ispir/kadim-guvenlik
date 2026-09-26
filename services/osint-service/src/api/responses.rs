//! # API Response Modelleri
//! 
//! Türkçe: HTTP yanıtları için veri modelleri.

use serde::{Deserialize, Serialize};

/// Türkçe: Genel API yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: None,
        }
    }
    
    pub fn success_with_message(data: T, message: &str) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: Some(message.to_string()),
        }
    }
    
    pub fn error(error: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.to_string()),
            message: None,
        }
    }
}

/// Türkçe: Araştırma başlatma yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationStarted {
    pub scan_id: String,
    pub status: String,
    pub message: String,
    pub target: String,
    pub modules: Vec<String>,
}

/// Türkçe: Araştırma durumu yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationStatus {
    pub scan_id: String,
    pub status: String,
    pub progress: u8,
    pub entity_count: u32,
    pub relationship_count: u32,
    pub current_module: Option<String>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}

/// Türkçe: Graf verisi yanıtı (frontend görselleştirme için)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub stats: GraphStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub label: String,
    pub icon: String,
    pub color: String,
    pub properties: serde_json::Value,
    pub confidence: f64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub edge_type: String,
    pub label: String,
    pub color: String,
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub total_nodes: u32,
    pub total_edges: u32,
    pub node_types: serde_json::Value,
    pub edge_types: serde_json::Value,
}

/// Türkçe: DNS sorgu yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookupResponse {
    pub domain: String,
    pub records: DnsRecords,
    pub resolved_ips: Vec<String>,
    pub cached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecords {
    #[serde(default)]
    pub a: Vec<String>,
    #[serde(default)]
    pub aaaa: Vec<String>,
    #[serde(default)]
    pub mx: Vec<MxRecord>,
    #[serde(default)]
    pub txt: Vec<String>,
    #[serde(default)]
    pub ns: Vec<String>,
    #[serde(default)]
    pub cname: Vec<String>,
    #[serde(default)]
    pub soa: Option<SoaRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecord {
    pub priority: u16,
    pub exchange: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoaRecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// Türkçe: WHOIS yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResponse {
    pub domain: String,
    pub registrar: Option<String>,
    pub registrant: Option<String>,
    pub created_date: Option<String>,
    pub updated_date: Option<String>,
    pub expiry_date: Option<String>,
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub dnssec: Option<bool>,
    pub raw: Option<String>,
    pub cached: bool,
}

/// Türkçe: SSL sertifika yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslResponse {
    pub host: String,
    pub port: u16,
    pub valid: bool,
    pub subject: SslSubject,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub expired: bool,
    pub days_until_expiry: i64,
    pub san: Vec<String>,
    pub fingerprint_sha256: String,
    pub protocol_version: String,
    pub cipher_suite: Option<String>,
    pub chain_valid: bool,
    pub cached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslSubject {
    pub cn: String,
    pub organization: Option<String>,
    pub country: Option<String>,
}

/// Türkçe: Subdomain keşfi yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResponse {
    pub domain: String,
    pub subdomains: Vec<SubdomainInfo>,
    pub total_found: u32,
    pub sources_used: Vec<String>,
    pub cached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainInfo {
    pub subdomain: String,
    pub ip: Option<String>,
    pub source: String,
    pub alive: Option<bool>,
}

/// Türkçe: IP intelligence yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInfoResponse {
    pub ip: String,
    pub version: u8,
    pub hostname: Option<String>,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub postal: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub asn_org: Option<String>,
    pub is_proxy: Option<bool>,
    pub is_vpn: Option<bool>,
    pub is_tor: Option<bool>,
    pub is_datacenter: Option<bool>,
    pub risk_score: Option<u8>,
    pub blacklists: Vec<String>,
    pub cached: bool,
}

/// Türkçe: Teknoloji tespiti yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechDetectionResponse {
    pub target: String,
    pub url: String,
    pub technologies: Vec<DetectedTech>,
    pub headers: serde_json::Value,
    pub meta_tags: serde_json::Value,
    pub cached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTech {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub confidence: f64,
    pub website: Option<String>,
    pub icon: Option<String>,
}

/// Türkçe: Entity listesi yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityListResponse {
    pub entities: Vec<serde_json::Value>,
    pub total: u64,
    pub limit: i64,
    pub skip: u64,
    pub has_more: bool,
}

/// Türkçe: Geçmiş listesi yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryListResponse {
    pub scans: Vec<ScanSummary>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub target: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub entity_count: u32,
    pub modules: Vec<String>,
}

/// Türkçe: İstatistikler yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub total_entities: u64,
    pub total_relationships: u64,
    pub total_scans: u64,
    pub tracked_domains: u64,
    pub scans_last_24h: u64,
    pub entity_breakdown: serde_json::Value,
    pub recent_activity: Vec<serde_json::Value>,
}

/// Türkçe: Domain listesi yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainListResponse {
    pub domains: Vec<TrackedDomain>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedDomain {
    pub id: String,
    pub domain: String,
    pub organization: String,
    pub added_at: String,
    pub last_scanned: Option<String>,
    pub scan_schedule: String,
    pub entity_count: Option<u32>,
}

/// Türkçe: Health check yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub mongodb: String,
    pub redis: String,
    pub uptime_secs: u64,
    /// API key ile çalışan entegrasyonların durumu (frontend rozetleri için).
    pub integrations: Vec<IntegrationStatus>,
}

/// Türkçe: Tek bir OSINT entegrasyonunun durumu (API key var mı, ücretli mi?).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationStatus {
    /// Kaynak adı: "shodan", "virustotal", "abuseipdb", "securitytrails"
    pub name: String,
    /// API key tanımlı ve kullanılabilir mi?
    pub configured: bool,
    /// Bu kaynak API key GEREKTİRİR mi? (false = ücretsiz/keysiz çalışır)
    pub requires_key: bool,
    /// Ücretsiz plan var mı? (kullanıcıya "buradan ücretsiz key al" ipucu için)
    pub free_tier: bool,
    /// Key alınabilecek/bilgi sayfası URL'i.
    pub signup_url: String,
    /// Kısa açıklama (Türkçe).
    pub note: String,
}

// ==================== DOMAIN PROFILE ====================

/// Türkçe: Domain Profil Özeti (Frontend: Investigate Sayfası)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainProfile {
    pub target: String,
    pub first_seen: Option<String>,
    pub last_scanned: Option<String>,
    pub total_scans: u32,
    pub scan_history: Vec<ProfileScanHistory>,
    pub entities: ProfileEntities,
    pub vulnerability_trend: Vec<VulnerabilityTrend>,
    pub services: Vec<NmapServiceInfo>,
    pub risk_score: u32,
    pub risk_factors: Vec<String>,
    
    // New Professional Stats
    pub geo_distribution: std::collections::HashMap<String, u32>,
    pub asn_info: Vec<AsnInfo>,
    pub ssl_health: Option<SslHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    pub asn: String,
    pub org: String,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslHealth {
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
    pub days_left: i64,
    pub is_valid: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileScanHistory {
    pub scan_id: String,
    pub date: String,
    pub scan_types: Vec<String>,
    pub findings_count: u32,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEntities {
    pub subdomains: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub open_ports: Vec<u16>,
    pub technologies: Vec<String>,
    pub ssl_info: Option<serde_json::Value>,
    pub whois_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityTrend {
    pub date: String,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

// ==================== NMAP SERVICE INFO ====================

/// Türkçe: Nmap Servis Bilgisi (Structured)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub version: String,
    pub state: String,
}

