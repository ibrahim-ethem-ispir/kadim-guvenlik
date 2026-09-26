// Türkçe: Tarama durum yönetimi ve veri modelleri (MongoDB entegrasyon hazır)
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use crate::tech_detector::Technology;

// Shared state to hold active scans - parking_lot::RwLock kullanılıyor
// parking_lot daha verimli, async-friendly ve poison-free
pub type SharedState = Arc<RwLock<AppState>>;

pub struct AppState {
    pub scans: HashMap<String, ScanStatus>,
}

// State güncelleme fonksiyonu - hem sync hem async context'te çalışır
// parking_lot poison olmadığı için unwrap/panic olmaz
pub fn update_scan_state<F>(state: &SharedState, scan_id: &str, f: F)
where
    F: FnOnce(&mut ScanStatus),
{
    let mut state_guard = state.write();
    if let Some(status) = state_guard.scans.get_mut(scan_id) {
        f(status);
    }
}

pub fn add_log(state: &SharedState, scan_id: &str, log: &str) {
    update_scan_state(state, scan_id, |s| {
        s.logs.push(log.to_string());
    });
}

// Taramanın iptal edilip edilmediğini kontrol et
pub fn is_scan_cancelled(state: &SharedState, scan_id: &str) -> bool {
    let state_guard = state.read();
    if let Some(status) = state_guard.scans.get(scan_id) {
        return status.cancelled;
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub domain: String,
    pub wordlist: String, // Can be "all" or a specific path
    pub concurrency: usize,
    pub delay_ms: u64,
    pub timeout_minutes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub id: String,
    pub state: ScanState,
    pub progress: f32, // 0.0 to 100.0
    pub current_step: String,
    pub total_subdomains: usize,
    pub scanned_subdomains: usize,
    pub logs: Vec<String>,
    pub result: Option<AnalysisResponse>,
    pub error: Option<String>,
    // Analytical Metrics
    pub start_time: u64, // Unix timestamp
    pub scan_rate: f32, // Subdomains per second
    pub estimated_time_remaining: u64, // Seconds
    pub current_wordlist: String,
    pub total_wordlists: usize,
    pub processed_wordlists: usize,
    // Cancellation flag - tarama iptal edildiğinde true olur
    #[serde(default)]
    pub cancelled: bool,
}

/// Türkçe: Genişletilmiş analiz sonucu (teknoloji tespiti ve altyapı bilgisi dahil)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResponse {
    pub domain: String,
    pub dns: DnsResult,
    pub http: HttpResult,
    pub subdomains: SubdomainResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spoof: Option<Vec<crate::spoof::SpoofResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_auth: Option<crate::spoof::SshAuthResult>,
    // Türkçe: Yeni eklenen alanlar
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResult {
    pub is_cf: bool,
    pub ips: Vec<String>,
}

/// Türkçe: HTTP analiz sonucu (teknoloji bilgisi dahil)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResult {
    pub headers: HashMap<String, String>,
    pub found_cf: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub page_title: Option<String>,
    pub technologies: Vec<Technology>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub found: Vec<SubdomainInfo>,
}

/// Türkçe: Genişletilmiş subdomain bilgisi (canlılık, teknoloji, altyapı)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainInfo {
    pub subdomain: String,
    pub ip: Option<String>,
    pub is_cf: bool,
    pub is_live: bool, // HTTP/HTTPS üzerinden erişilebilir mi?
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub infrastructure: InfrastructureInfo,
    pub technologies: Vec<Technology>,
    pub page_title: Option<String>,
}

/// Türkçe: Altyapı bilgisi (CDN, WAF, Cloud provider)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureInfo {
    pub provider: Option<String>, // "Cloudflare", "AWS", "Akamai", "Direct"
    pub is_cloud: bool,
    pub is_private_ip: bool,
    pub is_waf_protected: bool,
}

/// Türkçe: Tarama özet istatistikleri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_subdomains_found: usize,
    pub total_live_assets: usize,
    pub total_technologies: usize,
    pub cloud_hosted_count: usize,
    pub direct_ip_count: usize,
    pub top_technologies: Vec<TechCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechCount {
    pub name: String,
    pub count: usize,
    pub percentage: f32,
}

