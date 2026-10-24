//! # Scan Model
//! 
//! Türkçe: OSINT tarama kayıtları için veri modeli.
//! Tarihsel kayıt tutma ve raporlama için kullanılır.

use serde::{Deserialize, Serialize};
use mongodb::bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Türkçe: Tarama durumları
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// Tarama başlatıldı
    Started,
    /// Tarama devam ediyor
    Running,
    /// Tarama tamamlandı
    Completed,
    /// Tarama başarısız
    Failed,
    /// Tarama iptal edildi
    Cancelled,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Started => "started",
            ScanStatus::Running => "running",
            ScanStatus::Completed => "completed",
            ScanStatus::Failed => "failed",
            ScanStatus::Cancelled => "cancelled",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "started" => Some(ScanStatus::Started),
            "running" => Some(ScanStatus::Running),
            "completed" => Some(ScanStatus::Completed),
            "failed" => Some(ScanStatus::Failed),
            "cancelled" => Some(ScanStatus::Cancelled),
            _ => None,
        }
    }
}

/// Türkçe: OSINT modül tipleri
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OsintModule {
    /// DNS sorguları
    Dns,
    /// WHOIS bilgileri
    Whois,
    /// SSL/TLS analizi
    Ssl,
    /// Subdomain keşfi
    Subdomain,
    /// IP intelligence
    IpInfo,
    /// Teknoloji tespiti
    TechDetection,
    /// Port tarama (nmap entegrasyonu)
    PortScan,
    /// Zafiyet tarama (nikto/nuclei entegrasyonu)
    VulnScan,
    /// Tam OSINT araştırması
    FullInvestigation,
}

impl OsintModule {
    pub fn as_str(&self) -> &'static str {
        match self {
            OsintModule::Dns => "dns",
            OsintModule::Whois => "whois",
            OsintModule::Ssl => "ssl",
            OsintModule::Subdomain => "subdomain",
            OsintModule::IpInfo => "ip_info",
            OsintModule::TechDetection => "tech_detection",
            OsintModule::PortScan => "port_scan",
            OsintModule::VulnScan => "vuln_scan",
            OsintModule::FullInvestigation => "full_investigation",
        }
    }
}

/// Türkçe: OSINT tarama kaydı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    /// MongoDB ObjectId
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    
    /// Benzersiz tarama ID'si (UUID)
    pub scan_id: String,
    
    /// Tarama hedefi (domain, IP, email, vb.)
    pub target: String,
    
    /// Hedef tipi
    pub target_type: String,
    
    /// Çalıştırılan OSINT modülleri
    pub modules: Vec<String>,
    
    /// Tarama durumu
    pub status: ScanStatus,
    
    /// Başlangıç zamanı
    pub started_at: DateTime<Utc>,
    
    /// Tamamlanma zamanı
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    
    /// Bulunan entity sayısı
    #[serde(default)]
    pub entity_count: u32,
    
    /// Bulunan ilişki sayısı
    #[serde(default)]
    pub relationship_count: u32,
    
    /// Modül bazlı bulgular özeti
    #[serde(default)]
    pub findings_summary: HashMap<String, serde_json::Value>,
    
    /// Tarama başlatan (user, scheduled, api)
    #[serde(default = "default_initiated_by")]
    pub initiated_by: String,
    
    /// Hata mesajı (başarısız taramalar için)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    
    /// İlerleme yüzdesi (0-100)
    #[serde(default)]
    pub progress: u8,
}

fn default_initiated_by() -> String {
    "user".to_string()
}

impl Scan {
    /// Türkçe: Yeni tarama oluştur
    pub fn new(scan_id: String, target: String, target_type: &str, modules: Vec<String>) -> Self {
        Self {
            id: None,
            scan_id,
            target,
            target_type: target_type.to_string(),
            modules,
            status: ScanStatus::Started,
            started_at: Utc::now(),
            completed_at: None,
            entity_count: 0,
            relationship_count: 0,
            findings_summary: HashMap::new(),
            initiated_by: "user".to_string(),
            error_message: None,
            progress: 0,
        }
    }
    
    /// Türkçe: Taramayı tamamla
    pub fn complete(&mut self, entity_count: u32, relationship_count: u32) {
        self.status = ScanStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.entity_count = entity_count;
        self.relationship_count = relationship_count;
        self.progress = 100;
    }
    
    /// Türkçe: Taramayı başarısız olarak işaretle
    pub fn fail(&mut self, error: &str) {
        self.status = ScanStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error_message = Some(error.to_string());
    }
    
    /// Türkçe: Tarama süresini hesapla (saniye)
    pub fn duration_secs(&self) -> Option<i64> {
        self.completed_at.map(|end| {
            (end - self.started_at).num_seconds()
        })
    }
}

/// Türkçe: Araştırma isteği
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationRequest {
    /// Hedef (domain, IP, email)
    pub target: String,
    
    /// Çalıştırılacak modüller (boş ise tümü)
    #[serde(default)]
    pub modules: Vec<String>,
    
    /// Derinlik (1: shallow, 2: normal, 3: deep)
    #[serde(default = "default_depth")]
    pub depth: u8,
    
    /// Maksimum entity sayısı
    #[serde(default = "default_max_entities")]
    pub max_entities: u32,
}

fn default_depth() -> u8 {
    2
}

fn default_max_entities() -> u32 {
    500
}

/// Türkçe: Araştırma yanıtı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationResponse {
    /// Tarama ID'si
    pub scan_id: String,
    
    /// Durum
    pub status: String,
    
    /// İlerleme yüzdesi
    pub progress: u8,
    
    /// Mesaj
    pub message: String,
}
