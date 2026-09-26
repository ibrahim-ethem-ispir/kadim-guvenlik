//! Tarama modelleri

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Tarama durumu
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Tarama derinliği
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanDepth {
    /// Hızlı tarama - sadece fingerprint ve temel kontroller
    Quick,
    /// Varsayılan - fingerprint, JS analizi, temel fuzzing
    #[default]
    Standard,
    /// Derin tarama - tüm modüller aktif
    Deep,
    /// Agresif - headless browser + yoğun fuzzing
    Aggressive,
}

/// Tarama isteği
#[derive(Debug, Clone, Deserialize)]
pub struct ScanRequest {
    /// Hedef URL
    pub url: String,
    /// Tarama derinliği
    #[serde(default)]
    pub depth: ScanDepth,
    /// Aktif modüller (boşsa hepsi)
    #[serde(default)]
    pub modules: Vec<String>,
}

/// Tarama kaydı (MongoDB'de saklanır)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchScan {
    /// Benzersiz tarama ID'si
    #[serde(rename = "_id")]
    pub id: String,
    /// Hedef URL
    pub target_url: String,
    /// Çıkarılan domain
    pub domain: String,
    /// Tarama durumu
    pub status: ScanStatus,
    /// Tarama derinliği
    pub depth: ScanDepth,
    /// Aktif modüller
    pub modules: Vec<String>,
    
    // Sonuçlar
    /// Tespit edilen teknolojiler
    #[serde(default)]
    pub technologies: Vec<DetectedTechnology>,
    /// Bulunan zafiyetler/anomaliler
    #[serde(default)]
    pub findings: Vec<super::Finding>,
    /// Keşfedilen endpointler
    #[serde(default)]
    pub discovered_endpoints: Vec<String>,
    /// JS kaynaklarından çıkarılan secretlar
    #[serde(default)]
    pub secrets: Vec<SecretFinding>,
    
    // Meta
    /// Tarama logları
    #[serde(default)]
    pub logs: Vec<ScanLog>,
    /// Risk skoru (0-100)
    pub risk_score: Option<u8>,
    /// Başlangıç zamanı
    pub started_at: DateTime<Utc>,
    /// Bitiş zamanı
    pub completed_at: Option<DateTime<Utc>>,
    /// Hata mesajı (varsa)
    pub error: Option<String>,
}

/// Tespit edilen teknoloji
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTechnology {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub confidence: u8,
    pub cpe: Option<String>,
    pub website: Option<String>,
}

/// Secret bulgusu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    /// Secret türü (api_key, token, password, vb.)
    pub secret_type: String,
    /// Bulunan değer (maskelenmiş)
    pub value_masked: String,
    /// Kaynak dosya
    pub source_file: String,
    /// Satır numarası (varsa)
    pub line_number: Option<u32>,
    /// Güvenilirlik
    pub confidence: u8,
}

/// Tarama logu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanLog {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub module: String,
    pub message: String,
}

impl ResearchScan {
    /// Yeni tarama oluştur
    pub fn new(id: String, url: String, depth: ScanDepth, modules: Vec<String>) -> Self {
        let domain = url::Url::parse(&url)
            .map(|u| u.host_str().unwrap_or("unknown").to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        
        Self {
            id,
            target_url: url,
            domain,
            status: ScanStatus::Pending,
            depth,
            modules,
            technologies: Vec::new(),
            findings: Vec::new(),
            discovered_endpoints: Vec::new(),
            secrets: Vec::new(),
            logs: Vec::new(),
            risk_score: None,
            started_at: Utc::now(),
            completed_at: None,
            error: None,
        }
    }
    
    /// Log ekle
    pub fn add_log(&mut self, level: &str, module: &str, message: &str) {
        self.logs.push(ScanLog {
            timestamp: Utc::now(),
            level: level.to_string(),
            module: module.to_string(),
            message: message.to_string(),
        });
    }
}

/// Tarama özeti (liste görünümü için)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: String,
    pub target_url: String,
    pub domain: String,
    pub status: ScanStatus,
    pub risk_score: Option<u8>,
    pub finding_count: usize,
    pub tech_count: usize,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl From<&ResearchScan> for ScanSummary {
    fn from(scan: &ResearchScan) -> Self {
        Self {
            id: scan.id.clone(),
            target_url: scan.target_url.clone(),
            domain: scan.domain.clone(),
            status: scan.status.clone(),
            risk_score: scan.risk_score,
            finding_count: scan.findings.len(),
            tech_count: scan.technologies.len(),
            started_at: scan.started_at,
            completed_at: scan.completed_at,
        }
    }
}
