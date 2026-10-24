//! # Report Model
//! 
//! Türkçe: OSINT raporları için veri modeli.
//! PDF/JSON export ve tarihsel karşılaştırma için kullanılır.

use serde::{Deserialize, Serialize};
use mongodb::bson::oid::ObjectId;
use chrono::{DateTime, Utc};

/// Türkçe: Rapor formatları
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Json,
    Pdf,
    Html,
    Markdown,
}

impl ReportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReportFormat::Json => "json",
            ReportFormat::Pdf => "pdf",
            ReportFormat::Html => "html",
            ReportFormat::Markdown => "markdown",
        }
    }
    
    pub fn content_type(&self) -> &'static str {
        match self {
            ReportFormat::Json => "application/json",
            ReportFormat::Pdf => "application/pdf",
            ReportFormat::Html => "text/html",
            ReportFormat::Markdown => "text/markdown",
        }
    }
    
    pub fn extension(&self) -> &'static str {
        match self {
            ReportFormat::Json => "json",
            ReportFormat::Pdf => "pdf",
            ReportFormat::Html => "html",
            ReportFormat::Markdown => "md",
        }
    }
}

/// Türkçe: OSINT raporu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// MongoDB ObjectId
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    
    /// Benzersiz rapor ID'si
    pub report_id: String,
    
    /// Rapor başlığı
    pub title: String,
    
    /// Hedef domain/IP
    pub target: String,
    
    /// İlişkili tarama ID'leri
    pub scan_ids: Vec<String>,
    
    /// Oluşturulma zamanı
    pub created_at: DateTime<Utc>,
    
    /// Rapor formatı
    pub format: ReportFormat,
    
    /// Rapor içeriği (JSON ise inline, diğerleri için dosya yolu)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<serde_json::Value>,
    
    /// Dosya yolu (PDF, HTML için)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    
    /// Özet istatistikler
    pub summary: ReportSummary,
}

/// Türkçe: Rapor özeti
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Toplam entity sayısı
    pub total_entities: u32,
    
    /// Entity tiplerine göre dağılım
    pub entity_breakdown: serde_json::Value,
    
    /// Toplam ilişki sayısı
    pub total_relationships: u32,
    
    /// Bulunan subdomain sayısı
    pub subdomains_found: u32,
    
    /// Açık port sayısı
    pub open_ports: u32,
    
    /// Tespit edilen teknoloji sayısı
    pub technologies_detected: u32,
    
    /// Bulunan zafiyet sayısı (severity bazlı)
    pub vulnerabilities: VulnerabilitySummary,
    
    /// Risk skoru (0-100)
    pub risk_score: u8,
    
    /// Öneriler
    pub recommendations: Vec<String>,
}

/// Türkçe: Zafiyet özeti
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl VulnerabilitySummary {
    pub fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.info
    }
    
    /// Türkçe: Zafiyetlere göre risk skoru hesapla
    pub fn calculate_risk_score(&self) -> u8 {
        let score = (self.critical * 25 + self.high * 15 + self.medium * 8 + self.low * 3) as u32;
        score.min(100) as u8
    }
}

/// Türkçe: Rapor oluşturma isteği
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReportRequest {
    /// Hedef domain/IP
    pub target: String,
    
    /// Rapor başlığı (opsiyonel)
    #[serde(default)]
    pub title: Option<String>,
    
    /// Rapor formatı
    #[serde(default = "default_format")]
    pub format: ReportFormat,
    
    /// Dahil edilecek tarama ID'leri (boş ise son tarama)
    #[serde(default)]
    pub scan_ids: Vec<String>,
}

fn default_format() -> ReportFormat {
    ReportFormat::Json
}

/// Türkçe: Tarihsel karşılaştırma
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalComparison {
    /// Karşılaştırma başlığı
    pub title: String,
    
    /// Eski tarama tarihi
    pub old_scan_date: DateTime<Utc>,
    
    /// Yeni tarama tarihi
    pub new_scan_date: DateTime<Utc>,
    
    /// Yeni eklenen entity'ler
    pub new_entities: Vec<EntityChange>,
    
    /// Kaldırılan entity'ler
    pub removed_entities: Vec<EntityChange>,
    
    /// Değişen entity'ler
    pub changed_entities: Vec<EntityChange>,
    
    /// Yeni zafiyetler
    pub new_vulnerabilities: Vec<serde_json::Value>,
    
    /// Düzeltilen zafiyetler
    pub fixed_vulnerabilities: Vec<serde_json::Value>,
}

/// Türkçe: Entity değişikliği
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityChange {
    /// Entity tipi
    pub entity_type: String,
    
    /// Entity değeri
    pub value: String,
    
    /// Değişiklik detayı
    pub detail: Option<String>,
}
