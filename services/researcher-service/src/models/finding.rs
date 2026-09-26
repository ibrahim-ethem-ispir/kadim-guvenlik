//! Bulgu (Finding) modelleri

use serde::{Deserialize, Serialize};

/// Bulgu önemi
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Bulgu kategorisi
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Bilgi Sızıntısı
    InformationDisclosure,
    /// Cross-Site Scripting
    Xss,
    /// Güvensiz Konfigürasyon
    Misconfiguration,
    /// Açık Secret/API Key
    ExposedSecret,
    /// Bilinen Zafiyet (CVE)
    KnownVulnerability,
    /// Erişim Kontrolü Sorunu
    AccessControl,
    /// Hydration Uyumsuzluğu
    HydrationMismatch,
    /// Source Map Açık
    SourceMapExposed,
    /// Development Mode Aktif
    DevelopmentMode,
    /// Rate Limit Yok
    NoRateLimit,
    /// Diğer
    Other,
}

/// Güvenlik bulgusu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Benzersiz bulgu ID'si
    pub id: String,
    /// Önem derecesi
    pub severity: Severity,
    /// Kategori
    pub category: FindingCategory,
    /// Başlık
    pub title: String,
    /// Açıklama
    pub description: String,
    /// Kanıt (request/response snippet, kod parçası, vb.)
    pub evidence: String,
    /// Etkilenen URL veya dosya
    pub affected_url: String,
    /// Öneri
    pub recommendation: String,
    /// İlgili CVE (varsa)
    pub cve_id: Option<String>,
    /// İlgili CWE
    pub cwe_id: Option<String>,
    /// Tespit modülü
    pub detected_by: String,
    /// Güvenilirlik (0-100)
    pub confidence: u8,
    /// False positive olasılığı
    pub fp_probability: Option<f32>,
    /// Doğrudan erişim URL'i (varsa)
    pub resource_url: Option<String>,
}

impl Finding {
    /// Yeni bulgu oluştur
    pub fn new(
        severity: Severity,
        category: FindingCategory,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence: impl Into<String>,
        affected_url: impl Into<String>,
        detected_by: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            severity,
            category,
            title: title.into(),
            description: description.into(),
            evidence: evidence.into(),
            affected_url: affected_url.into(),
            recommendation: String::new(),
            cve_id: None,
            cwe_id: None,
            detected_by: detected_by.into(),
            confidence: 80,
            fp_probability: None,
            resource_url: None,
        }
    }
    
    /// Öneri ekle
    pub fn with_recommendation(mut self, rec: impl Into<String>) -> Self {
        self.recommendation = rec.into();
        self
    }
    
    /// Kaynak URL ekle (Tıklanabilir link için)
    pub fn with_resource_url(mut self, url: impl Into<String>) -> Self {
        self.resource_url = Some(url.into());
        self
    }
    
    /// CVE ekle
    pub fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve_id = Some(cve.into());
        self
    }
    
    /// CWE ekle
    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe.into());
        self
    }
    
    /// Güvenilirlik ayarla
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }
}

/// CVE bilgisi (nuclei-service'den gelir)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub cve_id: String,
    pub severity: Severity,
    pub description: String,
    pub affected_versions: Vec<String>,
    pub references: Vec<String>,
}
