//! Diğer Kadim servislerine HTTP client

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::models::DetectedTechnology;

/// Servis client'ı
pub struct ServiceClient {
    client: reqwest::Client,
    config: AppConfig,
}

impl ServiceClient {
    pub fn new(client: reqwest::Client, config: AppConfig) -> Self {
        Self { client, config }
    }
    
    /// Recon-service'den teknoloji tespiti
    pub async fn get_tech_detection(&self, domain: &str) -> Result<Vec<DetectedTechnology>> {
        let url = format!("{}/scan", self.config.recon_service_url);
        
        let response = self.client.post(&url)
            .json(&serde_json::json!({
                "target_domain": domain,
                "scan_type": "tech_only"
            }))
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await?;
        
        if response.status().is_success() {
            let result: ReconResponse = response.json().await?;
            // Teknoloji bilgilerini dönüştür
            Ok(result.technologies.into_iter().map(|t| DetectedTechnology {
                name: t.name,
                category: t.category,
                version: t.version,
                confidence: t.confidence as u8,
                cpe: t.cpe,
                website: t.website,
            }).collect())
        } else {
            Ok(Vec::new())
        }
    }
    
    /// OSINT-service'den domain bilgisi
    pub async fn get_osint_info(&self, domain: &str) -> Result<OsintInfo> {
        let url = format!("{}/domain/{}", self.config.osint_service_url, domain);
        
        let response = self.client.get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await?;
        
        if response.status().is_success() {
            let result: OsintResponse = response.json().await?;
            Ok(OsintInfo {
                dns_records: result.data.dns_records,
                whois_registrar: result.data.whois.map(|w| w.registrar),
                ssl_issuer: result.data.ssl.map(|s| s.issuer),
            })
        } else {
            Ok(OsintInfo::default())
        }
    }
    
    /// Nuclei-service'den CVE tarama başlat
    pub async fn start_nuclei_scan(&self, target: &str, tags: Vec<&str>) -> Result<String> {
        let url = format!("{}/scan", self.config.nuclei_service_url);
        let scan_id = uuid::Uuid::new_v4().to_string();
        
        let response = self.client.post(&url)
            .json(&serde_json::json!({
                "target": target,
                "scan_id": scan_id,
                "tags": tags,
                "severity": ["critical", "high"],
                "rate_limit": 50
            }))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;
        
        if response.status().is_success() {
            Ok(scan_id)
        } else {
            Err(anyhow::anyhow!("Nuclei taraması başlatılamadı"))
        }
    }
}

// Response types (diğer servislerden gelen)

#[derive(Debug, Deserialize)]
struct ReconResponse {
    #[serde(default)]
    technologies: Vec<ReconTech>,
}

#[derive(Debug, Deserialize)]
struct ReconTech {
    name: String,
    category: String,
    version: Option<String>,
    confidence: f32,
    cpe: Option<String>,
    website: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsintResponse {
    data: OsintData,
}

#[derive(Debug, Deserialize)]
struct OsintData {
    #[serde(default)]
    dns_records: Vec<String>,
    whois: Option<WhoisInfo>,
    ssl: Option<SslInfo>,
}

#[derive(Debug, Deserialize)]
struct WhoisInfo {
    registrar: String,
}

#[derive(Debug, Deserialize)]
struct SslInfo {
    issuer: String,
}

/// OSINT bilgisi
#[derive(Debug, Default, Serialize)]
pub struct OsintInfo {
    pub dns_records: Vec<String>,
    pub whois_registrar: Option<String>,
    pub ssl_issuer: Option<String>,
}
