//! Türkçe: VirusTotal API Entegrasyonu
//! 
//! Domain ve IP adresleri için malware/phishing tespiti ve reputation bilgisi sorgular.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use super::{IntegrationCache, RateLimiter};

/// Türkçe: VirusTotal API sonucu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalResult {
    pub target: String,
    pub target_type: String,  // "ip" veya "domain"
    pub malicious_count: u32,
    pub suspicious_count: u32,
    pub harmless_count: u32,
    pub undetected_count: u32,
    pub reputation: i32,
    pub last_analysis_date: Option<String>,
    pub categories: Vec<String>,
    pub detected_urls: Vec<DetectedUrl>,
    pub whois: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedUrl {
    pub url: String,
    pub positives: u32,
    pub scan_date: Option<String>,
}

/// Türkçe: VirusTotal API istemcisi
pub struct VirusTotalClient {
    client: Client,
    api_key: Option<String>,
    cache: Arc<IntegrationCache>,
    rate_limiter: RateLimiter,
}

impl VirusTotalClient {
    pub fn new(cache: Arc<IntegrationCache>) -> Self {
        // Boş string'i key sayma (docker-compose ${VIRUSTOTAL_API_KEY:-} boş geçebilir) —
        // aksi halde is_available() yanlışlıkla true döner.
        let api_key = std::env::var("VIRUSTOTAL_API_KEY").ok().filter(|s| !s.is_empty());
        
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            api_key,
            cache,
            rate_limiter: RateLimiter::new(4, 60), // 4 istek/dakika (ücretsiz tier)
        }
    }

    /// Türkçe: IP veya domain için VirusTotal bilgilerini sorgula
    pub async fn lookup(&self, target: &str) -> Result<VirusTotalResult, VirusTotalError> {
        let api_key = self.api_key.as_ref()
            .ok_or(VirusTotalError::NoApiKey)?;

        // Cache kontrol
        let cache_key = format!("virustotal:{}", target);
        if let Some(cached) = self.cache.get(&cache_key).await {
            if let Ok(result) = serde_json::from_str(&cached) {
                tracing::debug!("VirusTotal cache hit: {}", target);
                return Ok(result);
            }
        }

        // Rate limit kontrol
        if !self.rate_limiter.acquire().await {
            if let Some(wait_time) = self.rate_limiter.wait_time().await {
                tracing::warn!("VirusTotal rate limited, waiting {:?}", wait_time);
                tokio::time::sleep(wait_time).await;
            }
        }

        // Hedef tipi belirle
        let is_ip = target.parse::<std::net::IpAddr>().is_ok();
        let (endpoint, target_type) = if is_ip {
            ("ip_addresses", "ip")
        } else {
            ("domains", "domain")
        };

        // API isteği - v3 API
        let url = format!("https://www.virustotal.com/api/v3/{}/{}", endpoint, target);
        
        let response = self.client
            .get(&url)
            .header("x-apikey", api_key)
            .send()
            .await
            .map_err(|e| VirusTotalError::RequestFailed(e.to_string()))?;

        if response.status() == 404 {
            return Err(VirusTotalError::NotFound);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VirusTotalError::ApiError(format!("{}: {}", status, body)));
        }

        let data: serde_json::Value = response.json().await
            .map_err(|e| VirusTotalError::ParseError(e.to_string()))?;

        let result = self.parse_response(target, target_type, &data)?;

        // Cache'e kaydet
        if let Ok(json) = serde_json::to_string(&result) {
            self.cache.set(cache_key, json).await;
        }

        Ok(result)
    }

    fn parse_response(&self, target: &str, target_type: &str, data: &serde_json::Value) -> Result<VirusTotalResult, VirusTotalError> {
        let attributes = &data["data"]["attributes"];
        
        let last_analysis_stats = &attributes["last_analysis_stats"];
        let malicious_count = last_analysis_stats["malicious"].as_u64().unwrap_or(0) as u32;
        let suspicious_count = last_analysis_stats["suspicious"].as_u64().unwrap_or(0) as u32;
        let harmless_count = last_analysis_stats["harmless"].as_u64().unwrap_or(0) as u32;
        let undetected_count = last_analysis_stats["undetected"].as_u64().unwrap_or(0) as u32;

        let reputation = attributes["reputation"].as_i64().unwrap_or(0) as i32;

        let last_analysis_date = attributes["last_analysis_date"]
            .as_i64()
            .map(|ts| chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default());

        let categories: Vec<String> = attributes["categories"]
            .as_object()
            .map(|obj| obj.values().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let tags: Vec<String> = attributes["tags"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        Ok(VirusTotalResult {
            target: target.to_string(),
            target_type: target_type.to_string(),
            malicious_count,
            suspicious_count,
            harmless_count,
            undetected_count,
            reputation,
            last_analysis_date,
            categories,
            detected_urls: Vec::new(), // Detaylı URL analizi için ayrı istek gerekir
            whois: attributes["whois"].as_str().map(String::from),
            tags,
        })
    }

    pub fn is_available(&self) -> bool {
        self.api_key.is_some()
    }
}

#[derive(Debug)]
pub enum VirusTotalError {
    NoApiKey,
    NotFound,
    RequestFailed(String),
    ParseError(String),
    ApiError(String),
    RateLimited,
}

impl std::fmt::Display for VirusTotalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoApiKey => write!(f, "VirusTotal API key not configured"),
            Self::NotFound => write!(f, "Target not found in VirusTotal"),
            Self::RequestFailed(e) => write!(f, "Request failed: {}", e),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::ApiError(e) => write!(f, "API error: {}", e),
            Self::RateLimited => write!(f, "Rate limited"),
        }
    }
}

impl std::error::Error for VirusTotalError {}
