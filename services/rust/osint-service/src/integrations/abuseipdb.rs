//! Türkçe: AbuseIPDB API Entegrasyonu
//! 
//! IP adresleri için abuse/spam raporlarını ve güvenilirlik skorunu sorgular.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use super::{IntegrationCache, RateLimiter};

/// Türkçe: AbuseIPDB API sonucu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIPDBResult {
    pub ip: String,
    pub is_public: bool,
    pub ip_version: u8,
    pub is_whitelisted: bool,
    pub abuse_confidence_score: u32,  // 0-100, yüksek = kötü
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub usage_type: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub total_reports: u32,
    pub num_distinct_users: u32,
    pub last_reported_at: Option<String>,
    pub reports: Vec<AbuseReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseReport {
    pub reported_at: String,
    pub comment: Option<String>,
    pub categories: Vec<u8>,
    pub reporter_country: Option<String>,
}

/// Türkçe: AbuseIPDB API istemcisi
pub struct AbuseIPDBClient {
    client: Client,
    api_key: Option<String>,
    cache: Arc<IntegrationCache>,
    rate_limiter: RateLimiter,
}

impl AbuseIPDBClient {
    pub fn new(cache: Arc<IntegrationCache>) -> Self {
        // Boş string'i key sayma (docker-compose ${ABUSEIPDB_API_KEY:-} boş geçebilir) —
        // aksi halde is_available() yanlışlıkla true döner.
        let api_key = std::env::var("ABUSEIPDB_API_KEY").ok().filter(|s| !s.is_empty());
        
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            api_key,
            cache,
            rate_limiter: RateLimiter::new(60, 60), // 60 istek/dakika (ücretsiz tier)
        }
    }

    /// Türkçe: IP için AbuseIPDB bilgilerini sorgula
    pub async fn lookup(&self, ip: &str) -> Result<AbuseIPDBResult, AbuseIPDBError> {
        let api_key = self.api_key.as_ref()
            .ok_or(AbuseIPDBError::NoApiKey)?;

        // IP validasyonu
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(AbuseIPDBError::InvalidIP);
        }

        // Cache kontrol
        let cache_key = format!("abuseipdb:{}", ip);
        if let Some(cached) = self.cache.get(&cache_key).await {
            if let Ok(result) = serde_json::from_str(&cached) {
                tracing::debug!("AbuseIPDB cache hit: {}", ip);
                return Ok(result);
            }
        }

        // Rate limit kontrol
        if !self.rate_limiter.acquire().await {
            if let Some(wait_time) = self.rate_limiter.wait_time().await {
                tracing::warn!("AbuseIPDB rate limited, waiting {:?}", wait_time);
                tokio::time::sleep(wait_time).await;
            }
        }

        // API isteği
        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90&verbose=",
            ip
        );
        
        let response = self.client
            .get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| AbuseIPDBError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AbuseIPDBError::ApiError(format!("{}: {}", status, body)));
        }

        let data: serde_json::Value = response.json().await
            .map_err(|e| AbuseIPDBError::ParseError(e.to_string()))?;

        let result = self.parse_response(ip, &data)?;

        // Cache'e kaydet
        if let Ok(json) = serde_json::to_string(&result) {
            self.cache.set(cache_key, json).await;
        }

        Ok(result)
    }

    fn parse_response(&self, ip: &str, data: &serde_json::Value) -> Result<AbuseIPDBResult, AbuseIPDBError> {
        let d = &data["data"];
        
        let reports: Vec<AbuseReport> = d["reports"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(10) // Son 10 rapor
                    .filter_map(|r| {
                        Some(AbuseReport {
                            reported_at: r["reportedAt"].as_str()?.to_string(),
                            comment: r["comment"].as_str().map(|s| s.chars().take(200).collect()),
                            categories: r["categories"]
                                .as_array()
                                .map(|cats| cats.iter().filter_map(|c| c.as_u64().map(|n| n as u8)).collect())
                                .unwrap_or_default(),
                            reporter_country: r["reporterCountryCode"].as_str().map(String::from),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(AbuseIPDBResult {
            ip: ip.to_string(),
            is_public: d["isPublic"].as_bool().unwrap_or(true),
            ip_version: d["ipVersion"].as_u64().unwrap_or(4) as u8,
            is_whitelisted: d["isWhitelisted"].as_bool().unwrap_or(false),
            abuse_confidence_score: d["abuseConfidenceScore"].as_u64().unwrap_or(0) as u32,
            country_code: d["countryCode"].as_str().map(String::from),
            country_name: d["countryName"].as_str().map(String::from),
            usage_type: d["usageType"].as_str().map(String::from),
            isp: d["isp"].as_str().map(String::from),
            domain: d["domain"].as_str().map(String::from),
            total_reports: d["totalReports"].as_u64().unwrap_or(0) as u32,
            num_distinct_users: d["numDistinctUsers"].as_u64().unwrap_or(0) as u32,
            last_reported_at: d["lastReportedAt"].as_str().map(String::from),
            reports,
        })
    }

    /// Türkçe: Abuse kategori kodunu açıklamaya çevir
    pub fn category_to_string(category: u8) -> &'static str {
        match category {
            1 => "DNS Compromise",
            2 => "DNS Poisoning",
            3 => "Fraud Orders",
            4 => "DDoS Attack",
            5 => "FTP Brute-Force",
            6 => "Ping of Death",
            7 => "Phishing",
            8 => "Fraud VoIP",
            9 => "Open Proxy",
            10 => "Web Spam",
            11 => "Email Spam",
            12 => "Blog Spam",
            13 => "VPN IP",
            14 => "Port Scan",
            15 => "Hacking",
            16 => "SQL Injection",
            17 => "Spoofing",
            18 => "Brute-Force",
            19 => "Bad Web Bot",
            20 => "Exploited Host",
            21 => "Web App Attack",
            22 => "SSH",
            23 => "IoT Targeted",
            _ => "Unknown",
        }
    }

    pub fn is_available(&self) -> bool {
        self.api_key.is_some()
    }
}

#[derive(Debug)]
pub enum AbuseIPDBError {
    NoApiKey,
    InvalidIP,
    RequestFailed(String),
    ParseError(String),
    ApiError(String),
    RateLimited,
}

impl std::fmt::Display for AbuseIPDBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoApiKey => write!(f, "AbuseIPDB API key not configured"),
            Self::InvalidIP => write!(f, "Invalid IP address format"),
            Self::RequestFailed(e) => write!(f, "Request failed: {}", e),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::ApiError(e) => write!(f, "API error: {}", e),
            Self::RateLimited => write!(f, "Rate limited"),
        }
    }
}

impl std::error::Error for AbuseIPDBError {}
