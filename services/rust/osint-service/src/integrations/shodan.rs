//! Türkçe: Shodan API Entegrasyonu
//! 
//! IP adresleri için açık port, servis ve zafiyet bilgilerini sorgular.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use super::{IntegrationCache, RateLimiter};

/// Türkçe: Shodan API sonucu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanResult {
    pub ip: String,
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub services: Vec<ShodanService>,
    pub vulns: Vec<String>,
    pub last_update: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanService {
    pub port: u16,
    pub transport: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Vec<String>,
}

/// Türkçe: Shodan API istemcisi
pub struct ShodanClient {
    client: Client,
    api_key: Option<String>,
    cache: Arc<IntegrationCache>,
    rate_limiter: RateLimiter,
}

impl ShodanClient {
    pub fn new(cache: Arc<IntegrationCache>) -> Self {
        // Boş string'i (docker-compose ${SHODAN_API_KEY:-} ile boş geçince) key sayma —
        // aksi halde is_available() yanlışlıkla true döner ve boş key'le API çağrısı yapılır.
        let api_key = std::env::var("SHODAN_API_KEY").ok().filter(|s| !s.is_empty());
        
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            api_key,
            cache,
            rate_limiter: RateLimiter::new(1, 1), // 1 istek/saniye
        }
    }

    /// Türkçe: IP için Shodan bilgilerini sorgula
    pub async fn lookup(&self, ip: &str) -> Result<ShodanResult, ShodanError> {
        // API key yoksa hata dön
        let api_key = self.api_key.as_ref()
            .ok_or(ShodanError::NoApiKey)?;

        // Cache kontrol
        let cache_key = format!("shodan:{}", ip);
        if let Some(cached) = self.cache.get(&cache_key).await {
            if let Ok(result) = serde_json::from_str(&cached) {
                tracing::debug!("Shodan cache hit: {}", ip);
                return Ok(result);
            }
        }

        // Rate limit kontrol
        if !self.rate_limiter.acquire().await {
            if let Some(wait_time) = self.rate_limiter.wait_time().await {
                tracing::warn!("Shodan rate limited, waiting {:?}", wait_time);
                tokio::time::sleep(wait_time).await;
            }
        }

        // API isteği
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| ShodanError::RequestFailed(e.to_string()))?;

        if response.status() == 404 {
            return Err(ShodanError::NotFound);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ShodanError::ApiError(format!("{}: {}", status, body)));
        }

        let data: serde_json::Value = response.json().await
            .map_err(|e| ShodanError::ParseError(e.to_string()))?;

        // Sonucu parse et
        let result = self.parse_response(ip, &data)?;

        // Cache'e kaydet
        if let Ok(json) = serde_json::to_string(&result) {
            self.cache.set(cache_key, json).await;
        }

        Ok(result)
    }

    fn parse_response(&self, ip: &str, data: &serde_json::Value) -> Result<ShodanResult, ShodanError> {
        let ports: Vec<u16> = data["ports"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect())
            .unwrap_or_default();

        let hostnames: Vec<String> = data["hostnames"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let vulns: Vec<String> = data["vulns"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let tags: Vec<String> = data["tags"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let mut services = Vec::new();
        if let Some(data_arr) = data["data"].as_array() {
            for svc in data_arr {
                services.push(ShodanService {
                    port: svc["port"].as_u64().unwrap_or(0) as u16,
                    transport: svc["transport"].as_str().unwrap_or("tcp").to_string(),
                    product: svc["product"].as_str().map(String::from),
                    version: svc["version"].as_str().map(String::from),
                    banner: svc["data"].as_str().map(|s| s.chars().take(500).collect()),
                    cpe: svc["cpe"]
                        .as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                        .unwrap_or_default(),
                });
            }
        }

        Ok(ShodanResult {
            ip: ip.to_string(),
            ports,
            hostnames,
            country: data["country_name"].as_str().map(String::from),
            city: data["city"].as_str().map(String::from),
            org: data["org"].as_str().map(String::from),
            isp: data["isp"].as_str().map(String::from),
            asn: data["asn"].as_str().map(String::from),
            services,
            vulns,
            last_update: data["last_update"].as_str().map(String::from),
            tags,
        })
    }

    /// Türkçe: API key ayarlı mı kontrol et
    pub fn is_available(&self) -> bool {
        self.api_key.is_some()
    }
}

#[derive(Debug)]
pub enum ShodanError {
    NoApiKey,
    NotFound,
    RequestFailed(String),
    ParseError(String),
    ApiError(String),
    RateLimited,
}

impl std::fmt::Display for ShodanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoApiKey => write!(f, "Shodan API key not configured"),
            Self::NotFound => write!(f, "IP not found in Shodan"),
            Self::RequestFailed(e) => write!(f, "Request failed: {}", e),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::ApiError(e) => write!(f, "API error: {}", e),
            Self::RateLimited => write!(f, "Rate limited"),
        }
    }
}

impl std::error::Error for ShodanError {}
