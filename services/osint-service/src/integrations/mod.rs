//! Türkçe: External Threat Intelligence API Entegrasyonları
//! 
//! Bu modül Shodan, VirusTotal ve AbuseIPDB gibi dış kaynaklardan
//! tehdit istihbaratı verilerini çeker.

pub mod shodan;
pub mod virustotal;
pub mod abuseipdb;
pub mod cache;

use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Türkçe: Aggregate Reputation Score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub target: String,
    pub target_type: String,  // "ip" veya "domain"
    pub overall_score: f64,   // 0-100, yüksek = kötü
    pub risk_level: String,   // "low", "medium", "high", "critical"
    pub sources: Vec<SourceScore>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceScore {
    pub source: String,       // "shodan", "virustotal", "abuseipdb"
    pub score: f64,
    pub details: Option<String>,
    pub available: bool,
}

/// Türkçe: In-memory cache yapısı (Redis yerine basit implementasyon)
pub struct IntegrationCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

#[derive(Clone)]
struct CacheEntry {
    data: String,
    created_at: Instant,
}

impl IntegrationCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        let entries = self.entries.read().await;
        if let Some(entry) = entries.get(key) {
            if entry.created_at.elapsed() < self.ttl {
                return Some(entry.data.clone());
            }
        }
        None
    }

    pub async fn set(&self, key: String, value: String) {
        let mut entries = self.entries.write().await;
        entries.insert(key, CacheEntry {
            data: value,
            created_at: Instant::now(),
        });
    }

    /// Türkçe: Eski cache girişlerini temizle
    pub async fn cleanup(&self) {
        let mut entries = self.entries.write().await;
        entries.retain(|_, v| v.created_at.elapsed() < self.ttl);
    }
}

/// Türkçe: Rate limiter yapısı
pub struct RateLimiter {
    requests: RwLock<Vec<Instant>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: RwLock::new(Vec::new()),
            max_requests,
            window: Duration::from_secs(window_seconds),
        }
    }

    /// Türkçe: İstek yapılabilir mi kontrol et ve izin ver
    pub async fn acquire(&self) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        // Eski istekleri temizle
        requests.retain(|&t| now.duration_since(t) < self.window);
        
        if requests.len() < self.max_requests {
            requests.push(now);
            true
        } else {
            false
        }
    }

    /// Türkçe: Rate limit'e takılırsan ne kadar beklemen gerekiyor
    pub async fn wait_time(&self) -> Option<Duration> {
        let requests = self.requests.read().await;
        if requests.len() >= self.max_requests {
            if let Some(&oldest) = requests.first() {
                let elapsed = Instant::now().duration_since(oldest);
                if elapsed < self.window {
                    return Some(self.window - elapsed);
                }
            }
        }
        None
    }
}

/// Türkçe: Tüm entegrasyonları yöneten ana yapı
pub struct IntegrationManager {
    pub shodan: shodan::ShodanClient,
    pub virustotal: virustotal::VirusTotalClient,
    pub abuseipdb: abuseipdb::AbuseIPDBClient,
    pub cache: Arc<IntegrationCache>,
}

impl IntegrationManager {
    pub fn new() -> Self {
        let cache = Arc::new(IntegrationCache::new(3600)); // 1 saat TTL
        
        Self {
            shodan: shodan::ShodanClient::new(cache.clone()),
            virustotal: virustotal::VirusTotalClient::new(cache.clone()),
            abuseipdb: abuseipdb::AbuseIPDBClient::new(cache.clone()),
            cache,
        }
    }

    /// Türkçe: Tüm kaynaklardan aggregate reputation score hesapla
    pub async fn get_reputation(&self, target: &str) -> ReputationScore {
        let target_type = if Self::is_ip(target) { "ip" } else { "domain" };
        let mut sources = Vec::new();
        let mut total_score = 0.0;
        let mut source_count = 0;

        // Shodan (sadece IP için)
        if target_type == "ip" {
            match self.shodan.lookup(target).await {
                Ok(result) => {
                    let score = self.calculate_shodan_score(&result);
                    total_score += score;
                    source_count += 1;
                    sources.push(SourceScore {
                        source: "shodan".to_string(),
                        score,
                        details: Some(format!("{} açık port", result.ports.len())),
                        available: true,
                    });
                }
                Err(_) => {
                    sources.push(SourceScore {
                        source: "shodan".to_string(),
                        score: 0.0,
                        details: None,
                        available: false,
                    });
                }
            }
        }

        // VirusTotal
        match self.virustotal.lookup(target).await {
            Ok(result) => {
                let score = self.calculate_vt_score(&result);
                total_score += score;
                source_count += 1;
                sources.push(SourceScore {
                    source: "virustotal".to_string(),
                    score,
                    details: Some(format!("{} malicious detection", result.malicious_count)),
                    available: true,
                });
            }
            Err(_) => {
                sources.push(SourceScore {
                    source: "virustotal".to_string(),
                    score: 0.0,
                    details: None,
                    available: false,
                });
            }
        }

        // AbuseIPDB (sadece IP için)
        if target_type == "ip" {
            match self.abuseipdb.lookup(target).await {
                Ok(result) => {
                    let score = result.abuse_confidence_score as f64;
                    total_score += score;
                    source_count += 1;
                    sources.push(SourceScore {
                        source: "abuseipdb".to_string(),
                        score,
                        details: Some(format!("{} rapor", result.total_reports)),
                        available: true,
                    });
                }
                Err(_) => {
                    sources.push(SourceScore {
                        source: "abuseipdb".to_string(),
                        score: 0.0,
                        details: None,
                        available: false,
                    });
                }
            }
        }

        let overall_score = if source_count > 0 {
            total_score / source_count as f64
        } else {
            0.0
        };

        let risk_level = match overall_score {
            s if s >= 75.0 => "critical",
            s if s >= 50.0 => "high",
            s if s >= 25.0 => "medium",
            _ => "low",
        }.to_string();

        ReputationScore {
            target: target.to_string(),
            target_type: target_type.to_string(),
            overall_score,
            risk_level,
            sources,
            last_updated: chrono::Utc::now(),
        }
    }

    fn is_ip(target: &str) -> bool {
        target.parse::<std::net::IpAddr>().is_ok()
    }

    fn calculate_shodan_score(&self, result: &shodan::ShodanResult) -> f64 {
        let mut score = 0.0;
        
        // Açık port sayısına göre
        score += (result.ports.len() as f64).min(30.0);
        
        // Zafiyet varsa
        score += (result.vulns.len() as f64 * 10.0).min(50.0);
        
        // Tehlikeli portlar
        let dangerous_ports = [21, 22, 23, 3389, 5900, 445, 139];
        for port in &result.ports {
            if dangerous_ports.contains(port) {
                score += 5.0;
            }
        }
        
        score.min(100.0)
    }

    fn calculate_vt_score(&self, result: &virustotal::VirusTotalResult) -> f64 {
        let total = result.malicious_count + result.harmless_count + result.suspicious_count;
        if total == 0 {
            return 0.0;
        }
        
        let malicious_ratio = result.malicious_count as f64 / total as f64;
        (malicious_ratio * 100.0).min(100.0)
    }
}
