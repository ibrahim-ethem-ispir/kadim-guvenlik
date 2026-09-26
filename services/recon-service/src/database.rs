// Türkçe: MongoDB veritabanı bağlantı ve veri saklama modülü
// Tarama sonuçlarının kalıcı olarak saklanması ve geçmiş verilerin sorgulanması

use mongodb::{Client, Collection, bson::doc};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::tech_detector::Technology;

/// Veritabanı bağlantı yöneticisi
#[derive(Clone)]
pub struct Database {
    client: Client,
    db_name: String,
}

impl Database {
    /// Türkçe: MongoDB bağlantısı oluşturur
    /// Environment variable'dan URI alır
    pub async fn new() -> Result<Self, mongodb::error::Error> {
        let uri = std::env::var("MONGODB_URI")
            .unwrap_or_else(|_| "mongodb://mongodb:27017".to_string());
        
        let db_name = std::env::var("MONGODB_DATABASE")
            .unwrap_or_else(|_| "kadim_security".to_string());

        let client = Client::with_uri_str(&uri).await?;
        
        // Bağlantı testi
        client.database(&db_name)
            .run_command(doc! { "ping": 1 }, None)
            .await?;

        tracing::info!("MongoDB bağlantısı başarılı: {}", db_name);

        Ok(Self { client, db_name })
    }

    /// Tarama sonuçları için collection döner
    fn scans_collection(&self) -> Collection<ReconScanDocument> {
        self.client
            .database(&self.db_name)
            .collection("recon_scans")
    }

    /// Türkçe: Tarama sonucunu veritabanına kaydeder
    pub async fn save_scan(&self, scan: &ReconScanDocument) -> Result<(), mongodb::error::Error> {
        self.scans_collection()
            .insert_one(scan, None)
            .await?;
        
        tracing::info!("Tarama sonucu kaydedildi: {}", scan.scan_id);
        Ok(())
    }

    /// Türkçe: Scan ID ile tarama sonucunu getirir
    pub async fn get_scan(&self, scan_id: &str) -> Result<Option<ReconScanDocument>, mongodb::error::Error> {
        self.scans_collection()
            .find_one(doc! { "scan_id": scan_id }, None)
            .await
    }

    /// Türkçe: Belirli domain için tüm tarama geçmişini getirir (tarih sıralı)
    pub async fn get_domain_history(
        &self, 
        domain: &str,
        limit: i64
    ) -> Result<Vec<ReconScanDocument>, mongodb::error::Error> {
        use futures::stream::StreamExt;

        let mut cursor = self.scans_collection()
            .find(
                doc! { "target_domain": domain },
                mongodb::options::FindOptions::builder()
                    .sort(doc! { "timestamp": -1 }) // En yeni önce
                    .limit(limit)
                    .build()
            )
            .await?;

        let mut results = Vec::new();
        while let Some(doc) = cursor.next().await {
            if let Ok(scan) = doc {
                results.push(scan);
            }
        }

        Ok(results)
    }

    /// Türkçe: Belirli bir teknoloji kullanan tüm siteleri bulur
    pub async fn find_by_technology(
        &self,
        tech_name: &str,
        limit: i64
    ) -> Result<Vec<AssetSummary>, mongodb::error::Error> {
        use futures::stream::StreamExt;

        let mut cursor = self.scans_collection()
            .find(
                doc! { "assets.technologies.name": tech_name },
                mongodb::options::FindOptions::builder()
                    .limit(limit)
                    .build()
            )
            .await?;

        let mut results = Vec::new();
        while let Some(doc) = cursor.next().await {
            if let Ok(scan) = doc {
                // Sadece ilgili teknolojiye sahip asset'leri filtrele
                for asset in scan.assets {
                    if asset.technologies.iter().any(|t| t.name == tech_name) {
                        results.push(AssetSummary {
                            domain: scan.target_domain.clone(),
                            subdomain: asset.subdomain,
                            ip_address: asset.ip_address,
                            scan_date: scan.timestamp,
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    /// Türkçe: Tüm tarama geçmişini tarihe göre sıralı getirir (en yeni önce)
    pub async fn get_all_scans(
        &self,
        limit: i64
    ) -> Result<Vec<ReconScanSummary>, mongodb::error::Error> {
        use futures::stream::StreamExt;

        let mut cursor = self.scans_collection()
            .find(
                doc! {},
                mongodb::options::FindOptions::builder()
                    .sort(doc! { "timestamp": -1 })
                    .limit(limit)
                    .build()
            )
            .await?;

        let mut results = Vec::new();
        while let Some(doc) = cursor.next().await {
            if let Ok(scan) = doc {
                results.push(ReconScanSummary {
                    scan_id: scan.scan_id,
                    target_domain: scan.target_domain,
                    timestamp: scan.timestamp,
                    status: scan.status,
                    total_subdomains: scan.summary.total_subdomains_found,
                    total_live_assets: scan.summary.total_live_assets,
                    scan_duration_seconds: scan.summary.scan_duration_seconds,
                });
            }
        }

        Ok(results)
    }

    /// Türkçe: Tüm veritabanı istatistiklerini hesaplar (Dashboard için)
    pub async fn get_global_stats(&self) -> Result<GlobalStats, mongodb::error::Error> {
        use futures::stream::StreamExt;

        let mut cursor = self.scans_collection()
            .find(doc! {}, None)
            .await?;

        let mut total_scans = 0;
        let mut total_domains = std::collections::HashSet::new();
        let mut total_subdomains = 0;
        let mut total_live_assets = 0;
        let mut tech_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut provider_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        while let Some(doc) = cursor.next().await {
            if let Ok(scan) = doc {
                total_scans += 1;
                total_domains.insert(scan.target_domain);
                total_subdomains += scan.summary.total_subdomains_found;
                total_live_assets += scan.summary.total_live_assets;

                for asset in scan.assets {
                    for tech in asset.technologies {
                        *tech_counts.entry(tech.name).or_insert(0) += 1;
                    }
                    if let Some(provider) = asset.infrastructure.provider {
                        *provider_counts.entry(provider).or_insert(0) += 1;
                    }
                }
            }
        }

        let mut top_technologies: Vec<TechnologyStats> = tech_counts
            .into_iter()
            .map(|(name, count)| TechnologyStats { name, count })
            .collect();
        top_technologies.sort_by(|a, b| b.count.cmp(&a.count));
        top_technologies.truncate(20);

        let mut infrastructure_breakdown: Vec<InfrastructureStats> = provider_counts
            .into_iter()
            .map(|(provider, count)| InfrastructureStats { provider, count })
            .collect();
        infrastructure_breakdown.sort_by(|a, b| b.count.cmp(&a.count));

        Ok(GlobalStats {
            total_scans,
            total_domains: total_domains.len(),
            total_subdomains,
            total_live_assets,
            top_technologies,
            infrastructure_breakdown,
        })
    }
}

/// MongoDB'de saklanan tarama sonuç belgesi
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconScanDocument {
    pub scan_id: String,
    pub target_domain: String,
    pub timestamp: DateTime<Utc>,
    pub status: String, // "completed", "failed", "in_progress"
    pub config: ScanConfig,
    pub assets: Vec<AssetRecord>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub wordlist: String,
    pub concurrency: usize,
    pub timeout_minutes: u64,
}

/// Bulunan her varlık için detaylı kayıt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRecord {
    pub subdomain: String,
    pub ip_address: Option<String>,
    pub is_live: bool,
    pub status_code: Option<u16>,
    pub infrastructure: InfrastructureInfo,
    pub technologies: Vec<Technology>,
    pub page_title: Option<String>,
    pub response_time_ms: Option<u64>,
    pub content_length: Option<usize>,
    pub server_header: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureInfo {
    pub provider: Option<String>, // "Cloudflare", "AWS", "Akamai", "Direct"
    pub is_cloud: bool,
    pub is_private_ip: bool,
    pub is_waf_protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_subdomains_found: usize,
    pub total_live_assets: usize,
    pub total_technologies: usize,
    pub cloud_hosted_count: usize,
    pub direct_ip_count: usize,
    pub scan_duration_seconds: u64,
}

/// Teknoloji arama sonuç özeti
#[derive(Debug, Serialize)]
pub struct AssetSummary {
    pub domain: String,
    pub subdomain: String,
    pub ip_address: Option<String>,
    pub scan_date: DateTime<Utc>,
}

/// Türkçe: Tarama geçmişi özet (liste için)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconScanSummary {
    pub scan_id: String,
    pub target_domain: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
    pub total_subdomains: usize,
    pub total_live_assets: usize,
    pub scan_duration_seconds: u64,
}

/// Türkçe: Global istatistikler (dashboard için)
#[derive(Debug, Serialize)]
pub struct GlobalStats {
    pub total_scans: usize,
    pub total_domains: usize,
    pub total_subdomains: usize,
    pub total_live_assets: usize,
    pub top_technologies: Vec<TechnologyStats>,
    pub infrastructure_breakdown: Vec<InfrastructureStats>,
}

#[derive(Debug, Serialize)]
pub struct TechnologyStats {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct InfrastructureStats {
    pub provider: String,
    pub count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Manuel MongoDB bağlantısı gerektirir
    async fn test_database_connection() {
        let db = Database::new().await;
        assert!(db.is_ok());
    }
}
