//! # MongoDB Cache İşlemleri
//! 
//! Türkçe: Redis yerine MongoDB kullanarak önbellekleme ve geçici veri saklama.
//! `cache` koleksiyonunu kullanır ve TTL index ile otomatik temizleme sağlar.

use anyhow::Result;
use mongodb::bson::{doc, Document, DateTime};
use mongodb::options::{UpdateOptions, FindOneOptions};
use serde::{Serialize, de::DeserializeOwned};
use chrono::{Utc, Duration};

use crate::db::Database;

/// Cache TTL değerleri (saniye)
pub struct CacheTtl;

impl CacheTtl {
    /// DNS sonuçları - 1 saat
    pub const DNS: u64 = 3600;
    /// WHOIS sonuçları - 24 saat
    pub const WHOIS: u64 = 86400;
    /// SSL sertifika bilgileri - 6 saat
    pub const SSL: u64 = 21600;
    /// IP bilgileri - 12 saat
    pub const IP: u64 = 43200;
    /// Subdomain listesi - 2 saat
    pub const SUBDOMAIN: u64 = 7200;
    /// Teknoloji tespiti - 3 saat
    pub const TECH: u64 = 10800;
    /// Geçici işlem durumu - 1 saat
    pub const TEMP: u64 = 3600;
}

impl Database {
    /// Türkçe: Cache'den veri al
    pub async fn cache_get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let collection = self.collection::<Document>("cache");
        
        let filter = doc! {
            "key": key,
            "expires_at": { "$gt": DateTime::now() } // Süresi dolmamış olanlar
        };
        
        match collection.find_one(filter, None).await? {
            Some(doc) => {
                let json_str = doc.get_str("value")?;
                let value: T = serde_json::from_str(json_str)?;
                Ok(Some(value))
            },
            None => Ok(None)
        }
    }
    
    /// Türkçe: Cache'e veri kaydet (TTL ile)
    pub async fn cache_set<T: Serialize>(&self, key: &str, value: &T, ttl_secs: u64) -> Result<()> {
        let collection = self.collection::<Document>("cache");
        
        let json_str = serde_json::to_string(value)?;
        let expires_at = Utc::now() + Duration::seconds(ttl_secs as i64);
        
        let filter = doc! { "key": key };
        let update = doc! {
            "$set": {
                "value": json_str,
                "expires_at": DateTime::from_system_time(expires_at.into()),
                "updated_at": DateTime::now()
            }
        };
        
        let options = UpdateOptions::builder().upsert(true).build();
        collection.update_one(filter, update, options).await?;
        
        Ok(())
    }
    
    /// Türkçe: Cache'den sil
    pub async fn cache_delete(&self, key: &str) -> Result<()> {
        let collection = self.collection::<Document>("cache");
        collection.delete_one(doc! { "key": key }, None).await?;
        Ok(())
    }
    
    /// Türkçe: Pattern ile cache temizle
    pub async fn cache_delete_pattern(&self, pattern: &str) -> Result<u64> {
        let collection = self.collection::<Document>("cache");
        // Redis pattern glob style, MongoDB regex.
        // Convert glob * to .* for regex approximation or just usage regex directly if callers differ.
        // Redis keys call in redis_client used simple patterns like "osint:*"
        let regex_pattern = pattern.replace("*", ".*");
        
        let filter = doc! {
            "key": { "$regex": format!("^{}", regex_pattern) }
        };
        
        let result = collection.delete_many(filter, None).await?;
        Ok(result.deleted_count)
    }
    
    // ==================== OSINT CACHE HELPERS ====================
    
    /// Türkçe: DNS sorgu sonucunu cache'le
    pub async fn cache_dns_result<T: Serialize>(&self, domain: &str, result: &T) -> Result<()> {
        let key = format!("osint:dns:{}", domain);
        self.cache_set(&key, result, CacheTtl::DNS).await
    }
    
    /// Türkçe: DNS sonucunu cache'den al
    pub async fn get_cached_dns<T: DeserializeOwned>(&self, domain: &str) -> Result<Option<T>> {
        let key = format!("osint:dns:{}", domain);
        self.cache_get(&key).await
    }
    
    /// Türkçe: WHOIS sonucunu cache'le
    pub async fn cache_whois_result<T: Serialize>(&self, domain: &str, result: &T) -> Result<()> {
        let key = format!("osint:whois:{}", domain);
        self.cache_set(&key, result, CacheTtl::WHOIS).await
    }
    
    /// Türkçe: WHOIS sonucunu cache'den al
    pub async fn get_cached_whois<T: DeserializeOwned>(&self, domain: &str) -> Result<Option<T>> {
        let key = format!("osint:whois:{}", domain);
        self.cache_get(&key).await
    }
    
    /// Türkçe: SSL sonucunu cache'le
    pub async fn cache_ssl_result<T: Serialize>(&self, domain: &str, result: &T) -> Result<()> {
        let key = format!("osint:ssl:{}", domain);
        self.cache_set(&key, result, CacheTtl::SSL).await
    }
    
    /// Türkçe: SSL sonucunu cache'den al
    pub async fn get_cached_ssl<T: DeserializeOwned>(&self, domain: &str) -> Result<Option<T>> {
        let key = format!("osint:ssl:{}", domain);
        self.cache_get(&key).await
    }
    
    /// Türkçe: Subdomain listesini cache'le
    pub async fn cache_subdomains<T: Serialize>(&self, domain: &str, result: &T) -> Result<()> {
        let key = format!("osint:subdomains:{}", domain);
        self.cache_set(&key, result, CacheTtl::SUBDOMAIN).await
    }
    
    /// Türkçe: Subdomain listesini cache'den al
    pub async fn get_cached_subdomains<T: DeserializeOwned>(&self, domain: &str) -> Result<Option<T>> {
        let key = format!("osint:subdomains:{}", domain);
        self.cache_get(&key).await
    }
    
    /// Türkçe: IP bilgisini cache'le
    pub async fn cache_ip_info<T: Serialize>(&self, ip: &str, result: &T) -> Result<()> {
        let key = format!("osint:ip:{}", ip);
        self.cache_set(&key, result, CacheTtl::IP).await
    }
    
    /// Türkçe: IP bilgisini cache'den al
    pub async fn get_cached_ip_info<T: DeserializeOwned>(&self, ip: &str) -> Result<Option<T>> {
        let key = format!("osint:ip:{}", ip);
        self.cache_get(&key).await
    }
    
    /// Türkçe: Teknoloji tespiti sonucunu cache'le
    pub async fn cache_tech_result<T: Serialize>(&self, url: &str, result: &T) -> Result<()> {
        let hash = sha256_short(url);
        let key = format!("osint:tech:{}", hash);
        self.cache_set(&key, result, CacheTtl::TECH).await
    }
    
    /// Türkçe: Teknoloji tespiti sonucunu cache'den al
    pub async fn get_cached_tech<T: DeserializeOwned>(&self, url: &str) -> Result<Option<T>> {
        let hash = sha256_short(url);
        let key = format!("osint:tech:{}", hash);
        self.cache_get(&key).await
    }
    
    // ==================== İŞLEM DURUMU ====================
    
    /// Türkçe: Araştırma işlemi durumunu kaydet
    pub async fn set_investigation_status(&self, investigation_id: &str, status: &str) -> Result<()> {
        let key = format!("investigation:{}:status", investigation_id);
        // Status is simple string, treat as JSON string
        self.cache_set(&key, &status.to_string(), CacheTtl::TEMP).await
    }
    
    /// Türkçe: Araştırma işlemi durumunu al
    pub async fn get_investigation_status(&self, investigation_id: &str) -> Result<Option<String>> {
        let key = format!("investigation:{}:status", investigation_id);
        self.cache_get(&key).await
    }
    
    /// Türkçe: Araştırma ilerleme yüzdesini kaydet
    pub async fn set_investigation_progress(&self, investigation_id: &str, progress: u8) -> Result<()> {
        let key = format!("investigation:{}:progress", investigation_id);
        self.cache_set(&key, &progress, CacheTtl::TEMP).await
    }
    
    /// Türkçe: Araştırma ilerleme yüzdesini al
    pub async fn get_investigation_progress(&self, investigation_id: &str) -> Result<u8> {
        let key = format!("investigation:{}:progress", investigation_id);
        let val: Option<u8> = self.cache_get(&key).await?;
        Ok(val.unwrap_or(0))
    }
}

/// Türkçe: URL için kısa SHA256 hash (ilk 16 karakter)
fn sha256_short(input: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8])
}
