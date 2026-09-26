//! # Veritabanı Modülü
//! 
//! Türkçe: MongoDB ve Redis bağlantı yönetimi.
//! Connection pooling ile yüksek performans sağlar.

pub mod mongodb_client;
pub mod mongo_cache;

use anyhow::Result;
use crate::config::AppConfig;

/// Veritabanı bağlantıları - MongoDB ve Redis
#[derive(Clone)]
pub struct Database {
    /// MongoDB client
    pub mongo: mongodb::Client,
    /// MongoDB database handle
    pub mongo_db: mongodb::Database,
}

impl Database {
    /// Türkçe: MongoDB ve Redis bağlantılarını kur
    pub async fn connect(config: &AppConfig) -> Result<Self> {
        tracing::info!("🔌 MongoDB'ye bağlanılıyor: {}", &config.mongodb_uri[..50.min(config.mongodb_uri.len())]);
        
        // MongoDB bağlantısı
        let mongo_options = mongodb::options::ClientOptions::parse(&config.mongodb_uri).await?;
        let mongo = mongodb::Client::with_options(mongo_options)?;
        let mongo_db = mongo.database(&config.mongodb_database);
        
        // Bağlantıyı test et
        mongo_db.run_command(mongodb::bson::doc! { "ping": 1 }, None).await?;
        tracing::info!("✅ MongoDB bağlantısı başarılı");
        
        // Koleksiyonları ve index'leri oluştur
        Self::ensure_indexes(&mongo_db).await?;
        
        Ok(Self { mongo, mongo_db })
    }
    
    /// Türkçe: Gerekli koleksiyonları ve index'leri oluştur
    async fn ensure_indexes(db: &mongodb::Database) -> Result<()> {
        use mongodb::bson::doc;
        use mongodb::IndexModel;
        use mongodb::options::IndexOptions;
        
        tracing::info!("📊 Koleksiyon index'leri oluşturuluyor...");
        
        // entities koleksiyonu index'leri
        let entities = db.collection::<mongodb::bson::Document>("entities");
        entities.create_index(
            IndexModel::builder()
                .keys(doc! { "entity_type": 1, "value": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None
        ).await?;
        entities.create_index(
            IndexModel::builder()
                .keys(doc! { "last_seen": -1 })
                .build(),
            None
        ).await?;
        
        // relationships koleksiyonu index'leri
        let relationships = db.collection::<mongodb::bson::Document>("relationships");
        relationships.create_index(
            IndexModel::builder()
                .keys(doc! { "source_entity_id": 1 })
                .build(),
            None
        ).await?;
        relationships.create_index(
            IndexModel::builder()
                .keys(doc! { "target_entity_id": 1 })
                .build(),
            None
        ).await?;
        
        // scans koleksiyonu index'leri
        let scans = db.collection::<mongodb::bson::Document>("scans");
        scans.create_index(
            IndexModel::builder()
                .keys(doc! { "scan_id": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None
        ).await?;
        scans.create_index(
            IndexModel::builder()
                .keys(doc! { "target": 1, "started_at": -1 })
                .build(),
            None
        ).await?;
        
        // domains koleksiyonu index'leri
        let domains = db.collection::<mongodb::bson::Document>("domains");
        domains.create_index(
            IndexModel::builder()
                .keys(doc! { "domain": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None
        ).await?;
        
        // audit_logs koleksiyonu index'leri
        let audit_logs = db.collection::<mongodb::bson::Document>("audit_logs");
        audit_logs.create_index(
            IndexModel::builder()
                .keys(doc! { "timestamp": -1 })
                .build(),
            None
        ).await?;
        audit_logs.create_index(
            IndexModel::builder()
                .keys(doc! { "action": 1, "timestamp": -1 })
                .build(),
            None
        ).await?;
        
        // cache koleksiyonu index'leri (TTL)
        let cache = db.collection::<mongodb::bson::Document>("cache");
        cache.create_index(
            IndexModel::builder()
                .keys(doc! { "key": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None
        ).await?;
        cache.create_index(
            IndexModel::builder()
                .keys(doc! { "expires_at": 1 })
                .options(IndexOptions::builder().expire_after(std::time::Duration::from_secs(0)).build())
                .build(),
            None
        ).await?;
        
        tracing::info!("✅ Tüm index'ler oluşturuldu");
        
        Ok(())
    }
    
    /// Türkçe: Koleksiyon referansı al
    pub fn collection<T>(&self, name: &str) -> mongodb::Collection<T> 
    where 
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Unpin
    {
        self.mongo_db.collection(name)
    }
}
