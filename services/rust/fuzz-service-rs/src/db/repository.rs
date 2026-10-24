use mongodb::{Client, Collection, Database};
use mongodb::options::ClientOptions;
use chrono::Utc;
use futures::stream::TryStreamExt;
use tracing::info;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::{ActiveScan, ScanResult, ScanStatus};

pub struct FuzzRepository {
    db: Database,
}

impl FuzzRepository {
    pub async fn connect(config: &Config) -> Result<Self> {
        let mut options = ClientOptions::parse(&config.mongodb_uri)
            .await
            .map_err(|e| AppError::Database(e))?;
        
        options.app_name = Some("fuzz-service-rs".into());

        let client = Client::with_options(options)
            .map_err(|e| AppError::Database(e))?;

        // Ping to verify connection
        client.database("admin")
            .run_command(bson::doc! { "ping": 1 })
            .await
            .map_err(|e| AppError::Database(e))?;

        let db = client.database(&config.mongodb_database);
        
        info!("Connected to MongoDB: {}", config.mongodb_database);
        
        Ok(Self { db })
    }

    fn scans_collection(&self) -> Collection<ActiveScan> {
        self.db.collection("FuzzActiveScans")
    }

    fn results_collection(&self) -> Collection<ScanResult> {
        self.db.collection("FuzzLogs")
    }

    /// Create or update active scan record
    pub async fn upsert_scan(&self, scan: &ActiveScan) -> Result<()> {
        self.scans_collection()
            .update_one(
                bson::doc! { "scan_id": &scan.scan_id },
                bson::doc! {
                    "$set": {
                        "target": &scan.target,
                        "status": bson::to_bson(&scan.status).unwrap(),
                        "started_at": scan.started_at,
                        "findings_count": scan.findings_count as i32,
                    }
                },
            )
            .upsert(true)
            .await
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    /// Update scan status
    pub async fn update_scan_status(
        &self,
        scan_id: &str,
        status: ScanStatus,
        findings_count: u32,
        error: Option<String>,
    ) -> Result<()> {
        let mut update = bson::doc! {
            "status": bson::to_bson(&status).unwrap(),
            "findings_count": findings_count as i32,
        };

        if matches!(status, ScanStatus::Completed | ScanStatus::Failed) {
            update.insert("completed_at", Utc::now());
        }

        if let Some(err) = error {
            update.insert("error", err);
        }

        self.scans_collection()
            .update_one(
                bson::doc! { "scan_id": scan_id },
                bson::doc! { "$set": update },
            )
            .await
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    /// Get scan by ID
    pub async fn get_scan(&self, scan_id: &str) -> Result<Option<ActiveScan>> {
        self.scans_collection()
            .find_one(bson::doc! { "scan_id": scan_id })
            .await
            .map_err(|e| AppError::Database(e))
    }

    /// Save scan result (finding)
    pub async fn save_result(&self, result: &ScanResult) -> Result<()> {
        self.results_collection()
            .insert_one(result)
            .await
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    /// Get all results for a scan
    pub async fn get_results(&self, scan_id: &str) -> Result<Vec<ScanResult>> {
        let cursor = self.results_collection()
            .find(bson::doc! { "scan_id": scan_id })
            .sort(bson::doc! { "timestamp": 1 })
            .await
            .map_err(|e| AppError::Database(e))?;

        cursor
            .try_collect()
            .await
            .map_err(|e| AppError::Database(e))
    }

    /// Get result count for a scan
    pub async fn count_results(&self, scan_id: &str) -> Result<u64> {
        self.results_collection()
            .count_documents(bson::doc! { "scan_id": scan_id })
            .await
            .map_err(|e| AppError::Database(e))
    }
}
