//! # MongoDB İşlemleri
//! 
//! Türkçe: Entity, relationship ve scan kayıtları için MongoDB CRUD işlemleri.

use anyhow::Result;
use mongodb::bson::{doc, oid::ObjectId, Document};
use mongodb::options::{FindOptions, UpdateOptions};
use futures::TryStreamExt;

use crate::db::Database;
use crate::models::entity::{Entity, EntityType};
use crate::models::relationship::{Relationship, RelationshipType};
use crate::models::scan::{Scan, ScanStatus};

impl Database {
    // ==================== ENTITY İŞLEMLERİ ====================
    
    /// Türkçe: Yeni entity oluştur veya mevcut olanı güncelle (upsert)
    pub async fn upsert_entity(&self, entity: &Entity) -> Result<ObjectId> {
        let collection = self.collection::<Document>("entities");
        
        let filter = doc! {
            "entity_type": entity.entity_type.as_str(),
            "value": &entity.value
        };
        
        let now = chrono::Utc::now();
        
        let update = doc! {
            "$set": {
                "properties": mongodb::bson::to_bson(&entity.properties)?,
                "last_seen": mongodb::bson::DateTime::from_system_time(now.into()),
                "source": &entity.source,
                "confidence": entity.confidence,
                "tags": &entity.tags,
            },
            "$setOnInsert": {
                "entity_type": entity.entity_type.as_str(),
                "value": &entity.value,
                "first_seen": mongodb::bson::DateTime::from_system_time(now.into()),
            }
        };
        
        let options = UpdateOptions::builder().upsert(true).build();
        let result = collection.update_one(filter.clone(), update, options).await?;
        
        if let Some(id) = result.upserted_id {
            Ok(id.as_object_id().unwrap())
        } else {
            // Güncelleme yapıldı, mevcut ID'yi bul
            let doc = collection.find_one(filter, None).await?
                .ok_or_else(|| anyhow::anyhow!("Entity bulunamadı"))?;
            Ok(doc.get_object_id("_id")?)
        }
    }
    
    /// Türkçe: Entity ID ile getir
    pub async fn get_entity_by_id(&self, id: &ObjectId) -> Result<Option<Entity>> {
        let collection = self.collection::<Entity>("entities");
        Ok(collection.find_one(doc! { "_id": id }, None).await?)
    }
    
    /// Türkçe: Entity tip ve değer ile getir
    pub async fn get_entity(&self, entity_type: EntityType, value: &str) -> Result<Option<Entity>> {
        let collection = self.collection::<Entity>("entities");
        Ok(collection.find_one(doc! { 
            "entity_type": entity_type.as_str(),
            "value": value 
        }, None).await?)
    }
    
    /// Türkçe: Entity'leri listele (pagination ile)
    pub async fn list_entities(
        &self, 
        entity_type: Option<EntityType>,
        limit: i64,
        skip: u64
    ) -> Result<Vec<Entity>> {
        let collection = self.collection::<Entity>("entities");
        
        let filter = match entity_type {
            Some(t) => doc! { "entity_type": t.as_str() },
            None => doc! {}
        };
        
        let options = FindOptions::builder()
            .sort(doc! { "last_seen": -1 })
            .limit(limit)
            .skip(skip)
            .build();
        
        let cursor = collection.find(filter, options).await?;
        let entities: Vec<Entity> = cursor.try_collect().await?;
        
        Ok(entities)
    }
    
    /// Türkçe: Domain ile ilişkili tüm entity'leri getir (graph için)
    pub async fn get_entities_for_domain(&self, domain: &str) -> Result<Vec<Entity>> {
        let collection = self.collection::<Entity>("entities");
        
        // Domain entity'sini ve ilişkili tüm entity'leri bul
        let filter = doc! {
            "$or": [
                { "value": domain },
                { "value": { "$regex": format!("\\.{}$", regex::escape(domain)) } },
                { "properties.domain": domain },
                { "properties.host": domain }
            ]
        };
        
        let cursor = collection.find(filter, None).await?;
        let entities: Vec<Entity> = cursor.try_collect().await?;
        
        Ok(entities)
    }
    
    // ==================== RELATIONSHIP İŞLEMLERİ ====================
    
    /// Türkçe: Yeni relationship oluştur
    pub async fn create_relationship(&self, rel: &Relationship) -> Result<ObjectId> {
        let collection = self.collection::<Document>("relationships");
        
        // Duplicate kontrolü
        let existing = collection.find_one(doc! {
            "source_entity_id": rel.source_entity_id,
            "target_entity_id": rel.target_entity_id,
            "relationship_type": rel.relationship_type.as_str()
        }, None).await?;
        
        if let Some(doc) = existing {
            return Ok(doc.get_object_id("_id")?);
        }
        
        let doc = doc! {
            "source_entity_id": rel.source_entity_id,
            "target_entity_id": rel.target_entity_id,
            "relationship_type": rel.relationship_type.as_str(),
            "properties": mongodb::bson::to_bson(&rel.properties)?,
            "discovered_at": mongodb::bson::DateTime::from_system_time(chrono::Utc::now().into()),
            "source": &rel.source
        };
        
        let result = collection.insert_one(doc, None).await?;
        Ok(result.inserted_id.as_object_id().unwrap())
    }
    
    /// Türkçe: Entity'nin tüm ilişkilerini getir
    pub async fn get_relationships_for_entity(&self, entity_id: &ObjectId) -> Result<Vec<Relationship>> {
        let collection = self.collection::<Relationship>("relationships");
        
        let filter = doc! {
            "$or": [
                { "source_entity_id": entity_id },
                { "target_entity_id": entity_id }
            ]
        };
        
        let cursor = collection.find(filter, None).await?;
        let relationships: Vec<Relationship> = cursor.try_collect().await?;
        
        Ok(relationships)
    }
    
    /// Türkçe: Domain için tüm relationship'leri getir (graph edges)
    pub async fn get_relationships_for_domain(&self, domain: &str) -> Result<Vec<Relationship>> {
        // Önce domain ile ilişkili entity'lerin ID'lerini al
        let entities = self.get_entities_for_domain(domain).await?;
        let entity_ids: Vec<ObjectId> = entities.iter()
            .filter_map(|e| e.id)
            .collect();
        
        if entity_ids.is_empty() {
            return Ok(vec![]);
        }
        
        let collection = self.collection::<Relationship>("relationships");
        
        let filter = doc! {
            "$or": [
                { "source_entity_id": { "$in": &entity_ids } },
                { "target_entity_id": { "$in": &entity_ids } }
            ]
        };
        
        let cursor = collection.find(filter, None).await?;
        let relationships: Vec<Relationship> = cursor.try_collect().await?;
        
        Ok(relationships)
    }
    
    // ==================== SCAN İŞLEMLERİ ====================
    
    /// Türkçe: Yeni scan kaydı oluştur
    pub async fn create_scan(&self, scan: &Scan) -> Result<ObjectId> {
        let collection = self.collection::<Scan>("scans");
        let result = collection.insert_one(scan, None).await?;
        Ok(result.inserted_id.as_object_id().unwrap())
    }
    
    /// Türkçe: Scan durumunu güncelle
    pub async fn update_scan_status(
        &self, 
        scan_id: &str, 
        status: ScanStatus,
        entity_count: Option<u32>,
        relationship_count: Option<u32>
    ) -> Result<()> {
        let collection = self.collection::<Document>("scans");
        
        let mut update = doc! {
            "$set": {
                "status": status.as_str()
            }
        };
        
        if status == ScanStatus::Completed {
            update.get_document_mut("$set").unwrap().insert(
                "completed_at",
                mongodb::bson::DateTime::from_system_time(chrono::Utc::now().into())
            );
        }
        
        if let Some(count) = entity_count {
            update.get_document_mut("$set").unwrap().insert("entity_count", count as i32);
        }
        
        if let Some(count) = relationship_count {
            update.get_document_mut("$set").unwrap().insert("relationship_count", count as i32);
        }
        
        collection.update_one(doc! { "scan_id": scan_id }, update, None).await?;
        
        Ok(())
    }
    
    /// Türkçe: Scan ID ile getir
    pub async fn get_scan(&self, scan_id: &str) -> Result<Option<Scan>> {
        let collection = self.collection::<Scan>("scans");
        Ok(collection.find_one(doc! { "scan_id": scan_id }, None).await?)
    }
    
    /// Türkçe: Domain için scan geçmişi
    pub async fn get_domain_history(&self, domain: &str, limit: i64) -> Result<Vec<Scan>> {
        let collection = self.collection::<Scan>("scans");
        
        let options = FindOptions::builder()
            .sort(doc! { "started_at": -1 })
            .limit(limit)
            .build();
        
        let cursor = collection.find(doc! { "target": domain }, options).await?;
        let scans: Vec<Scan> = cursor.try_collect().await?;
        
        Ok(scans)
    }
    
    // ==================== DOMAIN YÖNETİMİ ====================
    
    /// Türkçe: Şirket domain'i ekle
    pub async fn add_company_domain(&self, domain: &str, organization: &str) -> Result<ObjectId> {
        let collection = self.collection::<Document>("domains");
        
        let doc = doc! {
            "domain": domain,
            "organization": organization,
            "added_at": mongodb::bson::DateTime::from_system_time(chrono::Utc::now().into()),
            "last_scanned": mongodb::bson::Bson::Null,
            "scan_schedule": "manual",
            "alert_settings": {
                "new_subdomain": true,
                "ssl_expiry": true,
                "new_vulnerability": true
            }
        };
        
        let result = collection.insert_one(doc, None).await?;
        Ok(result.inserted_id.as_object_id().unwrap())
    }
    
    /// Türkçe: Şirket domain'lerini listele
    pub async fn list_company_domains(&self) -> Result<Vec<Document>> {
        let collection = self.collection::<Document>("domains");
        let cursor = collection.find(doc! {}, None).await?;
        let domains: Vec<Document> = cursor.try_collect().await?;
        Ok(domains)
    }
    
    /// Türkçe: Domain sil
    pub async fn remove_company_domain(&self, id: &ObjectId) -> Result<bool> {
        let collection = self.collection::<Document>("domains");
        let result = collection.delete_one(doc! { "_id": id }, None).await?;
        Ok(result.deleted_count > 0)
    }
    
    // ==================== AUDIT LOG ====================
    
    /// Türkçe: Audit log kaydı oluştur
    pub async fn log_audit(&self, action: &str, target: &str, details: Option<&str>) -> Result<()> {
        let collection = self.collection::<Document>("audit_logs");
        
        let doc = doc! {
            "timestamp": mongodb::bson::DateTime::from_system_time(chrono::Utc::now().into()),
            "action": action,
            "target": target,
            "details": details.unwrap_or(""),
        };
        
        collection.insert_one(doc, None).await?;
        Ok(())
    }
    
    // ==================== İSTATİSTİKLER ====================
    
    /// Türkçe: OSINT istatistikleri
    pub async fn get_stats(&self) -> Result<Document> {
        let entities_count = self.collection::<Document>("entities").count_documents(doc! {}, None).await?;
        let relationships_count = self.collection::<Document>("relationships").count_documents(doc! {}, None).await?;
        let scans_count = self.collection::<Document>("scans").count_documents(doc! {}, None).await?;
        let domains_count = self.collection::<Document>("domains").count_documents(doc! {}, None).await?;
        
        // Son 24 saatteki taramalar
        let yesterday = chrono::Utc::now() - chrono::Duration::hours(24);
        let recent_scans = self.collection::<Document>("scans").count_documents(
            doc! { "started_at": { "$gte": mongodb::bson::DateTime::from_system_time(yesterday.into()) } },
            None
        ).await?;
        
        Ok(doc! {
            "total_entities": entities_count as i64,
            "total_relationships": relationships_count as i64,
            "total_scans": scans_count as i64,
            "tracked_domains": domains_count as i64,
            "scans_last_24h": recent_scans as i64
        })
    }
}
