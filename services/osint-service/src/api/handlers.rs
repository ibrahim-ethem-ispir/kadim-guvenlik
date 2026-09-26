//! # API Handlers
//! 
//! Türkçe: HTTP endpoint handler fonksiyonları.
//! Her endpoint için ayrı handler, iş mantığı OSINT modüllerine delege edilir.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use crate::AppState;
use crate::api::requests::*;
use crate::api::responses::*;
use crate::models::entity::{Entity, EntityType};
use crate::models::relationship::{Relationship, RelationshipType};
use crate::models::scan::{Scan, ScanStatus};
use crate::osint;
use crate::graph;
use mongodb::bson::oid::ObjectId;

// Uygulama başlangıç zamanı (uptime için)
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn get_start_time() -> &'static Instant {
    START_TIME.get_or_init(Instant::now)
}

// ==================== HEALTH CHECK ====================

/// Türkçe: Servis sağlık durumu kontrolü
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Json<HealthResponse> {
    let uptime = get_start_time().elapsed().as_secs();
    
    // MongoDB durumu
    let mongo_status = match state.db.mongo_db.run_command(
        mongodb::bson::doc! { "ping": 1 }, 
        None
    ).await {
        Ok(_) => "connected",
        Err(_) => "disconnected",
    };
    
    // Redis durumu
    let redis_status = "connected"; // ConnectionManager otomatik reconnect yapar

    // API key durumları — frontend "hangi kaynak aktif?" rozetleri için.
    let securitytrails_configured = std::env::var("SECURITYTRAILS_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some();

    let integrations = vec![
        IntegrationStatus {
            name: "shodan".to_string(),
            configured: state.integrations.shodan.is_available(),
            requires_key: true,
            free_tier: false,
            signup_url: "https://account.shodan.io/register".to_string(),
            note: "Port/servis istihbaratı. Ücretli (tek seferlik ~$49 membership).".to_string(),
        },
        IntegrationStatus {
            name: "virustotal".to_string(),
            configured: state.integrations.virustotal.is_available(),
            requires_key: true,
            free_tier: true,
            signup_url: "https://www.virustotal.com/gui/join-us".to_string(),
            note: "İtibar/zararlı tespiti. Ücretsiz plan: 4 istek/dk.".to_string(),
        },
        IntegrationStatus {
            name: "abuseipdb".to_string(),
            configured: state.integrations.abuseipdb.is_available(),
            requires_key: true,
            free_tier: true,
            signup_url: "https://www.abuseipdb.com/register".to_string(),
            note: "IP kötüye kullanım skoru. Ücretsiz plan: 1000 kontrol/gün.".to_string(),
        },
        IntegrationStatus {
            name: "securitytrails".to_string(),
            configured: securitytrails_configured,
            requires_key: true,
            free_tier: true,
            signup_url: "https://securitytrails.com/app/signup".to_string(),
            note: "Pasif DNS/subdomain geçmişi. Ücretsiz plan: 50 sorgu/ay.".to_string(),
        },
    ];

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        mongodb: mongo_status.to_string(),
        redis: redis_status.to_string(),
        uptime_secs: uptime,
        integrations,
    })
}

// ==================== INVESTIGATION ENDPOINTS ====================

/// Türkçe: Yeni OSINT araştırması başlat
pub async fn start_investigation(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InvestigateRequest>,
) -> Result<Json<ApiResponse<InvestigationStarted>>, StatusCode> {
    // Input validation
    if req.target.is_empty() {
        return Ok(Json(ApiResponse::error("Hedef belirtilmedi")));
    }
    
    let scan_id = Uuid::new_v4().to_string();
    
    // Hedef tipini tespit et
    let target_type = detect_target_type(&req.target);
    
    // Modülleri belirle
    let modules = if req.modules.is_empty() {
        get_default_modules(&target_type)
    } else {
        req.modules.clone()
    };
    
    // Scan kaydı oluştur
    let scan = Scan::new(
        scan_id.clone(),
        req.target.clone(),
        &target_type,
        modules.clone(),
    );
    
    // MongoDB'ye kaydet
    if let Err(e) = state.db.create_scan(&scan).await {
        tracing::error!("Scan kaydı oluşturulamadı: {}", e);
        return Ok(Json(ApiResponse::error("Tarama başlatılamadı")));
    }
    
    // Audit log
    let _ = state.db.log_audit("investigation_started", &req.target, Some(&scan_id)).await;
    
    // Background task olarak araştırmayı başlat
    let state_clone = state.clone();
    let scan_id_clone = scan_id.clone();
    let target = req.target.clone();
    let depth = req.depth;
    let max_entities = req.max_entities;
    
    let modules_clone = modules.clone();
    tokio::spawn(async move {
        if let Err(e) = osint::run_investigation(
            &state_clone,
            &scan_id_clone,
            &target,
            &modules_clone,
            depth,
            max_entities,
        ).await {
            tracing::error!("Araştırma hatası: {}", e);
            let _ = state_clone.db.update_scan_status(
                &scan_id_clone,
                ScanStatus::Failed,
                None,
                None,
            ).await;
        }
    });
    
    Ok(Json(ApiResponse::success(InvestigationStarted {
        scan_id,
        status: "started".to_string(),
        message: "Araştırma başlatıldı".to_string(),
        target: req.target,
        modules,
    })))
}

/// Türkçe: Araştırma durumunu sorgula
pub async fn get_investigation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<InvestigationStatus>>, StatusCode> {
    // MongoDB'den scan bilgisini al
    match state.db.get_scan(&id).await {
        Ok(Some(scan)) => {
            // Redis'ten progress bilgisini al
            let progress = state.db.get_investigation_progress(&id).await.unwrap_or(0);
            
            Ok(Json(ApiResponse::success(InvestigationStatus {
                scan_id: scan.scan_id,
                status: scan.status.as_str().to_string(),
                progress: if scan.status == ScanStatus::Completed { 100 } else { progress },
                entity_count: scan.entity_count,
                relationship_count: scan.relationship_count,
                current_module: None,
                started_at: scan.started_at.to_rfc3339(),
                completed_at: scan.completed_at.map(|t| t.to_rfc3339()),
                error: scan.error_message,
            })))
        }
        Ok(None) => {
            Ok(Json(ApiResponse::error("Araştırma bulunamadı")))
        }
        Err(e) => {
            tracing::error!("Scan sorgu hatası: {}", e);
            Ok(Json(ApiResponse::error("Veritabanı hatası")))
        }
    }
}

/// Türkçe: Araştırmayı iptal et
pub async fn cancel_investigation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    // Durumu cancelled olarak güncelle
    match state.db.update_scan_status(&id, ScanStatus::Cancelled, None, None).await {
        Ok(_) => {
            let _ = state.db.log_audit("investigation_cancelled", &id, None).await;
            Ok(Json(ApiResponse::success_with_message((), "Araştırma iptal edildi")))
        }
        Err(e) => {
            tracing::error!("İptal hatası: {}", e);
            Ok(Json(ApiResponse::error("İptal işlemi başarısız")))
        }
    }
}

// ==================== ENTITY ENDPOINTS ====================

/// Türkçe: Entity listesi
pub async fn list_entities(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<EntityFilter>,
) -> Result<Json<ApiResponse<EntityListResponse>>, StatusCode> {
    let entity_type = filter.entity_type.as_ref().and_then(|t| EntityType::from_str(t));
    
    match state.db.list_entities(entity_type, filter.limit, filter.skip).await {
        Ok(entities) => {
            let entity_jsons: Vec<serde_json::Value> = entities.iter()
                .map(|e| e.to_graph_node())
                .collect();
            
            Ok(Json(ApiResponse::success(EntityListResponse {
                total: entity_jsons.len() as u64,
                entities: entity_jsons,
                limit: filter.limit,
                skip: filter.skip,
                has_more: entities.len() as i64 >= filter.limit,
            })))
        }
        Err(e) => {
            tracing::error!("Entity listesi hatası: {}", e);
            Ok(Json(ApiResponse::error("Veriler alınamadı")))
        }
    }
}

/// Türkçe: Tek entity detayı
pub async fn get_entity(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let oid = match mongodb::bson::oid::ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => return Ok(Json(ApiResponse::error("Geçersiz ID formatı"))),
    };
    
    match state.db.get_entity_by_id(&oid).await {
        Ok(Some(entity)) => {
            Ok(Json(ApiResponse::success(entity.to_graph_node())))
        }
        Ok(None) => {
            Ok(Json(ApiResponse::error("Entity bulunamadı")))
        }
        Err(e) => {
            tracing::error!("Entity sorgu hatası: {}", e);
            Ok(Json(ApiResponse::error("Veritabanı hatası")))
        }
    }
}

/// Türkçe: Entity transform (genişletme)
pub async fn transform_entity(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<TransformRequest>,
) -> Result<Json<ApiResponse<GraphData>>, StatusCode> {
    let oid = match mongodb::bson::oid::ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => return Ok(Json(ApiResponse::error("Geçersiz ID formatı"))),
    };
    
    // Entity'yi al
    let entity = match state.db.get_entity_by_id(&oid).await {
        Ok(Some(e)) => e,
        Ok(None) => return Ok(Json(ApiResponse::error("Entity bulunamadı"))),
        Err(e) => {
            tracing::error!("Entity sorgu hatası: {}", e);
            return Ok(Json(ApiResponse::error("Veritabanı hatası")));
        }
    };
    
    // Transform işlemini çalıştır
    match graph::transform::run_transform(&state, &entity, &req.transform_type).await {
        Ok(graph_data) => Ok(Json(ApiResponse::success(graph_data))),
        Err(e) => {
            tracing::error!("Transform hatası: {}", e);
            Ok(Json(ApiResponse::error(&format!("Transform başarısız: {}", e))))
        }
    }
}

/// Türkçe: Entity ilişkileri
pub async fn get_entity_relationships(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<serde_json::Value>>>, StatusCode> {
    let oid = match mongodb::bson::oid::ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => return Ok(Json(ApiResponse::error("Geçersiz ID formatı"))),
    };
    
    match state.db.get_relationships_for_entity(&oid).await {
        Ok(relationships) => {
            let edges: Vec<serde_json::Value> = relationships.iter()
                .map(|r| r.to_graph_edge())
                .collect();
            Ok(Json(ApiResponse::success(edges)))
        }
        Err(e) => {
            tracing::error!("İlişki sorgu hatası: {}", e);
            Ok(Json(ApiResponse::error("Veriler alınamadı")))
        }
    }
}

// ==================== GRAPH ENDPOINTS ====================

/// Türkçe: Domain için graf verisi
pub async fn get_domain_graph(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> Result<Json<ApiResponse<GraphData>>, StatusCode> {
    // Entity'leri al
    let entities = match state.db.get_entities_for_domain(&domain).await {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Entity sorgu hatası: {}", e);
            return Ok(Json(ApiResponse::error("Veriler alınamadı")));
        }
    };
    
    // Relationship'leri al
    let relationships = match state.db.get_relationships_for_domain(&domain).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("İlişki sorgu hatası: {}", e);
            return Ok(Json(ApiResponse::error("Veriler alınamadı")));
        }
    };
    
    // Graph formatına dönüştür
    let nodes: Vec<GraphNode> = entities.iter()
        .map(|e| {
            let json = e.to_graph_node();
            serde_json::from_value(json).unwrap_or_else(|_| GraphNode {
                id: String::new(),
                node_type: String::new(),
                label: String::new(),
                icon: String::new(),
                color: String::new(),
                properties: serde_json::Value::Null,
                confidence: 1.0,
                tags: vec![],
            })
        })
        .collect();
    
    let edges: Vec<GraphEdge> = relationships.iter()
        .map(|r| {
            let json = r.to_graph_edge();
            serde_json::from_value(json).unwrap_or_else(|_| GraphEdge {
                id: String::new(),
                source: String::new(),
                target: String::new(),
                edge_type: String::new(),
                label: String::new(),
                color: String::new(),
                properties: serde_json::Value::Null,
            })
        })
        .collect();
    
    // İstatistikleri hesapla
    let mut node_types = serde_json::Map::new();
    for entity in &entities {
        let key = entity.entity_type.as_str().to_string();
        let count = node_types.get(&key)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        node_types.insert(key, serde_json::Value::Number((count + 1).into()));
    }
    
    let mut edge_types = serde_json::Map::new();
    for rel in &relationships {
        let key = rel.relationship_type.as_str().to_string();
        let count = edge_types.get(&key)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        edge_types.insert(key, serde_json::Value::Number((count + 1).into()));
    }
    
    Ok(Json(ApiResponse::success(GraphData {
        nodes,
        edges,
        stats: GraphStats {
            total_nodes: entities.len() as u32,
            total_edges: relationships.len() as u32,
            node_types: serde_json::Value::Object(node_types),
            edge_types: serde_json::Value::Object(edge_types),
        },
    })))
}

// ==================== HISTORY ENDPOINTS ====================

/// Türkçe: Tarama geçmişi listesi
pub async fn list_history(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HistoryFilter>,
) -> Result<Json<ApiResponse<HistoryListResponse>>, StatusCode> {
    let domain = filter.domain.as_deref().unwrap_or("");
    
    match state.db.get_domain_history(domain, filter.limit).await {
        Ok(scans) => {
            let summaries: Vec<ScanSummary> = scans.iter()
                .map(|s| ScanSummary {
                    scan_id: s.scan_id.clone(),
                    target: s.target.clone(),
                    status: s.status.as_str().to_string(),
                    started_at: s.started_at.to_rfc3339(),
                    completed_at: s.completed_at.map(|t| t.to_rfc3339()),
                    entity_count: s.entity_count,
                    modules: s.modules.clone(),
                })
                .collect();
            
            Ok(Json(ApiResponse::success(HistoryListResponse {
                total: summaries.len() as u64,
                scans: summaries,
            })))
        }
        Err(e) => {
            tracing::error!("Geçmiş sorgu hatası: {}", e);
            Ok(Json(ApiResponse::error("Veriler alınamadı")))
        }
    }
}

/// Türkçe: Belirli domain için geçmiş
pub async fn get_domain_history(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> Result<Json<ApiResponse<HistoryListResponse>>, StatusCode> {
    match state.db.get_domain_history(&domain, 100).await {
        Ok(scans) => {
            let summaries: Vec<ScanSummary> = scans.iter()
                .map(|s| ScanSummary {
                    scan_id: s.scan_id.clone(),
                    target: s.target.clone(),
                    status: s.status.as_str().to_string(),
                    started_at: s.started_at.to_rfc3339(),
                    completed_at: s.completed_at.map(|t| t.to_rfc3339()),
                    entity_count: s.entity_count,
                    modules: s.modules.clone(),
                })
                .collect();
            
            Ok(Json(ApiResponse::success(HistoryListResponse {
                total: summaries.len() as u64,
                scans: summaries,
            })))
        }
        Err(e) => {
            tracing::error!("Domain geçmişi hatası: {}", e);
            Ok(Json(ApiResponse::error("Veriler alınamadı")))
        }
    }
}

// ==================== REPORT ENDPOINTS ====================

/// Türkçe: Rapor oluştur
pub async fn create_report(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateReportRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    // TODO: Rapor oluşturma mantığı
    let report_id = Uuid::new_v4().to_string();
    
    let _ = state.db.log_audit("report_created", &req.target, Some(&report_id)).await;
    
    Ok(Json(ApiResponse::success(serde_json::json!({
        "report_id": report_id,
        "status": "created",
        "message": "Rapor oluşturuldu"
    }))))
}

/// Türkçe: Rapor getir
pub async fn get_report(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    // TODO: Rapor getirme mantığı
    Ok(Json(ApiResponse::error(&format!("Rapor bulunamadı: {}", id))))
}

// ==================== DOMAIN MANAGEMENT ====================

/// Türkçe: Takip edilen domain listesi
pub async fn list_domains(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<DomainListResponse>>, StatusCode> {
    match state.db.list_company_domains().await {
        Ok(domains) => {
            let tracked: Vec<TrackedDomain> = domains.iter()
                .map(|d| TrackedDomain {
                    id: d.get_object_id("_id")
                        .map(|oid| oid.to_hex())
                        .unwrap_or_default(),
                    domain: d.get_str("domain").unwrap_or("").to_string(),
                    organization: d.get_str("organization").unwrap_or("").to_string(),
                    added_at: d.get_datetime("added_at")
                        .map(|dt| chrono::DateTime::<chrono::Utc>::from(dt.to_system_time()).to_rfc3339())
                        .unwrap_or_default(),
                    last_scanned: d.get_datetime("last_scanned")
                        .ok()
                        .map(|dt| chrono::DateTime::<chrono::Utc>::from(dt.to_system_time()).to_rfc3339()),
                    scan_schedule: d.get_str("scan_schedule").unwrap_or("manual").to_string(),
                    entity_count: None,
                })
                .collect();
            
            Ok(Json(ApiResponse::success(DomainListResponse {
                total: tracked.len() as u64,
                domains: tracked,
            })))
        }
        Err(e) => {
            tracing::error!("Domain listesi hatası: {}", e);
            Ok(Json(ApiResponse::error("Veriler alınamadı")))
        }
    }
}

/// Türkçe: Domain ekle
pub async fn add_domain(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddDomainRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    match state.db.add_company_domain(&req.domain, &req.organization).await {
        Ok(id) => {
            let _ = state.db.log_audit("domain_added", &req.domain, None).await;
            Ok(Json(ApiResponse::success(serde_json::json!({
                "id": id.to_hex(),
                "message": "Domain eklendi"
            }))))
        }
        Err(e) => {
            tracing::error!("Domain ekleme hatası: {}", e);
            Ok(Json(ApiResponse::error("Domain eklenemedi")))
        }
    }
}

/// Türkçe: Domain kaldır
pub async fn remove_domain(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let oid = match mongodb::bson::oid::ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => return Ok(Json(ApiResponse::error("Geçersiz ID formatı"))),
    };
    
    match state.db.remove_company_domain(&oid).await {
        Ok(true) => {
            let _ = state.db.log_audit("domain_removed", &id, None).await;
            Ok(Json(ApiResponse::success_with_message((), "Domain kaldırıldı")))
        }
        Ok(false) => Ok(Json(ApiResponse::error("Domain bulunamadı"))),
        Err(e) => {
            tracing::error!("Domain silme hatası: {}", e);
            Ok(Json(ApiResponse::error("Domain kaldırılamadı")))
        }
    }
}

/// Türkçe: Domain taraması başlat
pub async fn scan_domain(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<InvestigationStarted>>, StatusCode> {
    // Domain bilgisini al ve araştırma başlat
    let oid = match mongodb::bson::oid::ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => return Ok(Json(ApiResponse::error("Geçersiz ID formatı"))),
    };
    
    let domains = match state.db.list_company_domains().await {
        Ok(d) => d,
        Err(_) => return Ok(Json(ApiResponse::error("Domain bulunamadı"))),
    };
    
    let domain_doc = domains.iter()
        .find(|d| d.get_object_id("_id").ok() == Some(oid));
    
    match domain_doc {
        Some(doc) => {
            let domain = doc.get_str("domain").unwrap_or("");
            let req = InvestigateRequest {
                target: domain.to_string(),
                modules: vec![],
                depth: 2,
                max_entities: 500,
            };
            start_investigation(State(state), Json(req)).await
        }
        None => Ok(Json(ApiResponse::error("Domain bulunamadı"))),
    }
}

// ==================== QUICK LOOKUP ENDPOINTS ====================

/// Türkçe: DNS sorgusu
pub async fn dns_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DnsLookupRequest>,
) -> Result<Json<ApiResponse<DnsLookupResponse>>, StatusCode> {
    match osint::dns::lookup(&state, &req.domain).await {
        Ok(response) => Ok(Json(ApiResponse::success(response))),
        Err(e) => {
            tracing::error!("DNS sorgu hatası: {}", e);
            Ok(Json(ApiResponse::error(&format!("DNS sorgusu başarısız: {}", e))))
        }
    }
}

/// Türkçe: WHOIS sorgusu
pub async fn whois_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WhoisLookupRequest>,
) -> Result<Json<ApiResponse<WhoisResponse>>, StatusCode> {
    match osint::whois::lookup(&state, &req.domain).await {
        Ok(response) => Ok(Json(ApiResponse::success(response))),
        Err(e) => {
            tracing::error!("WHOIS sorgu hatası: {}", e);
            Ok(Json(ApiResponse::error(&format!("WHOIS sorgusu başarısız: {}", e))))
        }
    }
}

/// Türkçe: SSL sertifika sorgusu
pub async fn ssl_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SslLookupRequest>,
) -> Result<Json<ApiResponse<SslResponse>>, StatusCode> {
    match osint::ssl::lookup(&state, &req.host, req.port).await {
        Ok(response) => Ok(Json(ApiResponse::success(response))),
        Err(e) => {
            tracing::error!("SSL sorgu hatası: {}", e);
            Ok(Json(ApiResponse::error(&format!("SSL sorgusu başarısız: {}", e))))
        }
    }
}

/// Türkçe: Subdomain keşfi
pub async fn subdomain_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubdomainLookupRequest>,
) -> Result<Json<ApiResponse<SubdomainResponse>>, StatusCode> {
    match osint::subdomain::discover(&state, &req.domain, Some(req.max_results as usize)).await {
        Ok(response) => Ok(Json(ApiResponse::success(response))),
        Err(e) => {
            tracing::error!("Subdomain keşif hatası: {}", e);
            Ok(Json(ApiResponse::error(&format!("Subdomain keşfi başarısız: {}", e))))
        }
    }
}

/// Türkçe: IP intelligence
pub async fn ip_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IpLookupRequest>,
) -> Result<Json<ApiResponse<IpInfoResponse>>, StatusCode> {
    match osint::ip::lookup(&state, &req.ip).await {
        Ok(response) => Ok(Json(ApiResponse::success(response))),
        Err(e) => {
            tracing::error!("IP sorgu hatası: {}", e);
            Ok(Json(ApiResponse::error(&format!("IP sorgusu başarısız: {}", e))))
        }
    }
}

/// Türkçe: Domain Profil (Aggregated Data)
pub async fn get_domain_profile(
    State(state): State<Arc<AppState>>,
    Path(target): Path<String>,
) -> Result<Json<ApiResponse<DomainProfile>>, StatusCode> {
    // 1. Domain entity'sini bul (metadata için)
    let domain_entity = state.db.get_entity(EntityType::Domain, &target).await.unwrap_or(None);
    
    // 2. Tarama geçmişini al
    let history = state.db.get_domain_history(&target, 10).await.unwrap_or(vec![]);
    
    // 3. İlişkili entity'leri al
    let entities = state.db.get_entities_for_domain(&target).await.unwrap_or(vec![]);
    
    // 4. Verileri kategorize et ve Analiz Yap
    let mut subdomains = Vec::new();
    let mut ips = Vec::new();
    let mut ports = Vec::new();
    let mut detailed_services = Vec::new();
    let mut technologies = Vec::new();
    let mut vulns = Vec::new();
    
    // Professional Analytics Collections
    let mut geo_map: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut asn_map: std::collections::HashMap<String, String> = std::collections::HashMap::new(); // ASN -> Org Name
    let mut asn_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut ssl_health: Option<SslHealth> = None;
    
    
    for e in &entities {
        match e.entity_type {
            EntityType::Subdomain => subdomains.push(e.value.clone()),
            EntityType::Ip => {
                ips.push(e.value.clone());
                
                // IP Intelligence Lookup (if not present)
                // This would ideally be cached or pre-fetched.
                // For this implementation, we check the entity properties if we saved enriched data
                if let Some(country) = e.properties.get("country_code").and_then(|v| v.as_str()) {
                    *geo_map.entry(country.to_string()).or_insert(0) += 1;
                }
                
                if let Some(asn) = e.properties.get("asn").and_then(|v| v.as_str()) {
                    let org = e.properties.get("asn_org").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                    asn_map.insert(asn.to_string(), org);
                    *asn_counts.entry(asn.to_string()).or_insert(0) += 1;
                }
            },
            EntityType::Port => {
                // Port değerini parse et (domain:port veya ip:port formatında olabilir)
                if let Some(port_str) = e.value.split(':').last() {
                    if let Ok(p) = port_str.parse::<u16>() {
                        ports.push(p);
                        
                        // Detailed Service Info
                        let protocol = e.properties.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
                        let service = e.properties.get("service").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                        let version = e.properties.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let port_state = e.properties.get("state").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                        
                        detailed_services.push(NmapServiceInfo {
                            port: p,
                            protocol,
                            service,
                            version,
                            state: port_state
                        });
                        
                        // Check for SSL on 443
                        if p == 443 && ssl_health.is_none() {
                             // Try to fetch cached SSL info
                             if let Ok(Some(ssl_data)) = state.db.get_cached_ssl::<SslResponse>(&target).await {
                                 let now = chrono::Utc::now();
                                 let expiry_date = chrono::DateTime::parse_from_rfc3339(&ssl_data.not_after).unwrap_or(now.into()).with_timezone(&chrono::Utc);
                                 let days_left = (expiry_date - now).num_days();
                                 
                                 let mut issues = Vec::new();
                                 if days_left < 30 { issues.push("Expires soon".to_string()); }
                                 if !ssl_data.valid { issues.push("Invalid certificate".to_string()); }
                                 
                                 ssl_health = Some(SslHealth {
                                     issuer: ssl_data.issuer,
                                     valid_from: ssl_data.not_before,
                                     valid_until: ssl_data.not_after,
                                     days_left: days_left,
                                     is_valid: ssl_data.valid,
                                     issues: issues,
                                 });
                             }
                        }
                    }
                }
            },
            EntityType::Technology => technologies.push(e.value.clone()),
            EntityType::Vulnerability => vulns.push(e),
            _ => {}
        }
    }
    
    // Aggregate ASN Info
    let asn_info: Vec<AsnInfo> = asn_counts.iter().map(|(asn, count)| {
        AsnInfo {
            asn: asn.clone(),
            org: asn_map.get(asn).cloned().unwrap_or_default(),
            count: *count,
        }
    }).collect();
    
    // 5. Risk skoru hesapla (Weighted Professional Scoring)
    let mut risk_score = 0;
    
    // Risk Factors Collection
    let mut risk_factors = Vec::new();
    
    // Score Calculation
    // Critical Vulns: 20 pts each
    // High Vulns: 10 pts each
    // Open Database Ports (3306, 5432, 27017, 6379): 15 pts each
    // Expired SSL: 10 pts
    
    let critical_vulns = vulns.iter().filter(|v| v.properties.get("severity").and_then(|s| s.as_str()) == Some("critical")).count();
    risk_score += (critical_vulns as u32) * 20;
    if critical_vulns > 0 { risk_factors.push(format!("{} Critical Vulnerabilities", critical_vulns)); }
    
    let high_vulns = vulns.iter().filter(|v| v.properties.get("severity").and_then(|s| s.as_str()) == Some("high")).count();
    risk_score += (high_vulns as u32) * 10;
     if high_vulns > 0 { risk_factors.push(format!("{} High Vulnerabilities", high_vulns)); }
     
    let risky_ports = [21, 22, 23, 3389, 3306, 5432, 27017, 6379, 9200];
    for p in &ports {
        if risky_ports.contains(p) {
            risk_score += 15;
            risk_factors.push(format!("Risky Port Detected: {}", p));
        }
    }
    
    if let Some(ssl) = &ssl_health {
        if !ssl.is_valid || ssl.days_left < 0 {
            risk_score += 20;
            risk_factors.push("Invalid/Expired SSL Certificate".to_string());
        }
    }
    
    // Baseline risk for open ports
    risk_score += (ports.len() as u32) * 1;
    
    if risk_score > 100 { risk_score = 100; }
    
    
    // 6. Profil geçmişi formatla
    let scan_history = history.iter().map(|s| ProfileScanHistory {
        scan_id: s.scan_id.clone(),
        date: s.started_at.to_rfc3339(),
        scan_types: s.modules.clone(),
        findings_count: s.entity_count,
        risk_score: 0, // Scan modelinde risk skoru yok, varsayılan 0
    }).collect();
    
    // 7. Yanıt oluştur
    let profile = DomainProfile {
        target: target.clone(),
        first_seen: domain_entity.as_ref().map(|e| e.first_seen.to_rfc3339()),
        last_scanned: history.first().map(|s| s.started_at.to_rfc3339()),
        total_scans: history.len() as u32,
        scan_history,
        entities: ProfileEntities {
            subdomains,
            ip_addresses: ips,
            open_ports: ports,
            technologies,
            ssl_info: None,
            whois_data: None,
        },
        vulnerability_trend: vec![],
        services: detailed_services,
        risk_score,
        risk_factors,
        
        // Professional Stats
        geo_distribution: geo_map,
        asn_info: asn_info,
        ssl_health: ssl_health,
    };
    
    Ok(Json(ApiResponse::success(profile)))
}

/// Türkçe: Teknoloji tespiti
pub async fn tech_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TechLookupRequest>,
) -> Result<Json<ApiResponse<TechDetectionResponse>>, StatusCode> {
    match osint::tech::detect(&state, &req.target).await {
        Ok(response) => Ok(Json(ApiResponse::success(response))),
        Err(e) => {
            tracing::error!("Tech tespit hatası: {}", e);
            Ok(Json(ApiResponse::error(&format!("Teknoloji tespiti başarısız: {}", e))))
        }
    }
}

// ==================== INTERNAL CALLBACKS ====================

/// Türkçe: Nmap sonucu al (internal)
pub async fn receive_nmap_result(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NmapResultCallback>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    tracing::info!("Nmap sonucu alındı: scan_id={}", req.scan_id);
    
    // 1. Hedef Entity'yi bul veya oluştur (Domain veya IP)
    // Nmap target IP veya Hostname olabilir.
    let target_type = if req.target.parse::<std::net::IpAddr>().is_ok() {
        EntityType::Ip
    } else {
        EntityType::Domain
    };
    
    let target_entity = Entity::new(
        target_type,
        req.target.clone(),
        "nmap"
    );
    // Varsa update, yoksa insert
    let target_id = state.db.upsert_entity(&target_entity).await.unwrap_or_else(|_| ObjectId::new());
    
    // 2. Port entity'lerini oluştur ve İLİŞKİLENDİR
    for port in &req.ports {
        // Port Entity: "1.2.3.4:80" veya "example.com:80"
        let port_value = format!("{}:{}", req.target, port.port);
        
        let mut port_entity = Entity::new(
            EntityType::Port,
            port_value,
            "nmap",
        )
        .with_property("port", serde_json::json!(port.port))
        .with_property("protocol", serde_json::json!(port.protocol))
        .with_property("state", serde_json::json!(port.state));
        
        if let Some(s) = &port.service { port_entity = port_entity.with_property("service", serde_json::json!(s)); }
        if let Some(v) = &port.version { port_entity = port_entity.with_property("version", serde_json::json!(v)); }
        
        // Port'u kaydet
        if let Ok(port_id) = state.db.upsert_entity(&port_entity).await {
            // Relationship: Target --[HAS_PORT]--> Port
            let rel = Relationship::new(
                target_id,
                port_id,
                RelationshipType::HasPort,
                "nmap"
            );
            let _ = state.db.create_relationship(&rel).await;
        }
    }
    
    Ok(Json(ApiResponse::success_with_message((), "Nmap sonucu işlendi ve graf bağlandı")))
}

/// Türkçe: Nikto sonucu al (internal)
pub async fn receive_nikto_result(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NiktoResultCallback>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    tracing::info!("Nikto sonucu alındı: scan_id={}", req.scan_id);
    
    // Vulnerability entity'lerini oluştur ve kaydet
    for vuln in &req.vulnerabilities {
        let entity = Entity::new(
            EntityType::Vulnerability,
            vuln.id.clone(),
            "nikto",
        )
        .with_property("name", serde_json::json!(vuln.name))
        .with_property("description", serde_json::json!(vuln.description))
        .with_property("severity", serde_json::json!(vuln.severity))
        .with_property("url", serde_json::json!(vuln.url))
        .with_property("references", serde_json::json!(vuln.references));
        
        let _ = state.db.upsert_entity(&entity).await;
    }
    
    Ok(Json(ApiResponse::success_with_message((), "Nikto sonucu işlendi")))
}

/// Türkçe: Nuclei sonucu al (internal)
pub async fn receive_nuclei_result(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NucleiResultCallback>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    tracing::info!("Nuclei sonucu alındı: scan_id={}", req.scan_id);
    
    // Vulnerability entity'lerini oluştur ve kaydet
    for finding in &req.findings {
        let entity = Entity::new(
            EntityType::Vulnerability,
            finding.template_id.clone(),
            "nuclei",
        )
        .with_property("name", serde_json::json!(finding.name))
        .with_property("severity", serde_json::json!(finding.severity))
        .with_property("matched_at", serde_json::json!(finding.matched_at))
        .with_property("description", serde_json::json!(finding.description))
        .with_property("tags", serde_json::json!(finding.tags))
        .with_property("references", serde_json::json!(finding.reference));
        
        let _ = state.db.upsert_entity(&entity).await;
    }
    
    Ok(Json(ApiResponse::success_with_message((), "Nuclei sonucu işlendi")))
}

// ==================== STATS ====================

/// Türkçe: OSINT istatistikleri
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<StatsResponse>>, StatusCode> {
    match state.db.get_stats().await {
        Ok(stats) => {
            Ok(Json(ApiResponse::success(StatsResponse {
                total_entities: stats.get_i64("total_entities").unwrap_or(0) as u64,
                total_relationships: stats.get_i64("total_relationships").unwrap_or(0) as u64,
                total_scans: stats.get_i64("total_scans").unwrap_or(0) as u64,
                tracked_domains: stats.get_i64("tracked_domains").unwrap_or(0) as u64,
                scans_last_24h: stats.get_i64("scans_last_24h").unwrap_or(0) as u64,
                entity_breakdown: serde_json::json!({}),
                recent_activity: vec![],
            })))
        }
        Err(e) => {
            tracing::error!("Stats hatası: {}", e);
            Ok(Json(ApiResponse::error("İstatistikler alınamadı")))
        }
    }
}

// ==================== HELPERS ====================

/// Türkçe: Hedef tipini tespit et (domain, ip, email)
fn detect_target_type(target: &str) -> String {
    // IP kontrolü
    if target.parse::<std::net::IpAddr>().is_ok() {
        return "ip".to_string();
    }
    
    // Email kontrolü
    if target.contains('@') && target.contains('.') {
        return "email".to_string();
    }
    
    // Varsayılan domain
    "domain".to_string()
}

/// Türkçe: Hedef tipine göre varsayılan modüller
fn get_default_modules(target_type: &str) -> Vec<String> {
    match target_type {
        "domain" => vec![
            "dns".to_string(),
            "whois".to_string(),
            "ssl".to_string(),
            "subdomain".to_string(),
            "tech".to_string(),
        ],
        "ip" => vec![
            "ip_info".to_string(),
            "rdns".to_string(),
        ],
        "email" => vec![
            "email_validate".to_string(),
            "domain_from_email".to_string(),
        ],
        _ => vec!["dns".to_string()],
    }
}

// ==================== EXTERNAL API LOOKUP ENDPOINTS ====================

/// Türkçe: Shodan IP lookup
pub async fn shodan_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IpLookupRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    tracing::info!("Shodan lookup başlatıldı: {}", &req.ip);
    
    if !state.integrations.shodan.is_available() {
        tracing::warn!("Shodan API key yapılandırılmamış");
        return Ok(Json(ApiResponse::error("Shodan API key yapılandırılmamış")));
    }
    
    match state.integrations.shodan.lookup(&req.ip).await {
        Ok(result) => {
            tracing::info!("Shodan lookup başarılı: {} - {} port bulundu", &req.ip, result.ports.len());
            let json = serde_json::to_value(result).unwrap_or_default();
            let _ = state.db.log_audit("shodan_lookup", &req.ip, None).await;
            Ok(Json(ApiResponse::success(json)))
        }
        Err(e) => {
            tracing::warn!("Shodan lookup hatası: {} - {}", &req.ip, e);
            Ok(Json(ApiResponse::error(&format!("Shodan sorgusu başarısız: {}", e))))
        }
    }
}

/// Türkçe: VirusTotal lookup (IP veya domain)
pub async fn virustotal_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TargetLookupRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    tracing::info!("VirusTotal lookup başlatıldı: {}", &req.target);
    
    if !state.integrations.virustotal.is_available() {
        tracing::warn!("VirusTotal API key yapılandırılmamış");
        return Ok(Json(ApiResponse::error("VirusTotal API key yapılandırılmamış")));
    }
    
    match state.integrations.virustotal.lookup(&req.target).await {
        Ok(result) => {
            tracing::info!("VirusTotal lookup başarılı: {} - malicious: {}, harmless: {}", 
                &req.target, result.malicious_count, result.harmless_count);
            let json = serde_json::to_value(result).unwrap_or_default();
            let _ = state.db.log_audit("virustotal_lookup", &req.target, None).await;
            Ok(Json(ApiResponse::success(json)))
        }
        Err(e) => {
            tracing::warn!("VirusTotal lookup hatası: {} - {}", &req.target, e);
            Ok(Json(ApiResponse::error(&format!("VirusTotal sorgusu başarısız: {}", e))))
        }
    }
}

/// Türkçe: AbuseIPDB lookup
pub async fn abuseipdb_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IpLookupRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    tracing::info!("AbuseIPDB lookup başlatıldı: {}", &req.ip);
    
    if !state.integrations.abuseipdb.is_available() {
        tracing::warn!("AbuseIPDB API key yapılandırılmamış");
        return Ok(Json(ApiResponse::error("AbuseIPDB API key yapılandırılmamış")));
    }
    
    match state.integrations.abuseipdb.lookup(&req.ip).await {
        Ok(result) => {
            tracing::info!("AbuseIPDB lookup başarılı: {} - abuse score: {}%, reports: {}", 
                &req.ip, result.abuse_confidence_score, result.total_reports);
            let json = serde_json::to_value(result).unwrap_or_default();
            let _ = state.db.log_audit("abuseipdb_lookup", &req.ip, None).await;
            Ok(Json(ApiResponse::success(json)))
        }
        Err(e) => {
            tracing::warn!("AbuseIPDB lookup hatası: {} - {}", &req.ip, e);
            Ok(Json(ApiResponse::error(&format!("AbuseIPDB sorgusu başarısız: {}", e))))
        }
    }
}

/// Türkçe: Aggregate reputation score (tüm kaynaklardan)
pub async fn reputation_lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TargetLookupRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    tracing::info!("Reputation lookup başlatıldı: {}", &req.target);
    
    let reputation = state.integrations.get_reputation(&req.target).await;
    
    tracing::info!("Reputation lookup tamamlandı: {} - score: {:.1}, risk: {}", 
        &req.target, reputation.overall_score, &reputation.risk_level);
    
    let json = serde_json::to_value(reputation).unwrap_or_default();
    let _ = state.db.log_audit("reputation_lookup", &req.target, None).await;
    
    Ok(Json(ApiResponse::success(json)))
}
