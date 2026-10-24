// Türkçe: Recon Intelligence Service - Gelişmiş Varlık Keşfi ve Teknoloji İstihbaratı
// Cloudflare Analyzer'dan evriltilmiş profesyonel recon servisi
mod dns;
mod http;
mod logger;
mod scan;
mod subdomain;
mod spoof;
#[path = "tech_detector_clean.rs"]
mod tech_detector; // Teknoloji tespit motoru (temiz versiyon)
mod database; // MongoDB entegrasyonu

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};
use parking_lot::RwLock;
use futures::stream::{self, StreamExt};
use tower_http::trace::TraceLayer;
use uuid::Uuid;
use crate::logger::{log_info, log_warn, log_error, init_scan_log};
use crate::scan::{
    ScanConfig, ScanStatus, ScanState, AnalysisResponse, DnsResult, HttpResult, SubdomainResult,
    SharedState, AppState, update_scan_state, add_log, is_scan_cancelled, ScanSummary,
};
use crate::database::Database;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    log_info("🚀 Starting Recon Intelligence Service (recon-service)...");

    // Türkçe: MongoDB bağlantısını kur (retry ile, başarısızsa servis başlamasın)
    let db = Some(connect_database_with_retry(5, std::time::Duration::from_secs(2)).await);

    let shared_state = Arc::new(RwLock::new(AppState {
        scans: HashMap::new(),
    }));

    let app = Router::new()
        .route("/analyze", post(create_scan))
        .route("/analyze/:id", get(get_scan_status))
        .route("/analyze/:id/cancel", post(cancel_scan))
        .route("/analyze/spoof", post(create_spoof_scan))
        .route("/analyze/verify", post(verify_spoof_endpoint))
        .route("/wordlists", get(list_wordlists))
        .route("/history", get(get_scan_history))
        .route("/history/:scan_id", get(get_scan_detail))
        .route("/history/domain/:domain", get(get_domain_history))
        .route("/stats", get(get_global_stats))
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http())
        .with_state((shared_state, db));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8004));
    log_info(&format!("🌐 Listening on {}", addr));
    log_info("✓ Recon Intelligence Service hazır");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Türkçe: MongoDB bağlantısını retry ile dener, başarısız olursa çıkış yapar
async fn connect_database_with_retry(max_retries: u32, base_delay: std::time::Duration) -> Database {
    for attempt in 1..=max_retries {
        match Database::new().await {
            Ok(db) => {
                log_info(&format!("✓ MongoDB bağlantısı başarılı (attempt {}/{})", attempt, max_retries));
                return db;
            }
            Err(e) => {
                log_warn(&format!("MongoDB bağlantısı başarısız (attempt {}/{}): {}", attempt, max_retries, e));
                if attempt == max_retries {
                    log_error(&format!("MongoDB bağlantısı kurulamadı, servis kapanıyor: {}", e));
                    std::process::exit(1);
                }
                let sleep_dur = base_delay.mul_f32(attempt as f32);
                tokio::time::sleep(sleep_dur).await;
            }
        }
    }

    // Unreachable: ya döner ya exit eder
    unreachable!()
}

// Türkçe: Health check endpoint (Docker healthcheck için)
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "recon-intelligence",
        "version": "1.0.0"
    }))
}

#[derive(Deserialize)]
struct CreateScanRequest {
    domain: String,
    #[serde(default = "default_wordlist")]
    wordlist: String,
    #[serde(default = "default_concurrency")]
    concurrency: usize,
    #[serde(default = "default_delay")]
    delay_ms: u64,
    #[serde(default = "default_timeout")]
    timeout_minutes: u64,
}

fn default_wordlist() -> String {
    "files/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt".to_string()
}
fn default_concurrency() -> usize { 50 }
fn default_delay() -> u64 { 0 }
fn default_timeout() -> u64 { 10 }

#[derive(Serialize)]
struct CreateScanResponse {
    scan_id: String,
}

#[derive(Serialize)]
struct WordlistListResponse {
    wordlists: Vec<WordlistEntry>,
}

#[derive(Serialize)]
struct WordlistEntry {
    path: String,
    description: String,
    size_bytes: u64,
}

async fn list_wordlists() -> Json<WordlistListResponse> {
    let base_path = "files/SecLists-master/Discovery/DNS";
    let mut wordlists = Vec::new();

    if let Ok(mut entries) = tokio::fs::read_dir(base_path).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(metadata) = entry.metadata().await {
                if metadata.is_file() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.ends_with(".txt") {
                            let description = format_wordlist_name(name);
                            wordlists.push(WordlistEntry {
                                path: format!("{}/{}", base_path, name),
                                description,
                                size_bytes: metadata.len(),
                            });
                        }
                    }
                }
            }
        }
    }
    
    // Sort by size (smallest first for better UX)
    wordlists.sort_by(|a, b| a.size_bytes.cmp(&b.size_bytes));

    Json(WordlistListResponse { wordlists })
}

/// Format wordlist filename into user-friendly description
fn format_wordlist_name(filename: &str) -> String {
    let name = filename.trim_end_matches(".txt");
    
    // Handle special cases with better formatting
    match name {
        "subdomains-top1million-5000" => "⚡ Quick Scan - Top 5K Subdomains".to_string(),
        "subdomains-top1million-20000" => "🚀 Fast Scan - Top 20K Subdomains".to_string(),
        "subdomains-top1million-110000" => "🔥 Deep Scan - Top 110K Subdomains".to_string(),
        "fierce-hostlist" => "🎯 Fierce Hostlist (Small)".to_string(),
        "namelist" => "📋 Common Names List".to_string(),
        "dns-Jhaddix" => "💎 Jhaddix DNS (26M - Comprehensive)".to_string(),
        "n0kovo_subdomains" => "🌟 N0kovo Subdomains (51M - Massive)".to_string(),
        "bug-bounty-program-subdomains-trickest-inventory" => "🐛 Bug Bounty Programs (Trickest)".to_string(),
        "combined_subdomains" => "🔗 Combined Subdomains (8M)".to_string(),
        "shubs-subdomains" => "📚 Shubs Subdomains (6M)".to_string(),
        "shubs-stackoverflow" => "💬 Shubs StackOverflow".to_string(),
        "bitquark-subdomains-top100000" => "⭐ Bitquark Top 100K".to_string(),
        "deepmagic.com-prefixes-top500" => "🔮 DeepMagic Top 500 Prefixes".to_string(),
        "deepmagic.com-prefixes-top50000" => "🔮 DeepMagic Top 50K Prefixes".to_string(),
        "sortedcombined-knock-dns recon-fierce-reconng" => "🛠️ Multi-Tool Combined".to_string(),
        "italian-subdomains" => "🇮🇹 Italian Subdomains".to_string(),
        "subdomains-spanish" => "🇪🇸 Spanish Subdomains".to_string(),
        "services-names" => "⚙️ Service Names".to_string(),
        "tlds" => "🌐 Top-Level Domains".to_string(),
        "FUZZSUBS_CYFARE_1" => "🎲 Fuzz Subdomains #1 (Cyfare)".to_string(),
        "FUZZSUBS_CYFARE_2" => "🎲 Fuzz Subdomains #2 (Cyfare)".to_string(),
        _ => {
            // Fallback: capitalize and replace dashes/underscores
            name.replace('-', " ")
                .replace('_', " ")
                .split_whitespace()
                .map(|word| {
                    let mut c = word.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        }
    }
}

async fn create_scan(
    State((state, db)): State<(SharedState, Option<Database>)>,
    Json(payload): Json<CreateScanRequest>,
) -> Json<CreateScanResponse> {
    let scan_id = Uuid::new_v4().to_string();
    let scan_id_clone = scan_id.clone();
    let state_clone = state.clone();
    let db_clone = db.clone();

    log_info(&format!("Creating scan {} for domain {}", scan_id, payload.domain));

    {
        let mut state_guard = state.write();
        state_guard.scans.insert(
            scan_id.clone(),
            ScanStatus {
                id: scan_id.clone(),
                state: ScanState::Pending,
                progress: 0.0,
                current_step: "Initializing scan...".to_string(),
                total_subdomains: 0,
                scanned_subdomains: 0,
                logs: vec![],
                result: None,
                error: None,
                start_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                scan_rate: 0.0,
                estimated_time_remaining: 0,
                current_wordlist: String::new(),
                total_wordlists: 0,
                processed_wordlists: 0,
                cancelled: false,
            },
        );
    }

    let config = ScanConfig {
        domain: payload.domain,
        wordlist: payload.wordlist,
        concurrency: payload.concurrency,
        delay_ms: payload.delay_ms,
        timeout_minutes: payload.timeout_minutes,
    };

    tokio::spawn(async move {
        // KRİTİK (recon-bitmeme): run_scan içinde `timeout_minutes` HİÇBİR yerde
        // uygulanmıyordu — yalnız loglanıyordu. DNS/HTTP/subdomain taraması ardışık
        // ve sınırsız çalışıyor; cevapsız (filtrelenen) hedeflerde saatlerce sürebilir.
        // Bu arada orchestrator poll'u 600sn'de vazgeçse bile bu spawn görevi ARKA
        // PLANDA çalışmaya devam ediyor → kullanıcı "recon hiç bitmiyor" yaşıyor.
        // Burada tüm taramayı gerçek bir DEADLINE ile sarıyoruz. Süre dolarsa görev
        // düşer ve durumu poll'un tanıdığı terminal bir state'e (Completed/Failed)
        // çekeriz — böylece kısmi sonuç varsa korunur, yoksa temiz biter.
        let deadline = std::time::Duration::from_secs(config.timeout_minutes.max(1) * 60);
        let timed_out = tokio::time::timeout(
            deadline,
            run_scan(state_clone.clone(), db_clone, scan_id_clone.clone(), config),
        )
        .await
        .is_err();

        if timed_out {
            log_warn(&format!(
                "Scan {} deadline ({}dk) aşıldı — kısmi sonuçla sonlandırılıyor",
                scan_id_clone, deadline.as_secs() / 60
            ));
            update_scan_state(&state_clone, &scan_id_clone, |s| {
                // Kullanıcı iptali değilse: terminal state'e çek ki poll takılmasın.
                if s.state == ScanState::Running || s.state == ScanState::Pending {
                    // Elde bir şey varsa Completed(kısmi), hiç yoksa Failed.
                    if s.result.is_some() || s.scanned_subdomains > 0 {
                        s.state = ScanState::Completed;
                        s.progress = 100.0;
                        s.current_step = "Süre sınırı — kısmi sonuç".to_string();
                    } else {
                        s.state = ScanState::Failed;
                        s.error = Some(format!(
                            "Süre sınırı ({}dk) aşıldı, sonuç üretilemedi",
                            deadline.as_secs() / 60
                        ));
                    }
                    s.logs.push(format!(
                        "⏱️ Tarama süre sınırına ({}dk) ulaştı ve sonlandırıldı",
                        deadline.as_secs() / 60
                    ));
                }
            });
        }
    });

    Json(CreateScanResponse { scan_id })
}

async fn get_scan_status(
    State((state, _)): State<(SharedState, Option<Database>)>,
    Path(id): Path<String>,
) -> Json<Option<ScanStatus>> {
    // parking_lot::RwLock - unwrap gerekmiyor
    let state_guard = state.read();
    Json(state_guard.scans.get(&id).cloned())
}

// Taramayı iptal etmek için endpoint - Durdur butonu için
#[derive(Serialize)]
struct CancelResponse {
    success: bool,
    message: String,
}

async fn cancel_scan(
    State((state, _)): State<(SharedState, Option<Database>)>,
    Path(id): Path<String>,
) -> Json<CancelResponse> {
    log_info(&format!("Cancel request received for scan: {}", id));
    
    let scan_exists = {
        // parking_lot::RwLock - unwrap gerekmiyor
        let state_read = state.read();
        state_read.scans.contains_key(&id)
    };
    
    if !scan_exists {
        return Json(CancelResponse {
            success: false,
            message: "Tarama bulunamadı".to_string(),
        });
    }
    
    // Taramayı iptal olarak işaretle - sync fonksiyon kullan
    update_scan_state(&state, &id, |s| {
        if s.state == ScanState::Running || s.state == ScanState::Pending {
            s.cancelled = true;
            s.state = ScanState::Cancelled;
            s.current_step = "Tarama iptal edildi".to_string();
            s.logs.push("⛔ Tarama kullanıcı tarafından iptal edildi".to_string());
            log_info(&format!("Scan {} cancelled by user", id));
        }
    });
    
    Json(CancelResponse {
        success: true,
        message: "Tarama iptal edildi".to_string(),
    })
}

async fn run_scan(state: SharedState, _db: Option<Database>, scan_id: String, config: ScanConfig) {
    init_scan_log(&config.domain);
    log_info(&format!("Starting background scan {} for {}", scan_id, config.domain));

    // Update state to Running
    update_scan_state(&state, &scan_id, |s| {
        s.state = ScanState::Running;
        s.current_step = "Starting DNS analysis...".to_string();
        s.logs.push(format!("🔧 Scan Configuration: Concurrency={}, Delay={}ms, Timeout={}min", 
            config.concurrency, config.delay_ms, config.timeout_minutes));
    });

    let mut all_logs = Vec::new();
    
    // İptal kontrolü - DNS öncesi
    if is_scan_cancelled(&state, &scan_id) {
        log_info(&format!("Scan {} cancelled before DNS analysis", scan_id));
        return;
    }
    
    // DNS Analysis
    add_log(&state, &scan_id, "🔍 DNS analysis started...");
    let dns_start = std::time::Instant::now();
    let dns_res = dns::analyze_dns(&config.domain).await;
    let dns_elapsed = dns_start.elapsed().as_secs_f32();
    for log in &dns_res.logs {
        add_log(&state, &scan_id, log);
    }
    add_log(&state, &scan_id, &format!("✅ DNS analysis completed in {:.2}s", dns_elapsed));
    all_logs.extend(dns_res.logs);

    // İptal kontrolü - HTTP öncesi
    if is_scan_cancelled(&state, &scan_id) {
        log_info(&format!("Scan {} cancelled before HTTP analysis", scan_id));
        return;
    }

    // HTTP Analysis with Tech Detection
    update_scan_state(&state, &scan_id, |s| s.current_step = "Analyzing HTTP & detecting technologies...".to_string());
    add_log(&state, &scan_id, "📡 HTTP analysis & tech detection started...");
    let http_start = std::time::Instant::now();
    let http_res = http::analyze_http_with_tech_detection(&config.domain).await;
    let http_elapsed = http_start.elapsed().as_secs_f32();
    for log in &http_res.logs {
        add_log(&state, &scan_id, log);
    }
    add_log(&state, &scan_id, &format!("✅ HTTP analysis completed in {:.2}s", http_elapsed));
    all_logs.extend(http_res.logs);

    // İptal kontrolü - Subdomain taraması öncesi
    if is_scan_cancelled(&state, &scan_id) {
        log_info(&format!("Scan {} cancelled before subdomain enumeration", scan_id));
        return;
    }

    // Subdomain Analysis
    update_scan_state(&state, &scan_id, |s| s.current_step = "Enumerating subdomains...".to_string());
    add_log(&state, &scan_id, &format!("🔎 Subdomain enumeration started (Wordlist: {})...", config.wordlist));
    
    let sub_start = std::time::Instant::now();
    let sub_res = subdomain::scan_subdomains(
        &config, 
        &state, 
        &scan_id
    ).await;
    let sub_elapsed = sub_start.elapsed().as_secs_f32();
    
    // İptal kontrolü - sonuçları işlemeden önce
    if is_scan_cancelled(&state, &scan_id) {
        log_info(&format!("Scan {} cancelled after subdomain enumeration", scan_id));
        return;
    }
    
    all_logs.extend(sub_res.logs);
    
    add_log(&state, &scan_id, &format!("✅ Subdomain enumeration completed in {:.2}s", sub_elapsed));
    add_log(&state, &scan_id, &format!("📊 Found {} total subdomains", sub_res.subdomains.len()));

    // Türkçe: Root domain'i de asset olarak ekle (HTTP analizi sonuçlarını koru)
    let root_asset = crate::scan::SubdomainInfo {
        subdomain: config.domain.clone(),
        ip: dns_res.ips.get(0).cloned(),
        is_cf: dns_res.is_cf || http_res.found_cf,
        is_live: http_res.status_code.map(|c| c < 500).unwrap_or(false),
        status_code: http_res.status_code,
        response_time_ms: http_res.response_time_ms,
        infrastructure: crate::scan::InfrastructureInfo {
            provider: if dns_res.is_cf || http_res.found_cf { Some("Cloudflare".to_string()) } else { None },
            is_cloud: dns_res.is_cf || http_res.found_cf,
            is_private_ip: false,
            is_waf_protected: dns_res.is_cf || http_res.found_cf,
        },
        technologies: http_res.technologies.clone(),
        page_title: http_res.page_title.clone(),
    };

    // Türkçe: Subdomain'leri HTTP + teknoloji tespiti ile zenginleştir
    let (enriched_subdomains, http_logs) = enrich_subdomains_with_http(
        sub_res.subdomains,
        &state,
        &scan_id,
        config.concurrency.min(20),
    ).await;
    for log in http_logs {
        add_log(&state, &scan_id, &log);
    }

    let mut all_assets = Vec::new();
    all_assets.push(root_asset);
    all_assets.extend(enriched_subdomains.clone());

    // Türkçe: Teknoloji istatistiklerini hesapla (root + subdomain)
    let mut tech_counts: HashMap<String, usize> = HashMap::new();
    for asset in &all_assets {
        for tech in &asset.technologies {
            *tech_counts.entry(tech.name.clone()).or_insert(0) += 1;
        }
    }
    let mut tech_vec: Vec<(String, usize)> = tech_counts.into_iter().collect();
    tech_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let total_assets = all_assets.len().max(1) as f32;
    let top_technologies: Vec<crate::scan::TechCount> = tech_vec.into_iter().take(10)
        .map(|(name, count)| crate::scan::TechCount { 
            name, 
            count,
            percentage: (count as f32 / total_assets) * 100.0,
        })
        .collect();

    let total_technologies: usize = all_assets.iter()
        .map(|s| s.technologies.len())
        .sum();

    // Finalize - sadece iptal edilmediyse
    let total_elapsed = dns_elapsed + http_elapsed + sub_elapsed;
    let total_elapsed_u64 = total_elapsed as u64;
    update_scan_state(&state, &scan_id, |s| {
        // Eğer iptal edilmişse Completed olarak işaretleme
        if s.cancelled {
            return;
        }
        s.state = ScanState::Completed;
        s.progress = 100.0;
        s.current_step = "Completed".to_string();
        s.logs.push(format!("✅ Analysis completed successfully in {:.2}s", total_elapsed));
        
        s.result = Some(AnalysisResponse {
            domain: config.domain.clone(),
            dns: DnsResult {
                is_cf: dns_res.is_cf,
                ips: dns_res.ips,
            },
            http: HttpResult {
                headers: http_res.headers,
                found_cf: http_res.found_cf,
                status_code: http_res.status_code,
                response_time_ms: http_res.response_time_ms,
                page_title: http_res.page_title,
                technologies: http_res.technologies,
            },
            summary: ScanSummary {
                total_subdomains_found: all_assets.len(),
                total_live_assets: all_assets.iter().filter(|s| s.is_live).count(),
                total_technologies,
                cloud_hosted_count: all_assets.iter().filter(|s| s.is_cf).count(),
                direct_ip_count: all_assets.iter().filter(|s| !s.is_cf).count(),
                top_technologies: top_technologies.clone(),
            },
            subdomains: SubdomainResult {
                found: all_assets.clone(),
            },
            spoof: None,
            ssh_auth: None,
        });
    });
    
    log_info(&format!("Scan {} completed successfully", scan_id));

    // Türkçe: MongoDB'ye kaydet (async, hata durumunda log)
    if let Some(db) = _db {
        add_log(&state, &scan_id, "💾 Saving scan results to database...");
        let doc = database::ReconScanDocument {
            scan_id: scan_id.clone(),
            target_domain: config.domain.clone(),
            timestamp: chrono::Utc::now(),
            status: "completed".to_string(),
            config: database::ScanConfig {
                wordlist: config.wordlist.clone(),
                concurrency: config.concurrency,
                timeout_minutes: config.timeout_minutes,
            },
            assets: all_assets.iter().map(|s| database::AssetRecord {
                subdomain: s.subdomain.clone(),
                ip_address: s.ip.clone(),
                is_live: s.is_live,
                status_code: s.status_code,
                infrastructure: database::InfrastructureInfo {
                    provider: s.infrastructure.provider.clone(),
                    is_cloud: s.infrastructure.is_cloud,
                    is_private_ip: s.infrastructure.is_private_ip,
                    is_waf_protected: s.infrastructure.is_waf_protected,
                },
                technologies: s.technologies.clone(),
                page_title: s.page_title.clone(),
                response_time_ms: s.response_time_ms,
                content_length: None,
                server_header: None,
            }).collect(),
            summary: database::ScanSummary {
                total_subdomains_found: all_assets.len(),
                total_live_assets: all_assets.iter().filter(|s| s.is_live).count(),
                total_technologies,
                cloud_hosted_count: all_assets.iter().filter(|s| s.is_cf).count(),
                direct_ip_count: all_assets.iter().filter(|s| !s.is_cf).count(),
                scan_duration_seconds: total_elapsed_u64,
            },
        };
        
        match db.save_scan(&doc).await {
            Ok(_) => {
                add_log(&state, &scan_id, "✓ Scan results saved to database");
                log_info(&format!("Scan {} saved to MongoDB", scan_id));
            }
            Err(e) => {
                add_log(&state, &scan_id, &format!("⚠️ Failed to save to database: {}", e));
                log_warn(&format!("MongoDB save failed for scan {}: {}", scan_id, e));
            }
        }
    }
}

/// Türkçe: Her subdomain için HTTP isteği atıp teknoloji/liveness bilgisiyle zenginleştirir
async fn enrich_subdomains_with_http(
    subdomains: Vec<crate::scan::SubdomainInfo>,
    state: &SharedState,
    scan_id: &str,
    concurrency: usize,
) -> (Vec<crate::scan::SubdomainInfo>, Vec<String>) {
    let mut logs = Vec::new();

    let results = stream::iter(subdomains)
        .map(|mut item| {
            let state = state.clone();
            let scan_id = scan_id.to_string();
            async move {
                let domain = item.subdomain.clone();
                let res = http::analyze_http_with_tech_detection(&domain).await;

                let is_live = matches!(res.status_code, Some(code) if code < 500);
                item.is_live = is_live;
                item.status_code = res.status_code;
                item.response_time_ms = res.response_time_ms;
                item.page_title = res.page_title;
                item.technologies = res.technologies;

                // Altyapı çıkarımları
                if res.found_cf && item.infrastructure.provider.is_none() {
                    item.infrastructure.provider = Some("Cloudflare".to_string());
                    item.infrastructure.is_cloud = true;
                    item.infrastructure.is_waf_protected = true;
                    item.is_cf = true;
                }

                let log_line = if let Some(code) = item.status_code {
                    format!("🌐 {} -> HTTP {} | live={} | techs={}", domain, code, item.is_live, item.technologies.len())
                } else {
                    format!("🌐 {} -> erişilemedi", domain)
                };

                add_log(&state, &scan_id, &log_line);
                (item, log_line)
            }
        })
        .buffer_unordered(concurrency.max(5))
        .collect::<Vec<_>>()
        .await;

    let mut enriched = Vec::with_capacity(results.len());
    for (item, log_line) in results {
        enriched.push(item);
        logs.push(log_line);
    }

    (enriched, logs)
}

// ============================================================================
// IP WHITELIST BYPASS ENDPOINTS
// ============================================================================

#[derive(Deserialize)]
struct CreateSpoofRequest {
    target_host: String,
    target_port: u16,
    whitelist_ip: String,
    scenario: String, // "ssh", "rdp", "admin", "database", "custom"
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
struct VerifySpoofRequest {
    target_host: String,
    target_port: u16,
    header_name: String,
    ip_value: String,
}

async fn create_spoof_scan(
    State((state, _)): State<(SharedState, Option<Database>)>,
    Json(payload): Json<CreateSpoofRequest>,
) -> Json<CreateScanResponse> {
    let scan_id = Uuid::new_v4().to_string();
    let scan_id_clone = scan_id.clone();
    let state_clone = state.clone();

    log_info(&format!("Creating IP whitelist bypass scan {} for {}:{}", 
        scan_id, payload.target_host, payload.target_port));

    {
        let mut state_guard = state.write();
        state_guard.scans.insert(
            scan_id.clone(),
            ScanStatus {
                id: scan_id.clone(),
                state: ScanState::Pending,
                progress: 0.0,
                current_step: "Initializing IP whitelist bypass test...".to_string(),
                total_subdomains: 0,
                scanned_subdomains: 0,
                logs: vec![],
                result: None,
                error: None,
                start_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                scan_rate: 0.0,
                estimated_time_remaining: 0,
                current_wordlist: String::new(),
                total_wordlists: 0,
                processed_wordlists: 0,
                cancelled: false,
            },
        );
    }

    tokio::spawn(async move {
        run_spoof_scan(state_clone, scan_id_clone, payload.target_host, payload.target_port, payload.whitelist_ip, payload.scenario, payload.username, payload.password).await;
    });

    Json(CreateScanResponse { scan_id })
}

async fn verify_spoof_endpoint(
    Json(payload): Json<VerifySpoofRequest>,
) -> Json<spoof::VerifyResult> {
    let result = spoof::verify_bypass(&payload.target_host, payload.target_port, &payload.header_name, &payload.ip_value).await;
    Json(result)
}

async fn run_spoof_scan(
    state: SharedState,
    scan_id: String,
    target_host: String,
    target_port: u16,
    whitelist_ip: String,
    scenario: String,
    username: Option<String>,
    password: Option<String>,
) {
    log_info(&format!("Starting IP whitelist bypass scan {} for {}:{}", scan_id, target_host, target_port));

    update_scan_state(&state, &scan_id, |s| {
        s.state = ScanState::Running;
        s.current_step = "Running IP Whitelist Bypass Analysis...".to_string();
    });

    if is_scan_cancelled(&state, &scan_id) { return; }

    let start_time = std::time::Instant::now();
    let spoof_res = spoof::test_ip_whitelist_bypass(&target_host, target_port, &whitelist_ip, &scenario, username.as_deref(), password.as_deref()).await;
    let elapsed = start_time.elapsed().as_secs_f32();

    for log in &spoof_res.logs {
        add_log(&state, &scan_id, log);
    }

    update_scan_state(&state, &scan_id, |s| {
        if s.cancelled { return; }
        s.state = ScanState::Completed;
        s.progress = 100.0;
        s.current_step = "IP Whitelist Bypass Analysis Completed".to_string();
        s.logs.push(format!("✅ Analysis completed in {:.2}s", elapsed));
        
        s.result = Some(AnalysisResponse {
            domain: target_host.clone(),
            dns: DnsResult { is_cf: false, ips: vec![] },
            http: HttpResult { 
                headers: std::collections::HashMap::new(), 
                found_cf: false,
                status_code: None,
                response_time_ms: None,
                page_title: None,
                technologies: vec![],
            },
            subdomains: SubdomainResult { found: vec![] },
            spoof: Some(spoof_res.successful_bypasses),
            ssh_auth: spoof_res.ssh_auth,
            summary: ScanSummary {
                total_subdomains_found: 0,
                total_live_assets: 0,
                total_technologies: 0,
                cloud_hosted_count: 0,
                direct_ip_count: 0,
                top_technologies: vec![],
            },
        });
    });
}

// ============================================================================
// HISTORY & STATISTICS ENDPOINTS
// ============================================================================

/// Türkçe: Tüm tarama geçmişini getir (son 100 kayıt)
async fn get_scan_history(
    State((_, db)): State<(SharedState, Option<Database>)>,
) -> Json<serde_json::Value> {
    if let Some(database) = db {
        match database.get_all_scans(100).await {
            Ok(scans) => Json(serde_json::json!({ "scans": scans })),
            Err(e) => Json(serde_json::json!({ 
                "error": format!("Database error: {}", e),
                "scans": []
            })),
        }
    } else {
        Json(serde_json::json!({ 
            "error": "Database not available",
            "scans": []
        }))
    }
}

/// Türkçe: Scan ID ile detaylı tarama sonucunu getir (MongoDB'den)
async fn get_scan_detail(
    State((_, db)): State<(SharedState, Option<Database>)>,
    Path(scan_id): Path<String>,
) -> Json<serde_json::Value> {
    if let Some(database) = db {
        match database.get_scan(&scan_id).await {
            Ok(Some(scan)) => Json(serde_json::to_value(scan).unwrap()),
            Ok(None) => Json(serde_json::json!({ "error": "Scan not found" })),
            Err(e) => Json(serde_json::json!({ "error": format!("Database error: {}", e) })),
        }
    } else {
        Json(serde_json::json!({ "error": "Database not available" }))
    }
}

/// Türkçe: Belirli domain için tarama geçmişini getir
async fn get_domain_history(
    State((_, db)): State<(SharedState, Option<Database>)>,
    Path(domain): Path<String>,
) -> Json<serde_json::Value> {
    if let Some(database) = db {
        match database.get_domain_history(&domain, 50).await {
            Ok(scans) => Json(serde_json::json!({ "domain": domain, "scans": scans })),
            Err(e) => Json(serde_json::json!({ 
                "error": format!("Database error: {}", e),
                "domain": domain,
                "scans": []
            })),
        }
    } else {
        Json(serde_json::json!({ 
            "error": "Database not available",
            "domain": domain,
            "scans": []
        }))
    }
}

/// Türkçe: Global istatistikleri getir (Dashboard için)
async fn get_global_stats(
    State((_, db)): State<(SharedState, Option<Database>)>,
) -> Json<serde_json::Value> {
    if let Some(database) = db {
        match database.get_global_stats().await {
            Ok(stats) => Json(serde_json::to_value(stats).unwrap()),
            Err(e) => Json(serde_json::json!({ "error": format!("Database error: {}", e) })),
        }
    } else {
        Json(serde_json::json!({ "error": "Database not available" }))
    }
}
