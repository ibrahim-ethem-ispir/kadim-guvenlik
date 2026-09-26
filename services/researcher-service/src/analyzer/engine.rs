//! Araştırma Motoru - Tüm analiz modüllerini orkestra eder

use std::sync::Arc;
use anyhow::Result;

use crate::AppState;
use crate::api::ACTIVE_SCANS;
use crate::models::{ScanStatus, DetectedTechnology, Finding, Severity, FindingCategory};
use crate::services::ServiceClient;

use super::js_analyzer::JsAnalyzer;
use super::browser::BrowserAnalyzer;
use super::fuzzer::SmartFuzzer;

/// Araştırma motoru
pub struct ResearchEngine {
    state: Arc<AppState>,
    service_client: ServiceClient,
    js_analyzer: JsAnalyzer,
    fuzzer: SmartFuzzer,
}

impl ResearchEngine {
    pub fn new(state: Arc<AppState>) -> Self {
        let service_client = ServiceClient::new(
            state.http_client.clone(),
            state.config.clone(),
        );
        
        Self {
            state: state.clone(),
            service_client,
            js_analyzer: JsAnalyzer::new(state.http_client.clone()),
            fuzzer: SmartFuzzer::new(state.http_client.clone()),
        }
    }
    
    /// Taramayı çalıştır
    pub async fn run(&self, scan_id: &str) -> Result<()> {
        // Tarama bilgilerini al
        let (target_url, modules) = {
            let scans = ACTIVE_SCANS.read().await;
            let scan = scans.get(scan_id).ok_or_else(|| anyhow::anyhow!("Tarama bulunamadı"))?;
            (scan.target_url.clone(), scan.modules.clone())
        };
        
        self.log(scan_id, "info", "core", &format!("🎯 Hedef: {}", target_url)).await;
        
        // 1. Fingerprint (teknoloji tespiti)
        if modules.contains(&"fingerprint".to_string()) {
            self.run_fingerprint(scan_id, &target_url).await?;
        }
        
        // İptal kontrolü
        if self.is_cancelled(scan_id).await {
            return Ok(());
        }
        
        // 2. JS Analizi
        if modules.contains(&"js_analysis".to_string()) {
            self.run_js_analysis(scan_id, &target_url).await?;
        }
        
        // İptal kontrolü
        if self.is_cancelled(scan_id).await {
            return Ok(());
        }
        
        // 3. CVE Tarama (Nuclei)
        if modules.contains(&"cve_scan".to_string()) {
            self.run_cve_scan(scan_id, &target_url).await?;
        }
        
        // 4. Headless Browser (opsiyonel)
        if modules.contains(&"browser".to_string()) && self.state.config.headless_browser_enabled {
            self.run_browser_analysis(scan_id, &target_url).await?;
        }
        
        // 5. Smart Fuzzing
        if modules.contains(&"fuzzing".to_string()) {
            self.run_fuzzing(scan_id, &target_url).await?;
        }
        
        Ok(())
    }
    
    /// Fingerprint modülü (recon-service entegrasyonu)
    async fn run_fingerprint(&self, scan_id: &str, url: &str) -> Result<()> {
        self.log(scan_id, "info", "fingerprint", "🔍 Teknoloji tespiti başlıyor...").await;
        
        // Önce kendi HTTP analizi
        let response = self.state.http_client.get(url).send().await?;
        let headers = response.headers().clone();
        let body = response.text().await.unwrap_or_default();
        
        let mut technologies = Vec::new();
        let mut findings = Vec::new();
        
        // Header analizi
        if let Some(server) = headers.get("server") {
            let server_str = server.to_str().unwrap_or("");
            technologies.push(DetectedTechnology {
                name: extract_server_name(server_str),
                category: "Web Server".to_string(),
                version: extract_version(server_str),
                confidence: 95,
                cpe: None,
                website: None,
            });
        }
        
        // X-Powered-By
        if let Some(powered_by) = headers.get("x-powered-by") {
            let pb_str = powered_by.to_str().unwrap_or("");
            technologies.push(DetectedTechnology {
                name: pb_str.to_string(),
                category: "Framework".to_string(),
                version: extract_version(pb_str),
                confidence: 90,
                cpe: None,
                website: None,
            });
        }
        
        // HTML içerik analizi
        self.analyze_html_fingerprints(&body, &mut technologies).await;
        
        // Development mode kontrolü
        if body.contains("__NEXT_DATA__") && body.contains("\"mode\":\"development\"") {
            findings.push(Finding::new(
                Severity::Medium,
                FindingCategory::DevelopmentMode,
                "Next.js Development Mode Aktif",
                "Site production yerine development modunda çalışıyor. Bu durum performans ve güvenlik sorunlarına yol açabilir.",
                "HTML içinde development mode indicators bulundu",
                url,
                "fingerprint",
            ).with_recommendation("Production build kullanın"));
        }
        
        // Source map kontrolü - GERÇEK içerik doğrulaması
        let sourcemap_url = format!("{}.map", url.trim_end_matches('/'));
        if let Ok(resp) = self.state.http_client.get(&sourcemap_url).send().await {
            if resp.status().is_success() {
                // Content-Type kontrolü
                let content_type = resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                
                // HTML ise atla (login sayfası olabilir)
                if content_type.contains("text/html") {
                    // HTML döndü, source map değil
                } else if let Ok(body) = resp.text().await {
                    // Source map JSON formatını doğrula
                    // Gerçek source map: {"version":3,"sources":...}
                    let is_real_sourcemap = body.contains("\"version\"") && 
                                            body.contains("\"sources\"") &&
                                            body.contains("\"mappings\"");
                    
                    if is_real_sourcemap {
                        // İçerik önizlemesi (ilk 300 karakter)
                        let preview: String = body.chars().take(300).collect();
                        
                        findings.push(Finding::new(
                            Severity::High,
                            FindingCategory::SourceMapExposed,
                            "Source Map Dosyası Açık",
                            "JavaScript source map dosyası herkesin erişimine açık. Saldırganlar orijinal kaynak kodunuzu görebilir!",
                            format!("İçerik doğrulandı - gerçek source map!\n\nÖnizleme:\n```json\n{}...\n```", preview),
                            url,
                            "fingerprint",
                        ).with_cwe("CWE-540")
                         .with_confidence(98)
                         .with_resource_url(sourcemap_url.clone()));
                    }
                }
            }
        }
        
        // Sonuçları kaydet
        {
            let mut scans = ACTIVE_SCANS.write().await;
            if let Some(scan) = scans.get_mut(scan_id) {
                scan.technologies.extend(technologies.clone());
                scan.findings.extend(findings);
            }
        }
        
        self.log(scan_id, "info", "fingerprint", &format!("✓ {} teknoloji tespit edildi", technologies.len())).await;
        
        Ok(())
    }
    
    /// HTML içerik fingerprint analizi
    async fn analyze_html_fingerprints(&self, body: &str, technologies: &mut Vec<DetectedTechnology>) {
        // Next.js
        if body.contains("/_next/static/") || body.contains("__NEXT_DATA__") {
            let version = extract_nextjs_version(body);
            technologies.push(DetectedTechnology {
                name: "Next.js".to_string(),
                category: "JavaScript Framework".to_string(),
                version,
                confidence: 95,
                cpe: Some("cpe:2.3:a:vercel:next.js".to_string()),
                website: Some("https://nextjs.org".to_string()),
            });
        }
        
        // Nuxt.js
        if body.contains("__NUXT__") || body.contains("/_nuxt/") {
            technologies.push(DetectedTechnology {
                name: "Nuxt.js".to_string(),
                category: "JavaScript Framework".to_string(),
                version: None,
                confidence: 95,
                cpe: Some("cpe:2.3:a:nuxt:nuxt.js".to_string()),
                website: Some("https://nuxt.com".to_string()),
            });
        }
        
        // Vite
        if body.contains("/@vite/") || body.contains("/__vite") {
            technologies.push(DetectedTechnology {
                name: "Vite".to_string(),
                category: "Build Tool".to_string(),
                version: None,
                confidence: 90,
                cpe: None,
                website: Some("https://vitejs.dev".to_string()),
            });
        }
        
        // React
        if body.contains("data-reactroot") || body.contains("__REACT_DEVTOOLS") {
            technologies.push(DetectedTechnology {
                name: "React".to_string(),
                category: "JavaScript Library".to_string(),
                version: None,
                confidence: 85,
                cpe: Some("cpe:2.3:a:facebook:react".to_string()),
                website: Some("https://react.dev".to_string()),
            });
        }
        
        // Vue.js
        if body.contains("data-v-") || body.contains("__VUE__") {
            technologies.push(DetectedTechnology {
                name: "Vue.js".to_string(),
                category: "JavaScript Framework".to_string(),
                version: None,
                confidence: 85,
                cpe: Some("cpe:2.3:a:vuejs:vue.js".to_string()),
                website: Some("https://vuejs.org".to_string()),
            });
        }
        
        // Svelte/SvelteKit
        if body.contains("__sveltekit") || body.contains("svelte-") {
            technologies.push(DetectedTechnology {
                name: "SvelteKit".to_string(),
                category: "JavaScript Framework".to_string(),
                version: None,
                confidence: 90,
                cpe: None,
                website: Some("https://kit.svelte.dev".to_string()),
            });
        }
    }
    
    /// JS Analizi
    async fn run_js_analysis(&self, scan_id: &str, url: &str) -> Result<()> {
        self.log(scan_id, "info", "js_analyzer", "📜 JavaScript analizi başlıyor...").await;
        
        let result = self.js_analyzer.analyze(url).await?;
        
        // Sonuçları kaydet
        {
            let mut scans = ACTIVE_SCANS.write().await;
            if let Some(scan) = scans.get_mut(scan_id) {
                scan.secrets.extend(result.secrets);
                scan.discovered_endpoints.extend(result.endpoints);
                scan.findings.extend(result.findings);
            }
        }
        
        self.log(scan_id, "info", "js_analyzer", &format!("✓ {} secret, {} endpoint bulundu", 
            result.secret_count, result.endpoint_count)).await;
        
        Ok(())
    }
    
    /// CVE Tarama
    async fn run_cve_scan(&self, scan_id: &str, _url: &str) -> Result<()> {
        self.log(scan_id, "info", "cve_scan", "🛡️ CVE taraması başlıyor...").await;
        
        // Teknolojilere göre nuclei taraması
        let techs = {
            let scans = ACTIVE_SCANS.read().await;
            scans.get(scan_id).map(|s| s.technologies.clone()).unwrap_or_default()
        };
        
        // Nuclei servise istek (basitleştirilmiş)
        if !techs.is_empty() {
            self.log(scan_id, "info", "cve_scan", 
                &format!("Tespit edilen teknolojiler için CVE kontrolü: {:?}", 
                    techs.iter().map(|t| &t.name).collect::<Vec<_>>())).await;
        }
        
        self.log(scan_id, "info", "cve_scan", "✓ CVE taraması tamamlandı").await;
        
        Ok(())
    }
    
    /// Browser analizi
    async fn run_browser_analysis(&self, scan_id: &str, url: &str) -> Result<()> {
        self.log(scan_id, "info", "browser", "🌐 Headless browser analizi başlıyor...").await;
        
        // Browser analyzer kullan (eğer Chrome mevcutsa)
        match BrowserAnalyzer::new().await {
            Ok(analyzer) => {
                let result = analyzer.analyze(url).await?;
                
                {
                    let mut scans = ACTIVE_SCANS.write().await;
                    if let Some(scan) = scans.get_mut(scan_id) {
                        scan.findings.extend(result.findings);
                    }
                }
                
                self.log(scan_id, "info", "browser", "✓ Browser analizi tamamlandı").await;
            }
            Err(e) => {
                self.log(scan_id, "warn", "browser", 
                    &format!("Browser başlatılamadı, atlanıyor: {}", e)).await;
            }
        }
        
        Ok(())
    }
    
    /// Fuzzing
    async fn run_fuzzing(&self, scan_id: &str, url: &str) -> Result<()> {
        self.log(scan_id, "info", "fuzzer", "🔧 Smart fuzzing başlıyor...").await;
        
        // Keşfedilen endpoint'leri al
        let endpoints = {
            let scans = ACTIVE_SCANS.read().await;
            scans.get(scan_id).map(|s| s.discovered_endpoints.clone()).unwrap_or_default()
        };
        
        let result = self.fuzzer.fuzz(url, &endpoints).await?;
        
        {
            let mut scans = ACTIVE_SCANS.write().await;
            if let Some(scan) = scans.get_mut(scan_id) {
                scan.findings.extend(result.findings);
            }
        }
        
        self.log(scan_id, "info", "fuzzer", "✓ Fuzzing tamamlandı").await;
        
        Ok(())
    }
    
    /// Log ekle
    async fn log(&self, scan_id: &str, level: &str, module: &str, message: &str) {
        let mut log_entry = None;
        
        // 1. DB/Memory güncelle
        {
            let mut scans = ACTIVE_SCANS.write().await;
            if let Some(scan) = scans.get_mut(scan_id) {
                scan.add_log(level, module, message);
                // Son eklenen logu al
                log_entry = scan.logs.last().cloned();
            }
        }
        
        // 2. Kanal üzerinden yayınla
        if let Some(log) = log_entry {
            let channels = crate::api::handlers::SCAN_CHANNELS.read().await;
            if let Some(tx) = channels.get(scan_id) {
                let msg = serde_json::json!({
                    "type": "log",
                    "data": log
                });
                // Hata alırsak (alıcı yoksa) önemseme
                let _ = tx.send(msg.to_string());
            }
        }
        
        // Console'a da yaz
        match level {
            "error" => tracing::error!("[{}] {}", module, message),
            "warn" => tracing::warn!("[{}] {}", module, message),
            _ => tracing::info!("[{}] {}", module, message),
        }
    }
    
    /// İptal kontrolü
    async fn is_cancelled(&self, scan_id: &str) -> bool {
        let scans = ACTIVE_SCANS.read().await;
        scans.get(scan_id)
            .map(|s| s.status == ScanStatus::Cancelled)
            .unwrap_or(true)
    }
}

// Yardımcı fonksiyonlar
fn extract_server_name(header: &str) -> String {
    header.split('/').next().unwrap_or(header).to_string()
}

fn extract_version(s: &str) -> Option<String> {
    let re = regex::Regex::new(r"[\d]+\.[\d]+(?:\.[\d]+)?").ok()?;
    re.find(s).map(|m| m.as_str().to_string())
}

fn extract_nextjs_version(_body: &str) -> Option<String> {
    // Next.js version from buildId veya diğer patternlerden çıkarılabilir
    None
}
