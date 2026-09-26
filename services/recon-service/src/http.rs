// Türkçe: HTTP analiz modülü - Teknoloji tespit entegrasyonu ile genişletilmiş
use reqwest::Client;
use crate::logger::{log_info, log_warn, log_error};
use crate::tech_detector::{detect_technologies, Technology};
use std::collections::HashMap;
use std::time::Instant;
use md5;

/// HTTP analiz sonucu (teknoloji tespiti dahil)
#[derive(Debug, Clone)]
pub struct HttpAnalysisResult {
    pub headers: HashMap<String, String>,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub page_title: Option<String>,
    pub content_length: Option<usize>,
    pub technologies: Vec<Technology>,
    pub found_cf: bool,
    pub logs: Vec<String>,
}

/// Türkçe: HTTP isteği atarak header analizi, teknoloji tespiti ve performans ölçümü yapar
/// Hem HTTP hem HTTPS dener, başarılı olan protokolü kullanır
pub async fn analyze_http_with_tech_detection(domain: &str) -> HttpAnalysisResult {
    let mut logs = Vec::new();
    let mut headers_map = HashMap::new();
    let mut found_cf = false;
    let mut status_code = None;
    let mut response_time_ms = None;
    let mut page_title = None;
    let mut content_length = None;
    let mut technologies = Vec::new();

    // Türkçe: User-Agent rotasyonu (anti-bot bypass için)
    let user_agents = vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    ];
    let user_agent = user_agents[rand::random::<usize>() % user_agents.len()];

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent(user_agent)
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .unwrap_or_default();

    // Türkçe: Önce HTTPS dene, başarısız olursa HTTP'ye geri dön
    let protocols = vec!["https", "http"];
    let total_protocols = protocols.len();
    
    for (idx, protocol) in protocols.iter().enumerate() {
        let url = if domain.starts_with("http") {
            domain.to_string()
        } else {
            format!("{}://{}", protocol, domain)
        };

        logs.push(format!("HTTP analizi başlatılıyor: {}", url));
        log_info(&format!("HTTP analizi başlatılıyor: {}", url));

        let start = Instant::now();
        
        match client.get(&url).send().await {
            Ok(resp) => {
                let elapsed = start.elapsed().as_millis() as u64;
                response_time_ms = Some(elapsed);
                status_code = Some(resp.status().as_u16());
                
                logs.push(format!("✓ Yanıt alındı: {} ({}ms)", resp.status(), elapsed));
                log_info(&format!("Yanıt alındı: {} ({}ms)", resp.status(), elapsed));

                let headers = resp.headers().clone();
                
                // Türkçe: Cookie'leri header'dan çıkar
                let mut cookies = HashMap::new();
                if let Some(cookie_values) = headers.get_all("set-cookie").iter().next() {
                    if let Ok(cookie_str) = cookie_values.to_str() {
                        for part in cookie_str.split(';') {
                            if let Some((k, _v)) = part.trim().split_once('=') {
                                cookies.insert(k.to_string(), String::new());
                            }
                        }
                    }
                }

                // Türkçe: Cloudflare, Akamai, AWS CloudFront tespiti
                let cdn_indicators = [
                    ("cf-ray", "Cloudflare"),
                    ("x-amz-cf-id", "AWS CloudFront"),
                    ("server", "cloudflare"),
                    ("server", "AkamaiGHost"),
                ];

                for (k, v) in headers.iter() {
                    let key = k.as_str().to_lowercase();
                    let value = v.to_str().unwrap_or("").to_string();
                    
                    headers_map.insert(key.clone(), value.clone());

                    // CDN/WAF tespiti
                    for (indicator_key, provider) in &cdn_indicators {
                        if key == *indicator_key && value.to_lowercase().contains(&provider.to_lowercase()) {
                            found_cf = true;
                            logs.push(format!("🛡️ {} tespit edildi", provider));
                            log_warn(&format!("{} tespit edildi", provider));
                        }
                    }
                }

                // Body content'i al (teknoloji tespiti için)
                if let Ok(body) = resp.text().await {
                    content_length = Some(body.len());

                    // Türkçe: Page title çıkarma
                    if let Some(title_match) = extract_title(&body) {
                        page_title = Some(title_match);
                        logs.push(format!("📄 Sayfa Başlığı: {}", page_title.as_ref().unwrap()));
                    }

                    // Türkçe: Favicon hash hesapla (MD5)
                    let mut favicon_hash = None;
                    let favicon_url = format!("{}://{}/favicon.ico", protocol, domain);
                    
                    if let Ok(fav_resp) = client.get(&favicon_url).send().await {
                        if fav_resp.status().is_success() {
                            if let Ok(fav_bytes) = fav_resp.bytes().await {
                                let digest = md5::compute(&fav_bytes);
                                favicon_hash = Some(format!("{:x}", digest));
                                logs.push(format!("🎨 Favicon hash: {}", favicon_hash.as_ref().unwrap()));
                            }
                        }
                    }

                    // Türkçe: Teknoloji tespiti motor (body, headers_map, cookies, favicon sırasıyla)
                    technologies = detect_technologies(&body, &headers_map, &cookies, favicon_hash.as_deref());

                    if !technologies.is_empty() {
                        logs.push(format!("🔍 {} teknoloji tespit edildi:", technologies.len()));
                        for tech in &technologies {
                            let version_str = tech.version.as_ref()
                                .map(|v| format!(" v{}", v))
                                .unwrap_or_default();
                            logs.push(format!("   • {} {} ({}% güven)", tech.name, version_str, tech.confidence));
                            log_info(&format!("Teknoloji: {} {}", tech.name, version_str));
                        }
                    }
                }

                // Başarılı response aldıysak döngüden çık
                break;
            }
            Err(e) => {
                logs.push(format!("✗ {} başarısız: {}", protocol.to_uppercase(), e));
                log_error(&format!("HTTP isteği başarısız ({}): {}", protocol, e));
                
                // Son protokol de başarısız olduysa error state'inde dön
                if idx == total_protocols - 1 {
                    logs.push("Tüm protokoller (HTTPS/HTTP) başarısız oldu".to_string());
                }
            }
        }
    }

    HttpAnalysisResult {
        headers: headers_map,
        status_code,
        response_time_ms,
        page_title,
        content_length,
        technologies,
        found_cf,
        logs,
    }
}

/// Türkçe: HTML'den <title> tag'ini çıkarır
fn extract_title(html: &str) -> Option<String> {
    use regex::Regex;
    let re = Regex::new(r"<title[^>]*>(.*?)</title>").ok()?;
    re.captures(html)?
        .get(1)
        .map(|m| m.as_str().trim().to_string())
}

/// Türkçe: Basit HTTP liveness check (sadece erişilebilirlik kontrolü)
pub async fn check_liveness(domain: &str) -> bool {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    for protocol in ["https", "http"] {
        let url = format!("{}://{}", protocol, domain);
        if let Ok(resp) = client.head(&url).send().await {
            if resp.status().is_success() || resp.status().is_redirection() {
                return true;
            }
        }
    }
    false
}

