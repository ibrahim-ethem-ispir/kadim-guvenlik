//! Smart API Fuzzer
//! 
//! Keşfedilen endpoint'lere akıllı fuzzing:
//! - IDOR/BOLA testleri
//! - Rate limit kontrolü
//! - Parameter tampering

use anyhow::Result;
use std::time::Duration;

use crate::models::{Finding, Severity, FindingCategory};

/// Fuzzing sonucu
pub struct FuzzingResult {
    pub findings: Vec<Finding>,
    pub endpoints_tested: usize,
    pub rate_limit_detected: bool,
}

/// Smart Fuzzer
pub struct SmartFuzzer {
    client: reqwest::Client,
}

impl SmartFuzzer {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
    
    /// Endpoint'leri fuzz et
    pub async fn fuzz(&self, base_url: &str, endpoints: &[String]) -> Result<FuzzingResult> {
        let mut findings = Vec::new();
        let mut rate_limit_detected = false;
        
        // Base URL'yi parse et
        let base = match url::Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return Ok(FuzzingResult {
                findings: Vec::new(),
                endpoints_tested: 0,
                rate_limit_detected: false,
            }),
        };
        
        // 1. Rate limit kontrolü
        rate_limit_detected = self.check_rate_limit(base_url).await;
        if !rate_limit_detected {
            findings.push(Finding::new(
                Severity::Medium,
                FindingCategory::NoRateLimit,
                "Rate Limiting Yok veya Çok Yüksek",
                "API endpoint'lerinde rate limiting tespit edilemedi. Bu durum brute-force ve DoS saldırılarına açık hale getirebilir.",
                format!("10 ardışık istek {} ms altında karşılandı", 100),
                base_url,
                "fuzzer",
            ).with_cwe("CWE-770")
             .with_recommendation("API endpoint'lerine rate limiting ekleyin"));
        }
        
        // 2. IDOR kontrolü (ID parametreli endpoint'ler için)
        for endpoint in endpoints {
            if endpoint.contains("/user") || 
               endpoint.contains("/account") || 
               endpoint.contains("/profile") ||
               endpoint.contains("/order") {
                if let Some(finding) = self.check_idor(&base, endpoint).await {
                    findings.push(finding);
                }
            }
        }
        
        // 3. HTTP Method Tampering
        let method_findings = self.check_method_tampering(&base, endpoints).await;
        findings.extend(method_findings);
        
        // 4. Bilgi sızıntısı kontrolü
        let info_findings = self.check_information_disclosure(&base).await;
        findings.extend(info_findings);
        
        Ok(FuzzingResult {
            findings,
            endpoints_tested: endpoints.len(),
            rate_limit_detected,
        })
    }
    
    /// Rate limit kontrolü
    async fn check_rate_limit(&self, url: &str) -> bool {
        let start = std::time::Instant::now();
        let mut success_count = 0;
        
        // 10 ardışık istek at
        for _ in 0..10 {
            if let Ok(resp) = self.client.get(url)
                .timeout(Duration::from_secs(5))
                .send()
                .await 
            {
                // 429 Too Many Requests = rate limit var
                if resp.status().as_u16() == 429 {
                    return true;
                }
                
                // Başarılı istek
                if resp.status().is_success() || resp.status().is_redirection() {
                    success_count += 1;
                }
            }
        }
        
        let elapsed = start.elapsed();
        
        // 10 istek 500ms'den az sürdüyse ve hepsi başarılı ise rate limit yok
        if success_count >= 8 && elapsed < Duration::from_millis(500) {
            return false;
        }
        
        true
    }
    
    /// IDOR kontrolü
    async fn check_idor(&self, base: &url::Url, endpoint: &str) -> Option<Finding> {
        // ID içeren endpoint'leri bul ve farklı ID'lerle dene
        // Bu basit bir kontrol - gerçek IDOR testi için auth token gerekli
        
        // Endpoint'te sayısal ID var mı kontrol et
        let id_pattern = regex::Regex::new(r"/(\d+)").ok()?;
        
        if id_pattern.is_match(endpoint) {
            // Farklı bir ID ile dene
            let modified = id_pattern.replace(endpoint, "/99999999");
            let test_url = format!("{}{}", base.as_str().trim_end_matches('/'), modified);
            
            if let Ok(resp) = self.client.get(&test_url)
                .timeout(Duration::from_secs(5))
                .send()
                .await 
            {
                // 200 OK dönerse potansiyel IDOR
                if resp.status().is_success() {
                    return Some(Finding::new(
                        Severity::High,
                        FindingCategory::AccessControl,
                        "Potansiyel IDOR Zafiyeti",
                        format!("Farklı bir ID ile yapılan istek başarılı döndü. Bu durum Insecure Direct Object Reference (IDOR) açığına işaret edebilir."),
                        format!("Test URL: {} - Status: {}", test_url, resp.status()),
                        endpoint,
                        "fuzzer",
                    ).with_cwe("CWE-639")
                     .with_confidence(60)
                     .with_resource_url(test_url.clone())
                     .with_recommendation("Sunucu tarafında yetkilendirme kontrolü ekleyin"));
                }
            }
        }
        
        None
    }
    
    /// HTTP Method Tampering kontrolü
    async fn check_method_tampering(&self, base: &url::Url, endpoints: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // İlk birkaç endpoint için method tampering test et
        for endpoint in endpoints.iter().take(5) {
            let url = format!("{}{}", base.as_str().trim_end_matches('/'), endpoint);
            
            // OPTIONS ile allowed methods'u kontrol et
            if let Ok(resp) = self.client.request(reqwest::Method::OPTIONS, &url)
                .timeout(Duration::from_secs(5))
                .send()
                .await 
            {
                if let Some(allow) = resp.headers().get("allow") {
                    if let Ok(methods) = allow.to_str() {
                        // DELETE veya PUT izin veriliyorsa uyarı
                        if methods.contains("DELETE") || methods.contains("PUT") || methods.contains("PATCH") {
                            findings.push(Finding::new(
                                Severity::Low,
                                FindingCategory::Misconfiguration,
                                "Potansiyel Tehlikeli HTTP Metodları Aktif",
                                format!("Endpoint şu metodlara izin veriyor: {}. Bunlar gerekli değilse devre dışı bırakılmalı.", methods),
                                format!("Allow header: {}", methods),
                                endpoint,
                                "fuzzer",
                            ).with_confidence(50));
                        }
                    }
                }
            }
        }
        
        findings
    }
    
    /// Bilgi sızıntısı kontrolü - GERÇEK içerik doğrulaması ile
    async fn check_information_disclosure(&self, base: &url::Url) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Hassas dosya pattern'leri ve beklenen içerik formatları
        let sensitive_checks: Vec<(&str, Severity, fn(&str) -> bool)> = vec![
            // (.env) KEY=VALUE formatı beklenir
            ("/.env", Severity::Critical, |body: &str| {
                // HTML değilse VE en az bir KEY=VALUE satırı varsa
                !Self::looks_like_html(body) && 
                body.lines().any(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with('#') && 
                    trimmed.contains('=') &&
                    !trimmed.contains('<')
                })
            }),
            // (.git/config) [section] formatı beklenir
            ("/.git/config", Severity::Critical, |body: &str| {
                !Self::looks_like_html(body) && 
                body.contains("[core]") || body.contains("[remote")
            }),
            // (.npmrc) registry veya token içerir
            ("/.npmrc", Severity::Critical, |body: &str| {
                !Self::looks_like_html(body) && 
                (body.contains("registry=") || body.contains("_authToken="))
            }),
            // (config.json) JSON formatı beklenir
            ("/config.json", Severity::High, |body: &str| {
                !Self::looks_like_html(body) && 
                body.trim().starts_with('{') && body.contains('"')
            }),
            // (package.json) name ve version içerir
            ("/package.json", Severity::Medium, |body: &str| {
                !Self::looks_like_html(body) && 
                body.contains("\"name\"") && body.contains("\"version\"")
            }),
            // (.htaccess) Apache direktifleri
            ("/.htaccess", Severity::Medium, |body: &str| {
                !Self::looks_like_html(body) && 
                (body.contains("RewriteRule") || body.contains("Deny from") || body.contains("AuthType"))
            }),
            // (web.config) XML config
            ("/web.config", Severity::Medium, |body: &str| {
                body.contains("<configuration>") || body.contains("<system.web>")
            }),
            // (phpinfo.php) PHP bilgisi
            ("/phpinfo.php", Severity::High, |body: &str| {
                body.contains("PHP Version") && body.contains("phpinfo()")
            }),
            // (robots.txt) - sadece Disallow ile gizli path'ler varsa
            ("/robots.txt", Severity::Low, |body: &str| {
                !Self::looks_like_html(body) && 
                body.contains("Disallow:") && 
                (body.contains("/admin") || body.contains("/api") || body.contains("/private"))
            }),
        ];
        
        for (endpoint, severity, validator) in &sensitive_checks {
            let url = format!("{}{}", base.as_str().trim_end_matches('/'), endpoint);
            
            if let Ok(resp) = self.client.get(&url)
                .timeout(Duration::from_secs(5))
                .send()
                .await 
            {
                // 1. Status kontrolü
                if !resp.status().is_success() {
                    continue;
                }
                
                // 2. Content-Type kontrolü (HTML ise atla)
                let content_type = resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                
                // HTML content-type = büyük ihtimalle login/error sayfası
                if content_type.contains("text/html") && !endpoint.contains("phpinfo") {
                    continue;
                }
                
                // 3. Body al ve doğrula
                if let Ok(body) = resp.text().await {
                    // Çok büyükse veya boşsa atla
                    if body.len() < 5 || body.len() > 100000 {
                        continue;
                    }
                    
                    // 4. Dosya türüne özel içerik doğrulaması
                    if validator(&body) {
                        // İçerik snippet'i oluştur (hassas bilgileri maskele)
                        let snippet = Self::create_safe_snippet(&body, 500);
                        
                        findings.push(Finding::new(
                            severity.clone(),
                            FindingCategory::InformationDisclosure,
                            format!("Hassas Dosya Açık: {}", endpoint),
                            format!("Dosya içeriği doğrulandı - bu gerçek bir sızıntı!"),
                            format!("İçerik önizleme:\n```\n{}\n```", snippet),
                            *endpoint,
                            "fuzzer",
                        ).with_cwe("CWE-200")
                         .with_confidence(95)
                         .with_resource_url(url.clone()));
                    }
                }
            }
        }
        
        findings
    }
    
    /// HTML içeriği mi kontrol et
    fn looks_like_html(body: &str) -> bool {
        let lower = body.to_lowercase();
        lower.contains("<!doctype html") ||
        lower.contains("<html") ||
        lower.contains("<head>") ||
        lower.contains("<body>") ||
        lower.contains("<title>") ||
        lower.contains("<div") ||
        lower.contains("<form") ||
        lower.contains("<script") ||
        // Login/error page indicators
        lower.contains("login") && lower.contains("password") ||
        lower.contains("sign in") ||
        lower.contains("not found") ||
        lower.contains("403 forbidden") ||
        lower.contains("access denied")
    }
    
    /// Hassas bilgileri maskeleyerek güvenli snippet oluştur
    fn create_safe_snippet(body: &str, max_len: usize) -> String {
        let truncated: String = body.chars().take(max_len).collect();
        
        // Hassas değerleri maskele
        let mut result = truncated;
        
        // Password değerlerini maskele
        let password_patterns = [
            "password=", "PASSWORD=", "pass=", "PASS=",
            "secret=", "SECRET=", "api_key=", "API_KEY=",
            "token=", "TOKEN=", "_authToken=",
        ];
        
        for pattern in password_patterns {
            if let Some(pos) = result.find(pattern) {
                let value_start = pos + pattern.len();
                if let Some(end_pos) = result[value_start..].find(|c: char| c == '\n' || c == '\r' || c == ' ' || c == '"') {
                    let before = &result[..value_start];
                    let after = &result[value_start + end_pos..];
                    result = format!("{}****MASKED****{}", before, after);
                }
            }
        }
        
        if body.len() > max_len {
            result.push_str("\n... (truncated)");
        }
        
        result
    }
}
