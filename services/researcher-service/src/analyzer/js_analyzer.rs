//! JavaScript Bundle Analizörü
//! 
//! JS dosyalarını indirip analiz eder:
//! - Secret scanning (API keys, tokens)
//! - Hidden endpoint discovery
//! - Dangerous function detection

use anyhow::Result;
use regex::Regex;
use lazy_static::lazy_static;

use crate::models::{Finding, Severity, FindingCategory, SecretFinding};

lazy_static! {
    // Secret pattern'leri
    static ref SECRET_PATTERNS: Vec<(&'static str, Regex, u8)> = vec![
        ("AWS Access Key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), 95),
        ("AWS Secret Key", Regex::new(r#"(?i)(aws_secret|aws_key|secret_key)\s*[=:]\s*["']([A-Za-z0-9/+=]{40})["']"#).unwrap(), 90),
        ("Google API Key", Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(), 95),
        ("GitHub Token", Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(), 95),
        ("GitHub OAuth", Regex::new(r"gho_[a-zA-Z0-9]{36}").unwrap(), 95),
        ("Stripe Key", Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(), 95),
        ("Slack Token", Regex::new(r"xox[baprs]-[0-9a-zA-Z-]{10,}").unwrap(), 90),
        ("JWT Token", Regex::new(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+").unwrap(), 80),
        ("Private Key", Regex::new(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----").unwrap(), 95),
        ("Generic API Key", Regex::new(r#"(?i)(api[_-]?key|apikey|api_secret)\s*[=:]\s*["']([a-zA-Z0-9]{16,})["']"#).unwrap(), 75),
        ("Password in Code", Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*["']([^"']{8,})["']"#).unwrap(), 70),
        ("Bearer Token", Regex::new(r#"(?i)bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"#).unwrap(), 85),
    ];
    
    // Endpoint pattern'leri
    static ref ENDPOINT_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"["'](/api/[^"']+)["']"#).unwrap(),
        Regex::new(r#"["'](/v[0-9]+/[^"']+)["']"#).unwrap(),
        Regex::new(r#"["'](/admin[^"']*)["']"#).unwrap(),
        Regex::new(r#"["'](/internal[^"']*)["']"#).unwrap(),
        Regex::new(r#"["'](/debug[^"']*)["']"#).unwrap(),
        Regex::new(r#"["'](/graphql[^"']*)["']"#).unwrap(),
        Regex::new(r#"["'](/rest/[^"']+)["']"#).unwrap(),
        Regex::new(r#"fetch\(["']([^"']+)["']\)"#).unwrap(),
        Regex::new(r#"axios\.(get|post|put|delete)\(["']([^"']+)["']"#).unwrap(),
    ];
    
    // Tehlikeli fonksiyonlar
    static ref DANGEROUS_FUNCTIONS: Vec<(&'static str, &'static str)> = vec![
        ("eval(", "eval() kullanımı kod enjeksiyonuna yol açabilir"),
        ("dangerouslySetInnerHTML", "React XSS riski - dangerouslySetInnerHTML kullanımı"),
        ("innerHTML", "innerHTML kullanımı XSS riski taşır"),
        ("document.write", "document.write() güvensiz DOM manipülasyonu"),
        ("setTimeout(", "String ile setTimeout potansiyel kod enjeksiyonu"),
        ("setInterval(", "String ile setInterval potansiyel kod enjeksiyonu"),
        ("new Function(", "Function constructor ile dinamik kod"),
    ];
}

/// JS Analiz sonucu
pub struct JsAnalysisResult {
    pub secrets: Vec<SecretFinding>,
    pub endpoints: Vec<String>,
    pub findings: Vec<Finding>,
    pub secret_count: usize,
    pub endpoint_count: usize,
}

/// JavaScript Analizör
pub struct JsAnalyzer {
    client: reqwest::Client,
}

impl JsAnalyzer {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
    
    /// URL'deki JS dosyalarını analiz et
    pub async fn analyze(&self, url: &str) -> Result<JsAnalysisResult> {
        let mut all_secrets = Vec::new();
        let mut all_endpoints = Vec::new();
        let mut all_findings = Vec::new();
        
        // Ana sayfayı indir
        let response = self.client.get(url).send().await?;
        let html = response.text().await?;
        
        // JS dosya URL'lerini çıkar
        let js_urls = self.extract_js_urls(&html, url);
        
        // Her JS dosyasını analiz et
        for js_url in &js_urls {
            if let Ok(js_content) = self.fetch_js(js_url).await {
                // Secret tarama
                let secrets = self.scan_secrets(&js_content, js_url);
                all_secrets.extend(secrets);
                
                // Endpoint keşfi
                let endpoints = self.discover_endpoints(&js_content);
                all_endpoints.extend(endpoints);
                
                // Tehlikeli fonksiyon kontrolü
                let findings = self.check_dangerous_functions(&js_content, js_url);
                all_findings.extend(findings);
            }
        }
        
        // Source map kontrolü
        for js_url in &js_urls {
            let map_url = format!("{}.map", js_url);
            if self.check_sourcemap(&map_url).await {
                all_findings.push(Finding::new(
                    Severity::High,
                    FindingCategory::SourceMapExposed,
                    "Source Map Açık",
                    format!("JS source map dosyası herkesin erişimine açık: {}", map_url),
                    format!("Source map URL: {}", map_url),
                    js_url,
                    "js_analyzer",
                ).with_cwe("CWE-540")
                 .with_recommendation("Production build'de source map'leri devre dışı bırakın"));
            }
        }
        
        // Duplicate'leri kaldır
        all_endpoints.sort();
        all_endpoints.dedup();
        
        let secret_count = all_secrets.len();
        let endpoint_count = all_endpoints.len();
        
        Ok(JsAnalysisResult {
            secrets: all_secrets,
            endpoints: all_endpoints,
            findings: all_findings,
            secret_count,
            endpoint_count,
        })
    }
    
    /// HTML'den JS URL'lerini çıkar
    fn extract_js_urls(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut urls = Vec::new();
        
        // <script src="..."> pattern
        let re = Regex::new(r#"<script[^>]+src=["']([^"']+\.js[^"']*)["']"#).unwrap();
        
        for cap in re.captures_iter(html) {
            if let Some(src) = cap.get(1) {
                let src_str = src.as_str();
                let full_url = if src_str.starts_with("http") {
                    src_str.to_string()
                } else if src_str.starts_with("//") {
                    format!("https:{}", src_str)
                } else if src_str.starts_with('/') {
                    if let Ok(base) = url::Url::parse(base_url) {
                        format!("{}://{}{}", base.scheme(), base.host_str().unwrap_or(""), src_str)
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };
                
                urls.push(full_url);
            }
        }
        
        // Sadece ilk 20 JS dosyasını analiz et (performance için)
        urls.truncate(20);
        urls
    }
    
    /// JS dosyasını indir
    async fn fetch_js(&self, url: &str) -> Result<String> {
        let response = self.client.get(url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;
        
        // Çok büyük dosyaları atlat (5MB üstü)
        if let Some(len) = response.content_length() {
            if len > 5 * 1024 * 1024 {
                return Err(anyhow::anyhow!("JS dosyası çok büyük"));
            }
        }
        
        Ok(response.text().await?)
    }
    
    /// Secret tarama
    fn scan_secrets(&self, content: &str, source: &str) -> Vec<SecretFinding> {
        let mut secrets = Vec::new();
        
        for (name, pattern, confidence) in SECRET_PATTERNS.iter() {
            for mat in pattern.find_iter(content) {
                let value = mat.as_str();
                
                // Maskeleme
                let masked = if value.len() > 10 {
                    format!("{}...{}", &value[..5], &value[value.len()-3..])
                } else {
                    "***".to_string()
                };
                
                // Satır numarasını bul
                let line_number = content[..mat.start()]
                    .matches('\n')
                    .count() as u32 + 1;
                
                secrets.push(SecretFinding {
                    secret_type: name.to_string(),
                    value_masked: masked,
                    source_file: source.to_string(),
                    line_number: Some(line_number),
                    confidence: *confidence,
                });
            }
        }
        
        secrets
    }
    
    /// Endpoint keşfi
    fn discover_endpoints(&self, content: &str) -> Vec<String> {
        let mut endpoints = Vec::new();
        
        for pattern in ENDPOINT_PATTERNS.iter() {
            for cap in pattern.captures_iter(content) {
                // İlk capture group'u al
                if let Some(endpoint) = cap.get(1) {
                    let ep = endpoint.as_str().to_string();
                    
                    // Geçerli bir endpoint mi kontrol et
                    if ep.starts_with('/') && !ep.contains("{{") && ep.len() < 200 {
                        endpoints.push(ep);
                    }
                }
            }
        }
        
        endpoints
    }
    
    /// Tehlikeli fonksiyon kontrolü
    fn check_dangerous_functions(&self, content: &str, source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for (pattern, description) in DANGEROUS_FUNCTIONS.iter() {
            if content.contains(pattern) {
                // Satır numarasını bul
                if let Some(pos) = content.find(pattern) {
                    let line = content[..pos].matches('\n').count() + 1;
                    
                    findings.push(Finding::new(
                        Severity::Medium,
                        FindingCategory::Misconfiguration,
                        format!("Tehlikeli Fonksiyon: {}", pattern),
                        description.to_string(),
                        format!("Satır {}: {}", line, pattern),
                        source,
                        "js_analyzer",
                    ).with_cwe("CWE-95")
                     .with_confidence(70));
                }
            }
        }
        
        findings
    }
    
    /// Source map kontrolü
    async fn check_sourcemap(&self, map_url: &str) -> bool {
        if let Ok(resp) = self.client.head(map_url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await 
        {
            return resp.status().is_success();
        }
        false
    }
}
