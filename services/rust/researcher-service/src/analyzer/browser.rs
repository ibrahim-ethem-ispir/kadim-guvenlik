//! Headless Browser Analizörü
//! 
//! Chrome DevTools Protocol ile DOM analizi:
//! - XSS testi
//! - Hydration mismatch detection
//! - Form/input keşfi

use anyhow::Result;

use crate::models::{Finding, Severity, FindingCategory};

/// Browser analiz sonucu
pub struct BrowserAnalysisResult {
    pub findings: Vec<Finding>,
    pub forms_found: Vec<FormInfo>,
    pub xss_vulnerable: bool,
}

/// Form bilgisi
#[derive(Debug, Clone)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    pub inputs: Vec<String>,
}

/// Headless Browser Analizör
pub struct BrowserAnalyzer {
    // chromiumoxide kütüphanesi ile browser kontrolü
    // Browser launch için Chrome/Chromium gerekli
}

impl BrowserAnalyzer {
    /// Yeni browser instance oluştur
    pub async fn new() -> Result<Self> {
        // Chrome binary'sini bul ve başlat
        // Docker container'da /usr/bin/chromium veya /usr/bin/google-chrome
        
        // Şimdilik basit bir implementasyon
        // Gerçek implementasyonda chromiumoxide kullanılacak
        Ok(Self {})
    }
    
    /// URL'yi analiz et
    pub async fn analyze(&self, url: &str) -> Result<BrowserAnalysisResult> {
        let mut findings = Vec::new();
        
        // HTTP client ile temel kontroller
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        
        let response = client.get(url).send().await?;
        let html = response.text().await?;
        
        // 1. Hydration mismatch kontrolü (SSR vs Client)
        if let Some(finding) = self.check_hydration_mismatch(&html, url) {
            findings.push(finding);
        }
        
        // 2. Potansiyel XSS noktaları
        let xss_points = self.find_xss_injection_points(&html, url);
        findings.extend(xss_points);
        
        // 3. Form keşfi
        let forms = self.discover_forms(&html);
        
        // 4. Console error/warning kontrolü (gerçek browser'da)
        // Bu özellik chromiumoxide ile tam browser'da çalışır
        
        let xss_vulnerable = findings.iter().any(|f| f.category == FindingCategory::Xss);
        
        Ok(BrowserAnalysisResult {
            findings,
            forms_found: forms,
            xss_vulnerable,
        })
    }
    
    /// Hydration mismatch kontrolü
    fn check_hydration_mismatch(&self, html: &str, url: &str) -> Option<Finding> {
        // Next.js hydration hataları
        if html.contains("Hydration failed") || 
           html.contains("Text content does not match") ||
           html.contains("There was an error while hydrating") {
            return Some(Finding::new(
                Severity::Medium,
                FindingCategory::HydrationMismatch,
                "SSR Hydration Uyumsuzluğu Tespit Edildi",
                "Sunucu tarafında render edilen HTML ile istemci tarafında oluşturulan DOM arasında uyumsuzluk var. Bu durum bilgi sızıntısına veya XSS açıklarına yol açabilir.",
                "Sayfa içeriğinde hydration error göstergeleri bulundu",
                url,
                "browser",
            ).with_cwe("CWE-79"));
        }
        
        // Nuxt.js hydration
        if html.contains("Nuxt hydration") && html.contains("mismatch") {
            return Some(Finding::new(
                Severity::Medium,
                FindingCategory::HydrationMismatch,
                "Nuxt.js Hydration Hatası",
                "Nuxt.js uygulamasında sunucu-istemci hydration uyumsuzluğu tespit edildi.",
                "Nuxt hydration mismatch bulundu",
                url,
                "browser",
            ));
        }
        
        None
    }
    
    /// XSS injection noktalarını bul
    fn find_xss_injection_points(&self, html: &str, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // URL parametrelerinin doğrudan HTML'e yansıması
        if let Ok(parsed_url) = url::Url::parse(url) {
            for (key, value) in parsed_url.query_pairs() {
                if html.contains(value.as_ref()) {
                    findings.push(Finding::new(
                        Severity::High,
                        FindingCategory::Xss,
                        "Potansiyel Reflected XSS",
                        format!("URL parametresi '{}' doğrudan sayfa içeriğine yansıyor. Bu durum XSS açığına işaret edebilir.", key),
                        format!("Parametre: {}={}", key, &value[..value.len().min(50)]),
                        url,
                        "browser",
                    ).with_cwe("CWE-79")
                     .with_confidence(60)
                     .with_recommendation("Kullanıcı girdilerini HTML encode edin"));
                }
            }
        }
        
        // Güvensiz inline event handler'lar
        let dangerous_handlers = ["onerror=", "onload=", "onclick=", "onmouseover="];
        for handler in &dangerous_handlers {
            if html.to_lowercase().contains(&format!("{}\"", handler)) {
                findings.push(Finding::new(
                    Severity::Low,
                    FindingCategory::Xss,
                    format!("Inline Event Handler: {}", handler),
                    "Inline JavaScript event handler'ları CSP bypass ve XSS risklerini artırır.",
                    format!("Handler bulundu: {}", handler),
                    url,
                    "browser",
                ).with_confidence(50));
            }
        }
        
        findings
    }
    
    /// Form keşfi
    fn discover_forms(&self, html: &str) -> Vec<FormInfo> {
        use scraper::{Html, Selector};
        
        let mut forms = Vec::new();
        let document = Html::parse_document(html);
        
        if let Ok(form_selector) = Selector::parse("form") {
            for form in document.select(&form_selector) {
                let action = form.value().attr("action").unwrap_or("/").to_string();
                let method = form.value().attr("method").unwrap_or("GET").to_uppercase();
                
                let mut inputs = Vec::new();
                if let Ok(input_selector) = Selector::parse("input, textarea, select") {
                    for input in form.select(&input_selector) {
                        if let Some(name) = input.value().attr("name") {
                            inputs.push(name.to_string());
                        }
                    }
                }
                
                forms.push(FormInfo {
                    action,
                    method,
                    inputs,
                });
            }
        }
        
        forms
    }
}

// XSS Test payloadları (gelecekte kullanılacak)
#[allow(dead_code)]
const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "{{constructor.constructor('alert(1)')()}}",
];
