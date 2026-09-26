//! Recon Module - Smart target analysis
//!
//! Analyzes target endpoints to find resource-intensive paths:
//! - Spider mode for endpoint discovery
//! - Latency analysis to identify slow endpoints
//! - Automatic weak point detection

use crate::EndpointInfo;
use std::time::Duration;

/// Analyze a target and discover endpoints with their latencies
pub async fn analyze_target(base_url: &str, max_endpoints: u32) -> Vec<EndpointInfo> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    
    let mut endpoints = Vec::new();
    
    // Common endpoints to test
    let common_paths = [
        "/",
        "/api",
        "/api/v1",
        "/api/v2",
        "/admin",
        "/login",
        "/auth",
        "/search",
        "/search?q=test",
        "/graphql",
        "/api/graphql",
        "/export",
        "/download",
        "/report",
        "/reports",
        "/analytics",
        "/dashboard",
        "/users",
        "/api/users",
        "/products",
        "/api/products",
        "/orders",
        "/api/orders",
        "/upload",
        "/files",
        "/images",
        "/static",
        "/assets",
        "/health",
        "/status",
        "/metrics",
        "/api/health",
        "/robots.txt",
        "/sitemap.xml",
        "/favicon.ico",
    ];
    
    let base = base_url.trim_end_matches('/');
    
    for (i, path) in common_paths.iter().enumerate() {
        if i >= max_endpoints as usize {
            break;
        }
        
        let url = format!("{}{}", base, path);
        
        if let Some(info) = probe_endpoint(&client, &url).await {
            endpoints.push(info);
        }
    }
    
    // Sort by latency (slowest first = most resource intensive)
    endpoints.sort_by(|a, b| b.latency_ms.cmp(&a.latency_ms));
    
    endpoints
}

/// Probe a single endpoint and measure its characteristics
async fn probe_endpoint(client: &reqwest::Client, url: &str) -> Option<EndpointInfo> {
    let start = std::time::Instant::now();
    
    match client.get(url).send().await {
        Ok(response) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let status_code = response.status().as_u16();
            let content_length = response.content_length().unwrap_or(0);
            
            // Consider endpoint "slow" if latency > 500ms
            let is_slow = latency_ms > 500;
            
            Some(EndpointInfo {
                url: url.to_string(),
                method: "GET".to_string(),
                latency_ms,
                status_code,
                content_length,
                is_slow,
            })
        }
        Err(_) => None,
    }
}

/// Deep spider to find more endpoints (follows links)
#[allow(dead_code)]
pub async fn spider_target(base_url: &str, max_depth: u32) -> Vec<String> {
    let mut discovered = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![base_url.to_string()];
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();
    
    for depth in 0..max_depth {
        let mut new_queue = Vec::new();
        
        for url in queue.iter() {
            if visited.contains(url) {
                continue;
            }
            visited.insert(url.clone());
            
            if let Ok(response) = client.get(url).send().await {
                if let Ok(body) = response.text().await {
                    // Extract links from HTML (simple regex approach)
                    let links = extract_links(&body, base_url);
                    for link in links {
                        if !visited.contains(&link) && link.starts_with(base_url) {
                            new_queue.push(link.clone());
                            discovered.push(link);
                        }
                    }
                }
            }
        }
        
        queue = new_queue;
        
        if queue.is_empty() {
            break;
        }
        
        tracing::info!("🕷️ Spider depth {}: found {} new URLs", depth + 1, queue.len());
    }
    
    discovered
}

/// Extract links from HTML content
fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();
    
    // Simple href extraction (not a full HTML parser)
    for cap in regex_lite::Regex::new(r#"href=["']([^"']+)["']"#)
        .unwrap()
        .captures_iter(html)
    {
        if let Some(href) = cap.get(1) {
            let link = href.as_str();
            
            // Convert relative to absolute
            if link.starts_with('/') {
                links.push(format!("{}{}", base_url.trim_end_matches('/'), link));
            } else if link.starts_with("http") {
                links.push(link.to_string());
            }
        }
    }
    
    links
}
