use anyhow::Result;
use crate::models::entity::{Entity, EntityType};
use crate::api::responses::SubdomainInfo;
use crate::osint::dns::DnsScanner;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use crate::AppState;
use crate::api::responses::SubdomainResponse;

pub struct SubdomainScanner {
    dns_scanner: Arc<DnsScanner>,
    wordlist: Vec<String>,
}

impl SubdomainScanner {
    pub fn new(dns_scanner: Arc<DnsScanner>) -> Self {
        // Basic Top 50 Subdomains for Phase 1
        let common_subdomains = vec![
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
            "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
            "dev", "www2", "admin", "forum", "ispsystem", "ns3", "mail2", "server", "ns4", "directory",
            "gdpr", "ads", "host", "crm", "cms", "api", "app", "dashboard", "portal", "support",
            "files", "video", "media", "images", "static", "assets", "cdn", "vpn", "remote", "login"
        ];

        Self {
            dns_scanner,
            wordlist: common_subdomains.into_iter().map(String::from).collect(),
        }
    }

    pub async fn scan(&self, domain: &str) -> Result<Vec<Entity>> {
        let mut findings = Vec::new();
        let concurrency_limit = 20;

        // Türkçe: Subdomain taraması için async stream oluştur
        // Her subdomain için DNS sorgusu yapılır ve sonuçlar toplanır
        let domain_owned = domain.to_string();
        let scan_futures = stream::iter(self.wordlist.clone()).map(move |sub| {
            let full_domain = format!("{}.{}", sub, domain_owned);
            let dns = self.dns_scanner.clone();
            async move {
                match dns.scan(&full_domain).await {
                    Ok(entities) if !entities.is_empty() => Some((full_domain, entities)),
                    _ => None,
                }
            }
        });

        let mut results = scan_futures.buffer_unordered(concurrency_limit);

        while let Some(result) = results.next().await {
            if let Some((full_domain, entities)) = result {
                let mut entity = Entity::new(
                    EntityType::Subdomain,
                    full_domain.clone(),
                    "subdomain_bruteforce"
                );
                
                entity = entity.with_property("parent_domain", domain.into());
                entity = entity.with_property("is_active", true.into());
                
                findings.push(entity);
                
                for mut related in entities {
                    related = related.with_tag(&format!("via_subdomain:{}", full_domain));
                    findings.push(related);
                }
            }
        }

        Ok(findings)
    }
}

pub async fn discover(_state: &Arc<AppState>, domain: &str, _max_results: Option<usize>) -> Result<SubdomainResponse> {
    let dns_scanner = Arc::new(DnsScanner::new()?);
    let scanner = SubdomainScanner::new(dns_scanner);
    
    let entities = scanner.scan(domain).await?;
    
    let mut subdomains_info = Vec::new();

    // Filter out only Subdomain entities from the findings
    // The findings also contain IPs etc, which we don't put in the list for now but could use
    for entity in &entities {
        if entity.entity_type == EntityType::Subdomain {
             subdomains_info.push(SubdomainInfo {
                 subdomain: entity.value.clone(),
                 ip: None, // We could extract this from related IP entities but keeping it simple for now
                 source: "bruteforce".to_string(),
                 alive: Some(true),
             });
        }
    }

    Ok(SubdomainResponse {
        domain: domain.to_string(),
        total_found: subdomains_info.len() as u32,
        subdomains: subdomains_info,
        sources_used: vec!["bruteforce".to_string()],
        cached: false,
    })
}
