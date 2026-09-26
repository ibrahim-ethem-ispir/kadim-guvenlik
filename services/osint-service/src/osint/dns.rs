use anyhow::{Result, Context};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use crate::models::entity::{Entity, EntityType};
use std::net::IpAddr;
use crate::AppState;
use crate::api::responses::{DnsLookupResponse, DnsRecords, MxRecord, SoaRecord};
use std::sync::Arc;

pub struct DnsScanner {
    resolver: TokioAsyncResolver,
}

impl DnsScanner {
    pub fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::google(),
            ResolverOpts::default(),
        );
        Ok(Self { resolver })
    }

    pub async fn scan(&self, domain: &str) -> Result<Vec<Entity>> {
        let mut findings = Vec::new();
        let target = format!("{}.", domain); 

        // 1. A Records (IPv4)
        if let Ok(response) = self.resolver.ipv4_lookup(&target).await {
            for ip in response.iter() {
                let mut entity = Entity::new(
                    EntityType::Ip,
                    ip.to_string(),
                    "dns_scanner_a"
                );
                
                entity = entity.with_property("record_type", "A".into())
                             .with_property("domain", domain.into())
                             .with_property("version", 4.into());
                             
                findings.push(entity);
            }
        }

        // 2. AAAA Records (IPv6)
        if let Ok(response) = self.resolver.ipv6_lookup(&target).await {
            for ip in response.iter() {
                let mut entity = Entity::new(
                    EntityType::Ip,
                    ip.to_string(),
                    "dns_scanner_aaaa"
                );
                
                entity = entity.with_property("record_type", "AAAA".into())
                             .with_property("domain", domain.into())
                             .with_property("version", 6.into());
                             
                findings.push(entity);
            }
        }

        // 3. MX Records
        if let Ok(response) = self.resolver.mx_lookup(&target).await {
            for mx in response.iter() {
                let exchange = mx.exchange().to_string();
                let pref = mx.preference();
                
                let mut entity = Entity::new(
                    EntityType::DnsRecord,
                    exchange.clone(),
                    "dns_scanner_mx"
                );

                entity = entity.with_property("priority", pref.into())
                             .with_property("record_type", "MX".into())
                             .with_property("domain", domain.into());
                             
                findings.push(entity);
                
                if !exchange.contains(domain) {
                     let mut mail_server = Entity::new(
                        EntityType::Domain,
                        exchange.trim_end_matches('.').to_string(),
                        "dns_scanner_mx_host"
                     );
                     mail_server = mail_server.with_tag("mail_server");
                     findings.push(mail_server);
                }
            }
        }

        // 4. NS Records
        if let Ok(response) = self.resolver.ns_lookup(&target).await {
            for ns in response.iter() {
                let ns_name = ns.to_string();
                let mut entity = Entity::new(
                    EntityType::DnsRecord,
                    ns_name.clone(),
                    "dns_scanner_ns"
                );

                entity = entity.with_property("record_type", "NS".into())
                             .with_property("domain", domain.into());
                             
                findings.push(entity);
                
                 let mut ns_domain = Entity::new(
                    EntityType::Domain,
                    ns_name.trim_end_matches('.').to_string(),
                    "dns_scanner_ns_host"
                 );
                 ns_domain = ns_domain.with_tag("nameserver");
                 findings.push(ns_domain);
            }
        }

        // 5. TXT Records
        if let Ok(response) = self.resolver.txt_lookup(&target).await {
            for txt in response.iter() {
                let txt_data = txt.iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect::<Vec<String>>()
                    .join("");
                
                let mut entity = Entity::new(
                    EntityType::DnsRecord,
                    if txt_data.len() > 50 { 
                        format!("{}...", &txt_data[0..47]) 
                    } else { 
                        txt_data.clone() 
                    },
                    "dns_scanner_txt"
                );

                entity = entity.with_property("record_type", "TXT".into())
                             .with_property("full_content", txt_data.into())
                             .with_property("domain", domain.into());
                             
                findings.push(entity);
            }
        }
        
        // 6. CNAME Records
         if let Ok(response) = self.resolver.lookup(&target, RecordType::CNAME).await {
            for cname in response.iter() {
                let cname_str = cname.to_string();
                let mut entity = Entity::new(
                    EntityType::DnsRecord,
                    cname_str.clone(),
                    "dns_scanner_cname"
                );
                
                 entity = entity.with_property("record_type", "CNAME".into())
                             .with_property("domain", domain.into());
                             
                findings.push(entity);
            }
        }

        Ok(findings)
    }
}

pub async fn lookup(_state: &Arc<AppState>, domain: &str) -> Result<DnsLookupResponse> {
    let scanner = DnsScanner::new()?;
    let entities = scanner.scan(domain).await?;
    
    let mut records = DnsRecords {
        a: vec![],
        aaaa: vec![],
        mx: vec![],
        txt: vec![],
        ns: vec![],
        cname: vec![],
        soa: None,
    };
    
    let mut resolved_ips = Vec::new();

    for entity in entities {
        match entity.properties.get("record_type").and_then(|v| v.as_str()) {
            Some("A") => {
                records.a.push(entity.value.clone());
                resolved_ips.push(entity.value.clone());
            },
            Some("AAAA") => {
                records.aaaa.push(entity.value.clone());
                 resolved_ips.push(entity.value.clone());
            },
            Some("MX") => {
                let priority = entity.properties.get("priority").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                records.mx.push(MxRecord { priority, exchange: entity.value.clone() });
            },
            Some("NS") => records.ns.push(entity.value.clone()),
            Some("TXT") => {
                 let full = entity.properties.get("full_content").and_then(|v| v.as_str()).unwrap_or(&entity.value);
                 records.txt.push(full.to_string());
            },
            Some("CNAME") => records.cname.push(entity.value.clone()),
            _ => {}
        }
    }

    Ok(DnsLookupResponse {
        domain: domain.to_string(),
        records,
        resolved_ips,
        cached: false,
    })
}
