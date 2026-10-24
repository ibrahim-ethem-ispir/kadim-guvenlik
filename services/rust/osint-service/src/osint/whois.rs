use anyhow::Result;
use crate::models::entity::{Entity, EntityType};
use whois_rust::{WhoIs, WhoIsLookupOptions};
use regex::Regex;
use crate::AppState;
use crate::api::responses::WhoisResponse;
use std::sync::Arc;

pub struct WhoisScanner {
    mapping: String,
}

impl WhoisScanner {
    pub fn new() -> Result<Self> {
        let mapping = r#"{
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "io": "whois.nic.io",
            "me": "whois.nic.me",
            "info": "whois.afilias.net",
            "tr": "whois.nic.tr",
            "gov": "whois.dotgov.gov",
            "edu": "whois.educause.edu"
        }"#;

        Ok(Self { mapping: mapping.to_string() })
    }

    pub async fn scan(&self, domain: &str) -> Result<Entity> {
         let domain_owned = domain.to_string();
         let mapping = self.mapping.clone();
         
         // Türkçe: Blocking task içinde WHOIS sorgusu yapılıyor
         // WhoIsLookupOptions::from_string ile domain lookup yapılır
         let raw_result = tokio::task::spawn_blocking(move || {
            let whois = WhoIs::from_string(mapping).map_err(|e| anyhow::anyhow!("Whois config error: {:?}", e))?;
            let options = WhoIsLookupOptions::from_string(&domain_owned).map_err(|e| anyhow::anyhow!("Invalid domain: {:?}", e))?;
            whois.lookup(options).map_err(|e| anyhow::anyhow!("Whois lookup failed: {:?}", e))
         }).await??;

         let mut entity = Entity::new(
             EntityType::Domain,
             domain.to_string(),
             "whois_scanner"
         );
         
         let registrar_re = Regex::new(r"(?i)Registrar:\s*(.+)").unwrap();
         let created_re = Regex::new(r"(?i)(Creation Date|Created On|Registration Date):\s*(.+)").unwrap();
         let expiry_re = Regex::new(r"(?i)(Registry Expiry Date|Expiration Date|Expires On):\s*(.+)").unwrap();
         let updated_re = Regex::new(r"(?i)(Updated Date|Last Updated On):\s*(.+)").unwrap();
         let ns_re = Regex::new(r"(?i)Name Server:\s*(.+)").unwrap();

         let mut registrar = None;
         let mut created = None;
         let mut expiry = None;
         let mut updated = None;
         let mut nameservers = Vec::new();

         for line in raw_result.lines() {
             let line = line.trim();
             if let Some(caps) = registrar_re.captures(line) {
                 registrar = Some(caps[1].trim().to_string());
             }
             if let Some(caps) = created_re.captures(line) {
                 created = Some(caps[2].trim().to_string());
             }
             if let Some(caps) = expiry_re.captures(line) {
                 expiry = Some(caps[2].trim().to_string());
             }
             if let Some(caps) = updated_re.captures(line) {
                 updated = Some(caps[2].trim().to_string());
             }
             if let Some(caps) = ns_re.captures(line) {
                 nameservers.push(caps[1].trim().to_lowercase());
             }
         }
         
         if let Some(r) = registrar { entity = entity.with_property("registrar", r.into()); }
         if let Some(c) = created { entity = entity.with_property("created_date", c.into()); }
         if let Some(e) = expiry { entity = entity.with_property("expiry_date", e.into()); }
         if let Some(u) = updated { entity = entity.with_property("updated_date", u.into()); }
         
         entity = entity.with_property("nameservers", nameservers.into());
         entity = entity.with_property("raw_whois", raw_result.into());
         
         Ok(entity)
    }
}

pub async fn lookup(_state: &Arc<AppState>, domain: &str) -> Result<WhoisResponse> {
    let scanner = WhoisScanner::new()?;
    let entity = scanner.scan(domain).await?;
    
    // Extract properties safely
    let registrar = entity.properties.get("registrar").and_then(|v| v.as_str()).map(String::from);
    let created = entity.properties.get("created_date").and_then(|v| v.as_str()).map(String::from);
    let updated = entity.properties.get("updated_date").and_then(|v| v.as_str()).map(String::from);
    let expiry = entity.properties.get("expiry_date").and_then(|v| v.as_str()).map(String::from);
    let raw = entity.properties.get("raw_whois").and_then(|v| v.as_str()).map(String::from);
    
    let nameservers = entity.properties.get("nameservers")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_else(Vec::new);

    Ok(WhoisResponse {
        domain: domain.to_string(),
        registrar,
        registrant: None, // Not parsing typical registrant for now
        created_date: created,
        updated_date: updated,
        expiry_date: expiry,
        nameservers,
        status: vec![],
        dnssec: None,
        raw,
        cached: false,
    })
}
