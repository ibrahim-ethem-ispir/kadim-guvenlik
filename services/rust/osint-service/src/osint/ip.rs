use crate::AppState;
use crate::api::responses::IpInfoResponse;
use anyhow::{Result, Context};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AsnInfo {
    pub asn: String,
    pub org: String,
    pub isp: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpGeoInfo {
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub lat: f64,
    pub lon: f64,
    pub timezone: String,
    pub isp: String,
    pub org: String,
    pub as_number: String,
}

/// Türkçe: IP adresi hakkında OSINT verisi toplar
pub async fn lookup(state: &Arc<AppState>, ip: &str) -> Result<IpInfoResponse> {
    // 1. Önce cache kontrolü yap
    if let Ok(Some(cached)) = state.db.get_cached_ip_info::<IpInfoResponse>(ip).await {
        return Ok(cached);
    }

    // 2. IP-API.com kullanarak veri çek (Ücretsiz endpoint, rate limit dikkat)
    // Production'da kendi DB'miz veya ücretli API kullanılmalı
    let url = format!("http://ip-api.com/json/{}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query", ip);
    
    let resp = reqwest::get(&url)
        .await
        .context("IP API request failed")?
        .json::<serde_json::Value>()
        .await
        .context("Failed to parse IP API response")?;

    if resp.get("status").and_then(|s| s.as_str()) != Some("success") {
        return Err(anyhow::anyhow!("IP lookup failed: {:?}", resp.get("message")));
    }

    // 3. Veriyi parse et
    let asn_str = resp.get("as").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (asn, asn_org) = parse_asn_string(&asn_str);

    let info = IpInfoResponse {
        ip: ip.to_string(),
        asn: asn,
        org: resp.get("org").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        isp: resp.get("isp").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        country: resp.get("country").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        country_code: resp.get("countryCode").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        city: resp.get("city").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        region: resp.get("regionName").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        timezone: resp.get("timezone").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        loc: format!("{},{}", 
            resp.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0),
            resp.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0)
        ),
    };

    // 4. Cache'e kaydet (12 saat)
    let _ = state.db.cache_ip_info(ip, &info).await;

    Ok(info)
}

/// "AS15169 Google LLC" formatındaki stringi parçalar
fn parse_asn_string(asn_str: &str) -> (String, String) {
    if let Some((asn, org)) = asn_str.split_once(' ') {
        (asn.to_string(), org.to_string())
    } else {
        (asn_str.to_string(), "".to_string())
    }
}
