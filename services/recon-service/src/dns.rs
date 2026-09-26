use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use ipnetwork::IpNetwork;
use std::str::FromStr;
use crate::logger::{log_info, log_warn, log_error};

// Cloudflare IP ranges (IPv4 and IPv6)
// Source: https://www.cloudflare.com/ips/
const CF_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

pub struct DnsAnalysisResult {
    pub is_cf: bool,
    pub ips: Vec<String>,
    pub logs: Vec<String>,
}

pub async fn analyze_dns(domain: &str) -> DnsAnalysisResult {
    let mut logs = Vec::new();
    logs.push(format!("DNS analizi başlatıldı: {}", domain));
    log_info(&format!("DNS analizi başlatıldı: {}", domain));

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mut ips_found = Vec::new();
    let mut is_cf = true;

    match resolver.lookup_ip(domain).await {
        Ok(ips) => {
            for ip in ips {
                let ip_str = ip.to_string();
                ips_found.push(ip_str.clone());
                logs.push(format!("Bulunan IP: {}", ip_str));
                log_info(&format!("Bulunan IP: {}", ip_str));

                if !is_cloudflare_ip(&ip_str) {
                    is_cf = false;
                    logs.push(format!("⚠️  IP Cloudflare aralığında DEĞİL: {}", ip_str));
                    log_warn(&format!("⚠️  IP Cloudflare aralığında DEĞİL: {}", ip_str));
                } else {
                    logs.push(format!("🛡️  IP Cloudflare aralığında: {}", ip_str));
                    log_info(&format!("🛡️  IP Cloudflare aralığında: {}", ip_str));
                }
            }
        }
        Err(e) => {
            logs.push(format!("DNS çözümlenemedi: {}", e));
            log_error(&format!("DNS çözümlenemedi: {}", e));
            is_cf = false;
        }
    }

    DnsAnalysisResult {
        is_cf,
        ips: ips_found,
        logs,
    }
}

pub fn is_cloudflare_ip(ip: &str) -> bool {
    let ip_addr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    for range in CF_RANGES {
        if let Ok(network) = IpNetwork::from_str(range) {
            if network.contains(ip_addr) {
                return true;
            }
        }
    }
    false
}
