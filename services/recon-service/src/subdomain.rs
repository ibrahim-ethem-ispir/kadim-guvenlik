use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use futures::stream::{self, StreamExt};
use parking_lot::RwLock;
use crate::dns;
use crate::scan::{ScanConfig, SubdomainInfo, InfrastructureInfo, SharedState, update_scan_state, is_scan_cancelled};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub struct SubdomainAnalysisResult {
    pub subdomains: Vec<SubdomainInfo>,
    pub logs: Vec<String>,
}

pub async fn scan_subdomains(
    config: &ScanConfig,
    state: &SharedState,
    scan_id: &str,
) -> SubdomainAnalysisResult {
    let mut logs = Vec::new();
    let mut found_subdomains = Vec::new();

    // 1. Collect all wordlist files
    let mut wordlist_files = Vec::new();
    if config.wordlist == "all" {
        let base_path = "files/SecLists-master/Discovery/DNS";
        if let Ok(mut entries) = tokio::fs::read_dir(base_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(metadata) = entry.metadata().await {
                    if metadata.is_file() {
                        if let Some(name) = entry.file_name().to_str() {
                            if name.ends_with(".txt") {
                                wordlist_files.push(format!("{}/{}", base_path, name));
                            }
                        }
                    }
                }
            }
        }
    } else {
        wordlist_files.push(config.wordlist.clone());
    }

    update_scan_state(state, scan_id, |s| {
        s.total_wordlists = wordlist_files.len();
        s.processed_wordlists = 0;
    });

    // 2. Read all subdomains into memory (deduplicated)
    let mut subdomains_to_scan = std::collections::HashSet::new();
    
    for (idx, path) in wordlist_files.iter().enumerate() {
        // İptal kontrolü - her wordlist okumadan önce
        if is_scan_cancelled(state, scan_id) {
            let msg = "⛔ Tarama iptal edildi - wordlist okuma durduruluyor".to_string();
            logs.push(msg.clone());
            update_scan_state(state, scan_id, |s| s.logs.push(msg.clone()));
            return SubdomainAnalysisResult {
                subdomains: vec![],
                logs,
            };
        }
        
        let filename = path.split('/').last().unwrap_or("unknown");
        let msg = format!("📖 Reading wordlist ({}/{}): {}", idx + 1, wordlist_files.len(), filename);
        logs.push(msg.clone());
        update_scan_state(state, scan_id, |s| {
            s.logs.push(msg.clone());
            s.current_wordlist = filename.to_string();
            s.current_step = format!("Reading wordlist {}/{}", idx + 1, wordlist_files.len());
        });

        if let Ok(file) = File::open(path).await {
            let reader = BufReader::new(file);
            let mut lines = reader.lines();
            let mut count = 0;
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.trim().is_empty() {
                    subdomains_to_scan.insert(format!("{}.{}", line.trim(), config.domain));
                    count += 1;
                }
            }
            let msg = format!("✅ Loaded {} entries from {}", count, filename);
            logs.push(msg.clone());
            update_scan_state(state, scan_id, |s| {
                s.logs.push(msg.clone());
                s.processed_wordlists = idx + 1; // Properly increment after processing
            });
        } else {
            let msg = format!("⚠️ Could not open wordlist: {}", path);
            logs.push(msg.clone());
            update_scan_state(state, scan_id, |s| {
                s.logs.push(msg.clone());
                s.processed_wordlists = idx + 1; // Still increment even on error
            });
        }
    }

    let total_subdomains = subdomains_to_scan.len();
    update_scan_state(state, scan_id, |s| {
        s.total_subdomains = total_subdomains;
        s.scanned_subdomains = 0;
        s.logs.push(format!("Total unique subdomains to scan: {}", total_subdomains));
        s.start_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    });

    // İptal kontrolü - tarama başlamadan önce
    if is_scan_cancelled(state, scan_id) {
        let msg = "⛔ Tarama iptal edildi - DNS taraması başlatılmıyor".to_string();
        logs.push(msg.clone());
        update_scan_state(state, scan_id, |s| s.logs.push(msg.clone()));
        return SubdomainAnalysisResult {
            subdomains: vec![],
            logs,
        };
    }

    // KRİTİK (recon-bitmeme): Varsayılan ResolverOpts, cevapsız (filtrelenen)
    // resolver'larda her sorguyu uzun uzun bekletir → binlerce kelimelik listede
    // tarama pratikte hiç bitmez. Kısıtlı egress'li kurumsal/banka ağlarında bu
    // özellikle can yakar. Sorgu başına kesin bir üst sınır + tek deneme koy.
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.timeout = Duration::from_secs(3);
    resolver_opts.attempts = 1;
    let resolver = Arc::new(TokioAsyncResolver::tokio(ResolverConfig::default(), resolver_opts));
    let subdomains_vec: Vec<String> = subdomains_to_scan.into_iter().collect();

    // 3. Scan with concurrency and delay
    let start_time = std::time::Instant::now();
    let total_count = subdomains_vec.len();
    let scanned_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let last_log_time = Arc::new(RwLock::new(std::time::Instant::now()));
    let cancelled_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    
    let results = stream::iter(subdomains_vec)
        .map(|subdomain| {
            let resolver = resolver.clone();
            let state = state.clone();
            let scan_id = scan_id.to_string();
            let delay = config.delay_ms;
            let start_time = start_time;
            let scanned_counter = scanned_counter.clone();
            let last_log_time = last_log_time.clone();
            let cancelled_flag = cancelled_flag.clone();
            
            async move {
                // İptal edilmişse işlemi atla
                if cancelled_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return None;
                }
                
                // Her 50 taramada bir iptal kontrolü yap
                let current_count = scanned_counter.load(std::sync::atomic::Ordering::Relaxed);
                if current_count % 50 == 0 && is_scan_cancelled(&state, &scan_id) {
                    cancelled_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }
                
                // Apply delay if configured
                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }

                let result = match resolver.lookup_ip(&subdomain).await {
                    Ok(ips) => Some((subdomain, ips)),
                    Err(_) => None,
                };

                // Increment counter atomically
                let current_count = scanned_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                
                // Batch update progress (every 10 scans or every 2 seconds)
                let should_update = current_count % 10 == 0 || {
                    let last_time = last_log_time.read();
                    last_time.elapsed().as_secs() >= 2
                };
                
                if should_update {
                    let elapsed_secs = start_time.elapsed().as_secs_f32();
                    let scan_rate = if elapsed_secs > 0.0 { current_count as f32 / elapsed_secs } else { 0.0 };
                    let remaining = total_count.saturating_sub(current_count);
                    let eta = if scan_rate > 0.0 { (remaining as f32 / scan_rate) as u64 } else { 0 };
                    
                    update_scan_state(&state, &scan_id, |s| {
                        s.scanned_subdomains = current_count;
                        s.progress = (current_count as f32 / total_count as f32) * 100.0;
                        s.scan_rate = scan_rate;
                        s.estimated_time_remaining = eta;
                        s.current_step = format!("Scanning subdomains... ({}/{})", current_count, total_count);
                    });
                    
                    // Log progress every 100 scans
                    if current_count % 100 == 0 {
                        let msg = format!("⚡ Progress: {}/{} ({:.1}%) - Rate: {:.1} sub/s - ETA: {}s", 
                            current_count, total_count, 
                            (current_count as f32 / total_count as f32) * 100.0,
                            scan_rate, eta);
                        update_scan_state(&state, &scan_id, |s| s.logs.push(msg));
                        
                        // Update last log time
                        let mut last_time = last_log_time.write();
                        *last_time = std::time::Instant::now();
                    }
                }

                result
            }
        })
        .buffer_unordered(config.concurrency)
        .collect::<Vec<_>>()
        .await;
    
    // Final progress update
    let elapsed_secs = start_time.elapsed().as_secs_f32();
    update_scan_state(state, scan_id, |s| {
        s.scanned_subdomains = total_count;
        s.progress = 100.0;
        s.current_step = "Processing results...".to_string();
        let msg = format!("✅ Scanning completed! Total: {} subdomains in {:.1}s", total_count, elapsed_secs);
        s.logs.push(msg);
    });

    // 4. Process results
    for result in results {
        if let Some((subdomain, ips)) = result {
            for ip in ips {
                let ip_str = ip.to_string();
                let is_cf = dns::is_cloudflare_ip(&ip_str);
                
                let msg = format!("Found: {} -> {} [{}]", subdomain, ip_str, if is_cf { "CF" } else { "Real IP" });
                logs.push(msg.clone());
                update_scan_state(state, scan_id, |s| s.logs.push(msg.clone()));
                
                found_subdomains.push(SubdomainInfo {
                    subdomain: subdomain.clone(),
                    ip: Some(ip_str),
                    is_cf,
                    is_live: false, // Heniz HTTP kontrolü yapılmadı
                    status_code: None,
                    response_time_ms: None,
                    infrastructure: InfrastructureInfo {
                        provider: if is_cf { Some("Cloudflare".to_string()) } else { None },
                        is_cloud: is_cf,
                        is_private_ip: false,
                        is_waf_protected: is_cf,
                    },
                    technologies: vec![],
                    page_title: None,
                });
            }
        }
    }

    SubdomainAnalysisResult {
        subdomains: found_subdomains,
        logs,
    }
}

