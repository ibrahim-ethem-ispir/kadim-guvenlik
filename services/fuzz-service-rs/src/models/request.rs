use serde::{Deserialize, Serialize};

/// Scan presets for quick configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanPreset {
    /// 20 threads, depth 1, fast scan
    Quick,
    /// 50 threads, depth 2, balanced (default)
    #[default]
    Normal,
    /// 100 threads, depth 4, --thorough flag
    Thorough,
    /// 5 threads, rate-limit 10, quiet mode
    Stealth,
}

impl ScanPreset {
    /// Get feroxbuster CLI args for this preset
    pub fn to_args(&self) -> Vec<String> {
        match self {
            ScanPreset::Quick => vec![
                "-t".into(), "20".into(),
                "-d".into(), "1".into(),
            ],
            ScanPreset::Normal => vec![
                "-t".into(), "50".into(),
                "-d".into(), "2".into(),
                "--auto-tune".into(),
                // SOFT-404 KALKANI: bazı hostlar OLMAYAN yola da 200/farklı-içerik döner
                // (wildcard). feroxbuster o zaman TÜM wordlist'i "bulgu" sanıp binlerce çöp
                // üretir (gözlemlenen: tek hostta 5000 sahte bulgu). 404'leri açıkça dışla;
                // wildcard/benzerlik elemesi ayrıca orchestrator post-filter'da yapılır.
                "-C".into(), "404".into(),
            ],
            ScanPreset::Thorough => vec![
                "-t".into(), "100".into(),
                "-d".into(), "4".into(),
                "--thorough".into(),
                "-C".into(), "404".into(),
            ],
            ScanPreset::Stealth => vec![
                "-t".into(), "5".into(),
                "-d".into(), "2".into(),
                "--rate-limit".into(), "10".into(),
                "-q".into(),
            ],
        }
    }
}

/// Detailed scan configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanConfig {
    /// Number of concurrent threads (default: 50)
    pub threads: Option<u16>,
    /// Maximum recursion depth (default: 4, 0 = infinite)
    pub depth: Option<u8>,
    /// File extensions to search (.php, .txt, etc)
    #[serde(default)]
    pub extensions: Vec<String>,
    /// HTTP methods to use (GET, POST, etc)
    #[serde(default)]
    pub methods: Vec<String>,
    /// Status codes to include (allow list)
    #[serde(default)]
    pub status_codes: Vec<u16>,
    /// Status codes to filter out (deny list)
    #[serde(default)]
    pub filter_status: Vec<u16>,
    /// Response sizes to filter out
    #[serde(default)]
    pub filter_size: Vec<u64>,
    /// Words count to filter out
    #[serde(default)]
    pub filter_words: Vec<u32>,
    /// Rate limit (requests per second)
    pub rate_limit: Option<u32>,
    /// Auto-tune: automatically lower scan rate on errors
    #[serde(default)]
    pub auto_tune: bool,
    /// Auto-bail: stop on excessive errors
    #[serde(default)]
    pub auto_bail: bool,
    /// Follow redirects
    #[serde(default)]
    pub redirects: bool,
    /// Skip TLS certificate verification
    #[serde(default)]
    pub insecure: bool,
    /// Request timeout in seconds
    pub timeout: Option<u16>,
    /// Custom headers
    #[serde(default)]
    pub headers: Vec<String>,
    /// No recursion
    #[serde(default)]
    pub no_recursion: bool,
}

impl ScanConfig {
    /// Convert config to feroxbuster CLI args
    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        
        if let Some(threads) = self.threads {
            args.extend(["-t".into(), threads.to_string()]);
        }
        
        if let Some(depth) = self.depth {
            args.extend(["-d".into(), depth.to_string()]);
        }
        
        for ext in &self.extensions {
            args.extend(["-x".into(), ext.clone()]);
        }
        
        for method in &self.methods {
            args.extend(["-m".into(), method.clone()]);
        }
        
        for code in &self.status_codes {
            args.extend(["-s".into(), code.to_string()]);
        }
        
        for code in &self.filter_status {
            args.extend(["-C".into(), code.to_string()]);
        }
        
        for size in &self.filter_size {
            args.extend(["-S".into(), size.to_string()]);
        }
        
        for words in &self.filter_words {
            args.extend(["-W".into(), words.to_string()]);
        }
        
        if let Some(rate) = self.rate_limit {
            args.extend(["--rate-limit".into(), rate.to_string()]);
        }
        
        if self.auto_tune {
            args.push("--auto-tune".into());
        }
        
        if self.auto_bail {
            args.push("--auto-bail".into());
        }
        
        if self.redirects {
            args.push("-r".into());
        }
        
        if self.insecure {
            args.push("-k".into());
        }
        
        if let Some(timeout) = self.timeout {
            args.extend(["-T".into(), timeout.to_string()]);
        }
        
        for header in &self.headers {
            args.extend(["-H".into(), header.clone()]);
        }
        
        if self.no_recursion {
            args.push("-n".into());
        }
        
        args
    }
}

/// Main scan request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeroxRequest {
    /// Target URL to scan
    pub target: String,
    /// Unique scan identifier
    pub scan_id: String,
    /// Wordlist filename (relative to /app/files)
    #[serde(default = "default_wordlist")]
    pub wordlist: String,
    /// Scan preset (quick, normal, thorough, stealth)
    pub preset: Option<ScanPreset>,
    /// Detailed configuration (overrides preset)
    #[serde(default)]
    pub config: ScanConfig,
    /// Enable smart seeding (OSINT enrichment)
    #[serde(default)]
    pub smart_seeding: bool,
}

fn default_wordlist() -> String {
    "common.txt".into()
}

/// Start scan response
#[derive(Debug, Serialize)]
pub struct StartScanResponse {
    pub status: String,
    pub scan_id: String,
    pub message: String,
}
