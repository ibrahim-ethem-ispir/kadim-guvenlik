//! Attack Module - Dictionary, Brute Force, Hybrid, Rule-based attacks
//!
//! Modern cracking techniques (2024/2025 best practices):
//! - **Streaming** parallel dictionary attack using rayon + BufReader
//! - Optimized brute force with charset explosion
//! - Hybrid attacks (wordlist + rules)
//! - Mask attacks (pattern-based)
//! - Combinator attacks (word1 + word2)
//!
//! ÖNEMLİ: Bu modül büyük wordlist'leri (23M+ satır) bellek taşırmadan
//! işleyebilmek için streaming I/O kullanır. `read_to_string` yerine
//! `BufReader::lines()` iterator'ü tercih edilir.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::io::{BufRead, BufReader, Write};
use std::fs::File;
use rayon::prelude::*;
use md5::{Md5, Digest as Md5Digest};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use blake2::{Blake2b512, Blake2s256};
use hex;

use crate::hash_types::HashType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaltPosition {
    Prefix,
    Suffix,
}


/// Attack configuration
#[derive(Debug, Clone)]
pub struct AttackConfig {
    pub hash: String,
    pub hash_type: HashType,
    pub attack_mode: AttackMode,
    pub wordlist_path: Option<String>,
    pub charset: Option<String>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub rules: Vec<Rule>,
    pub threads: usize,
    pub export_tried: bool,
    pub job_id: Option<String>,
    pub salt: Option<String>,
    pub salt_position: Option<SaltPosition>,
}

#[derive(Debug, Clone)]
pub enum AttackMode {
    Dictionary,      // Wordlist-based
    BruteForce,      // Character set exhaustion
    Hybrid,          // Wordlist + rules
    Mask,            // Pattern-based (?l?l?l?l?d?d)
    Combinator,      // word1 + word2
}

/// Transformation rules for hybrid attacks
#[derive(Debug, Clone)]
pub enum Rule {
    Append(String),           // Append suffix: password -> password123
    Prepend(String),          // Prepend prefix: password -> 123password
    Capitalize,               // password -> Password
    UpperCase,                // password -> PASSWORD
    LowerCase,                // PASSWORD -> password
    Reverse,                  // password -> drowssap
    LeetSpeak,                // password -> p4ssw0rd
    DuplicateWord,            // password -> passwordpassword
    ToggleCase(usize),        // Toggle case at position
    AppendYear,               // password -> password2024
    AppendSpecial,            // password -> password!
    CombineRules(Vec<Rule>),  // Apply multiple rules
}

/// Attack result
#[derive(Debug, Clone)]
pub struct AttackResult {
    pub found: bool,
    pub password: Option<String>,
    pub attempts: u64,
    pub elapsed_ms: u64,
    pub rate: f64, // hashes per second
}

/// Progress callback with log streaming
pub struct AttackProgress {
    pub attempts: AtomicU64,
    pub found: AtomicBool,
    pub result: parking_lot::RwLock<Option<String>>,
    pub cancelled: AtomicBool,
    pub log_buffer: parking_lot::RwLock<Vec<String>>,
    pub total_words: AtomicU64,
}

impl AttackProgress {
    pub fn new() -> Self {
        Self {
            attempts: AtomicU64::new(0),
            found: AtomicBool::new(false),
            result: parking_lot::RwLock::new(None),
            cancelled: AtomicBool::new(false),
            log_buffer: parking_lot::RwLock::new(Vec::new()),
            total_words: AtomicU64::new(0),
        }
    }
    
    /// Add log entry (thread-safe, batched)
    pub fn add_log(&self, msg: String) {
        let mut logs = self.log_buffer.write();
        logs.push(msg);
        // Keep last 500 logs to prevent memory explosion
        if logs.len() > 500 {
            logs.drain(0..100);
        }
    }
    
    /// Drain logs for sending to client
    pub fn drain_logs(&self) -> Vec<String> {
        let mut logs = self.log_buffer.write();
        std::mem::take(&mut *logs)
    }
}

/// Main attack runner
pub fn run_attack(config: &AttackConfig, progress: Arc<AttackProgress>) -> AttackResult {
    let start = std::time::Instant::now();
    
    let target_hash = config.hash.to_lowercase();
    
    tracing::info!("⚔️ Starting {:?} attack on hash: {}...", config.attack_mode, &target_hash[..16.min(target_hash.len())]);
    progress.add_log(format!("⚔️ Saldırı başlatılıyor: {:?}", config.attack_mode));
    
    let result = match config.attack_mode {
        AttackMode::Dictionary => dictionary_attack(&target_hash, config, progress.clone()),
        AttackMode::BruteForce => bruteforce_attack(&target_hash, config, progress.clone()),
        AttackMode::Hybrid => hybrid_attack(&target_hash, config, progress.clone()),
        AttackMode::Mask => mask_attack(&target_hash, config, progress.clone()),
        AttackMode::Combinator => combinator_attack(&target_hash, config, progress.clone()),
    };
    
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let attempts = progress.attempts.load(Ordering::Relaxed);
    let rate = if elapsed_ms > 0 {
        (attempts as f64 / elapsed_ms as f64) * 1000.0
    } else {
        0.0
    };
    
    if result.is_some() {
        tracing::info!("✅ Attack completed - PASSWORD FOUND after {} attempts in {}ms", attempts, elapsed_ms);
        progress.add_log(format!("✅ Tarama tamamlandı - {} deneme, {}ms", attempts, elapsed_ms));
    } else {
        tracing::info!("❌ Attack completed - Password NOT FOUND after {} attempts in {}ms", attempts, elapsed_ms);
        progress.add_log(format!("❌ Tarama tamamlandı - şifre bulunamadı ({} deneme)", attempts));
    }
    
    AttackResult {
        found: result.is_some(),
        password: result,
        attempts,
        elapsed_ms,
        rate,
    }
}

/// Debug için public hash fonksiyonu - hash hesaplama doğrulaması
pub fn hash_password_debug(password: &str, hash_type: &HashType) -> String {
    hash_password(password, hash_type, None, None)
}

/// Hash a candidate password
fn hash_password(password: &str, hash_type: &HashType, salt: Option<&str>, salt_pos: Option<SaltPosition>) -> String {
    // Helper macro to handle salt for digest algorithms
    macro_rules! update_digest {
        ($hasher:expr) => {
            match (salt, salt_pos) {
                (Some(s), Some(SaltPosition::Prefix)) => {
                    $hasher.update(s.as_bytes());
                    $hasher.update(password.as_bytes());
                }
                (Some(s), Some(SaltPosition::Suffix)) => {
                    $hasher.update(password.as_bytes());
                    $hasher.update(s.as_bytes());
                }
                _ => $hasher.update(password.as_bytes()),
            }
        };
    }

    match hash_type {
        HashType::Md5 => {
            let mut hasher = Md5::new();
            update_digest!(hasher);
            hex::encode(hasher.finalize())
        }
        HashType::Sha1 => {
            let mut hasher = Sha1::new();
            update_digest!(hasher);
            hex::encode(hasher.finalize())
        }
        HashType::Sha256 => {
            let mut hasher = Sha256::new();
            update_digest!(hasher);
            hex::encode(hasher.finalize())
        }
        HashType::Sha512 => {
            let mut hasher = Sha512::new();
            update_digest!(hasher);
            hex::encode(hasher.finalize())
        }
        HashType::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            update_digest!(hasher);
            hex::encode(hasher.finalize())
        }
        HashType::Sha3_512 => {
            let mut hasher = Sha3_512::new();
            update_digest!(hasher);
            hex::encode(hasher.finalize())
        }
        HashType::Blake2b512 => {
            let mut hasher = Blake2b512::new();
            update_digest!(hasher);
            hex::encode(hasher.finalize())
        }
        HashType::Blake2s256 => {
            let mut hasher = Blake2s256::new();
            update_digest!(hasher);
            hex::encode(hasher.finalize())
        }
        HashType::Blake3 => {
            // Blake3 hasher accepts multiple updates
            let mut hasher = blake3::Hasher::new();
            match (salt, salt_pos) {
                (Some(s), Some(SaltPosition::Prefix)) => {
                    hasher.update(s.as_bytes());
                    hasher.update(password.as_bytes());
                }
                (Some(s), Some(SaltPosition::Suffix)) => {
                    hasher.update(password.as_bytes());
                    hasher.update(s.as_bytes());
                }
                _ => { hasher.update(password.as_bytes()); }
            }
            hasher.finalize().to_hex().to_string()
        }
        HashType::Ntlm => {
            // NTLM doesn't standardly support "salt" in the same way (it's internal), 
            // but if user provides it, we treat it as concatenation
            // Convert combined string to UTF-16LE
             match (salt, salt_pos) {
                (Some(s), Some(SaltPosition::Prefix)) => ntlm_hash(&format!("{}{}", s, password)),
                (Some(s), Some(SaltPosition::Suffix)) => ntlm_hash(&format!("{}{}", password, s)),
                _ => ntlm_hash(password),
            }
        }
        // For bcrypt/scrypt/argon2 we use verification not generation
        _ => {
            // Fallback to MD5 for unknown types
            let mut hasher = Md5::new();
            update_digest!(hasher);
            hex::encode(hasher.finalize())
        }
    }
}

/// NTLM hash implementation (MD4 of UTF-16LE)
fn ntlm_hash(password: &str) -> String {
    use md4::{Md4, Digest};
    
    // Convert to UTF-16LE
    let utf16: Vec<u16> = password.encode_utf16().collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|&x| x.to_le_bytes()).collect();
    
    // MD4 hash
    let mut hasher = Md4::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize()).to_uppercase()
}

/// Dictionary attack - STREAMING parallel wordlist processing
/// 
/// KRİTİK DEĞİŞİKLİK (2024/2025):
/// - `read_to_string` yerine `BufReader::lines()` kullanılıyor
/// - Dosya RAM'e yüklenmez, satır satır stream edilir
/// - Chunk-based parallel processing ile 23M+ satır destekleniyor
/// - Memory: O(chunk_size) instead of O(file_size)
fn dictionary_attack(
    target: &str,
    config: &AttackConfig,
    progress: Arc<AttackProgress>,
) -> Option<String> {
    let wordlist_path = match config.wordlist_path.as_ref() {
        Some(p) => p,
        None => {
            tracing::error!("❌ No wordlist path provided");
            progress.add_log("❌ Wordlist yolu belirtilmedi!".to_string());
            return None;
        }
    };
    
    tracing::info!("📖 Streaming wordlist: {}", wordlist_path);
    progress.add_log(format!("📖 Wordlist streaming başlatılıyor: {}", wordlist_path));
    
    // Dosya boyutunu al (progress için)
    let file_size = std::fs::metadata(wordlist_path)
        .map(|m| m.len())
        .unwrap_or(0);
    
    // Tahmini satır sayısı (ortalama 10 byte/satır)
    let estimated_lines = file_size / 10;
    
    progress.add_log(format!(
        "📊 Dosya boyutu: {} MB, tahmini {} satır",
        file_size / 1024 / 1024,
        estimated_lines
    ));
    
    // Dosyayı streaming olarak aç
    let file = match File::open(wordlist_path) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("❌ Failed to open wordlist: {} - {}", wordlist_path, e);
            progress.add_log(format!("❌ Wordlist açılamadı: {}", e));
            return None;
        }
    };
    
    // 16MB buffer ile BufReader oluştur (performans için)
    let reader = BufReader::with_capacity(16 * 1024 * 1024, file);
    
    let hash_type = config.hash_type.clone();
    let salt = config.salt.as_deref();
    let salt_pos = config.salt_position.clone();
    let target_lower = target.to_lowercase();
    
    tracing::info!("🔐 Target hash: {} (type: {:?})", target_lower, hash_type);
    progress.add_log(format!(
        "🔐 Hedef hash: {}... (tip: {:?})",
        &target_lower[..16.min(target_lower.len())],
        hash_type
    ));
    
    // Setup export writer if enabled
    let export_writer = if config.export_tried {
        if let Some(job_id) = &config.job_id {
            let path = format!("/app/files/logs/{}_tried.txt", job_id);
            let _ = std::fs::create_dir_all("/app/files/logs");
            match File::create(&path) {
                Ok(f) => {
                    progress.add_log(format!("💾 Dışa aktarma aktif: {}", path));
                    Some(Arc::new(parking_lot::Mutex::new(std::io::BufWriter::with_capacity(1024 * 1024, f))))
                },
                Err(e) => {
                    progress.add_log(format!("❌ Dışa aktarma dosyası oluşturulamadı: {}", e));
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    
    // Chunk-based streaming processing
    // Her chunk'ta 100K kelime - balance between memory and parallelism
    const CHUNK_SIZE: usize = 100_000;
    let mut chunk: Vec<String> = Vec::with_capacity(CHUNK_SIZE);
    let mut total_lines_read: u64 = 0;
    let mut result: Option<String> = None;
    let mut first_words_logged = false;
    
    progress.add_log("🚀 Streaming + paralel tarama başlatılıyor...".to_string());
    
    // Satır satır oku (streaming)
    for line_result in reader.lines() {
        // Early termination check
        if progress.cancelled.load(Ordering::Relaxed) || progress.found.load(Ordering::Relaxed) {
            break;
        }
        
        match line_result {
            Ok(line) => {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() {
                    chunk.push(trimmed);
                    total_lines_read += 1;
                    
                    // Debug: İlk 3 kelimeyi göster
                    if !first_words_logged && chunk.len() == 3 {
                        progress.add_log("📋 İlk 3 şifre örneği (debug):".to_string());
                        for (i, word) in chunk.iter().take(3).enumerate() {
                            let sample_hash = hash_password(word, &hash_type, salt, salt_pos).to_lowercase();
                            let preview = if sample_hash.len() > 32 { &sample_hash[..32] } else { &sample_hash };
                            progress.add_log(format!("   #{}: \"{}\" → {}...", i+1, word, preview));
                        }
                        first_words_logged = true;
                    }
                    
                    // Chunk dolduğunda paralel işle
                    if chunk.len() >= CHUNK_SIZE {
                        progress.total_words.store(total_lines_read, Ordering::SeqCst);
                        
                        result = process_chunk_parallel(
                            &chunk,
                            &target_lower,
                            &hash_type,
                            salt,
                            salt_pos,
                            &progress,
                            &export_writer,
                            total_lines_read,
                        );
                        
                        if result.is_some() {
                            break;
                        }
                        
                        chunk.clear();
                        
                        // Her chunk'tan sonra progress log
                        let pct = if estimated_lines > 0 {
                            (total_lines_read as f64 / estimated_lines as f64 * 100.0).min(100.0) as u32
                        } else {
                            0
                        };
                        progress.add_log(format!(
                            "📊 [~{}%] {} satır işlendi, devam ediyor...",
                            pct, total_lines_read
                        ));
                    }
                }
            }
            Err(e) => {
                // UTF-8 hatası - atla ve devam et
                tracing::trace!("⚠️ Satır okuma hatası: {}", e);
            }
        }
    }
    
    // Kalan chunk'ı işle
    if result.is_none() && !chunk.is_empty() && !progress.cancelled.load(Ordering::Relaxed) {
        progress.total_words.store(total_lines_read, Ordering::SeqCst);
        result = process_chunk_parallel(
            &chunk,
            &target_lower,
            &hash_type,
            salt,
            salt_pos,
            &progress,
            &export_writer,
            total_lines_read,
        );
    }
    
    // Final log
    let final_attempts = progress.attempts.load(Ordering::Relaxed);
    tracing::info!(
        "📊 Dictionary attack tamamlandı: {} satır okundu, {} deneme yapıldı",
        total_lines_read, final_attempts
    );
    progress.add_log(format!(
        "📊 Streaming tamamlandı: {} satır okundu, {} deneme yapıldı",
        total_lines_read, final_attempts
    ));
    
    result
}

/// Chunk'ı paralel olarak işle
/// 
/// Bu yardımcı fonksiyon bir kelime chunk'ını rayon ile paralel işler.
fn process_chunk_parallel(
    chunk: &[String],
    target_lower: &str,
    hash_type: &HashType,
    salt: Option<&str>,
    salt_pos: Option<SaltPosition>,
    progress: &Arc<AttackProgress>,
    export_writer: &Option<Arc<parking_lot::Mutex<std::io::BufWriter<File>>>>,
    total_read: u64,
) -> Option<String> {
    let log_interval: u64 = if chunk.len() > 10_000 { 5000 } else { 1000 };
    
    chunk.par_iter().find_map_any(|word| {
        // Check for cancellation
        if progress.cancelled.load(Ordering::Relaxed) || progress.found.load(Ordering::Relaxed) {
            return None;
        }
        
        let attempt_num = progress.attempts.fetch_add(1, Ordering::Relaxed) + 1;
        
        // Log every N attempts
        if attempt_num % log_interval == 0 {
            let pct = if total_read > 0 {
                (attempt_num as f64 / total_read as f64 * 100.0) as u32
            } else {
                0
            };
            progress.add_log(format!("🔍 [{:>3}%] Deneme #{}: {}", pct, attempt_num, word));
        }
        
        // Export if enabled
        if let Some(writer) = export_writer {
            let mut w = writer.lock();
            let _ = writeln!(w, "{}", word);
        }
        
        let candidate_hash = hash_password(word, hash_type, salt, salt_pos).to_lowercase();
        if candidate_hash == target_lower {
            tracing::info!("🎉 PASSWORD FOUND: {}", word);
            progress.add_log(format!("🎉 ŞİFRE BULUNDU: {}", word));
            progress.found.store(true, Ordering::SeqCst);
            *progress.result.write() = Some(word.to_string());
            Some(word.to_string())
        } else {
            None
        }
    })
}

/// Brute force attack with charset (enhanced with logging)
fn bruteforce_attack(
    target: &str,
    config: &AttackConfig,
    progress: Arc<AttackProgress>,
) -> Option<String> {
    let charset = config.charset.as_ref().map(|s| s.as_str()).unwrap_or("abcdefghijklmnopqrstuvwxyz0123456789");
    let min_len = config.min_length.unwrap_or(1);
    let max_len = config.max_length.unwrap_or(6);
    let hash_type = config.hash_type.clone();
    let salt = config.salt.as_deref();
    let salt_pos = config.salt_position.clone();
    let target_lower = target.to_lowercase();
    
    let charset_bytes: Vec<u8> = charset.as_bytes().to_vec();
    let charset_len = charset_bytes.len();
    
    // Calculate total combinations across all lengths
    let total_all: u64 = (min_len..=max_len).map(|l| (charset_len as u64).pow(l as u32)).sum();
    progress.total_words.store(total_all, Ordering::SeqCst);
    progress.add_log(format!("💪 Brute force: charset={} karakterler, uzunluk {}-{}", charset_len, min_len, max_len));
    progress.add_log(format!("📊 Toplam {} kombinasyon denenecek", total_all));
    progress.add_log("🚀 Paralel brute force başlatılıyor...".to_string());
    
    // Setup export writer if enabled
    let export_writer = if config.export_tried {
        if let Some(job_id) = &config.job_id {
            let path = format!("/app/files/logs/{}_tried.txt", job_id);
            let _ = std::fs::create_dir_all("/app/files/logs");
            match std::fs::File::create(&path) {
                Ok(f) => Some(Arc::new(parking_lot::Mutex::new(std::io::BufWriter::with_capacity(1024 * 1024, f)))),
                Err(_) => None
            }
        } else { None }
    } else { None };
    
    for length in min_len..=max_len {
        if progress.cancelled.load(Ordering::Relaxed) || progress.found.load(Ordering::Relaxed) {
            break;
        }
        
        // Generate all combinations of given length
        let total_combinations: u64 = (charset_len as u64).pow(length as u32);
        progress.add_log(format!("🔢 Uzunluk {} taranıyor: {} kombinasyon", length, total_combinations));
        
        let log_interval: u64 = if total_combinations > 1_000_000 { 50000 } else if total_combinations > 100_000 { 10000 } else { 1000 };
        
        // Process in parallel chunks
        let result: Option<String> = (0..total_combinations).into_par_iter().find_map_any(|i| {
            if progress.cancelled.load(Ordering::Relaxed) || progress.found.load(Ordering::Relaxed) {
                return None;
            }
            
            let attempt_num = progress.attempts.fetch_add(1, Ordering::Relaxed) + 1;
            
            // Generate candidate from index
            let candidate = index_to_password(i, &charset_bytes, length);
            
            if attempt_num % log_interval == 0 {
                let pct = (attempt_num as f64 / total_all as f64 * 100.0) as u32;
                progress.add_log(format!("💪 [{:>3}%] Deneme #{}: {}", pct, attempt_num, candidate));
            }
            
            // Export if enabled
            if let Some(writer) = &export_writer {
                let mut w = writer.lock();
                let _ = writeln!(w, "{}", candidate);
            }

            let candidate_hash = hash_password(&candidate, &hash_type, salt, salt_pos).to_lowercase();
            
            if candidate_hash == target_lower {
                progress.add_log(format!("🎉 ŞİFRE BULUNDU: {}", candidate));
                progress.found.store(true, Ordering::SeqCst);
                *progress.result.write() = Some(candidate.clone());
                Some(candidate)
            } else {
                None
            }
        });
        
        if result.is_some() {
            return result;
        }
    }
    
    None
}

/// Convert index to password string (for brute force enumeration)
fn index_to_password(mut index: u64, charset: &[u8], length: usize) -> String {
    let charset_len = charset.len() as u64;
    let mut result = vec![0u8; length];
    
    for i in (0..length).rev() {
        result[i] = charset[(index % charset_len) as usize];
        index /= charset_len;
    }
    
    String::from_utf8(result).unwrap_or_default()
}

/// Hybrid attack - STREAMING wordlist with rules (enhanced)
/// 
/// KRİTİK: Streaming I/O ile büyük wordlist desteği
fn hybrid_attack(
    target: &str,
    config: &AttackConfig,
    progress: Arc<AttackProgress>,
) -> Option<String> {
    let wordlist_path = match config.wordlist_path.as_ref() {
        Some(p) => p,
        None => {
            progress.add_log("❌ Wordlist yolu belirtilmedi!".to_string());
            return None;
        }
    };
    
    // Streaming ile dosyayı aç
    let file = match File::open(wordlist_path) {
        Ok(f) => f,
        Err(e) => {
            progress.add_log(format!("❌ Wordlist açılamadı: {}", e));
            return None;
        }
    };
    
    let file_size = std::fs::metadata(wordlist_path).map(|m| m.len()).unwrap_or(0);
    let estimated_lines = file_size / 10;
    
    progress.add_log(format!("📊 Hibrit tarama: ~{} kelime, dosya boyutu {} MB", estimated_lines, file_size / 1024 / 1024));
    
    let reader = BufReader::with_capacity(16 * 1024 * 1024, file);
    let hash_type = config.hash_type.clone();
    let salt = config.salt.as_deref();
    let salt_pos = config.salt_position.clone();
    let target_lower = target.to_lowercase();
    
    // Default rules if none provided
    let rules = if config.rules.is_empty() {
        get_default_rules()
    } else {
        config.rules.clone()
    };
    
    progress.add_log(format!("🔀 {} kural uygulanacak", rules.len()));
    progress.add_log("🚀 Streaming hibrit tarama başlatılıyor...".to_string());
    
    let export_writer = if config.export_tried {
        if let Some(job_id) = &config.job_id {
            let path = format!("/app/files/logs/{}_tried.txt", job_id);
            let _ = std::fs::create_dir_all("/app/files/logs");
            File::create(&path).ok().map(|f| 
                Arc::new(parking_lot::Mutex::new(std::io::BufWriter::with_capacity(1024 * 1024, f)))
            )
        } else { None }
    } else { None };
    
    const CHUNK_SIZE: usize = 50_000;
    let mut chunk: Vec<String> = Vec::with_capacity(CHUNK_SIZE);
    let mut total_lines_read: u64 = 0;
    let mut result: Option<String> = None;
    
    for line_result in reader.lines() {
        if progress.cancelled.load(Ordering::Relaxed) || progress.found.load(Ordering::Relaxed) {
            break;
        }
        
        if let Ok(line) = line_result {
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                chunk.push(trimmed);
                total_lines_read += 1;
                
                if chunk.len() >= CHUNK_SIZE {
                    progress.total_words.store(total_lines_read * rules.len() as u64, Ordering::SeqCst);
                    
                    result = process_hybrid_chunk(
                        &chunk,
                        &target_lower,
                        &hash_type,
                        salt,
                        salt_pos,
                        &rules,
                        &progress,
                        &export_writer,
                    );
                    
                    if result.is_some() {
                        break;
                    }
                    chunk.clear();
                }
            }
        }
    }
    
    // Kalan chunk'ı işle
    if result.is_none() && !chunk.is_empty() && !progress.cancelled.load(Ordering::Relaxed) {
        result = process_hybrid_chunk(&chunk, &target_lower, &hash_type, salt, salt_pos, &rules, &progress, &export_writer);
    }
    
    result
}

/// Hybrid chunk'ı paralel işle
fn process_hybrid_chunk(
    chunk: &[String],
    target_lower: &str,
    hash_type: &HashType,
    salt: Option<&str>,
    salt_pos: Option<SaltPosition>,
    rules: &[Rule],
    progress: &Arc<AttackProgress>,
    export_writer: &Option<Arc<parking_lot::Mutex<std::io::BufWriter<File>>>>,
) -> Option<String> {
    let log_interval: u64 = 2000;
    
    chunk.par_iter().find_map_any(|word| {
        if progress.cancelled.load(Ordering::Relaxed) || progress.found.load(Ordering::Relaxed) {
            return None;
        }
        
        for rule in rules {
            let variations = apply_rule(word, rule);
            
            for variation in variations {
                let attempt_num = progress.attempts.fetch_add(1, Ordering::Relaxed) + 1;
                
                if attempt_num % log_interval == 0 {
                    progress.add_log(format!("🔀 Deneme #{}: {} (kural)", attempt_num, variation));
                }
                
                if let Some(writer) = export_writer {
                    let mut w = writer.lock();
                    let _ = writeln!(w, "{}", variation);
                }
                
                let candidate_hash = hash_password(&variation, hash_type, salt, salt_pos).to_lowercase();
                if candidate_hash == target_lower {
                    progress.add_log(format!("🎉 ŞİFRE BULUNDU: {}", variation));
                    progress.found.store(true, Ordering::SeqCst);
                    *progress.result.write() = Some(variation.clone());
                    return Some(variation);
                }
            }
        }
        None
    })
}

/// Apply transformation rule to word
fn apply_rule(word: &str, rule: &Rule) -> Vec<String> {
    match rule {
        Rule::Append(suffix) => vec![format!("{}{}", word, suffix)],
        Rule::Prepend(prefix) => vec![format!("{}{}", prefix, word)],
        Rule::Capitalize => {
            let mut chars: Vec<char> = word.chars().collect();
            if !chars.is_empty() {
                chars[0] = chars[0].to_uppercase().next().unwrap_or(chars[0]);
            }
            vec![chars.into_iter().collect()]
        }
        Rule::UpperCase => vec![word.to_uppercase()],
        Rule::LowerCase => vec![word.to_lowercase()],
        Rule::Reverse => vec![word.chars().rev().collect()],
        Rule::LeetSpeak => vec![word
            .replace('a', "4")
            .replace('e', "3")
            .replace('i', "1")
            .replace('o', "0")
            .replace('s', "5")
            .replace('t', "7")],
        Rule::DuplicateWord => vec![format!("{}{}", word, word)],
        Rule::ToggleCase(pos) => {
            let mut chars: Vec<char> = word.chars().collect();
            if *pos < chars.len() {
                chars[*pos] = if chars[*pos].is_uppercase() {
                    chars[*pos].to_lowercase().next().unwrap_or(chars[*pos])
                } else {
                    chars[*pos].to_uppercase().next().unwrap_or(chars[*pos])
                };
            }
            vec![chars.into_iter().collect()]
        }
        Rule::AppendYear => {
            vec![
                format!("{}2024", word),
                format!("{}2023", word),
                format!("{}2022", word),
                format!("{}123", word),
                format!("{}1234", word),
            ]
        }
        Rule::AppendSpecial => {
            vec![
                format!("{}!", word),
                format!("{}@", word),
                format!("{}#", word),
                format!("{}$", word),
                format!("{}*", word),
                format!("{}.", word),
            ]
        }
        Rule::CombineRules(rules) => {
            let mut results = vec![word.to_string()];
            for r in rules {
                let mut new_results = Vec::new();
                for w in &results {
                    new_results.extend(apply_rule(w, r));
                }
                results = new_results;
            }
            results
        }
    }
}

/// Get default rules for hybrid attack
fn get_default_rules() -> Vec<Rule> {
    vec![
        Rule::Capitalize,
        Rule::AppendYear,
        Rule::AppendSpecial,
        Rule::LeetSpeak,
        Rule::Append("123".to_string()),
        Rule::Append("1".to_string()),
        Rule::Append("!".to_string()),
        Rule::CombineRules(vec![Rule::Capitalize, Rule::Append("123".to_string())]),
        Rule::CombineRules(vec![Rule::Capitalize, Rule::Append("!".to_string())]),
    ]
}

/// Mask attack - pattern based (e.g., ?l?l?l?d?d for 3 lower + 2 digits)
fn mask_attack(
    target: &str,
    config: &AttackConfig,
    progress: Arc<AttackProgress>,
) -> Option<String> {
    // Simplified mask: direct to brute force with specific charset
    bruteforce_attack(target, config, progress)
}

/// Combinator attack - STREAMING word1 + word2 from wordlist (enhanced)
/// 
/// NOT: Combinator için tüm kelimeleri RAM'de tutmak gerekiyor (O(n^2) kombinasyon)
/// Bu nedenle büyük wordlist'ler için max 50K kelime limiti var.
fn combinator_attack(
    target: &str,
    config: &AttackConfig,
    progress: Arc<AttackProgress>,
) -> Option<String> {
    let wordlist_path = match config.wordlist_path.as_ref() {
        Some(p) => p,
        None => {
            progress.add_log("❌ Wordlist yolu belirtilmedi!".to_string());
            return None;
        }
    };
    
    // Streaming ile oku ama bellek için limit koy
    let file = match File::open(wordlist_path) {
        Ok(f) => f,
        Err(e) => {
            progress.add_log(format!("❌ Wordlist açılamadı: {}", e));
            return None;
        }
    };
    
    let reader = BufReader::with_capacity(16 * 1024 * 1024, file);
    
    // Combinator için max 50K kelime (50K x 50K = 2.5B kombinasyon zaten çok fazla)
    const MAX_WORDS: usize = 50_000;
    let mut words: Vec<String> = Vec::with_capacity(MAX_WORDS);
    
    for line_result in reader.lines() {
        if let Ok(line) = line_result {
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                words.push(trimmed);
                if words.len() >= MAX_WORDS {
                    progress.add_log(format!(
                        "⚠️ Combinator limiti: {} kelime ile sınırlandı (RAM koruması)",
                        MAX_WORDS
                    ));
                    break;
                }
            }
        }
    }
    
    let hash_type = config.hash_type.clone();
    let salt = config.salt.as_deref();
    let salt_pos = config.salt_position.clone();
    let target_lower = target.to_lowercase();
    
    let word_count = words.len();
    let total_combinations = (word_count * word_count) as u64;
    progress.total_words.store(total_combinations, Ordering::SeqCst);
    progress.add_log(format!(
        "🔗 Birleştirici tarama: {} kelime × {} kelime = {} kombinasyon",
        word_count, word_count, total_combinations
    ));
    progress.add_log("🚀 Paralel birleştirici tarama başlatılıyor...".to_string());

    let export_writer = if config.export_tried {
        if let Some(job_id) = &config.job_id {
            let path = format!("/app/files/logs/{}_tried.txt", job_id);
            let _ = std::fs::create_dir_all("/app/files/logs");
            File::create(&path).ok().map(|f|
                Arc::new(parking_lot::Mutex::new(std::io::BufWriter::with_capacity(1024 * 1024, f)))
            )
        } else { None }
    } else { None };

    let log_interval: u64 = if total_combinations > 100_000 { 10000 } else if total_combinations > 10_000 { 1000 } else { 100 };
    
    words.par_iter().find_map_any(|word1| {
        if progress.cancelled.load(Ordering::Relaxed) || progress.found.load(Ordering::Relaxed) {
            return None;
        }
        
        for word2 in &words {
            if progress.cancelled.load(Ordering::Relaxed) || progress.found.load(Ordering::Relaxed) {
                return None;
            }
            
            let combined = format!("{}{}", word1, word2);
            let attempt_num = progress.attempts.fetch_add(1, Ordering::Relaxed) + 1;
            
            if attempt_num % log_interval == 0 {
                let pct = (attempt_num as f64 / total_combinations as f64 * 100.0) as u32;
                progress.add_log(format!("🔗 [{:>3}%] Deneme #{}: {}", pct, attempt_num, combined));
            }

            if let Some(writer) = &export_writer {
                let mut w = writer.lock();
                let _ = writeln!(w, "{}", combined);
            }

            let candidate_hash = hash_password(&combined, &hash_type, salt, salt_pos).to_lowercase();
            if candidate_hash == target_lower {
                progress.add_log(format!("🎉 ŞİFRE BULUNDU: {}", combined));
                progress.found.store(true, Ordering::SeqCst);
                *progress.result.write() = Some(combined.clone());
                return Some(combined);
            }
        }
        None
    })
}

/// Check bcrypt password
pub fn verify_bcrypt(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// Check argon2 password
pub fn verify_argon2(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
}
