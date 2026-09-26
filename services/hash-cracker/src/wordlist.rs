//! Wordlist Management Module
//!
//! Provides wordlist discovery, loading, and information

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistEntry {
    pub path: String,
    pub name: String,
    pub description: String,
    pub size_bytes: u64,
    pub line_count: Option<u64>,
    pub category: String,
    pub emoji: String,
}

/// Get base path for wordlists (handles Docker vs local)
fn get_base_path() -> &'static str {
    // Docker container mounts files at /app/files
    if Path::new("/app/files").exists() {
        "/app/files"
    } else {
        // Local development fallback
        "files"
    }
}

/// List all available wordlists from SecLists
pub async fn list_wordlists() -> Vec<WordlistEntry> {
    let base = get_base_path();
    let base_paths = vec![
        base.to_string(),
        format!("{}/generated", base),
        format!("{}/SecLists-master/Passwords", base),
        format!("{}/SecLists-master/Passwords/Common-Credentials", base),
        format!("{}/SecLists-master/Passwords/Leaked-Databases", base),
        format!("{}/SecLists-master/Passwords/WiFi-WPA", base),
    ];
    
    let mut wordlists = Vec::new();
    
    tracing::info!("🔍 Scanning wordlists from base: {}", base);
    
    for base_path in &base_paths {
        tracing::debug!("📂 Checking directory: {}", base_path);
        
        if let Ok(mut entries) = tokio::fs::read_dir(base_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(metadata) = entry.metadata().await {
                    if metadata.is_file() {
                        if let Some(name) = entry.file_name().to_str() {
                            if name.ends_with(".txt") {
                                let path = entry.path();
                                let full_path = path.to_string_lossy().to_string();
                                let (description, category, emoji) = format_wordlist_info(name, base_path);
                                
                                tracing::debug!("📝 Found wordlist: {} ({} bytes)", name, metadata.len());
                                
                                wordlists.push(WordlistEntry {
                                    path: full_path,
                                    name: name.to_string(),
                                    description,
                                    size_bytes: metadata.len(),
                                    line_count: estimate_line_count(metadata.len()),
                                    category,
                                    emoji,
                                });
                            }
                        }
                    }
                }
            }
        } else {
            tracing::warn!("⚠️ Could not read directory: {}", base_path);
        }
    }
    
    tracing::info!("✅ Found {} wordlists", wordlists.len());
    
    // Sort by size (smallest first for better UX)
    wordlists.sort_by(|a, b| a.size_bytes.cmp(&b.size_bytes));
    
    wordlists
}

/// Merge all available wordlists into a single combined wordlist file
/// Returns the path to the merged wordlist file
///
/// KRİTİK DEĞİŞİKLİK (2024/2025):
/// - `read_to_string` yerine streaming `BufReader::lines()` kullanılıyor
/// - Recursive directory traversal ile TÜM alt dizinler taranıyor
/// - Her dosya için hata loglama (silent failure önleme)
/// - Memory-efficient: O(unique_words) for HashSet only
pub async fn merge_all_wordlists() -> Result<String, std::io::Error> {
    use std::collections::HashSet;
    use std::io::{BufRead, BufReader, Write, BufWriter};
    
    let base = get_base_path();
    
    tracing::info!("🔀 Starting comprehensive wordlist merge from: {}", base);
    
    // Blocking task'ta çalıştır - I/O intensive işlem
    let merged_path = format!("{}/merged_wordlist.txt", base);
    let merged_path_clone = merged_path.clone();
    
    let result = tokio::task::spawn_blocking(move || -> std::io::Result<(String, u64, usize, usize)> {
        let base_path = if std::path::Path::new("/app/files").exists() {
            "/app/files"
        } else {
            "files"
        };
        
        // Recursive olarak tüm .txt dosyalarını bul
        let mut all_files: Vec<std::path::PathBuf> = Vec::new();
        
        fn find_txt_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>, depth: usize) {
            if depth > 10 { return; } // Güvenlik: max 10 seviye
            
            // logs/ dizinini atla - bu bizim çıktı loglarımız
            if let Some(dir_name) = dir.file_name().and_then(|n| n.to_str()) {
                if dir_name == "logs" || dir_name == "generated" {
                    tracing::debug!("📁 Atlanıyor: {} (sistem dizini)", dir.display());
                    return;
                }
            }
            
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_dir() {
                        find_txt_files(&path, files, depth + 1);
                    } else if path.is_file() {
                        if let Some(ext) = path.extension() {
                            if ext == "txt" {
                                // Hariç tutulan dosyalar:
                                // - merged_wordlist.txt (kendi çıktımız)
                                // - *_tried.txt (tarama logları)
                                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                    let should_skip = name == "merged_wordlist.txt" 
                                        || name.ends_with("_tried.txt")
                                        || name.starts_with(".");
                                    
                                    if !should_skip {
                                        files.push(path);
                                    } else {
                                        tracing::debug!("📄 Atlanıyor: {} (sistem dosyası)", name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        find_txt_files(std::path::Path::new(base_path), &mut all_files, 0);
        
        let files_found = all_files.len();
        tracing::info!("📂 {} wordlist dosyası bulundu", files_found);
        
        if files_found == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Hiçbir wordlist dosyası bulunamadı",
            ));
        }
        
        // Duplicate detection için HashSet - 30M kelime için ~1.5GB RAM gerekir
        let mut seen: HashSet<String> = HashSet::with_capacity(30_000_000);
        
        // Output file
        let output_file = std::fs::File::create(&merged_path_clone)?;
        let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, output_file);
        
        let mut files_processed: usize = 0;
        let mut files_failed: usize = 0;
        let mut total_lines: u64 = 0;
        
        for (idx, file_path) in all_files.iter().enumerate() {
            let file_name = file_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            
            // Dosyayı streaming ile oku
            match std::fs::File::open(file_path) {
                Ok(file) => {
                    let reader = BufReader::with_capacity(16 * 1024 * 1024, file);
                    let mut file_new_words: u64 = 0;
                    
                    for line_result in reader.lines() {
                        match line_result {
                            Ok(line) => {
                                let trimmed = line.trim();
                                if !trimmed.is_empty() && !seen.contains(trimmed) {
                                    seen.insert(trimmed.to_string());
                                    writeln!(writer, "{}", trimmed)?;
                                    file_new_words += 1;
                                }
                                total_lines += 1;
                            }
                            Err(_) => {
                                // UTF-8 hatası - satırı atla
                            }
                        }
                    }
                    
                    files_processed += 1;
                    
                    // Her 50 dosyada bir progress log
                    if idx % 50 == 0 || idx == files_found - 1 {
                        tracing::info!(
                            "📊 [{}/{}] {} işlendi, {} yeni kelime, toplam {} unique",
                            idx + 1, files_found, file_name, file_new_words, seen.len()
                        );
                    }
                }
                Err(e) => {
                    files_failed += 1;
                    tracing::warn!("❌ Dosya okunamadı: {} - {}", file_name, e);
                }
            }
        }
        
        writer.flush()?;
        
        let unique_count = seen.len() as u64;
        tracing::info!(
            "✅ Birleştirme tamamlandı: {} dosya işlendi, {} başarısız, {} satır okundu, {} unique kelime",
            files_processed, files_failed, total_lines, unique_count
        );
        
        Ok((merged_path_clone, unique_count, files_processed, files_failed))
    }).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))??;
    
    tracing::info!(
        "✅ Merged wordlist saved to: {} ({} unique passwords from {} files)",
        result.0, result.1, result.2
    );
    
    Ok(merged_path)
}

/// Estimate line count based on file size (average ~10 bytes per password)
fn estimate_line_count(size: u64) -> Option<u64> {
    Some(size / 10)
}

/// Format wordlist filename into user-friendly description
fn format_wordlist_info(filename: &str, base_path: &str) -> (String, String, String) {
    let name = filename.trim_end_matches(".txt");
    
    // Determine category
    let category = if base_path.contains("Common-Credentials") {
        "Common Passwords".to_string()
    } else if base_path.contains("Leaked-Databases") {
        "Leaked Databases".to_string()
    } else if base_path.contains("WiFi-WPA") {
        "WiFi / WPA".to_string()
    } else {
        "General".to_string()
    };
    
    // Special wordlist mappings with descriptions and emojis
    let name_lower = name.to_lowercase();
    let (desc, emoji): (String, &str) = match name_lower.as_str() {
        // Popular lists
        "rockyou" => ("RockYou 2009 Leak - 14M passwords".to_string(), "🎸"),
        "darkc0de" => ("Darkc0de Collection - 15M passwords".to_string(), "🌑"),
        "10k-most-common" => ("Top 10K Most Common Passwords".to_string(), "⭐"),
        "xato-net-10-million-passwords" => ("Xato.net 10M Password Collection".to_string(), "📊"),
        
        _ => {
            // Check patterns
            if name_lower.contains("top-1000000") {
                ("Top 1M Most Common - Comprehensive".to_string(), "🔥")
            } else if name_lower.contains("top-100000") {
                ("Top 100K Most Common - Fast".to_string(), "⚡")
            } else if name_lower.contains("top-10000") {
                ("Top 10K Most Common - Quick".to_string(), "🚀")
            } else if name_lower.contains("top-1000") {
                ("Top 1K Most Common - Ultra Quick".to_string(), "💨")
            } else if name_lower.contains("2024") {
                ("2024 Most Used Passwords (Latest)".to_string(), "🆕")
            } else if name_lower.contains("2023") {
                ("2023 Most Used Passwords".to_string(), "📅")
            } else if name_lower.contains("2022") {
                ("2022 Most Used Passwords".to_string(), "📆")
            } else if name_lower.contains("wifi") || name_lower.contains("wpa") {
                ("WiFi / WPA Password List".to_string(), "📶")
            } else if name_lower.contains("ssh") {
                ("SSH Common Passwords".to_string(), "🔑")
            } else if name_lower.contains("darkweb") {
                ("Dark Web Leaked Passwords".to_string(), "🕸️")
            } else if name_lower.contains("mysql") || name_lower.contains("sql") {
                ("Database Default Passwords".to_string(), "🗄️")
            } else {
                // Default formatting
                let formatted = name
                    .replace('-', " ")
                    .replace('_', " ")
                    .split_whitespace()
                    .map(|word| {
                        let mut c = word.chars();
                        match c.next() {
                            None => String::new(),
                            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                (formatted, "📝")
            }
        }
    };
    
    (desc, category, emoji.to_string())
}

/// Load wordlist content
pub async fn load_wordlist(path: &str) -> Result<Vec<String>, std::io::Error> {
    let content = tokio::fs::read_to_string(path).await?;
    Ok(content.lines().map(|s| s.to_string()).collect())
}

/// Get wordlist statistics
pub async fn get_wordlist_stats(path: &str) -> Option<WordlistStats> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    let lines: Vec<&str> = content.lines().collect();
    
    let total = lines.len();
    let avg_length: f64 = if total > 0 {
        lines.iter().map(|s| s.len()).sum::<usize>() as f64 / total as f64
    } else {
        0.0
    };
    
    let max_length = lines.iter().map(|s| s.len()).max().unwrap_or(0);
    let min_length = lines.iter().map(|s| s.len()).min().unwrap_or(0);
    
    Some(WordlistStats {
        total_passwords: total as u64,
        average_length: avg_length,
        max_length,
        min_length,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistStats {
    pub total_passwords: u64,
    pub average_length: f64,
    pub max_length: usize,
    pub min_length: usize,
}
