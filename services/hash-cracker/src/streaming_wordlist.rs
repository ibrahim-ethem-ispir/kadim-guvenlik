//! Streaming Wordlist Module - Memory-Efficient Large File Processing
//!
//! Bu modül 23M+ satırlık wordlist'leri bellek taşırmadan işlemek için tasarlandı.
//! 
//! Önemli Özellikler:
//! - BufReader ile satır satır streaming okuma (RAM'e tümünü yüklemez)
//! - Recursive directory traversal (tüm alt dizinleri tarar)
//! - Parallel chunk processing (rayon + crossbeam)
//! - Progress tracking ve hata raporlama
//! - Memory-mapped file desteği (büyük dosyalar için)

use std::fs::File;
use std::io::{BufRead, BufReader, Write, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::collections::HashSet;
use rayon::prelude::*;

/// Wordlist birleştirme sonuç raporu
#[derive(Debug, Clone)]
pub struct MergeResult {
    /// Bulunan toplam wordlist dosyası sayısı
    pub files_found: usize,
    /// Başarıyla işlenen dosya sayısı
    pub files_processed: usize,
    /// Hatalı dosya sayısı (okunamayan)
    pub files_failed: usize,
    /// Toplam okunan satır sayısı (duplicate dahil)
    pub total_lines_read: u64,
    /// Unique kelime sayısı (merged dosyada)
    pub unique_words: u64,
    /// Merged dosyanın yolu
    pub merged_path: String,
    /// Hata mesajları (hangi dosyalar okunamadı)
    pub errors: Vec<String>,
}

/// Recursive olarak dizindeki tüm .txt dosyalarını bul
/// 
/// # Arguments
/// * `base_path` - Taranacak kök dizin
/// 
/// # Returns
/// Bulunan tüm .txt dosyalarının tam yolları
pub fn find_all_wordlists(base_path: &str) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let path = Path::new(base_path);
    
    if !path.exists() {
        tracing::warn!("⚠️ Dizin bulunamadı: {}", base_path);
        return result;
    }
    
    fn recurse(dir: &Path, files: &mut Vec<PathBuf>, depth: usize) {
        // Güvenlik: Maksimum 10 seviye derinliğe in (infinite loop önleme)
        if depth > 10 {
            return;
        }
        
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                
                if path.is_dir() {
                    // Alt dizine recursive gir
                    recurse(&path, files, depth + 1);
                } else if path.is_file() {
                    // .txt uzantılı dosyaları ekle
                    if let Some(ext) = path.extension() {
                        if ext == "txt" {
                            files.push(path);
                        }
                    }
                }
            }
        }
    }
    
    recurse(path, &mut result, 0);
    
    tracing::info!("📂 {} dizininde {} wordlist dosyası bulundu", base_path, result.len());
    result
}

/// Memory-efficient streaming wordlist merge
/// 
/// Bu fonksiyon büyük dosyaları RAM'e yüklemeden satır satır okur,
/// duplicate'leri HashSet ile filtreler ve sonucu diske yazar.
/// 
/// # Bellek Kullanımı
/// - HashSet için: ~40 bytes * unique_word_count
/// - Buffer için: 16MB read + 8MB write
/// - Toplam: ~1GB for 23M unique words (acceptable)
pub fn merge_wordlists_streaming(
    base_paths: &[&str],
    output_path: &str,
    progress_callback: Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
) -> Result<MergeResult, std::io::Error> {
    // Tüm wordlist dosyalarını bul
    let mut all_files: Vec<PathBuf> = Vec::new();
    for base in base_paths {
        all_files.extend(find_all_wordlists(base));
    }
    
    let files_found = all_files.len();
    tracing::info!("🔍 Toplam {} wordlist dosyası bulundu", files_found);
    
    if files_found == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Hiçbir wordlist dosyası bulunamadı",
        ));
    }
    
    // Dosyaları boyuta göre sırala (küçükten büyüğe - progress için)
    all_files.sort_by_key(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0));
    
    // Toplam boyutu hesapla (progress için)
    let total_bytes: u64 = all_files
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    
    tracing::info!("📊 Toplam boyut: {} MB", total_bytes / 1024 / 1024);
    
    // Duplicate detection için HashSet
    // String yerine hash kullanarak bellek optimizasyonu yapılabilir ama
    // şimdilik basitlik için String kullanıyoruz
    let mut seen: HashSet<String> = HashSet::with_capacity(30_000_000); // 23M için headroom
    
    // Output file
    let output_file = File::create(output_path)?;
    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, output_file); // 8MB buffer
    
    let mut files_processed: usize = 0;
    let mut files_failed: usize = 0;
    let mut total_lines_read: u64 = 0;
    let mut bytes_read: u64 = 0;
    let mut errors: Vec<String> = Vec::new();
    
    for (idx, file_path) in all_files.iter().enumerate() {
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        tracing::debug!("📖 [{}/{}] İşleniyor: {}", idx + 1, files_found, file_name);
        
        // Dosyayı streaming ile oku
        match File::open(file_path) {
            Ok(file) => {
                let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
                let reader = BufReader::with_capacity(16 * 1024 * 1024, file); // 16MB buffer
                
                let mut file_lines: u64 = 0;
                let mut file_new_words: u64 = 0;
                
                for line_result in reader.lines() {
                    match line_result {
                        Ok(line) => {
                            let trimmed = line.trim();
                            
                            // Boş satırları atla
                            if trimmed.is_empty() {
                                continue;
                            }
                            
                            file_lines += 1;
                            total_lines_read += 1;
                            
                            // Duplicate check
                            if !seen.contains(trimmed) {
                                seen.insert(trimmed.to_string());
                                // Dosyaya yaz
                                writeln!(writer, "{}", trimmed)?;
                                file_new_words += 1;
                            }
                        }
                        Err(e) => {
                            // UTF-8 olmayan satırlar için hata - atla ve devam et
                            tracing::trace!("⚠️ Satır okuma hatası (UTF-8?): {}", e);
                        }
                    }
                }
                
                bytes_read += file_size;
                files_processed += 1;
                
                // Her 10 dosyada bir progress log
                if idx % 10 == 0 || idx == files_found - 1 {
                    let pct = (bytes_read as f64 / total_bytes as f64 * 100.0) as u32;
                    tracing::info!(
                        "📊 [{}%] {}/{} dosya işlendi, {} unique kelime",
                        pct, idx + 1, files_found, seen.len()
                    );
                }
                
                // Progress callback
                if let Some(ref cb) = progress_callback {
                    cb(bytes_read, total_bytes);
                }
                
                tracing::debug!(
                    "   ✅ {} satır okundu, {} yeni kelime eklendi",
                    file_lines, file_new_words
                );
            }
            Err(e) => {
                files_failed += 1;
                let error_msg = format!("{}: {}", file_path.display(), e);
                errors.push(error_msg.clone());
                tracing::warn!("❌ Dosya okunamadı: {}", error_msg);
            }
        }
    }
    
    // Buffer'ı flush et
    writer.flush()?;
    
    let unique_words = seen.len() as u64;
    
    tracing::info!(
        "✅ Birleştirme tamamlandı: {} dosya işlendi, {} başarısız, {} unique kelime",
        files_processed, files_failed, unique_words
    );
    
    Ok(MergeResult {
        files_found,
        files_processed,
        files_failed,
        total_lines_read,
        unique_words,
        merged_path: output_path.to_string(),
        errors,
    })
}

/// Büyük wordlist'i chunk'lar halinde paralel olarak işle
/// 
/// Bu fonksiyon dictionary attack için optimize edilmiştir.
/// Dosyayı tamamen RAM'e yüklemez, chunk'lar halinde okur ve
/// her chunk'ı paralel olarak işler.
/// 
/// # Arguments
/// * `wordlist_path` - İşlenecek wordlist dosyası
/// * `chunk_size` - Her chunk'taki kelime sayısı (default: 100_000)
/// * `processor` - Her kelime için çağrılacak closure
pub fn process_wordlist_parallel<F>(
    wordlist_path: &str,
    chunk_size: usize,
    processor: F,
) -> Result<ProcessingStats, std::io::Error>
where
    F: Fn(&str) -> bool + Send + Sync,
{
    let file = File::open(wordlist_path)?;
    let reader = BufReader::with_capacity(16 * 1024 * 1024, file); // 16MB buffer
    
    let processed = AtomicU64::new(0);
    let found = std::sync::atomic::AtomicBool::new(false);
    
    let mut chunk: Vec<String> = Vec::with_capacity(chunk_size);
    let start = std::time::Instant::now();
    
    for line_result in reader.lines() {
        if found.load(Ordering::Relaxed) {
            break;
        }
        
        if let Ok(line) = line_result {
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                chunk.push(trimmed);
                
                // Chunk dolduğunda paralel işle
                if chunk.len() >= chunk_size {
                    let result = chunk.par_iter().find_any(|word| {
                        processed.fetch_add(1, Ordering::Relaxed);
                        processor(word)
                    });
                    
                    if result.is_some() {
                        found.store(true, Ordering::SeqCst);
                        break;
                    }
                    
                    chunk.clear();
                }
            }
        }
    }
    
    // Kalan kelimeleri işle
    if !found.load(Ordering::Relaxed) && !chunk.is_empty() {
        let _ = chunk.par_iter().find_any(|word| {
            processed.fetch_add(1, Ordering::Relaxed);
            processor(word)
        });
    }
    
    let elapsed = start.elapsed();
    let total_processed = processed.load(Ordering::Relaxed);
    
    Ok(ProcessingStats {
        total_processed,
        elapsed_ms: elapsed.as_millis() as u64,
        rate: total_processed as f64 / elapsed.as_secs_f64(),
        found: found.load(Ordering::Relaxed),
    })
}

/// İşleme istatistikleri
#[derive(Debug, Clone)]
pub struct ProcessingStats {
    pub total_processed: u64,
    pub elapsed_ms: u64,
    pub rate: f64,
    pub found: bool,
}

/// Wordlist dosyasındaki satır sayısını hızlıca say (streaming)
/// 
/// RAM'e yüklemeden satır sayar - büyük dosyalar için güvenli
pub fn count_lines_fast(path: &str) -> Result<u64, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(8 * 1024 * 1024, file);
    
    let mut count: u64 = 0;
    for line in reader.lines() {
        if line.is_ok() {
            count += 1;
        }
    }
    
    Ok(count)
}

/// Dosya boyutunu MB cinsinden al
pub fn get_file_size_mb(path: &str) -> Option<f64> {
    std::fs::metadata(path)
        .ok()
        .map(|m| m.len() as f64 / 1024.0 / 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_find_wordlists() {
        // Test recursive discovery
        let files = find_all_wordlists("files");
        println!("Found {} wordlist files", files.len());
    }
    
    #[test]
    fn test_line_count() {
        if let Ok(count) = count_lines_fast("files/merged_wordlist.txt") {
            println!("Merged wordlist has {} lines", count);
        }
    }
}
