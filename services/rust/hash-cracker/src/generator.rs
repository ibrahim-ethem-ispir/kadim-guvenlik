//! Wordlist Generator Module
//! 
//! Handles custom wordlist generation based on patterns and rules.

use std::io::Write;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct GenerationRequest {
    pub name: String,
    pub base_word: Option<String>,
    pub pattern: Option<String>, // e.g., "?d?d" for 2 digits
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub charset: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenerationResult {
    pub path: String,
    pub count: u64,
    pub size_bytes: u64,
}

/// Generate a custom wordlist
pub async fn generate_wordlist(req: GenerationRequest) -> Result<GenerationResult, String> {
    let base_path = if std::path::Path::new("/app/files").exists() {
        "/app/files"
    } else {
        "files"
    };
    
    // Ensure directory exists
    let _ = std::fs::create_dir_all(format!("{}/generated", base_path));
    
    let filename = format!("{}/generated/{}.txt", base_path, sanitize_filename(&req.name));
    let path = std::path::Path::new(&filename);
    
    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let mut writer = std::io::BufWriter::new(file);
    
    let mut count = 0u64;
    
    // 1. Pattern based generation (if pattern provided)
    if let Some(pattern) = &req.pattern {
        let base = req.base_word.clone().unwrap_or_default();
        count += generate_pattern(&mut writer, &base, pattern)?;
    } 
    // 2. Pure combinatorial based on lengths (if no pattern but lengths given)
    else if let (Some(min), Some(max)) = (req.min_length, req.max_length) {
        let charset = req.charset.clone().unwrap_or_else(|| "abcdefghijklmnopqrstuvwxyz0123456789".to_string());
        count += generate_bruteforce(&mut writer, &charset, min, max, &req.base_word)?;
    }
    // 3. Just base word (fallback)
    else if let Some(base) = &req.base_word {
        writeln!(writer, "{}", base).map_err(|e| e.to_string())?;
        count += 1;
    }
    
    writer.flush().map_err(|e| e.to_string())?;
    
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    
    Ok(GenerationResult {
        path: filename,
        count,
        size_bytes: metadata.len(),
    })
}

fn sanitize_filename(name: &str) -> String {
    name.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_")
}

fn generate_pattern(writer: &mut std::io::BufWriter<std::fs::File>, base: &str, pattern: &str) -> Result<u64, String> {
    // Simple pattern parser:
    // ?d = digits (0-9)
    // ?l = lowercase (a-z)
    // ?u = uppercase (A-Z)
    // ?s = symbols
    
    // Convert pattern to charset list
    let mut parts: Vec<Vec<char>> = Vec::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    
    while i < chars.len() {
        if chars[i] == '?' && i + 1 < chars.len() {
            match chars[i+1] {
                'd' => parts.push(('0'..='9').collect()),
                'l' => parts.push(('a'..='z').collect()),
                'u' => parts.push(('A'..='Z').collect()),
                's' => parts.push("!@#$%^&*()-_+=[]{}|;:,.<>?".chars().collect()),
                'a' => parts.push("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=[]{}|;:,.<>?".chars().collect()),
                c => parts.push(vec![c]), // Literal ?x -> x (if unknown)
            }
            i += 2;
        } else {
            parts.push(vec![chars[i]]);
            i += 1;
        }
    }
    
    let mut count = 0;
    
    // Recursive generator
    if parts.is_empty() {
        writeln!(writer, "{}", base).map_err(|e| e.to_string())?;
        return Ok(1);
    }
    
    let mut current = vec![0; parts.len()]; // Indices for each part
    
    loop {
        // Build string
        let mut suffix = String::new();
        for (part_idx, charset_idx) in current.iter().enumerate() {
            suffix.push(parts[part_idx][*charset_idx]);
        }
        
        writeln!(writer, "{}{}", base, suffix).map_err(|e| e.to_string())?;
        count += 1;
        
        // Increment indices
        let mut next = false;
        for i in (0..parts.len()).rev() {
            if current[i] + 1 < parts[i].len() {
                current[i] += 1;
                next = true;
                // Reset following
                for j in (i+1)..parts.len() {
                    current[j] = 0;
                }
                break;
            }
        }
        
        if !next {
            break;
        }
        
        // Safety break for disk/time
        if count > 10_000_000 {
            return Err("Generated list exceeds 10 million entries".to_string());
        }
    }
    
    Ok(count)
}

fn generate_bruteforce(
    writer: &mut std::io::BufWriter<std::fs::File>, 
    charset: &str, 
    min: usize, 
    max: usize, 
    base: &Option<String>
) -> Result<u64, String> {
    let chars: Vec<char> = charset.chars().collect();
    let char_len = chars.len();
    let mut count = 0;
    
    let base_str = base.clone().unwrap_or_default();
    
    for len in min..=max {
        let total_combos = (char_len as u128).pow(len as u32);
        if total_combos > 5_000_000 {
             return Err(format!("Combinations too large for file generation: {}", total_combos));
        }
        
        // Iterative generation for this length
        let mut indices = vec![0; len];
        
        loop {
            let mut word = String::with_capacity(base_str.len() + len);
            word.push_str(&base_str);
            for &idx in &indices {
                word.push(chars[idx]);
            }
            
            writeln!(writer, "{}", word).map_err(|e| e.to_string())?;
            count += 1;
            
            // Increment
            let mut carry = true;
            for i in (0..len).rev() {
                if indices[i] + 1 < char_len {
                    indices[i] += 1;
                    carry = false;
                    break;
                } else {
                    indices[i] = 0;
                }
            }
            
            if carry {
                break;
            }
        }
    }
    
    Ok(count)
}
