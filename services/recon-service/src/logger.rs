use chrono::Local;
use colored::*;
use std::fs::{OpenOptions, File};
use std::io::Write;
use std::sync::Mutex;
use once_cell::sync::Lazy;


// Global log file lock to prevent interleaving
static CURRENT_LOG_FILE: Lazy<Mutex<Option<File>>> = Lazy::new(|| Mutex::new(None));

/// Initialize a new log file for a scan with timestamp and domain
pub fn init_scan_log(domain: &str) {
    std::fs::create_dir_all("log").ok();
    
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let filename = format!("log/{}_{}.log", timestamp, domain.replace(".", "_"));
    
    match OpenOptions::new()
        .append(true)
        .create(true)
        .open(&filename)
    {
        Ok(file) => {
            // Lock scope'u daraltıyoruz - deadlock önlemek için
            // log_info çağrılmadan ÖNCE lock'u bırakmalıyız
            {
                let mut log_file = CURRENT_LOG_FILE.lock().unwrap();
                *log_file = Some(file);
            } // lock burada bırakılıyor
            
            // Şimdi güvenle log_info çağırabiliriz
            log_info(&format!("=== CF Analyzer Log Started: {} ===", domain));
            log_info(&format!("Timestamp: {}", Local::now().format("%Y-%m-%d %H:%M:%S")));
        }
        Err(e) => {
            eprintln!("Failed to create log file {}: {}", filename, e);
        }
    }
}

pub fn log_info(message: &str) {
    log("INFO", message, Color::Green);
}

pub fn log_warn(message: &str) {
    log("WARN", message, Color::Yellow);
}

pub fn log_error(message: &str) {
    log("ERROR", message, Color::Red);
}

pub fn log_verbose(message: &str) {
    log("VERBOSE", message, Color::Cyan);
}

fn log(level: &str, message: &str, color: Color) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let console_msg = format!("[{}] [{}] {}", now, level, message);
    
    println!("{}", console_msg.color(color));

    if let Ok(mut log_file_opt) = CURRENT_LOG_FILE.lock() {
        if let Some(ref mut file) = *log_file_opt {
            writeln!(file, "{}", console_msg).ok();
            // Dosyaya hemen yaz (flush) - logların kaybolmaması için kritik
            file.flush().ok();
        }
    }
}
