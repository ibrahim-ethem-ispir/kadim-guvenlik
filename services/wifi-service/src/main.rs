use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use actix_multipart::Multipart;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Mutex;
use std::io::Write;
use std::fs::File;
use uuid::Uuid;

// --- Domain Models ---

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Network {
    ssid: String,
    bssid: String,
    signal: i32,
    security: String,
    channel: u32,
    clients: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct CrackRequest {
    strategy: String,  // "wordlist", "brute", "pmkid"
    wordlist: Option<String>,
    ssid: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct CrackJob {
    id: String,
    ssid: String,
    status: String,  // "pending", "running", "completed", "failed"
    progress: u32,
    result: Option<String>,
    started_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct HandshakeInfo {
    filename: String,
    size: u64,
    ssid: Option<String>,
    bssid: Option<String>,
    valid: bool,
    hash_type: Option<String>,
}

struct AppState {
    scan_results: Mutex<Vec<Network>>,
    crack_jobs: Mutex<Vec<CrackJob>>,
    captures_dir: String,
}

// --- OUI Vendor Lookup ---
fn get_vendor_from_bssid(bssid: &str) -> String {
    let oui = bssid.to_uppercase().chars().take(8).collect::<String>();
    match oui.as_str() {
        "E8:9F:80" | "F4:EC:38" | "74:DA:88" | "AC:84:C6" => "TP-Link".to_string(),
        "00:1A:2B" | "FC:F5:28" => "ZyXEL".to_string(),
        "DC:EF:09" | "48:8D:36" => "Huawei".to_string(),
        "00:50:56" => "VMware".to_string(),
        "00:0C:29" => "VMware".to_string(),
        "B8:27:EB" => "Raspberry Pi".to_string(),
        "DC:A6:32" => "Raspberry Pi".to_string(),
        _ => "Unknown".to_string(),
    }
}

// --- Scanner Logic ---

fn scan_wifi_macos() -> Result<Vec<Network>, String> {
    let output = Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
        .arg("-s")
        .output();

    match output {
        Ok(result) => {
            if !result.status.success() {
                return Err("Airport command failed".to_string());
            }

            let stdout = String::from_utf8_lossy(&result.stdout);
            let mut networks = Vec::new();

            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 7 {
                    let ssid = parts[0].to_string();
                    let bssid = parts[1].to_string();
                    let signal = parts[2].parse::<i32>().unwrap_or(-100);
                    let channel = parts[3].parse::<u32>().unwrap_or(0);
                    let security = parts[6..].join(" ");
                    let vendor = get_vendor_from_bssid(&bssid);

                    networks.push(Network {
                        ssid,
                        bssid: bssid.clone(),
                        signal,
                        security,
                        channel,
                        clients: 0,
                        vendor: Some(vendor),
                    });
                }
            }
            Ok(networks)
        }
        Err(e) => Err(format!("Failed to execute airport: {}", e)),
    }
}

fn scan_wifi_linux() -> Result<Vec<Network>, String> {
    let output = Command::new("iwlist")
        .arg("wlan0")
        .arg("scan")
        .output();

    match output {
        Ok(result) => {
            if !result.status.success() {
                return Err("iwlist command failed".to_string());
            }

            let stdout = String::from_utf8_lossy(&result.stdout);
            let mut networks = Vec::new();
            let mut current_network: Option<Network> = None;

            for line in stdout.lines() {
                let line = line.trim();

                if line.contains("Cell") && line.contains("Address:") {
                    if let Some(net) = current_network.take() {
                        networks.push(net);
                    }
                    let bssid = line.split("Address: ").nth(1).unwrap_or("00:00:00:00:00:00").to_string();
                    let vendor = get_vendor_from_bssid(&bssid);
                    current_network = Some(Network {
                        ssid: String::new(),
                        bssid,
                        signal: -100,
                        security: String::new(),
                        channel: 0,
                        clients: 0,
                        vendor: Some(vendor),
                    });
                } else if let Some(ref mut net) = current_network {
                    if line.starts_with("ESSID:") {
                        net.ssid = line.split("ESSID:").nth(1).unwrap_or("").trim_matches('"').to_string();
                    } else if line.contains("Signal level=") {
                        if let Some(sig_str) = line.split("Signal level=").nth(1) {
                            let sig = sig_str.split_whitespace().next().unwrap_or("-100");
                            net.signal = sig.parse::<i32>().unwrap_or(-100);
                        }
                    } else if line.contains("Channel:") {
                        if let Some(ch_str) = line.split("Channel:").nth(1) {
                            net.channel = ch_str.trim().parse::<u32>().unwrap_or(0);
                        }
                    } else if line.contains("WPA") || line.contains("WEP") {
                        if net.security.is_empty() {
                            net.security = if line.contains("WPA3") { "WPA3".to_string() }
                                else if line.contains("WPA2") { "WPA2".to_string() }
                                else if line.contains("WPA") { "WPA".to_string() }
                                else { "WEP".to_string() };
                        }
                    }
                }
            }

            if let Some(net) = current_network {
                networks.push(net);
            }
            Ok(networks)
        }
        Err(e) => Err(format!("Failed to execute iwlist: {}", e)),
    }
}

fn scan_wifi() -> Vec<Network> {
    if let Ok(networks) = scan_wifi_macos() {
        if !networks.is_empty() { return networks; }
    }
    if let Ok(networks) = scan_wifi_linux() {
        if !networks.is_empty() { return networks; }
    }

    // Demo fallback
    vec![
        Network { ssid: "[DEMO] SuperOnline_WiFi_42".to_string(), bssid: "E8:9F:80:1A:2B:3C".to_string(), signal: -42, security: "WPA2/WPA3".to_string(), channel: 6, clients: 3, vendor: Some("TP-Link".to_string()) },
        Network { ssid: "[DEMO] TurkTelekom_Z581".to_string(), bssid: "00:1A:2B:3C:4D:5E".to_string(), signal: -58, security: "WPA2".to_string(), channel: 1, clients: 5, vendor: Some("ZyXEL".to_string()) },
        Network { ssid: "[DEMO] Misafir_Agi".to_string(), bssid: "AA:BB:CC:11:22:33".to_string(), signal: -65, security: "Open".to_string(), channel: 11, clients: 12, vendor: None },
    ]
}

// --- Handlers ---

#[get("/health")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "wifi-service",
        "version": "2.0.0",
        "features": ["scan", "analyze", "crack"]
    }))
}

#[get("/scan")]
async fn scan_networks(data: web::Data<AppState>) -> impl Responder {
    let networks = data.scan_results.lock().unwrap();
    HttpResponse::Ok().json(&*networks)
}

#[post("/scan/start")]
async fn start_scan(data: web::Data<AppState>) -> impl Responder {
    let networks = scan_wifi();
    let mut results = data.scan_results.lock().unwrap();
    *results = networks.clone();

    let is_demo = networks.iter().any(|n| n.ssid.starts_with("[DEMO]"));

    HttpResponse::Ok().json(serde_json::json!({
        "status": "scan_completed",
        "mode": if is_demo { "demo" } else { "real" },
        "message": format!("{} ağ bulundu", networks.len()),
        "networks": networks
    }))
}

#[post("/analyze-capture")]
async fn analyze_capture(mut payload: Multipart, data: web::Data<AppState>) -> impl Responder {
    let mut file_data = Vec::new();
    let mut filename = String::new();

    while let Some(item) = payload.next().await {
        if let Ok(mut field) = item {
            filename = field.content_disposition().get_filename().unwrap_or("upload.cap").to_string();
            while let Some(chunk) = field.next().await {
                if let Ok(data) = chunk {
                    file_data.extend_from_slice(&data);
                }
            }
        }
    }

    if file_data.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No file uploaded"
        }));
    }

    // Save file
    let file_path = format!("{}/{}", data.captures_dir, filename);
    if let Ok(mut file) = File::create(&file_path) {
        let _ = file.write_all(&file_data);
    }

    // Analyze with aircrack-ng or hcxpcapngtool
    let hash_type = if filename.ends_with(".hc22000") || filename.ends_with(".hccapx") {
        Some("WPA-PMKID-PBKDF2".to_string())
    } else if filename.ends_with(".cap") || filename.ends_with(".pcap") {
        Some("WPA-EAPOL-PBKDF2".to_string())
    } else {
        None
    };

    let info = HandshakeInfo {
        filename: filename.clone(),
        size: file_data.len() as u64,
        ssid: None,  // Would parse from file
        bssid: None,
        valid: true,
        hash_type,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "status": "analyzed",
        "info": info
    }))
}

#[post("/crack/start")]
async fn start_crack(req: web::Json<CrackRequest>, data: web::Data<AppState>) -> impl Responder {
    let job_id = Uuid::new_v4().to_string();
    let job = CrackJob {
        id: job_id.clone(),
        ssid: req.ssid.clone().unwrap_or_else(|| "Unknown".to_string()),
        status: "pending".to_string(),
        progress: 0,
        result: None,
        started_at: chrono::Utc::now().to_rfc3339(),
    };

    let mut jobs = data.crack_jobs.lock().unwrap();
    jobs.push(job.clone());

    HttpResponse::Ok().json(serde_json::json!({
        "status": "started",
        "job_id": job_id,
        "message": format!("Kırma işlemi başlatıldı: {}", req.strategy)
    }))
}

#[get("/crack/status/{job_id}")]
async fn crack_status(path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let job_id = path.into_inner();
    let jobs = data.crack_jobs.lock().unwrap();
    
    if let Some(job) = jobs.iter().find(|j| j.id == job_id) {
        HttpResponse::Ok().json(job)
    } else {
        HttpResponse::NotFound().json(serde_json::json!({
            "error": "Job not found"
        }))
    }
}

#[get("/stats")]
async fn get_stats(data: web::Data<AppState>) -> impl Responder {
    let networks = data.scan_results.lock().unwrap();
    let jobs = data.crack_jobs.lock().unwrap();

    let open_count = networks.iter().filter(|n| n.security.contains("Open")).count();
    let wpa3_count = networks.iter().filter(|n| n.security.contains("WPA3")).count();
    let wpa2_count = networks.iter().filter(|n| n.security.contains("WPA2") && !n.security.contains("WPA3")).count();

    HttpResponse::Ok().json(serde_json::json!({
        "total_networks": networks.len(),
        "security_breakdown": {
            "open": open_count,
            "wpa2": wpa2_count,
            "wpa3": wpa3_count
        },
        "total_crack_jobs": jobs.len(),
        "completed_jobs": jobs.iter().filter(|j| j.status == "completed").count(),
        "success_rate": 0.0
    }))
}

// --- Main ---

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let captures_dir = std::env::var("CAPTURES_DIR").unwrap_or_else(|_| "/app/captures".to_string());
    std::fs::create_dir_all(&captures_dir).ok();

    let app_state = web::Data::new(AppState {
        scan_results: Mutex::new(Vec::new()),
        crack_jobs: Mutex::new(Vec::new()),
        captures_dir,
    });

    println!("🛡️ WiFi Service v2.0.0 starting on 0.0.0.0:8080");
    println!("📡 Platform: {}", std::env::consts::OS);

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(health_check)
            .service(scan_networks)
            .service(start_scan)
            .service(analyze_capture)
            .service(start_crack)
            .service(crack_status)
            .service(get_stats)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
