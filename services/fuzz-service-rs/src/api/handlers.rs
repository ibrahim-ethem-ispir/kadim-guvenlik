use std::sync::Arc;
use std::path::PathBuf;
use std::fs;
use axum::{
    extract::{Path, State},
    Json,
    response::sse::{Event, KeepAlive, Sse},
};
use chrono::Utc;
use futures::stream::Stream;
use tokio::sync::mpsc;
use tracing::{info, error};

use crate::error::Result;
use crate::models::{
    FeroxRequest, StartScanResponse, ScanStatus, ActiveScan,
    ScanResult, ScanEvent, WordlistInfo, WordlistsResponse,
};
use crate::services::FeroxScanner;
use crate::AppState;

/// Health check
pub async fn health(State(_state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let version = FeroxScanner::version().await.unwrap_or_else(|_| "unknown".into());
    
    Json(serde_json::json!({
        "status": "healthy",
        "service": "fuzz-service-rs",
        "engine": "feroxbuster",
        "version": version,
        "mongodb": "connected"
    }))
}

/// Start a new scan
pub async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FeroxRequest>,
) -> Result<Json<StartScanResponse>> {
    let scan_id = request.scan_id.clone();
    let scan_id_response = scan_id.clone(); // For response after async block
    let target = request.target.clone();

    info!(scan_id = %scan_id, target = %target, "Starting scan");

    // Create active scan record
    let active_scan = ActiveScan {
        id: None,
        scan_id: scan_id.clone(),
        target: target.clone(),
        status: ScanStatus::Running,
        started_at: Utc::now(),
        completed_at: None,
        error: None,
        findings_count: 0,
    };

    state.db.upsert_scan(&active_scan).await?;

    // Spawn background scan task
    let db = state.db.clone();
    let scanner = state.scanner.clone();
    let scan_request = request.clone();

    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::channel::<ScanResult>(100);

        // Spawn result saver task
        let db_saver = db.clone();
        let saver_scan_id = scan_id.clone();
        let saver_handle = tokio::spawn(async move {
            let mut count = 0u32;
            while let Some(result) = rx.recv().await {
                if let Err(e) = db_saver.save_result(&result).await {
                    error!("Failed to save result: {}", e);
                }
                count += 1;
                
                // Update count periodically
                if count % 10 == 0 {
                    let _ = db_saver.update_scan_status(
                        &saver_scan_id,
                        ScanStatus::Running,
                        count,
                        None,
                    ).await;
                }
            }
            count
        });

        // Run the scan
        let scan_result = scanner.scan(scan_request, tx).await;

        // Get final count
        let final_count = saver_handle.await.unwrap_or(0);

        // Update final status
        match scan_result {
            Ok(()) => {
                let _ = db.update_scan_status(
                    &scan_id,
                    ScanStatus::Completed,
                    final_count,
                    None,
                ).await;
                info!(scan_id = %scan_id, findings = final_count, "Scan completed");
            }
            Err(e) => {
                let _ = db.update_scan_status(
                    &scan_id,
                    ScanStatus::Failed,
                    final_count,
                    Some(e.to_string()),
                ).await;
                error!(scan_id = %scan_id, error = %e, "Scan failed");
            }
        }
    });

    Ok(Json(StartScanResponse {
        status: "started".into(),
        scan_id: scan_id_response,
        message: format!("Scan started for {}", target),
    }))
}

/// Get scan results
pub async fn get_results(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> Result<Json<Vec<ScanResult>>> {
    let results = state.db.get_results(&scan_id).await?;
    Ok(Json(results))
}

/// Get scan status
pub async fn get_scan_status(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> Result<Json<Option<ActiveScan>>> {
    let scan = state.db.get_scan(&scan_id).await?;
    Ok(Json(scan))
}

/// SSE stream for real-time scan updates
pub async fn stream_scan(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> Sse<impl Stream<Item = std::result::Result<Event, std::convert::Infallible>>> {
    let db = state.db.clone();
    let scan_id_clone = scan_id.clone();

    let stream = async_stream::stream! {
        let mut last_count = 0u64;
        
        loop {
            // Get current scan status
            let scan = match db.get_scan(&scan_id_clone).await {
                Ok(Some(s)) => s,
                Ok(None) => {
                    yield Ok(Event::default()
                        .event("error")
                        .json_data(ScanEvent::Error { 
                            message: "Scan not found".into() 
                        })
                        .unwrap());
                    break;
                }
                Err(e) => {
                    yield Ok(Event::default()
                        .event("error")  
                        .json_data(ScanEvent::Error { 
                            message: e.to_string() 
                        })
                        .unwrap());
                    break;
                }
            };

            // Get new results since last check
            let current_count = db.count_results(&scan_id_clone).await.unwrap_or(0);
            
            if current_count > last_count {
                // Send progress update
                yield Ok(Event::default()
                    .event("progress")
                    .json_data(ScanEvent::Progress {
                        scan_id: scan_id_clone.clone(),
                        status: scan.status.clone(),
                        findings_count: current_count as u32,
                    })
                    .unwrap());
                    
                last_count = current_count;
            }

            // Check if scan is complete
            if matches!(scan.status, ScanStatus::Completed | ScanStatus::Failed) {
                yield Ok(Event::default()
                    .event("complete")
                    .json_data(ScanEvent::Complete {
                        scan_id: scan_id_clone.clone(),
                        status: scan.status,
                        findings_count: scan.findings_count,
                    })
                    .unwrap());
                break;
            }

            // Send heartbeat
            yield Ok(Event::default()
                .event("heartbeat")
                .json_data(ScanEvent::Heartbeat)
                .unwrap());

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// List available wordlists
pub async fn list_wordlists(
    State(state): State<Arc<AppState>>,
) -> Result<Json<WordlistsResponse>> {
    let base_path = PathBuf::from(&state.config.wordlist_path);
    let web_content_path = base_path.join("SecLists-master/Discovery/Web-Content");

    let mut wordlists = Vec::new();

    // Predefined metadata for common wordlists
    let metadata: std::collections::HashMap<&str, (&str, &str, &str, bool)> = [
        ("common.txt", ("Common", "En yaygın dizin ve dosyalar (~4,600 satır)", "general", true)),
        ("directory-list-2.3-small.txt", ("Directory Small", "DirBuster küçük liste (~87k satır)", "directories", false)),
        ("directory-list-2.3-medium.txt", ("Directory Medium", "DirBuster orta liste (~220k satır)", "directories", false)),
        ("big.txt", ("Big", "Büyük genel amaçlı liste (~20k satır)", "general", false)),
        ("quickhits.txt", ("QuickHits", "Hassas dosya ve dizinler için hızlı liste", "general", true)),
        ("raft-large-directories.txt", ("RAFT Large", "RAFT büyük dizin listesi", "directories", false)),
        ("raft-medium-directories.txt", ("RAFT Medium", "RAFT orta dizin listesi", "directories", false)),
    ].iter().cloned().collect();

    if web_content_path.exists() {
        if let Ok(entries) = fs::read_dir(&web_content_path) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "txt" {
                        if let Some(filename) = path.file_name().and_then(|s| s.to_str()) {
                            let size_bytes = fs::metadata(&path)
                                .map(|m| m.len())
                                .unwrap_or(0);
                            
                            let line_count = if size_bytes < 1_000_000 {
                                fs::read_to_string(&path)
                                    .map(|s| s.lines().count() as u64)
                                    .unwrap_or(0)
                            } else {
                                size_bytes / 20 // Estimate
                            };

                            let (name, description, category, recommended) = metadata
                                .get(filename)
                                .cloned()
                                .unwrap_or((filename, "Wordlist dosyası", "custom", false));

                            let size_label = if line_count < 10_000 {
                                "small"
                            } else if line_count < 100_000 {
                                "medium"
                            } else {
                                "large"
                            };

                            wordlists.push(WordlistInfo {
                                filename: filename.to_string(),
                                path: path.to_string_lossy().to_string(),
                                name: name.to_string(),
                                description: description.to_string(),
                                category: category.to_string(),
                                size_label: size_label.to_string(),
                                size_bytes,
                                line_count,
                                recommended,
                                tooltip: None,
                            });
                        }
                    }
                }
            }
        }
    }

    // Sort: recommended first, then by line count
    wordlists.sort_by(|a, b| {
        match (a.recommended, b.recommended) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.line_count.cmp(&b.line_count),
        }
    });

    let total = wordlists.len();
    Ok(Json(WordlistsResponse { wordlists, total }))
}
