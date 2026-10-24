use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};

use crate::error::{AppError, Result};
use crate::models::{FeroxRequest, FeroxbusterOutput, ScanResult, ScanPreset};

/// Feroxbuster CLI wrapper
pub struct FeroxScanner {
    wordlist_base_path: String,
}

impl FeroxScanner {
    pub fn new(wordlist_base_path: String) -> Self {
        Self { wordlist_base_path }
    }

    /// Find wordlist file path
    fn find_wordlist(&self, filename: &str) -> Result<PathBuf> {
        // Sanitize filename to prevent traversal
        let filename = PathBuf::from(filename)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("common.txt")
            .to_string();

        // Try direct path first
        let direct = PathBuf::from(&self.wordlist_base_path).join(&filename);
        if direct.exists() {
            return Ok(direct);
        }

        // Try SecLists Discovery/Web-Content
        let seclists = PathBuf::from(&self.wordlist_base_path)
            .join("SecLists-master/Discovery/Web-Content")
            .join(&filename);
        if seclists.exists() {
            return Ok(seclists);
        }

        // Fallback to common.txt
        let fallback = PathBuf::from(&self.wordlist_base_path)
            .join("SecLists-master/Discovery/Web-Content/common.txt");
        if fallback.exists() {
            warn!("Wordlist {} not found, using common.txt", filename);
            return Ok(fallback);
        }

        Err(AppError::NotFound(format!("Wordlist not found: {}", filename)))
    }

    /// Build feroxbuster command arguments
    fn build_args(&self, request: &FeroxRequest, wordlist_path: &PathBuf) -> Vec<String> {
        let mut args = vec![
            "-u".into(), request.target.clone(),
            "-w".into(), wordlist_path.to_string_lossy().to_string(),
            "--json".into(),   // Output JSON for parsing
            "--silent".into(), // Required when using --json without --output
        ];

        // Apply preset first
        if let Some(preset) = &request.preset {
            args.extend(preset.to_args());
        } else {
            // Default to Normal preset
            args.extend(ScanPreset::Normal.to_args());
        }

        // Then apply custom config (overrides preset)
        args.extend(request.config.to_args());

        args
    }

    /// Run feroxbuster scan with result streaming
    pub async fn scan(
        &self,
        request: FeroxRequest,
        result_tx: mpsc::Sender<ScanResult>,
    ) -> Result<()> {
        let wordlist_path = self.find_wordlist(&request.wordlist)?;
        let args = self.build_args(&request, &wordlist_path);
        let scan_id = request.scan_id.clone();

        info!(
            scan_id = %scan_id,
            target = %request.target,
            wordlist = %wordlist_path.display(),
            "Starting feroxbuster scan"
        );
        debug!("Feroxbuster args: {:?}", args);

        let mut child = Command::new("feroxbuster")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| AppError::Feroxbuster(format!("Failed to spawn feroxbuster: {}", e)))?;

        let stdout = child.stdout.take()
            .ok_or_else(|| AppError::Feroxbuster("Failed to capture stdout".into()))?;

        let stderr = child.stderr.take()
            .ok_or_else(|| AppError::Feroxbuster("Failed to capture stderr".into()))?;

        // Spawn stderr logger
        let stderr_handle = tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.trim().is_empty() {
                    debug!("feroxbuster stderr: {}", line);
                }
            }
        });

        // Process stdout (JSON output)
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut findings_count = 0u32;

        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Try to parse as JSON
            match serde_json::from_str::<FeroxbusterOutput>(line) {
                Ok(output) => {
                    // Only process "response" type entries (actual findings)
                    if output.output_type == "response" {
                        let result = output.to_scan_result(&scan_id);
                        findings_count += 1;
                        
                        debug!(
                            url = %result.url,
                            status = result.status,
                            "Found: {}", result.url
                        );

                        if result_tx.send(result).await.is_err() {
                            warn!("Result channel closed, stopping scan");
                            break;
                        }
                    }
                }
                Err(e) => {
                    // Not all lines are JSON (status messages, etc)
                    debug!("Non-JSON line: {} ({})", line, e);
                }
            }
        }

        // Wait for process completion
        let status = child.wait().await
            .map_err(|e| AppError::Feroxbuster(format!("Failed to wait for feroxbuster: {}", e)))?;

        // Wait for stderr handler
        let _ = stderr_handle.await;

        if status.success() {
            info!(
                scan_id = %scan_id,
                findings_count = findings_count,
                "Scan completed successfully"
            );
            Ok(())
        } else {
            let code = status.code().unwrap_or(-1);
            error!(scan_id = %scan_id, exit_code = code, "Feroxbuster exited with error");
            Err(AppError::Feroxbuster(format!("Feroxbuster exited with code: {}", code)))
        }
    }

    /// Get feroxbuster version
    pub async fn version() -> Result<String> {
        let output = Command::new("feroxbuster")
            .arg("-V")
            .output()
            .await
            .map_err(|e| AppError::Feroxbuster(format!("Failed to get version: {}", e)))?;

        String::from_utf8(output.stdout)
            .map(|s| s.trim().to_string())
            .map_err(|e| AppError::Internal(format!("Invalid version output: {}", e)))
    }
}
