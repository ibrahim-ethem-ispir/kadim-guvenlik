use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use bson::oid::ObjectId;

/// Single scan finding (parsed from feroxbuster JSON output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// MongoDB ObjectId
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// Scan identifier
    pub scan_id: String,
    /// Found URL
    pub url: String,
    /// Original requested path
    pub original_url: String,
    /// HTTP status code
    pub status: u16,
    /// HTTP method used
    pub method: String,
    /// Response content length
    pub content_length: i64,
    /// Word count in response
    pub word_count: i64,
    /// Line count in response
    pub line_count: i64,
    /// Response Content-Type
    #[serde(default)]
    pub content_type: String,
    /// When this result was found
    #[serde(default = "Utc::now")]
    pub timestamp: DateTime<Utc>,
}

/// Feroxbuster JSON output format
#[derive(Debug, Deserialize)]
pub struct FeroxbusterOutput {
    #[serde(rename = "type")]
    pub output_type: String,
    pub url: String,
    pub original_url: String,
    pub status: u16,
    pub method: String,
    pub content_length: i64,
    pub word_count: i64,
    pub line_count: i64,
    #[serde(default)]
    pub content_type: String,
}

impl FeroxbusterOutput {
    pub fn to_scan_result(self, scan_id: &str) -> ScanResult {
        ScanResult {
            id: None,
            scan_id: scan_id.to_string(),
            url: self.url,
            original_url: self.original_url,
            status: self.status,
            method: self.method,
            content_length: self.content_length,
            word_count: self.word_count,
            line_count: self.line_count,
            content_type: self.content_type,
            timestamp: Utc::now(),
        }
    }
}

/// Scan status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Active scan record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveScan {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub scan_id: String,
    pub target: String,
    pub status: ScanStatus,
    // KRİTİK: MongoDB'ye BSON DateTime olarak yazılır; okurken chrono'nun VARSAYILAN serde'si
    // RFC 3339 STRING beklediğinden BSON DateTime (map) gelince "invalid type: map, expected
    // an RFC 3339 formatted date and time string" ile /status endpoint'i HTTP 500 patlıyordu
    // → orchestrator fuzz'ı hiç "completed" göremeyip her taramayı timeout'a düşürüyordu. Bu
    // helper alanı BSON DateTime olarak (de)serialize eder — tip uyuşmazlığı biter.
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime_optional")]
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub findings_count: u32,
}

/// SSE event for real-time updates
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ScanEvent {
    /// New finding discovered
    Finding { data: ScanResult },
    /// Progress update
    Progress {
        scan_id: String,
        status: ScanStatus,
        findings_count: u32,
    },
    /// Scan completed
    Complete {
        scan_id: String,
        status: ScanStatus,
        findings_count: u32,
    },
    /// Error occurred
    Error { message: String },
    /// Heartbeat to keep connection alive
    Heartbeat,
}

/// Wordlist metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct WordlistInfo {
    pub filename: String,
    pub path: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub size_label: String,
    pub size_bytes: u64,
    pub line_count: u64,
    pub recommended: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tooltip: Option<String>,
}

/// Wordlist list response
#[derive(Debug, Serialize)]
pub struct WordlistsResponse {
    pub wordlists: Vec<WordlistInfo>,
    pub total: usize,
}
