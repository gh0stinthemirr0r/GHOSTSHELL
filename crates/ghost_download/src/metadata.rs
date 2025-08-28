use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Download metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadMeta {
    pub id: String,
    pub url: String,
    pub vault_path: String,
    pub original_filename: String,
    pub sealed_filename: String,
    pub hash: String,
    pub signature: String,
    pub size: u64,
    pub downloaded_at: DateTime<Utc>,
    pub tab_id: Option<String>,
}

impl DownloadMeta {
    /// Create new download metadata
    pub fn new(
        id: String,
        url: String,
        vault_path: String,
        original_filename: String,
        sealed_filename: String,
        hash: String,
        signature: String,
        size: u64,
        tab_id: Option<String>,
    ) -> Self {
        Self {
            id,
            url,
            vault_path,
            original_filename,
            sealed_filename,
            hash,
            signature,
            size,
            downloaded_at: Utc::now(),
            tab_id,
        }
    }

    /// Get display name
    pub fn display_name(&self) -> &str {
        &self.original_filename
    }

    /// Get file extension
    pub fn extension(&self) -> Option<&str> {
        std::path::Path::new(&self.original_filename)
            .extension()
            .and_then(|ext| ext.to_str())
    }

    /// Format file size for display
    pub fn format_size(&self) -> String {
        format_bytes(self.size)
    }
}

/// Download status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadStatus {
    Pending,
    Downloading,
    Sealing,
    Completed,
    Failed(String),
    Cancelled,
}

impl DownloadStatus {
    /// Check if download is active
    pub fn is_active(&self) -> bool {
        matches!(self, DownloadStatus::Downloading | DownloadStatus::Sealing)
    }

    /// Check if download is complete
    pub fn is_complete(&self) -> bool {
        matches!(self, DownloadStatus::Completed)
    }

    /// Check if download failed
    pub fn is_failed(&self) -> bool {
        matches!(self, DownloadStatus::Failed(_))
    }
}

/// Active download tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveDownload {
    pub meta: DownloadMeta,
    pub status: DownloadStatus,
    pub progress: f64, // 0.0 to 1.0
    pub bytes_downloaded: u64,
    pub started_at: DateTime<Utc>,
    pub estimated_completion: Option<DateTime<Utc>>,
}

impl ActiveDownload {
    /// Create new active download
    pub fn new(meta: DownloadMeta) -> Self {
        Self {
            meta,
            status: DownloadStatus::Pending,
            progress: 0.0,
            bytes_downloaded: 0,
            started_at: Utc::now(),
            estimated_completion: None,
        }
    }

    /// Update download progress
    pub fn update_progress(&mut self, bytes_downloaded: u64, total_size: Option<u64>) {
        self.bytes_downloaded = bytes_downloaded;
        
        if let Some(total) = total_size {
            self.progress = bytes_downloaded as f64 / total as f64;
            self.meta.size = total;
        }

        // Estimate completion time
        if self.progress > 0.0 && self.progress < 1.0 {
            let elapsed = Utc::now().signed_duration_since(self.started_at);
            let total_time = elapsed.num_seconds() as f64 / self.progress;
            let remaining_time = total_time - elapsed.num_seconds() as f64;
            
            if remaining_time > 0.0 {
                self.estimated_completion = Some(
                    Utc::now() + chrono::Duration::seconds(remaining_time as i64)
                );
            }
        }
    }

    /// Set download status
    pub fn set_status(&mut self, status: DownloadStatus) {
        self.status = status;
        
        if matches!(self.status, DownloadStatus::Completed | DownloadStatus::Failed(_) | DownloadStatus::Cancelled) {
            self.estimated_completion = None;
        }
    }
}

/// Format bytes for human-readable display
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}
