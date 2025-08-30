//! Report archive management
//! 
//! Handles storage and retrieval of generated report artifacts

use crate::{ReportArtifact, ReportError, ReportResult, ReportFormat};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Report archive manager
pub struct ReportArchive {
    /// Database connection pool
    db_path: Option<PathBuf>,
    /// Archive directory
    archive_dir: PathBuf,
}

/// Archive query filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveQuery {
    /// Filter by report name pattern
    pub name_pattern: Option<String>,
    /// Filter by creator
    pub created_by: Option<String>,
    /// Filter by format
    pub format: Option<ReportFormat>,
    /// Filter by date range
    pub date_start: Option<DateTime<Utc>>,
    pub date_end: Option<DateTime<Utc>>,
    /// Limit number of results
    pub limit: Option<u32>,
    /// Offset for pagination
    pub offset: Option<u32>,
}

/// Archive statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveStats {
    /// Total number of reports
    pub total_reports: u64,
    /// Reports by format
    pub by_format: HashMap<ReportFormat, u64>,
    /// Reports by creator
    pub by_creator: HashMap<String, u64>,
    /// Total storage size in bytes
    pub total_size_bytes: u64,
    /// Oldest report date
    pub oldest_report: Option<DateTime<Utc>>,
    /// Newest report date
    pub newest_report: Option<DateTime<Utc>>,
}

impl ReportArchive {
    /// Create a new report archive
    pub fn new(archive_dir: PathBuf) -> ReportResult<Self> {
        // Ensure archive directory exists
        std::fs::create_dir_all(&archive_dir)
            .map_err(|e| ReportError::Io(e))?;
        
        Ok(Self {
            db_path: None,
            archive_dir,
        })
    }
    
    /// Initialize the archive with database connection
    pub async fn initialize(&self) -> ReportResult<()> {
        info!("Initializing report archive at: {:?}", self.archive_dir);
        
        // In a real implementation, would initialize SQLite database
        // For now, we'll use file-based storage
        
        Ok(())
    }
    
    /// Store a report artifact in the archive
    pub async fn store_artifact(&self, artifact: &ReportArtifact) -> ReportResult<()> {
        debug!("Storing artifact in archive: {}", artifact.path);
        
        // Create metadata file alongside the report
        let metadata_path = self.get_metadata_path(&artifact.report_id, &artifact.format);
        let metadata_json = serde_json::to_string_pretty(artifact)
            .map_err(|e| ReportError::Serialization(e))?;
        
        tokio::fs::write(&metadata_path, metadata_json).await
            .map_err(|e| ReportError::Io(e))?;
        
        info!("Stored artifact metadata: {:?}", metadata_path);
        Ok(())
    }
    
    /// Retrieve a report artifact by ID and format
    pub async fn get_artifact(&self, report_id: &str, format: &ReportFormat) -> ReportResult<Option<ReportArtifact>> {
        let metadata_path = self.get_metadata_path(report_id, format);
        
        if !metadata_path.exists() {
            return Ok(None);
        }
        
        let metadata_json = tokio::fs::read_to_string(&metadata_path).await
            .map_err(|e| ReportError::Io(e))?;
        
        let artifact: ReportArtifact = serde_json::from_str(&metadata_json)
            .map_err(|e| ReportError::Serialization(e))?;
        
        Ok(Some(artifact))
    }
    
    /// List all artifacts for a report
    pub async fn get_report_artifacts(&self, report_id: &str) -> ReportResult<Vec<ReportArtifact>> {
        let mut artifacts = Vec::new();
        
        // Check for each format
        for format in &[ReportFormat::Csv, ReportFormat::Xlsx, ReportFormat::Pdf] {
            if let Some(artifact) = self.get_artifact(report_id, format).await? {
                artifacts.push(artifact);
            }
        }
        
        Ok(artifacts)
    }
    
    /// Search the archive with filters
    pub async fn search(&self, query: &ArchiveQuery) -> ReportResult<Vec<ReportArtifact>> {
        debug!("Searching archive with query: {:?}", query);
        
        let mut artifacts = Vec::new();
        
        // Read all metadata files in the archive directory
        let mut entries = tokio::fs::read_dir(&self.archive_dir).await
            .map_err(|e| ReportError::Io(e))?;
        
        while let Some(entry) = entries.next_entry().await.map_err(|e| ReportError::Io(e))? {
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(metadata_json) = tokio::fs::read_to_string(&path).await {
                    if let Ok(artifact) = serde_json::from_str::<ReportArtifact>(&metadata_json) {
                        if self.matches_query(&artifact, query).await {
                            artifacts.push(artifact);
                        }
                    }
                }
            }
        }
        
        // Sort by creation date (newest first)
        artifacts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        
        // Apply pagination
        if let Some(offset) = query.offset {
            if offset as usize >= artifacts.len() {
                return Ok(Vec::new());
            }
            artifacts = artifacts.into_iter().skip(offset as usize).collect();
        }
        
        if let Some(limit) = query.limit {
            artifacts.truncate(limit as usize);
        }
        
        debug!("Found {} matching artifacts", artifacts.len());
        Ok(artifacts)
    }
    
    /// Check if an artifact matches the query filters
    async fn matches_query(&self, artifact: &ReportArtifact, query: &ArchiveQuery) -> bool {
        // Format filter
        if let Some(ref format_filter) = query.format {
            if &artifact.format != format_filter {
                return false;
            }
        }
        
        // Date range filter
        if let Some(start) = query.date_start {
            if artifact.created_at < start {
                return false;
            }
        }
        
        if let Some(end) = query.date_end {
            if artifact.created_at > end {
                return false;
            }
        }
        
        // Name pattern filter (check metadata)
        if let Some(ref pattern) = query.name_pattern {
            if let Some(job_name) = artifact.metadata.get("job_name") {
                if !job_name.to_lowercase().contains(&pattern.to_lowercase()) {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        // Creator filter
        if let Some(ref creator_filter) = query.created_by {
            if let Some(creator) = artifact.metadata.get("created_by") {
                if creator != creator_filter {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        true
    }
    
    /// Get archive statistics
    pub async fn get_stats(&self) -> ReportResult<ArchiveStats> {
        let mut total_reports = 0u64;
        let mut by_format = HashMap::new();
        let mut by_creator = HashMap::new();
        let mut total_size_bytes = 0u64;
        let mut oldest_report: Option<DateTime<Utc>> = None;
        let mut newest_report: Option<DateTime<Utc>> = None;
        
        // Read all metadata files
        let mut entries = tokio::fs::read_dir(&self.archive_dir).await
            .map_err(|e| ReportError::Io(e))?;
        
        while let Some(entry) = entries.next_entry().await.map_err(|e| ReportError::Io(e))? {
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(metadata_json) = tokio::fs::read_to_string(&path).await {
                    if let Ok(artifact) = serde_json::from_str::<ReportArtifact>(&metadata_json) {
                        total_reports += 1;
                        
                        // Count by format
                        *by_format.entry(artifact.format.clone()).or_insert(0) += 1;
                        
                        // Count by creator
                        if let Some(creator) = artifact.metadata.get("created_by") {
                            *by_creator.entry(creator.clone()).or_insert(0) += 1;
                        }
                        
                        // Add to total size
                        total_size_bytes += artifact.size;
                        
                        // Update date range
                        oldest_report = Some(match oldest_report {
                            None => artifact.created_at,
                            Some(existing) => existing.min(artifact.created_at),
                        });
                        
                        newest_report = Some(match newest_report {
                            None => artifact.created_at,
                            Some(existing) => existing.max(artifact.created_at),
                        });
                    }
                }
            }
        }
        
        Ok(ArchiveStats {
            total_reports,
            by_format,
            by_creator,
            total_size_bytes,
            oldest_report,
            newest_report,
        })
    }
    
    /// Delete an artifact from the archive
    pub async fn delete_artifact(&self, report_id: &str, format: &ReportFormat) -> ReportResult<()> {
        let metadata_path = self.get_metadata_path(report_id, format);
        
        // Load artifact to get file path
        if let Some(artifact) = self.get_artifact(report_id, format).await? {
            // Delete the actual report file
            if let Ok(report_path) = PathBuf::from(&artifact.path).canonicalize() {
                if report_path.exists() {
                    tokio::fs::remove_file(&report_path).await
                        .map_err(|e| ReportError::Io(e))?;
                    debug!("Deleted report file: {:?}", report_path);
                }
            }
            
            // Delete the metadata file
            if metadata_path.exists() {
                tokio::fs::remove_file(&metadata_path).await
                    .map_err(|e| ReportError::Io(e))?;
                debug!("Deleted metadata file: {:?}", metadata_path);
            }
            
            info!("Deleted artifact: {} ({})", report_id, format);
        }
        
        Ok(())
    }
    
    /// Clean up old artifacts based on retention policy
    pub async fn cleanup_old_artifacts(&self, retention_days: u32) -> ReportResult<u32> {
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);
        let mut deleted_count = 0u32;
        
        info!("Cleaning up artifacts older than {} days (before {})", retention_days, cutoff_date);
        
        let query = ArchiveQuery {
            name_pattern: None,
            created_by: None,
            format: None,
            date_start: None,
            date_end: Some(cutoff_date),
            limit: None,
            offset: None,
        };
        
        let old_artifacts = self.search(&query).await?;
        
        for artifact in old_artifacts {
            self.delete_artifact(&artifact.report_id, &artifact.format).await?;
            deleted_count += 1;
        }
        
        info!("Cleaned up {} old artifacts", deleted_count);
        Ok(deleted_count)
    }
    
    /// Get the metadata file path for a report
    fn get_metadata_path(&self, report_id: &str, format: &ReportFormat) -> PathBuf {
        self.archive_dir.join(format!("{}-{}.json", report_id, format))
    }
    
    /// Export archive index as JSON
    pub async fn export_index(&self) -> ReportResult<String> {
        let query = ArchiveQuery {
            name_pattern: None,
            created_by: None,
            format: None,
            date_start: None,
            date_end: None,
            limit: None,
            offset: None,
        };
        
        let artifacts = self.search(&query).await?;
        let stats = self.get_stats().await?;
        
        let index = ArchiveIndex {
            generated_at: Utc::now(),
            stats,
            artifacts,
        };
        
        serde_json::to_string_pretty(&index)
            .map_err(|e| ReportError::Serialization(e))
    }
}

impl Default for ArchiveQuery {
    fn default() -> Self {
        Self {
            name_pattern: None,
            created_by: None,
            format: None,
            date_start: None,
            date_end: None,
            limit: Some(100),
            offset: None,
        }
    }
}

/// Archive index for export
#[derive(Debug, Serialize, Deserialize)]
struct ArchiveIndex {
    /// When the index was generated
    generated_at: DateTime<Utc>,
    /// Archive statistics
    stats: ArchiveStats,
    /// All artifacts
    artifacts: Vec<ReportArtifact>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_archive_basic() {
        let temp_dir = TempDir::new().unwrap();
        let archive = ReportArchive::new(temp_dir.path().to_path_buf()).unwrap();
        archive.initialize().await.unwrap();
        
        let artifact = ReportArtifact {
            report_id: "test-report".to_string(),
            format: ReportFormat::Pdf,
            path: "/tmp/test.pdf".to_string(),
            hash: "abc123".to_string(),
            signature: "sig123".to_string(),
            size: 1024,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        
        archive.store_artifact(&artifact).await.unwrap();
        
        let retrieved = archive.get_artifact("test-report", &ReportFormat::Pdf).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().report_id, "test-report");
    }
    
    #[tokio::test]
    async fn test_archive_search() {
        let temp_dir = TempDir::new().unwrap();
        let archive = ReportArchive::new(temp_dir.path().to_path_buf()).unwrap();
        archive.initialize().await.unwrap();
        
        let mut artifact = ReportArtifact {
            report_id: "test-report-1".to_string(),
            format: ReportFormat::Csv,
            path: "/tmp/test1.csv".to_string(),
            hash: "abc123".to_string(),
            signature: "sig123".to_string(),
            size: 1024,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        artifact.metadata.insert("job_name".to_string(), "Test Report".to_string());
        artifact.metadata.insert("created_by".to_string(), "analyst".to_string());
        
        archive.store_artifact(&artifact).await.unwrap();
        
        let query = ArchiveQuery {
            format: Some(ReportFormat::Csv),
            ..Default::default()
        };
        
        let results = archive.search(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].report_id, "test-report-1");
    }
}
