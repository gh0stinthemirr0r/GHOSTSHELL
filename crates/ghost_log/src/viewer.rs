//! GUI viewer components for GhostLog
//! 
//! Provides data structures and logic for the log viewer interface

use crate::{LogError, Result, GhostLogEntry, LogSeverity, SearchQuery, SearchResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Filter configuration for the log viewer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewerFilter {
    /// Date/time range
    pub time_range: Option<TimeRange>,
    /// Selected modules (empty = all)
    pub modules: Vec<String>,
    /// Selected severities (empty = all)
    pub severities: Vec<LogSeverity>,
    /// Search text
    pub search_text: Option<String>,
    /// Enable regex search
    pub regex_search: bool,
    /// Event ID filter
    pub event_id_filter: Option<String>,
}

impl Default for ViewerFilter {
    fn default() -> Self {
        Self {
            time_range: None,
            modules: Vec::new(),
            severities: Vec::new(),
            search_text: None,
            regex_search: false,
            event_id_filter: None,
        }
    }
}

impl ViewerFilter {
    /// Convert to search query
    pub fn to_search_query(&self, limit: Option<usize>, offset: Option<usize>) -> SearchQuery {
        SearchQuery {
            text: self.search_text.clone(),
            module: if self.modules.len() == 1 {
                Some(self.modules[0].clone())
            } else {
                None // TODO: Support multiple modules in search
            },
            severity: if self.severities.len() == 1 {
                Some(self.severities[0].clone())
            } else {
                None // TODO: Support multiple severities in search
            },
            event_id: self.event_id_filter.clone(),
            start_time: self.time_range.as_ref().map(|r| r.start),
            end_time: self.time_range.as_ref().map(|r| r.end),
            limit,
            offset,
            regex: self.regex_search,
        }
    }
}

/// Time range for filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeRange {
    /// Create a time range for the last N hours
    pub fn last_hours(hours: i64) -> Self {
        let end = Utc::now();
        let start = end - chrono::Duration::hours(hours);
        Self { start, end }
    }

    /// Create a time range for the last N days
    pub fn last_days(days: i64) -> Self {
        let end = Utc::now();
        let start = end - chrono::Duration::days(days);
        Self { start, end }
    }

    /// Create a time range for today
    pub fn today() -> Self {
        let now = Utc::now();
        let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
        let end = now;
        Self { start, end }
    }
}

/// Viewer state for the GUI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewerState {
    /// Current filter settings
    pub filter: ViewerFilter,
    /// Current page (for pagination)
    pub current_page: usize,
    /// Items per page
    pub items_per_page: usize,
    /// Whether live mode is enabled
    pub live_mode: bool,
    /// Selected entry for detail view
    pub selected_entry: Option<String>, // Entry ID
    /// Sort configuration
    pub sort: SortConfig,
}

impl Default for ViewerState {
    fn default() -> Self {
        Self {
            filter: ViewerFilter::default(),
            current_page: 0,
            items_per_page: 100,
            live_mode: false,
            selected_entry: None,
            sort: SortConfig::default(),
        }
    }
}

/// Sort configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortConfig {
    /// Field to sort by
    pub field: SortField,
    /// Sort direction
    pub direction: SortDirection,
}

impl Default for SortConfig {
    fn default() -> Self {
        Self {
            field: SortField::Timestamp,
            direction: SortDirection::Descending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortField {
    Timestamp,
    Module,
    Severity,
    EventId,
    Message,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortDirection {
    Ascending,
    Descending,
}

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Export format
    pub format: ExportFormat,
    /// Include signatures in export
    pub include_signatures: bool,
    /// Include context data
    pub include_context: bool,
    /// Filter to apply for export
    pub filter: ViewerFilter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Csv,
    Pdf,
}

/// Export result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    /// Path to exported file
    pub file_path: String,
    /// Number of entries exported
    pub entry_count: usize,
    /// Export timestamp
    pub timestamp: DateTime<Utc>,
    /// File hash for integrity
    pub file_hash: String,
    /// PQ signature of the export
    pub signature: Option<String>,
}

/// Log viewer manager
pub struct LogViewer {
    search_indexer: Option<std::sync::Arc<crate::search::SearchIndexer>>,
}

impl LogViewer {
    /// Create a new log viewer
    pub fn new(search_indexer: Option<std::sync::Arc<crate::search::SearchIndexer>>) -> Self {
        Self { search_indexer }
    }

    /// Search logs with the current filter
    pub async fn search(&self, state: &ViewerState) -> Result<SearchResult> {
        let indexer = self.search_indexer.as_ref()
            .ok_or_else(|| LogError::InvalidInput("Search indexer not available".to_string()))?;

        let offset = state.current_page * state.items_per_page;
        let query = state.filter.to_search_query(Some(state.items_per_page), Some(offset));

        indexer.search(&query).await
    }

    /// Get available modules for filtering
    pub async fn get_available_modules(&self) -> Result<Vec<String>> {
        let indexer = self.search_indexer.as_ref()
            .ok_or_else(|| LogError::InvalidInput("Search indexer not available".to_string()))?;

        let stats = indexer.get_stats().await;
        
        // Extract module names from stats
        // This is a simplified implementation - in practice would query the index directly
        Ok(vec![
            "ssh".to_string(),
            "terminal".to_string(),
            "vault".to_string(),
            "vpn".to_string(),
            "browse".to_string(),
            "script".to_string(),
            "dash".to_string(),
            "report".to_string(),
        ])
    }

    /// Export logs based on configuration
    pub async fn export(&self, config: &ExportConfig) -> Result<ExportResult> {
        let indexer = self.search_indexer.as_ref()
            .ok_or_else(|| LogError::InvalidInput("Search indexer not available".to_string()))?;

        // Search with no limits for export
        let query = config.filter.to_search_query(None, None);
        let search_result = indexer.search(&query).await?;

        // Generate export based on format
        let (file_path, file_hash) = match config.format {
            ExportFormat::Json => self.export_json(&search_result.entries, config).await?,
            ExportFormat::Csv => self.export_csv(&search_result.entries, config).await?,
            ExportFormat::Pdf => self.export_pdf(&search_result.entries, config).await?,
        };

        // TODO: Sign the export with PQ signature
        let signature = None;

        Ok(ExportResult {
            file_path,
            entry_count: search_result.entries.len(),
            timestamp: Utc::now(),
            file_hash,
            signature,
        })
    }

    async fn export_json(&self, entries: &[GhostLogEntry], config: &ExportConfig) -> Result<(String, String)> {
        let export_data = if config.include_context {
            serde_json::to_string_pretty(entries)?
        } else {
            // Create simplified entries without context
            let simplified: Vec<_> = entries.iter().map(|entry| {
                serde_json::json!({
                    "timestamp": entry.timestamp,
                    "module": entry.module,
                    "severity": entry.severity,
                    "event_id": entry.event_id,
                    "message": entry.message,
                    "id": entry.id,
                })
            }).collect();
            serde_json::to_string_pretty(&simplified)?
        };

        // TODO: Write to actual file and calculate hash
        let file_path = format!("ghostlog_export_{}.json", Utc::now().format("%Y%m%d_%H%M%S"));
        let file_hash = "placeholder_hash".to_string();

        Ok((file_path, file_hash))
    }

    async fn export_csv(&self, entries: &[GhostLogEntry], _config: &ExportConfig) -> Result<(String, String)> {
        let mut csv_content = String::new();
        csv_content.push_str("timestamp,module,severity,event_id,message,id\n");

        for entry in entries {
            csv_content.push_str(&format!(
                "{},{},{},{:?},{},{}\n",
                entry.timestamp.to_rfc3339(),
                entry.module,
                format!("{:?}", entry.severity),
                entry.event_id,
                entry.message.replace(',', ";"), // Simple CSV escaping
                entry.id
            ));
        }

        // TODO: Write to actual file and calculate hash
        let file_path = format!("ghostlog_export_{}.csv", Utc::now().format("%Y%m%d_%H%M%S"));
        let file_hash = "placeholder_hash".to_string();

        Ok((file_path, file_hash))
    }

    async fn export_pdf(&self, entries: &[GhostLogEntry], _config: &ExportConfig) -> Result<(String, String)> {
        // TODO: Implement PDF generation
        // For now, return placeholder
        let file_path = format!("ghostlog_export_{}.pdf", Utc::now().format("%Y%m%d_%H%M%S"));
        let file_hash = "placeholder_hash".to_string();

        Ok((file_path, file_hash))
    }

    /// Get viewer statistics
    pub async fn get_stats(&self) -> Result<ViewerStats> {
        let indexer = self.search_indexer.as_ref()
            .ok_or_else(|| LogError::InvalidInput("Search indexer not available".to_string()))?;

        let index_stats = indexer.get_stats().await;

        Ok(ViewerStats {
            total_entries: index_stats.get("total_entries")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            modules: index_stats.get("modules")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            unique_events: index_stats.get("unique_events")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            severity_breakdown: index_stats.get("severity_breakdown")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
        })
    }
}

/// Viewer statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewerStats {
    pub total_entries: u64,
    pub modules: u64,
    pub unique_events: u64,
    pub severity_breakdown: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_range() {
        let range = TimeRange::last_hours(24);
        assert!(range.start < range.end);
        
        let duration = range.end.signed_duration_since(range.start);
        assert_eq!(duration.num_hours(), 24);
    }

    #[test]
    fn test_viewer_filter() {
        let filter = ViewerFilter {
            search_text: Some("test".to_string()),
            modules: vec!["ssh".to_string()],
            ..Default::default()
        };

        let query = filter.to_search_query(Some(50), Some(0));
        assert_eq!(query.text, Some("test".to_string()));
        assert_eq!(query.module, Some("ssh".to_string()));
        assert_eq!(query.limit, Some(50));
    }
}
