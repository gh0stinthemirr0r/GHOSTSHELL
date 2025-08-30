//! Full-text search engine for GhostLog
//! 
//! Provides fast searching across all log entries with filtering capabilities

use crate::{Result, GhostLogEntry, LogSeverity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Search query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    /// Full-text search term
    pub text: Option<String>,
    /// Filter by module
    pub module: Option<String>,
    /// Filter by severity
    pub severity: Option<LogSeverity>,
    /// Filter by event ID
    pub event_id: Option<String>,
    /// Start time filter
    pub start_time: Option<DateTime<Utc>>,
    /// End time filter
    pub end_time: Option<DateTime<Utc>>,
    /// Maximum number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Enable regex matching
    pub regex: bool,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            text: None,
            module: None,
            severity: None,
            event_id: None,
            start_time: None,
            end_time: None,
            limit: Some(100),
            offset: None,
            regex: false,
        }
    }
}

/// Search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Matching log entries
    pub entries: Vec<GhostLogEntry>,
    /// Total number of matches (before limit/offset)
    pub total_matches: usize,
    /// Search execution time in milliseconds
    pub execution_time_ms: u64,
    /// Whether results were truncated
    pub truncated: bool,
}

/// In-memory search index for fast lookups
#[derive(Debug)]
pub struct SearchIndex {
    /// All entries indexed by ID
    entries: HashMap<Uuid, GhostLogEntry>,
    /// Text index (simplified - in production would use proper full-text search)
    text_index: HashMap<String, Vec<Uuid>>,
    /// Module index
    module_index: HashMap<String, Vec<Uuid>>,
    /// Severity index
    severity_index: HashMap<LogSeverity, Vec<Uuid>>,
    /// Event ID index
    event_index: HashMap<String, Vec<Uuid>>,
}

impl SearchIndex {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            text_index: HashMap::new(),
            module_index: HashMap::new(),
            severity_index: HashMap::new(),
            event_index: HashMap::new(),
        }
    }

    fn add_entry(&mut self, entry: GhostLogEntry) {
        let id = entry.id;
        
        // Add to text index (simplified tokenization)
        let text = format!("{} {}", entry.message, entry.event_id);
        for word in text.to_lowercase().split_whitespace() {
            self.text_index.entry(word.to_string()).or_default().push(id);
        }

        // Add to other indexes
        self.module_index.entry(entry.module.clone()).or_default().push(id);
        self.severity_index.entry(entry.severity.clone()).or_default().push(id);
        self.event_index.entry(entry.event_id.clone()).or_default().push(id);

        // Store the entry
        self.entries.insert(id, entry);
    }

    fn search(&self, query: &SearchQuery) -> Vec<&GhostLogEntry> {
        let mut candidates: Option<Vec<Uuid>> = None;

        // Text search
        if let Some(ref text) = query.text {
            let text_candidates = if query.regex {
                // Simplified regex support - in production would use proper regex engine
                self.entries.values()
                    .filter(|entry| {
                        let search_text = format!("{} {}", entry.message, entry.event_id);
                        search_text.contains(text)
                    })
                    .map(|entry| entry.id)
                    .collect()
            } else {
                let lowercase_text = text.to_lowercase();
                let words: Vec<&str> = lowercase_text.split_whitespace().collect();
                let mut text_matches = Vec::new();
                
                for word in words {
                    if let Some(word_matches) = self.text_index.get(word) {
                        if text_matches.is_empty() {
                            text_matches = word_matches.clone();
                        } else {
                            // Intersection for AND behavior
                            text_matches.retain(|id| word_matches.contains(id));
                        }
                    } else {
                        text_matches.clear();
                        break;
                    }
                }
                text_matches
            };

            candidates = Some(text_candidates);
        }

        // Module filter
        if let Some(ref module) = query.module {
            let module_candidates = self.module_index.get(module).cloned().unwrap_or_default();
            candidates = Some(match candidates {
                Some(existing) => existing.into_iter().filter(|id| module_candidates.contains(id)).collect(),
                None => module_candidates,
            });
        }

        // Severity filter
        if let Some(ref severity) = query.severity {
            let severity_candidates = self.severity_index.get(severity).cloned().unwrap_or_default();
            candidates = Some(match candidates {
                Some(existing) => existing.into_iter().filter(|id| severity_candidates.contains(id)).collect(),
                None => severity_candidates,
            });
        }

        // Event ID filter
        if let Some(ref event_id) = query.event_id {
            let event_candidates = self.event_index.get(event_id).cloned().unwrap_or_default();
            candidates = Some(match candidates {
                Some(existing) => existing.into_iter().filter(|id| event_candidates.contains(id)).collect(),
                None => event_candidates,
            });
        }

        // Get all entries if no filters applied
        let final_candidates = candidates.unwrap_or_else(|| self.entries.keys().cloned().collect());

        // Convert to entries and apply time filters
        let mut results: Vec<&GhostLogEntry> = final_candidates
            .iter()
            .filter_map(|id| self.entries.get(id))
            .filter(|entry| {
                if let Some(start) = query.start_time {
                    if entry.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = query.end_time {
                    if entry.timestamp > end {
                        return false;
                    }
                }
                true
            })
            .collect();

        // Sort by timestamp (newest first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        results
    }
}

/// Search indexer for real-time indexing
pub struct SearchIndexer {
    index: RwLock<SearchIndex>,
    _log_directory: std::path::PathBuf,
}

impl SearchIndexer {
    /// Create a new search indexer
    pub async fn new(log_directory: &Path) -> Result<Self> {
        Ok(Self {
            index: RwLock::new(SearchIndex::new()),
            _log_directory: log_directory.to_path_buf(),
        })
    }

    /// Index a new log entry
    pub async fn index_entry(&self, entry: &GhostLogEntry) -> Result<()> {
        let mut index = self.index.write().await;
        index.add_entry(entry.clone());
        Ok(())
    }

    /// Search the index
    pub async fn search(&self, query: &SearchQuery) -> Result<SearchResult> {
        let start_time = std::time::Instant::now();
        
        let index = self.index.read().await;
        let results = index.search(query);
        
        let total_matches = results.len();
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(100);
        
        let paginated_results: Vec<GhostLogEntry> = results
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();

        let execution_time = start_time.elapsed();
        let truncated = total_matches > offset + paginated_results.len();

        Ok(SearchResult {
            entries: paginated_results,
            total_matches,
            execution_time_ms: execution_time.as_millis() as u64,
            truncated,
        })
    }

    /// Get statistics about the index
    pub async fn get_stats(&self) -> HashMap<String, serde_json::Value> {
        let index = self.index.read().await;
        let mut stats = HashMap::new();
        
        stats.insert("total_entries".to_string(), serde_json::Value::Number(index.entries.len().into()));
        stats.insert("modules".to_string(), serde_json::Value::Number(index.module_index.len().into()));
        stats.insert("unique_events".to_string(), serde_json::Value::Number(index.event_index.len().into()));
        
        // Severity breakdown
        let mut severity_counts = HashMap::new();
        for (severity, entries) in &index.severity_index {
            severity_counts.insert(format!("{:?}", severity), entries.len());
        }
        stats.insert("severity_breakdown".to_string(), serde_json::to_value(severity_counts).unwrap());
        
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_search_indexer() {
        let temp_dir = tempfile::tempdir().unwrap();
        let indexer = SearchIndexer::new(temp_dir.path()).await.unwrap();

        // Add test entries
        let entry1 = GhostLogEntry::new("ssh", LogSeverity::Info, "ssh-connect", "User connected");
        let entry2 = GhostLogEntry::new("terminal", LogSeverity::Error, "term-error", "Command failed");
        
        indexer.index_entry(&entry1).await.unwrap();
        indexer.index_entry(&entry2).await.unwrap();

        // Test text search
        let query = SearchQuery {
            text: Some("connected".to_string()),
            ..Default::default()
        };
        let results = indexer.search(&query).await.unwrap();
        assert_eq!(results.entries.len(), 1);
        assert_eq!(results.entries[0].message, "User connected");

        // Test module filter
        let query = SearchQuery {
            module: Some("terminal".to_string()),
            ..Default::default()
        };
        let results = indexer.search(&query).await.unwrap();
        assert_eq!(results.entries.len(), 1);
        assert_eq!(results.entries[0].module, "terminal");
    }
}
