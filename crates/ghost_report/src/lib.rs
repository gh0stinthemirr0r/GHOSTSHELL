//! GHOSTSHELL GhostReport - Automated Reporting Engine
//!
//! Generates structured CSV/XLSX/PDF reports from GhostLog and GhostDash analytics
//! with PQ-signed outputs, compliance-ready formats, and cyberpunk-themed previews.

pub mod engine;
pub mod builder;
pub mod sources;
pub mod exporters;
pub mod scheduler;
pub mod archive;
pub mod templates;

// Re-export main types
pub use engine::*;
pub use builder::*;
pub use sources::*;
pub use exporters::*;
pub use scheduler::*;
pub use archive::*;
pub use templates::*;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Report generation errors
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("Invalid report configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Data source error: {0}")]
    DataSource(String),
    
    #[error("Export format error: {0}")]
    ExportFormat(String),
    
    #[error("Signature error: {0}")]
    Signature(String),
    
    #[error("Cryptography error: {0}")]
    Crypto(#[from] ghost_pq::CryptoError),
    
    #[error("Vault storage error: {0}")]
    VaultStorage(String),
    
    #[error("Scheduling error: {0}")]
    Scheduling(String),
    
    #[error("Template error: {0}")]
    Template(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Database error: {0}")]
    Database(String),
}

/// Result type for report operations
pub type ReportResult<T> = Result<T, ReportError>;

/// Report job configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportJob {
    /// Unique report identifier
    pub id: String,
    /// Human-readable report name
    pub name: String,
    /// Data sources to include
    pub sources: Vec<ReportSource>,
    /// Filters to apply
    pub filters: ReportFilters,
    /// Output formats to generate
    pub formats: Vec<ReportFormat>,
    /// Report creator
    pub created_by: String,
    /// Creation timestamp
    pub timestamp: DateTime<Utc>,
    /// Scheduling configuration
    pub schedule: Option<ReportSchedule>,
    /// Template to use
    pub template: Option<String>,
    /// PQ signature
    pub signature: Option<String>,
}

/// Report data sources
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportSource {
    /// GhostLog data by module
    GhostLog { modules: Vec<String> },
    /// GhostDash system analytics
    GhostDashSystem,
    /// GhostDash network analytics
    GhostDashNetwork,
    /// GhostDash interface tables
    GhostDashInterfaces,
    /// GhostDash DNS servers
    GhostDashDns,
    /// GhostDash routing tables
    GhostDashRoutes,
    /// GhostDash network connections
    GhostDashConnections,
}

/// Report filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFilters {
    /// Time range start
    pub time_start: Option<DateTime<Utc>>,
    /// Time range end
    pub time_end: Option<DateTime<Utc>>,
    /// Log severity filter
    pub severity: Option<Vec<String>>,
    /// Module filter
    pub modules: Option<Vec<String>>,
    /// Network interface filter
    pub interfaces: Option<Vec<String>>,
    /// Connection state filter
    pub connection_states: Option<Vec<String>>,
    /// Custom filters
    pub custom: Option<HashMap<String, String>>,
}

/// Report output formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ReportFormat {
    /// Comma-separated values
    Csv,
    /// Excel spreadsheet with charts
    Xlsx,
    /// Formatted PDF report
    Pdf,
}

/// Report scheduling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSchedule {
    /// Schedule frequency
    pub frequency: ScheduleFrequency,
    /// Next execution time
    pub next_run: DateTime<Utc>,
    /// Whether schedule is active
    pub enabled: bool,
    /// Timezone for scheduling
    pub timezone: Option<String>,
}

/// Schedule frequency options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScheduleFrequency {
    /// Run once only
    Once,
    /// Daily execution
    Daily,
    /// Weekly execution
    Weekly,
    /// Monthly execution
    Monthly,
    /// Custom cron expression
    Cron(String),
}

/// Generated report artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportArtifact {
    /// Parent report job ID
    pub report_id: String,
    /// Output format
    pub format: ReportFormat,
    /// File path in vault
    pub path: String,
    /// File content hash
    pub hash: String,
    /// PQ signature
    pub signature: String,
    /// File size in bytes
    pub size: u64,
    /// Generation timestamp
    pub created_at: DateTime<Utc>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Report generation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStats {
    /// Total reports generated
    pub total_reports: u64,
    /// Reports by format
    pub by_format: HashMap<ReportFormat, u64>,
    /// Reports by source
    pub by_source: HashMap<String, u64>,
    /// Average generation time (ms)
    pub avg_generation_time_ms: f64,
    /// Total data processed (bytes)
    pub total_data_processed: u64,
    /// Failed generations
    pub failed_generations: u64,
}

/// Report preview data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPreview {
    /// Report metadata
    pub metadata: ReportJob,
    /// Sample data rows
    pub sample_data: Vec<HashMap<String, serde_json::Value>>,
    /// Data statistics
    pub stats: PreviewStats,
    /// Estimated file sizes
    pub estimated_sizes: HashMap<ReportFormat, u64>,
}

/// Preview statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewStats {
    /// Total rows that would be included
    pub total_rows: u64,
    /// Rows by source
    pub rows_by_source: HashMap<String, u64>,
    /// Date range covered
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Unique modules/interfaces
    pub unique_entities: HashMap<String, u64>,
}

impl Default for ReportFilters {
    fn default() -> Self {
        Self {
            time_start: None,
            time_end: None,
            severity: None,
            modules: None,
            interfaces: None,
            connection_states: None,
            custom: None,
        }
    }
}

impl ReportJob {
    /// Create a new report job
    pub fn new(name: String, created_by: String) -> Self {
        Self {
            id: format!("report-{}", Uuid::new_v4()),
            name,
            sources: Vec::new(),
            filters: ReportFilters::default(),
            formats: vec![ReportFormat::Pdf],
            created_by,
            timestamp: Utc::now(),
            schedule: None,
            template: None,
            signature: None,
        }
    }
    
    /// Add a data source
    pub fn add_source(mut self, source: ReportSource) -> Self {
        self.sources.push(source);
        self
    }
    
    /// Set filters
    pub fn with_filters(mut self, filters: ReportFilters) -> Self {
        self.filters = filters;
        self
    }
    
    /// Set output formats
    pub fn with_formats(mut self, formats: Vec<ReportFormat>) -> Self {
        self.formats = formats;
        self
    }
    
    /// Set schedule
    pub fn with_schedule(mut self, schedule: ReportSchedule) -> Self {
        self.schedule = Some(schedule);
        self
    }
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportFormat::Csv => write!(f, "csv"),
            ReportFormat::Xlsx => write!(f, "xlsx"),
            ReportFormat::Pdf => write!(f, "pdf"),
        }
    }
}

impl std::str::FromStr for ReportFormat {
    type Err = ReportError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "csv" => Ok(ReportFormat::Csv),
            "xlsx" => Ok(ReportFormat::Xlsx),
            "pdf" => Ok(ReportFormat::Pdf),
            _ => Err(ReportError::InvalidConfig(format!("Unknown format: {}", s))),
        }
    }
}
