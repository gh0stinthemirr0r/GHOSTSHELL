//! GhostScript - Script Management and Execution Engine
//! 
//! Provides secure script repository, execution, and management for Python, PowerShell, and Batch scripts

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub mod repository;
pub mod execution;
pub mod runners;
pub mod editor;
// Policy module removed for single-user mode
pub mod archive;
pub mod engine;

pub use repository::*;
pub use execution::*;
pub use runners::*;
pub use editor::*;
// Policy module removed for single-user mode
pub use archive::*;
pub use engine::*;

/// Script language types supported by GhostScript
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ScriptLanguage {
    Python,
    PowerShell,
    Batch,
}

impl ScriptLanguage {
    pub fn extension(&self) -> &'static str {
        match self {
            ScriptLanguage::Python => "py",
            ScriptLanguage::PowerShell => "ps1",
            ScriptLanguage::Batch => "bat",
        }
    }
    
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "py" => Some(ScriptLanguage::Python),
            "ps1" => Some(ScriptLanguage::PowerShell),
            "bat" | "cmd" => Some(ScriptLanguage::Batch),
            _ => None,
        }
    }
}

/// Script metadata stored in repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptMetadata {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub language: ScriptLanguage,
    pub tags: Vec<String>,
    pub created_by: String,
    pub modified_by: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub file_path: PathBuf,
    pub hash: String,
    pub signature: Option<String>,
    pub parameters: Vec<ScriptParameter>,
    pub rollback_script_id: Option<String>,
}

/// Script parameter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptParameter {
    pub name: String,
    pub description: Option<String>,
    pub param_type: ParameterType,
    pub required: bool,
    pub default_value: Option<String>,
}

/// Parameter types for script execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterType {
    String,
    Integer,
    Float,
    Boolean,
    Path,
    Enum { options: Vec<String> },
}

/// Script execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub id: String,
    pub script_id: String,
    pub script_name: String,
    pub executor: String,
    pub parameters: HashMap<String, String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub runtime_ms: u64,
    pub timestamp: DateTime<Utc>,
    pub signature: Option<String>,
    pub status: ExecutionStatus,
}

/// Execution status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Running,
    Success,
    Failed,
    Cancelled,
    TimedOut,
}

/// Script repository configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptRepositoryConfig {
    /// Base directory where scripts are stored
    pub scripts_directory: PathBuf,
    /// Maximum script file size in bytes
    pub max_file_size: u64,
    /// Allowed script languages
    pub allowed_languages: Vec<ScriptLanguage>,
    /// Whether to require PQ signatures
    pub require_signatures: bool,
    /// Execution timeout in seconds
    pub execution_timeout: u64,
}

impl Default for ScriptRepositoryConfig {
    fn default() -> Self {
        Self {
            scripts_directory: PathBuf::from("./ghostscripts"),
            max_file_size: 10 * 1024 * 1024, // 10MB
            allowed_languages: vec![
                ScriptLanguage::Python,
                ScriptLanguage::PowerShell,
                ScriptLanguage::Batch,
            ],
            require_signatures: true,
            execution_timeout: 300, // 5 minutes
        }
    }
}

/// Execution configuration for running scripts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    /// Working directory for script execution
    pub working_directory: Option<PathBuf>,
    /// Environment variables to set
    pub environment: HashMap<String, String>,
    /// Resource limits
    pub limits: ExecutionLimits,
    /// Whether to capture output
    pub capture_output: bool,
    /// Timeout in seconds
    pub timeout: Option<u64>,
}

/// Resource limits for script execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLimits {
    /// Maximum memory usage in bytes
    pub max_memory: Option<u64>,
    /// Maximum CPU time in seconds
    pub max_cpu_time: Option<u64>,
    /// Maximum number of processes
    pub max_processes: Option<u32>,
    /// Network access allowed
    pub network_access: bool,
    /// File system access restrictions
    pub filesystem_access: FilesystemAccess,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_memory: Some(1024 * 1024 * 1024), // 1GB
            max_cpu_time: Some(300), // 5 minutes
            max_processes: Some(10),
            network_access: false,
            filesystem_access: FilesystemAccess::ReadOnly,
        }
    }
}

/// Filesystem access restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilesystemAccess {
    /// Full access to filesystem
    Full,
    /// Read-only access
    ReadOnly,
    /// Access restricted to specific directories
    Restricted { allowed_paths: Vec<PathBuf> },
    /// No filesystem access
    None,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            working_directory: None,
            environment: HashMap::new(),
            limits: ExecutionLimits {
                max_memory: Some(512 * 1024 * 1024), // 512MB
                max_cpu_time: Some(300), // 5 minutes
                max_processes: Some(10),
                network_access: false,
                filesystem_access: FilesystemAccess::ReadOnly,
            },
            capture_output: true,
            timeout: Some(300),
        }
    }
}

/// Script search query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptSearchQuery {
    /// Text search in name and description
    pub text: Option<String>,
    /// Filter by language
    pub language: Option<ScriptLanguage>,
    /// Filter by tags
    pub tags: Option<Vec<String>>,
    /// Filter by author
    pub author: Option<String>,
    /// Date range filter
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Maximum results to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Script repository statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryStats {
    pub total_scripts: usize,
    pub scripts_by_language: HashMap<ScriptLanguage, usize>,
    pub total_executions: usize,
    pub recent_executions: usize,
    pub success_rate: f64,
    pub average_runtime_ms: f64,
    pub storage_size_bytes: u64,
}

/// Execution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    pub total_runs: usize,
    pub successful_runs: usize,
    pub failed_runs: usize,
    pub average_runtime_ms: f64,
    pub runs_by_language: HashMap<ScriptLanguage, usize>,
    pub runs_by_user: HashMap<String, usize>,
    pub recent_activity: Vec<ExecutionRecord>,
}

/// Script validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub suggestions: Vec<String>,
}

/// Error types for GhostScript operations
#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Cryptography error: {0}")]
    Crypto(#[from] ghost_pq::CryptoError),
    
    #[error("Vault error: {0}")]
    Vault(String),
    
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    
    #[error("Execution error: {0}")]
    Execution(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Script not found: {0}")]
    ScriptNotFound(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
    
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

pub type ScriptResult<T> = Result<T, ScriptError>;

/// Script import/export bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptBundle {
    pub metadata: ScriptMetadata,
    pub content: String,
    pub signature: String,
    pub exported_by: String,
    pub exported_at: DateTime<Utc>,
}

/// Schedule configuration for automated script execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptSchedule {
    pub id: String,
    pub script_id: String,
    pub name: String,
    pub cron_expression: String,
    pub timezone: Option<String>,
    pub parameters: HashMap<String, String>,
    pub enabled: bool,
    pub created_by: String,
    pub created: DateTime<Utc>,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: DateTime<Utc>,
}

/// Live execution stream event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionEvent {
    Started { execution_id: String },
    Stdout { data: String },
    Stderr { data: String },
    Progress { percent: f32, message: Option<String> },
    Finished { exit_code: Option<i32>, runtime_ms: u64 },
    Error { message: String },
}
