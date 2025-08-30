//! GHOSTSHELL GhostDash - System Dashboard + Network Analytics
//! 
//! Comprehensive dashboard system providing:
//! - Real-time system telemetry and health monitoring
//! - Network analytics with queryable tables
//! - Cross-platform network information collection
//! - PQ-signed exports and snapshots
//! - Policy-aware access control

pub mod dashboard;
pub mod collectors;
pub mod tables;
pub mod exports;
pub mod analytics;
pub mod system_simple;
pub use system_simple as system;

pub use dashboard::*;
pub use collectors::*;
pub use tables::*;
pub use exports::*;
pub use analytics::*;
pub use system::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DashError {
    #[error("System information error: {0}")]
    SystemError(String),
    
    #[error("Network collection error: {0}")]
    NetworkError(String),
    
    #[error("Export error: {0}")]
    ExportError(String),
    
    #[error("Policy error: {0}")]
    PolicyError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Cryptography error: {0}")]
    CryptoError(#[from] ghost_pq::CryptoError),
    
    #[error("Vault error: {0}")]
    VaultError(#[from] ghost_vault::VaultError),
    
    #[error("Log error: {0}")]
    LogError(#[from] ghost_log::LogError),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, DashError>;
