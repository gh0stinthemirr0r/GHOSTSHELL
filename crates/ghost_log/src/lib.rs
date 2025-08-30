//! GHOSTSHELL GhostLog - System-Wide Logging Engine
//! 
//! Comprehensive logging system with:
//! - Centralized logging from all GhostShell modules
//! - PQ-signed log rotation with standardized naming
//! - Full-text search engine with GUI interface
//! - Policy-aware redaction and access control
//! - Tamper-evident storage with hash chaining

pub mod daemon;
pub mod rotation;
pub mod search;
pub mod manifest;
pub mod viewer;
pub mod logger;
pub mod storage;
pub mod entry;
pub mod chain;
pub mod query;

pub use daemon::*;
pub use rotation::*;
pub use search::*;
pub use manifest::*;
pub use viewer::*;
pub use logger::*;
pub use storage::*;
pub use entry::*;
pub use chain::*;
pub use query::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LogError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Cryptography error: {0}")]
    CryptoError(#[from] ghost_pq::CryptoError),
    
    #[error("Hash chain verification failed: {0}")]
    ChainVerificationFailed(String),
    
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    
    #[error("Invalid log entry: {0}")]
    InvalidEntry(String),
    
    #[error("Log tampering detected: {0}")]
    TamperingDetected(String),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Date parsing error: {0}")]
    ParseError(#[from] chrono::ParseError),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, LogError>;
