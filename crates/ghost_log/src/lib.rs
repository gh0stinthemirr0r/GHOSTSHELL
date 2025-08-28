//! GHOSTSHELL Audit Log
//! 
//! Tamper-evident audit logging system with hash chaining and digital signatures
//! for comprehensive security event tracking and compliance.

pub mod logger;
pub mod storage;
pub mod entry;
pub mod chain;
pub mod query;

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
