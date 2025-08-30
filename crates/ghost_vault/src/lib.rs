//! GHOSTSHELL Vault
//! 
//! Secure storage for secrets, SSH keys, API tokens, and configuration profiles
//! using post-quantum cryptography and policy-based access control.

pub mod vault;
pub mod storage;
pub mod secrets;
pub mod mfa;
pub mod encryption;

pub use vault::*;
pub use storage::*;
pub use secrets::*;
pub use mfa::*;
pub use encryption::*;

use thiserror::Error;
use serde::{Deserialize, Serialize};

/// Vault statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStats {
    pub total_secrets: u64,
    pub expired_secrets: u64,
    pub mfa_users: u64,
    pub active_sessions: u64,
}

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault is locked")]
    VaultLocked,
    
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("MFA required")]
    MfaRequired,
    
    #[error("MFA verification failed")]
    MfaFailed,
    
    #[error("Secret not found: {0}")]
    SecretNotFound(String),
    
    #[error("Secret already exists: {0}")]
    SecretExists(String),
    
    #[error("Invalid secret type: {0}")]
    InvalidSecretType(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Cryptography error: {0}")]
    CryptoError(#[from] ghost_pq::CryptoError),
    
    // Policy error removed for single-user mode
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Date parsing error: {0}")]
    ParseError(#[from] chrono::ParseError),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
