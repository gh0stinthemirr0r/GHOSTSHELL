//! GHOSTSHELL Policy Engine
//! 
//! This crate provides a declarative policy system for controlling access to
//! sensitive operations including terminal, SSH, vault, clipboard, files, and network.

pub mod policy;
pub mod evaluator;
pub mod context;
pub mod decision;

pub use policy::*;
pub use evaluator::*;
pub use context::*;
pub use decision::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy parsing failed: {0}")]
    ParseError(String),
    
    #[error("Policy validation failed: {0}")]
    ValidationError(String),
    
    #[error("Policy evaluation failed: {0}")]
    EvaluationError(String),
    
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
    
    #[error("Invalid condition: {0}")]
    InvalidCondition(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("TOML error: {0}")]
    TomlError(#[from] toml::de::Error),
    
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

pub type Result<T> = std::result::Result<T, PolicyError>;
