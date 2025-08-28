use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use once_cell::sync::Lazy;

pub mod ssh_errors;
pub mod terminal_errors;
pub mod vault_errors;
pub mod vpn_errors;
pub mod compliance_errors;

pub use ssh_errors::SSHErrorMapper;
pub use terminal_errors::TerminalErrorMapper;
pub use vault_errors::VaultErrorMapper;
pub use vpn_errors::VPNErrorMapper;
pub use compliance_errors::ComplianceErrorMapper;

/// Error mapping result
pub type ErrorMapResult<T> = Result<T, ErrorMapError>;

/// Error mapping errors
#[derive(Error, Debug)]
pub enum ErrorMapError {
    #[error("Pattern compilation failed: {0}")]
    PatternError(String),
    #[error("No mapping found for error: {0}")]
    NoMappingFound(String),
    #[error("Invalid error format: {0}")]
    InvalidFormat(String),
}

/// Error categories for classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorCategory {
    Authentication,
    Authorization,
    Network,
    Cryptography,
    Policy,
    Configuration,
    Resource,
    Timeout,
    Unknown,
}

/// Error severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Error mapping entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMapping {
    pub pattern: String,
    pub category: ErrorCategory,
    pub severity: ErrorSeverity,
    pub description: String,
    pub common_causes: Vec<String>,
    pub suggested_actions: Vec<String>,
    pub playbook_refs: Vec<String>,
    pub confidence: f64,
}

/// Error classification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorClassification {
    pub category: ErrorCategory,
    pub severity: ErrorSeverity,
    pub description: String,
    pub common_causes: Vec<String>,
    pub suggested_actions: Vec<String>,
    pub playbook_refs: Vec<String>,
    pub confidence: f64,
    pub matched_pattern: String,
}

/// Main error mapper trait
pub trait ErrorMapper {
    fn classify_error(&self, error_text: &str) -> ErrorMapResult<ErrorClassification>;
    fn get_category(&self) -> &str;
    fn get_patterns(&self) -> &[ErrorMapping];
}

/// Universal error classifier that combines all mappers
pub struct UniversalErrorMapper {
    ssh_mapper: SSHErrorMapper,
    terminal_mapper: TerminalErrorMapper,
    vault_mapper: VaultErrorMapper,
    vpn_mapper: VPNErrorMapper,
    compliance_mapper: ComplianceErrorMapper,
}

impl UniversalErrorMapper {
    pub fn new() -> Self {
        Self {
            ssh_mapper: SSHErrorMapper::new(),
            terminal_mapper: TerminalErrorMapper::new(),
            vault_mapper: VaultErrorMapper::new(),
            vpn_mapper: VPNErrorMapper::new(),
            compliance_mapper: ComplianceErrorMapper::new(),
        }
    }

    pub fn classify_error(&self, error_text: &str, context: Option<&str>) -> ErrorMapResult<ErrorClassification> {
        // Try context-specific mapper first if context is provided
        if let Some(ctx) = context {
            match ctx.to_lowercase().as_str() {
                "ssh" => {
                    if let Ok(result) = self.ssh_mapper.classify_error(error_text) {
                        return Ok(result);
                    }
                }
                "terminal" => {
                    if let Ok(result) = self.terminal_mapper.classify_error(error_text) {
                        return Ok(result);
                    }
                }
                "vault" => {
                    if let Ok(result) = self.vault_mapper.classify_error(error_text) {
                        return Ok(result);
                    }
                }
                "vpn" => {
                    if let Ok(result) = self.vpn_mapper.classify_error(error_text) {
                        return Ok(result);
                    }
                }
                "compliance" => {
                    if let Ok(result) = self.compliance_mapper.classify_error(error_text) {
                        return Ok(result);
                    }
                }
                _ => {}
            }
        }

        // Try all mappers in order of likelihood
        let mappers: Vec<&dyn ErrorMapper> = vec![
            &self.ssh_mapper,
            &self.terminal_mapper,
            &self.vault_mapper,
            &self.vpn_mapper,
            &self.compliance_mapper,
        ];

        for mapper in mappers {
            if let Ok(result) = mapper.classify_error(error_text) {
                return Ok(result);
            }
        }

        // Return generic classification if no specific match
        Ok(ErrorClassification {
            category: ErrorCategory::Unknown,
            severity: ErrorSeverity::Warning,
            description: "Unrecognized error pattern".to_string(),
            common_causes: vec!["Unknown system error".to_string()],
            suggested_actions: vec!["Check system logs for more details".to_string()],
            playbook_refs: vec![],
            confidence: 0.1,
            matched_pattern: "generic".to_string(),
        })
    }
}

impl Default for UniversalErrorMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility function to compile regex patterns safely
pub fn compile_pattern(pattern: &str) -> Result<Regex, ErrorMapError> {
    Regex::new(pattern).map_err(|e| ErrorMapError::PatternError(e.to_string()))
}

/// Common error patterns used across mappers
pub static COMMON_PATTERNS: Lazy<HashMap<&str, &str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("permission_denied", r"(?i)permission\s+denied");
    m.insert("connection_refused", r"(?i)connection\s+refused");
    m.insert("timeout", r"(?i)timeout|timed\s+out");
    m.insert("not_found", r"(?i)not\s+found|no\s+such");
    m.insert("invalid_key", r"(?i)invalid\s+key|bad\s+key");
    m.insert("expired", r"(?i)expired|expir");
    m.insert("unauthorized", r"(?i)unauthorized|not\s+authorized");
    m.insert("network_unreachable", r"(?i)network\s+unreachable|no\s+route");
    m
});
