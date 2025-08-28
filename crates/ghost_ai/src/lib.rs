use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub mod engine;
pub mod classifier;
pub mod suggestion;

pub use engine::AIEngine;
pub use classifier::{ErrorClassifier, ErrorCategory};
pub use suggestion::{AISuggestion, SuggestionContext, SuggestionResult, AIError};

/// AI suggestion types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SuggestionSource {
    Terminal,
    SSH,
    Compliance,
    Vault,
    VPN,
    Report,
}

/// AI confidence levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConfidenceLevel {
    Low,      // 0.0 - 0.4
    Medium,   // 0.4 - 0.7
    High,     // 0.7 - 0.9
    VeryHigh, // 0.9 - 1.0
}

impl From<f64> for ConfidenceLevel {
    fn from(confidence: f64) -> Self {
        match confidence {
            c if c < 0.4 => ConfidenceLevel::Low,
            c if c < 0.7 => ConfidenceLevel::Medium,
            c if c < 0.9 => ConfidenceLevel::High,
            _ => ConfidenceLevel::VeryHigh,
        }
    }
}

/// AI suggestion priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SuggestionPriority {
    Info,
    Warning,
    Critical,
}

/// Evidence reference for AI suggestions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub ref_type: String,
    pub ref_id: String,
    pub description: String,
}

/// AI suggestion metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestionMetadata {
    pub id: String,
    pub source: SuggestionSource,
    pub timestamp: DateTime<Utc>,
    pub confidence: f64,
    pub confidence_level: ConfidenceLevel,
    pub priority: SuggestionPriority,
    pub evidence_refs: Vec<EvidenceRef>,
    pub signature: Option<String>,
}

impl SuggestionMetadata {
    pub fn new(source: SuggestionSource, confidence: f64, priority: SuggestionPriority) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            source,
            timestamp: Utc::now(),
            confidence,
            confidence_level: confidence.into(),
            priority,
            evidence_refs: Vec::new(),
            signature: None,
        }
    }

    pub fn add_evidence(&mut self, ref_type: String, ref_id: String, description: String) {
        self.evidence_refs.push(EvidenceRef {
            ref_type,
            ref_id,
            description,
        });
    }
}

/// AI engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIConfig {
    pub enabled: bool,
    pub min_confidence: f64,
    pub max_suggestions_per_error: usize,
    pub enable_learning: bool,
    pub enable_signing: bool,
    pub response_timeout_ms: u64,
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence: 0.3,
            max_suggestions_per_error: 3,
            enable_learning: true,
            enable_signing: true,
            response_timeout_ms: 500,
        }
    }
}

/// AI engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIStats {
    pub total_suggestions: u64,
    pub suggestions_by_source: HashMap<String, u64>,
    pub average_confidence: f64,
    pub average_response_time_ms: f64,
    pub successful_suggestions: u64,
    pub failed_suggestions: u64,
}

impl Default for AIStats {
    fn default() -> Self {
        Self {
            total_suggestions: 0,
            suggestions_by_source: HashMap::new(),
            average_confidence: 0.0,
            average_response_time_ms: 0.0,
            successful_suggestions: 0,
            failed_suggestions: 0,
        }
    }
}
