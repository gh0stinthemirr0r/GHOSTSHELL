use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

pub mod signals;
pub mod evaluator;
pub mod scoring;

pub use signals::*;
pub use evaluator::*;
pub use scoring::*;

/// Core signal value with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalValue {
    pub key: String,
    pub value: f64,
    pub target: Option<f64>,
    pub timestamp: DateTime<Utc>,
    pub confidence: f64,
    pub source: String,
    pub metadata: HashMap<String, String>,
}

/// Signal collection window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeWindow {
    Last24Hours,
    Last7Days,
    Last30Days,
    Last90Days,
    Custom { start: DateTime<Utc>, end: DateTime<Utc> },
}

/// Control evaluation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ControlStatus {
    Pass,
    Partial,
    Fail,
    Unknown,
}

/// Control evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvaluation {
    pub control_id: String,
    pub status: ControlStatus,
    pub confidence: f64,
    pub rationale: Vec<String>,
    pub signals: Vec<SignalValue>,
    pub evidence_refs: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub remediation_suggestions: Vec<String>,
}

/// Posture snapshot for a framework
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureSnapshot {
    pub snapshot_id: Uuid,
    pub framework_id: String,
    pub timestamp: DateTime<Utc>,
    pub overall_score: f64,
    pub domain_scores: HashMap<String, f64>,
    pub control_evaluations: Vec<ControlEvaluation>,
    pub total_controls: usize,
    pub passed_controls: usize,
    pub failed_controls: usize,
    pub partial_controls: usize,
    pub unknown_controls: usize,
}

/// Error types for ghost_align
#[derive(Debug, thiserror::Error)]
pub enum AlignError {
    #[error("Signal collection failed: {0}")]
    SignalCollection(String),
    
    #[error("Evaluation failed: {0}")]
    Evaluation(String),
    
    #[error("Scoring failed: {0}")]
    Scoring(String),
    
    #[error("Invalid configuration: {0}")]
    Configuration(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type AlignResult<T> = Result<T, AlignError>;
