use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;
use std::path::PathBuf;

pub mod bundle;
pub mod graph;
pub mod export;

pub use bundle::*;
pub use graph::*;
pub use export::*;

/// Evidence artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub artifact_id: Uuid,
    pub artifact_type: ArtifactType,
    pub name: String,
    pub description: String,
    pub file_path: Option<PathBuf>,
    pub content_hash: String,
    pub signature: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub metadata: HashMap<String, String>,
    pub related_controls: Vec<String>,
}

/// Types of evidence artifacts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ArtifactType {
    GhostLog,
    Report,
    Configuration,
    Screenshot,
    PCAP,
    Certificate,
    Policy,
    AuditLog,
    Custom(String),
}

/// Evidence bundle manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub bundle_id: Uuid,
    pub name: String,
    pub description: String,
    pub framework_id: String,
    pub snapshot_id: Option<Uuid>,
    pub control_ids: Vec<String>,
    pub artifacts: Vec<EvidenceArtifact>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub signature: Option<String>,
    pub verification_manifest: VerificationManifest,
}

/// Verification manifest for bundle integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationManifest {
    pub manifest_version: String,
    pub bundle_hash: String,
    pub artifact_hashes: HashMap<Uuid, String>,
    pub signatures: HashMap<Uuid, String>,
    pub verification_timestamp: DateTime<Utc>,
    pub signing_key_id: Option<String>,
}

/// Evidence collection request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRequest {
    pub request_id: Uuid,
    pub framework_id: String,
    pub control_ids: Vec<String>,
    pub artifact_types: Vec<ArtifactType>,
    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub include_metadata: bool,
    pub requester: String,
    pub purpose: String,
}

/// Evidence collection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCollection {
    pub request_id: Uuid,
    pub artifacts: Vec<EvidenceArtifact>,
    pub collection_timestamp: DateTime<Utc>,
    pub collection_duration_ms: u64,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Error types for ghost_evidence
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("Artifact not found: {0}")]
    ArtifactNotFound(String),
    
    #[error("Bundle creation failed: {0}")]
    BundleCreation(String),
    
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),
    
    #[error("Export failed: {0}")]
    Export(String),
    
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("PQ crypto error: {0}")]
    Crypto(#[from] ghost_pq::CryptoError),
    
    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
}

pub type EvidenceResult<T> = Result<T, EvidenceError>;
