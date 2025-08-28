use serde::{Deserialize, Serialize};

/// Post-quantum posture of a TLS connection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PQPosture {
    /// Pure post-quantum cryptography (Kyber + Dilithium/Falcon)
    PurePostQuantum,
    /// Hybrid mode (PQ + classical algorithms)
    Hybrid,
    /// Classical cryptography only (RSA, ECDSA, etc.)
    Classical,
    /// Unknown or failed to determine
    Unknown,
}

impl PQPosture {
    /// Get the badge color for UI display
    pub fn badge_color(&self) -> &'static str {
        match self {
            PQPosture::PurePostQuantum => "cyan",
            PQPosture::Hybrid => "purple", 
            PQPosture::Classical => "amber",
            PQPosture::Unknown => "gray",
        }
    }

    /// Get the display name
    pub fn display_name(&self) -> &'static str {
        match self {
            PQPosture::PurePostQuantum => "PQ",
            PQPosture::Hybrid => "Hybrid",
            PQPosture::Classical => "Classical", 
            PQPosture::Unknown => "Unknown",
        }
    }

    /// Check if this posture is compliant with policy
    pub fn is_compliant(&self, allow_classical: bool, allow_hybrid: bool) -> bool {
        match self {
            PQPosture::PurePostQuantum => true,
            PQPosture::Hybrid => allow_hybrid,
            PQPosture::Classical => allow_classical,
            PQPosture::Unknown => false,
        }
    }
}

/// TLS connection metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSConnectionInfo {
    pub hostname: String,
    pub port: u16,
    pub posture: PQPosture,
    pub cipher_suite: Option<String>,
    pub protocol_version: Option<String>,
    pub certificate_info: Option<CertificateInfo>,
    pub established_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub valid_to: chrono::DateTime<chrono::Utc>,
    pub signature_algorithm: String,
    pub is_pq_signed: bool,
}
