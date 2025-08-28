use serde::{Deserialize, Serialize};

/// Configuration for GhostTLS behavior
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GhostTLSConfig {
    /// Allow classical-only TLS connections
    pub allow_classical: bool,
    /// Allow hybrid PQ/classical connections
    pub allow_hybrid: bool,
    /// Require pure post-quantum connections only
    pub pq_only: bool,
    /// Timeout for TLS handshake (seconds)
    pub handshake_timeout: u64,
    /// Enable detailed logging
    pub verbose_logging: bool,
    /// Custom CA certificates to trust
    pub custom_ca_certs: Vec<String>,
}

impl Default for GhostTLSConfig {
    fn default() -> Self {
        Self {
            allow_classical: false,  // Deny classical by default
            allow_hybrid: true,      // Allow hybrid by default
            pq_only: false,          // Not pure PQ only by default
            handshake_timeout: 30,
            verbose_logging: true,
            custom_ca_certs: vec![],
        }
    }
}

impl GhostTLSConfig {
    /// Create a PQ-only configuration
    pub fn pq_only() -> Self {
        Self {
            allow_classical: false,
            allow_hybrid: false,
            pq_only: true,
            ..Default::default()
        }
    }

    /// Create a permissive configuration (for testing)
    pub fn permissive() -> Self {
        Self {
            allow_classical: true,
            allow_hybrid: true,
            pq_only: false,
            ..Default::default()
        }
    }
}
