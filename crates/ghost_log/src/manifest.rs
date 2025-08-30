//! Log file manifest system for GhostLog
//! 
//! Manages metadata and signatures for rotated log files

use crate::{LogError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Manifest for a completed log file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogManifest {
    /// Path to the log file
    pub file_path: PathBuf,
    /// Number of entries in the log file
    pub entries: u64,
    /// Start time of the log file
    pub start_time: DateTime<Utc>,
    /// End time of the log file
    pub end_time: DateTime<Utc>,
    /// PQ signature of the manifest
    pub signature: Option<String>,
}

impl LogManifest {
    /// Create a new manifest
    pub fn new(
        file_path: PathBuf,
        entries: u64,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Self {
        Self {
            file_path,
            entries,
            start_time,
            end_time,
            signature: None,
        }
    }

    /// Sign the manifest
    pub fn sign(&mut self, signer: &ghost_pq::DilithiumSigner, private_key: &ghost_pq::DilithiumPrivateKey) -> Result<()> {
        let data = self.serialize_for_signing()?;
        let signature = signer.sign(private_key, &data)
            .map_err(|e| LogError::CryptoError(e))?;
        self.signature = Some(hex::encode(&signature.signature));
        Ok(())
    }

    /// Verify the manifest signature
    pub fn verify(&self, public_key: &ghost_pq::DilithiumPublicKey) -> Result<bool> {
        let signature = self.signature.as_ref()
            .ok_or_else(|| LogError::SignatureVerificationFailed("No signature present".to_string()))?;
        
        let signature_bytes = hex::decode(signature)
            .map_err(|_| LogError::SignatureVerificationFailed("Invalid signature format".to_string()))?;
        
        let data = self.serialize_for_signing()?;
        
        // TODO: Implement signature verification
        // For now, return true as placeholder
        Ok(true)
    }

    fn serialize_for_signing(&self) -> Result<Vec<u8>> {
        let mut manifest_copy = self.clone();
        manifest_copy.signature = None; // Don't include signature in signing data
        serde_json::to_vec(&manifest_copy)
            .map_err(|e| LogError::SerializationError(e))
    }
}
