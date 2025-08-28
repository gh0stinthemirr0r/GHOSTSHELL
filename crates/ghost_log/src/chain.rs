use crate::{LogEntry, LogError, Result};
use ghost_pq::{generate_dilithium_keypair, sign_with_dilithium, verify_with_dilithium, sha3_256, DilithiumPublicKey, DilithiumPrivateKey, DilithiumVariant};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Hash chain manager for tamper-evident logging
pub struct HashChain {
    signing_key: Option<DilithiumPrivateKey>,
    verification_key: DilithiumPublicKey,
    chain_metadata: ChainMetadata,
}

/// Metadata about the hash chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    pub chain_id: String,
    pub created_at: DateTime<Utc>,
    pub last_sequence: u64,
    pub last_hash: Option<String>,
    pub total_entries: u64,
    pub verification_key: String, // Base64 encoded public key
    pub algorithm: String,
}

/// Batch of log entries for efficient signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogBatch {
    pub batch_id: String,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub entries: Vec<LogEntry>,
    pub batch_hash: String,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
}

/// Chain verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    pub is_valid: bool,
    pub total_entries: u64,
    pub verified_entries: u64,
    pub broken_links: Vec<BrokenLink>,
    pub invalid_signatures: Vec<u64>,
    pub verification_time_ms: u64,
}

/// Information about a broken chain link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokenLink {
    pub sequence_number: u64,
    pub expected_hash: String,
    pub actual_hash: String,
    pub entry_id: String,
}

impl HashChain {
    /// Create a new hash chain with generated signing keys
    pub fn new(chain_id: String) -> Result<Self> {
        let (public_key, private_key) = generate_dilithium_keypair()
            .map_err(|e| LogError::CryptoError(e))?;

        let metadata = ChainMetadata {
            chain_id,
            created_at: Utc::now(),
            last_sequence: 0,
            last_hash: None,
            total_entries: 0,
            verification_key: base64::encode(&public_key.as_bytes()),
            algorithm: "Dilithium".to_string(),
        };

        Ok(Self {
            signing_key: Some(private_key),
            verification_key: public_key,
            chain_metadata: metadata,
        })
    }

    /// Create hash chain from existing metadata (verification only)
    pub fn from_metadata(metadata: ChainMetadata) -> Result<Self> {
        let verification_key_bytes = base64::decode(&metadata.verification_key)
            .map_err(|e| LogError::InvalidInput(format!("Invalid verification key: {}", e)))?;
        
        let verification_key = DilithiumPublicKey::from_bytes(verification_key_bytes, DilithiumVariant::default())
            .map_err(|e| LogError::CryptoError(e))?;

        Ok(Self {
            signing_key: None,
            verification_key,
            chain_metadata: metadata,
        })
    }

    /// Add an entry to the chain
    pub fn add_entry(&mut self, mut entry: LogEntry) -> Result<LogEntry> {
        // Set sequence number
        self.chain_metadata.last_sequence += 1;
        entry.sequence_number = self.chain_metadata.last_sequence;

        // Set previous hash for chaining
        entry.set_previous_hash(self.chain_metadata.last_hash.clone());

        // Calculate and set hash
        let hash = entry.calculate_hash()?;
        entry.set_hash(hash.clone());

        // Update chain metadata
        self.chain_metadata.last_hash = Some(hash);
        self.chain_metadata.total_entries += 1;

        tracing::debug!("Added entry {} to chain", entry.sequence_number);
        Ok(entry)
    }

    /// Create a signed batch of entries
    pub fn create_batch(&self, entries: Vec<LogEntry>) -> Result<LogBatch> {
        if entries.is_empty() {
            return Err(LogError::InvalidInput("Cannot create empty batch".to_string()));
        }

        let signing_key = self.signing_key.as_ref()
            .ok_or_else(|| LogError::InvalidInput("No signing key available".to_string()))?;

        let sequence_start = entries.first().unwrap().sequence_number;
        let sequence_end = entries.last().unwrap().sequence_number;

        // Calculate batch hash
        let batch_data = serde_json::to_string(&entries)?;
        let batch_hash = hex::encode(sha3_256(batch_data.as_bytes()));

        // Sign the batch hash
        let signature = sign_with_dilithium(signing_key, batch_hash.as_bytes())
            .map_err(|e| LogError::CryptoError(e))?;

        let batch = LogBatch {
            batch_id: uuid::Uuid::new_v4().to_string(),
            sequence_start,
            sequence_end,
            entries,
            batch_hash,
            signature: base64::encode(signature),
            timestamp: Utc::now(),
        };

        tracing::info!("Created signed batch {} with {} entries", 
            batch.batch_id, batch.entries.len());
        Ok(batch)
    }

    /// Verify a batch signature
    pub fn verify_batch(&self, batch: &LogBatch) -> Result<bool> {
        // Recalculate batch hash
        let batch_data = serde_json::to_string(&batch.entries)?;
        let calculated_hash = hex::encode(sha3_256(batch_data.as_bytes()));

        if calculated_hash != batch.batch_hash {
            return Ok(false);
        }

        // Verify signature
        let signature = base64::decode(&batch.signature)
            .map_err(|e| LogError::InvalidInput(format!("Invalid signature format: {}", e)))?;

        let is_valid = verify_with_dilithium(&self.verification_key, batch.batch_hash.as_bytes(), &signature)
            .map_err(|e| LogError::CryptoError(e))?;

        Ok(is_valid)
    }

    /// Verify the entire chain integrity
    pub fn verify_chain(&self, entries: &[LogEntry]) -> Result<ChainVerification> {
        let start_time = std::time::Instant::now();
        let mut verification = ChainVerification {
            is_valid: true,
            total_entries: entries.len() as u64,
            verified_entries: 0,
            broken_links: Vec::new(),
            invalid_signatures: Vec::new(),
            verification_time_ms: 0,
        };

        let mut previous_hash: Option<String> = None;

        for entry in entries {
            // Verify entry hash
            if !entry.verify_hash()? {
                verification.is_valid = false;
                verification.invalid_signatures.push(entry.sequence_number);
                continue;
            }

            // Verify chain link
            if let Some(ref prev_hash) = previous_hash {
                if entry.previous_hash.as_ref() != Some(prev_hash) {
                    verification.is_valid = false;
                    verification.broken_links.push(BrokenLink {
                        sequence_number: entry.sequence_number,
                        expected_hash: prev_hash.clone(),
                        actual_hash: entry.previous_hash.clone().unwrap_or_default(),
                        entry_id: entry.id.to_string(),
                    });
                    continue;
                }
            }

            previous_hash = Some(entry.hash.clone());
            verification.verified_entries += 1;
        }

        verification.verification_time_ms = start_time.elapsed().as_millis() as u64;

        tracing::info!("Chain verification completed: {}/{} entries verified", 
            verification.verified_entries, verification.total_entries);

        Ok(verification)
    }

    /// Get chain statistics
    pub fn get_stats(&self) -> ChainStats {
        ChainStats {
            chain_id: self.chain_metadata.chain_id.clone(),
            total_entries: self.chain_metadata.total_entries,
            last_sequence: self.chain_metadata.last_sequence,
            created_at: self.chain_metadata.created_at,
            has_signing_key: self.signing_key.is_some(),
            algorithm: self.chain_metadata.algorithm.clone(),
        }
    }

    /// Export chain metadata
    pub fn export_metadata(&self) -> ChainMetadata {
        self.chain_metadata.clone()
    }

    /// Update chain metadata (for loading from storage)
    pub fn update_metadata(&mut self, metadata: ChainMetadata) {
        self.chain_metadata = metadata;
    }

    /// Get verification key for external verification
    pub fn verification_key(&self) -> Vec<u8> {
        self.verification_key.as_bytes()
    }

    /// Check if chain can sign (has private key)
    pub fn can_sign(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Create a chain checkpoint for efficient verification
    pub fn create_checkpoint(&self, up_to_sequence: u64) -> Result<ChainCheckpoint> {
        let checkpoint_data = serde_json::json!({
            "chain_id": self.chain_metadata.chain_id,
            "sequence": up_to_sequence,
            "last_hash": self.chain_metadata.last_hash,
            "timestamp": Utc::now()
        });

        let checkpoint_hash = hex::encode(sha3_256(checkpoint_data.to_string().as_bytes()));

        // Sign checkpoint if we have signing key
        let signature = if let Some(ref signing_key) = self.signing_key {
            let sig = sign_with_dilithium(signing_key, checkpoint_hash.as_bytes())
                .map_err(|e| LogError::CryptoError(e))?;
            Some(base64::encode(sig))
        } else {
            None
        };

        Ok(ChainCheckpoint {
            chain_id: self.chain_metadata.chain_id.clone(),
            sequence: up_to_sequence,
            hash: checkpoint_hash,
            signature,
            timestamp: Utc::now(),
            metadata: checkpoint_data,
        })
    }

    /// Verify a checkpoint
    pub fn verify_checkpoint(&self, checkpoint: &ChainCheckpoint) -> Result<bool> {
        // Recalculate checkpoint hash
        let calculated_hash = hex::encode(sha3_256(checkpoint.metadata.to_string().as_bytes()));
        
        if calculated_hash != checkpoint.hash {
            return Ok(false);
        }

        // Verify signature if present
        if let Some(ref signature) = checkpoint.signature {
            let sig_bytes = base64::decode(signature)
                .map_err(|e| LogError::InvalidInput(format!("Invalid checkpoint signature: {}", e)))?;
            
            let is_valid = verify_with_dilithium(&self.verification_key, checkpoint.hash.as_bytes(), &sig_bytes)
                .map_err(|e| LogError::CryptoError(e))?;
            
            Ok(is_valid)
        } else {
            // No signature to verify
            Ok(true)
        }
    }
}

/// Chain statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStats {
    pub chain_id: String,
    pub total_entries: u64,
    pub last_sequence: u64,
    pub created_at: DateTime<Utc>,
    pub has_signing_key: bool,
    pub algorithm: String,
}

/// Chain checkpoint for efficient verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCheckpoint {
    pub chain_id: String,
    pub sequence: u64,
    pub hash: String,
    pub signature: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

/// Chain integrity report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub chain_id: String,
    pub verification: ChainVerification,
    pub checkpoints_verified: u32,
    pub batches_verified: u32,
    pub recommendations: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

impl IntegrityReport {
    /// Generate recommendations based on verification results
    pub fn generate_recommendations(&mut self) {
        self.recommendations.clear();

        if !self.verification.is_valid {
            self.recommendations.push("Chain integrity compromised - investigate immediately".to_string());
        }

        if !self.verification.broken_links.is_empty() {
            self.recommendations.push(format!(
                "Found {} broken chain links - check for tampering", 
                self.verification.broken_links.len()
            ));
        }

        if !self.verification.invalid_signatures.is_empty() {
            self.recommendations.push(format!(
                "Found {} invalid signatures - verify signing keys", 
                self.verification.invalid_signatures.len()
            ));
        }

        if self.verification.verified_entries < self.verification.total_entries {
            let failed_ratio = (self.verification.total_entries - self.verification.verified_entries) as f64 
                / self.verification.total_entries as f64;
            
            if failed_ratio > 0.1 {
                self.recommendations.push("High failure rate - consider chain reconstruction".to_string());
            }
        }

        if self.recommendations.is_empty() {
            self.recommendations.push("Chain integrity verified - no issues found".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Actor, ActorType, Resource, ResourceType, Action, Outcome, EventType, Severity};

    fn create_test_entry(sequence: u64, message: &str) -> LogEntry {
        let actor = Actor {
            actor_type: ActorType::User,
            id: "test_user".to_string(),
            name: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
        };

        let resource = Resource {
            resource_type: ResourceType::Log,
            id: None,
            name: None,
            path: None,
            attributes: HashMap::new(),
        };

        LogEntry::new(
            sequence,
            EventType::AuditEvent,
            Severity::Info,
            actor,
            resource,
            Action::Create,
            Outcome::Success,
            message.to_string(),
        )
    }

    #[test]
    fn test_hash_chain_creation() {
        let chain = HashChain::new("test_chain".to_string()).unwrap();
        
        assert_eq!(chain.chain_metadata.chain_id, "test_chain");
        assert_eq!(chain.chain_metadata.total_entries, 0);
        assert!(chain.can_sign());
    }

    #[test]
    fn test_entry_chaining() {
        let mut chain = HashChain::new("test_chain".to_string()).unwrap();
        
        let entry1 = create_test_entry(0, "First entry");
        let chained_entry1 = chain.add_entry(entry1).unwrap();
        
        assert_eq!(chained_entry1.sequence_number, 1);
        assert!(chained_entry1.previous_hash.is_none());
        assert!(!chained_entry1.hash.is_empty());
        
        let entry2 = create_test_entry(0, "Second entry");
        let chained_entry2 = chain.add_entry(entry2).unwrap();
        
        assert_eq!(chained_entry2.sequence_number, 2);
        assert_eq!(chained_entry2.previous_hash, Some(chained_entry1.hash.clone()));
    }

    #[test]
    fn test_batch_creation_and_verification() {
        let chain = HashChain::new("test_chain".to_string()).unwrap();
        
        let entries = vec![
            create_test_entry(1, "Entry 1"),
            create_test_entry(2, "Entry 2"),
            create_test_entry(3, "Entry 3"),
        ];
        
        let batch = chain.create_batch(entries).unwrap();
        
        assert_eq!(batch.sequence_start, 1);
        assert_eq!(batch.sequence_end, 3);
        assert_eq!(batch.entries.len(), 3);
        assert!(!batch.signature.is_empty());
        
        let is_valid = chain.verify_batch(&batch).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_chain_verification() {
        let mut chain = HashChain::new("test_chain".to_string()).unwrap();
        
        let entry1 = create_test_entry(0, "Entry 1");
        let entry2 = create_test_entry(0, "Entry 2");
        let entry3 = create_test_entry(0, "Entry 3");
        
        let chained_entries = vec![
            chain.add_entry(entry1).unwrap(),
            chain.add_entry(entry2).unwrap(),
            chain.add_entry(entry3).unwrap(),
        ];
        
        let verification = chain.verify_chain(&chained_entries).unwrap();
        
        assert!(verification.is_valid);
        assert_eq!(verification.verified_entries, 3);
        assert!(verification.broken_links.is_empty());
        assert!(verification.invalid_signatures.is_empty());
    }

    #[test]
    fn test_checkpoint_creation_and_verification() {
        let chain = HashChain::new("test_chain".to_string()).unwrap();
        
        let checkpoint = chain.create_checkpoint(100).unwrap();
        
        assert_eq!(checkpoint.chain_id, "test_chain");
        assert_eq!(checkpoint.sequence, 100);
        assert!(!checkpoint.hash.is_empty());
        assert!(checkpoint.signature.is_some());
        
        let is_valid = chain.verify_checkpoint(&checkpoint).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_tamper_detection() {
        let mut chain = HashChain::new("test_chain".to_string()).unwrap();
        
        let entry1 = create_test_entry(0, "Entry 1");
        let entry2 = create_test_entry(0, "Entry 2");
        
        let mut chained_entries = vec![
            chain.add_entry(entry1).unwrap(),
            chain.add_entry(entry2).unwrap(),
        ];
        
        // Tamper with the first entry
        chained_entries[0].details.message = "Tampered entry".to_string();
        
        let verification = chain.verify_chain(&chained_entries).unwrap();
        
        assert!(!verification.is_valid);
        assert_eq!(verification.verified_entries, 1); // Only second entry is valid
        assert_eq!(verification.invalid_signatures.len(), 1);
    }
}
