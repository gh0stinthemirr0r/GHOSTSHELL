use crate::{EvidenceBundle, EvidenceArtifact, VerificationManifest, EvidenceResult};
use chrono::Utc;
use uuid::Uuid;
use std::collections::HashMap;
use sha3::{Digest, Sha3_256};
use ghost_pq::signatures::{DilithiumPrivateKey, DilithiumSigner};
use base64::prelude::*;

/// Evidence bundle builder
pub struct BundleBuilder {
    name: String,
    description: String,
    framework_id: String,
    control_ids: Vec<String>,
    artifacts: Vec<EvidenceArtifact>,
    created_by: String,
}

impl BundleBuilder {
    pub fn new(name: String, framework_id: String, created_by: String) -> Self {
        Self {
            name,
            description: String::new(),
            framework_id,
            control_ids: Vec::new(),
            artifacts: Vec::new(),
            created_by,
        }
    }

    pub fn description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    pub fn add_control(mut self, control_id: String) -> Self {
        if !self.control_ids.contains(&control_id) {
            self.control_ids.push(control_id);
        }
        self
    }

    pub fn add_artifact(mut self, artifact: EvidenceArtifact) -> Self {
        // Add control IDs from artifact
        for control_id in &artifact.related_controls {
            if !self.control_ids.contains(control_id) {
                self.control_ids.push(control_id.clone());
            }
        }
        self.artifacts.push(artifact);
        self
    }

    pub async fn build(self, signing_key: Option<&DilithiumPrivateKey>) -> EvidenceResult<EvidenceBundle> {
        let bundle_id = Uuid::new_v4();
        let created_at = Utc::now();

        // Calculate artifact hashes
        let mut artifact_hashes = HashMap::new();
        for artifact in &self.artifacts {
            artifact_hashes.insert(artifact.artifact_id, artifact.content_hash.clone());
        }

        // Calculate bundle hash
        let bundle_content = serde_json::to_string(&(
            &bundle_id,
            &self.name,
            &self.framework_id,
            &self.control_ids,
            &artifact_hashes,
            &created_at,
        ))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(bundle_content.as_bytes());
        let bundle_hash = format!("sha3-256:{}", hex::encode(hasher.finalize()));

        // Create verification manifest
        let mut verification_manifest = VerificationManifest {
            manifest_version: "1.0".to_string(),
            bundle_hash: bundle_hash.clone(),
            artifact_hashes,
            signatures: HashMap::new(),
            verification_timestamp: created_at,
            signing_key_id: None,
        };

        // Sign bundle if key provided
        let bundle_signature = if let Some(key) = signing_key {
            let signer = DilithiumSigner::new(key.variant)?;
            let signature = signer.sign(key, bundle_hash.as_bytes())?;
            let signature_b64 = base64::prelude::BASE64_STANDARD.encode(&signature.signature);
            verification_manifest.signing_key_id = Some("dilithium-bundle-key".to_string());
            Some(signature_b64)
        } else {
            None
        };

        // Sign individual artifacts if key provided
        if let Some(key) = signing_key {
            let signer = DilithiumSigner::new(key.variant)?;
            for artifact in &self.artifacts {
                let signature = signer.sign(key, artifact.content_hash.as_bytes())?;
                let signature_b64 = base64::prelude::BASE64_STANDARD.encode(&signature.signature);
                verification_manifest.signatures.insert(artifact.artifact_id, signature_b64);
            }
        }

        Ok(EvidenceBundle {
            bundle_id,
            name: self.name,
            description: self.description,
            framework_id: self.framework_id,
            snapshot_id: None,
            control_ids: self.control_ids,
            artifacts: self.artifacts,
            created_at,
            created_by: self.created_by,
            signature: bundle_signature,
            verification_manifest,
        })
    }
}

/// Bundle verification utilities
pub struct BundleVerifier;

impl BundleVerifier {
    pub async fn verify_bundle(
        bundle: &EvidenceBundle,
        public_key: Option<&ghost_pq::signatures::DilithiumPublicKey>,
    ) -> EvidenceResult<VerificationResult> {
        let mut result = VerificationResult {
            bundle_valid: true,
            artifacts_valid: true,
            signature_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Verify bundle hash
        let bundle_content = serde_json::to_string(&(
            &bundle.bundle_id,
            &bundle.name,
            &bundle.framework_id,
            &bundle.control_ids,
            &bundle.verification_manifest.artifact_hashes,
            &bundle.created_at,
        ))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(bundle_content.as_bytes());
        let calculated_hash = format!("sha3-256:{}", hex::encode(hasher.finalize()));

        if calculated_hash != bundle.verification_manifest.bundle_hash {
            result.bundle_valid = false;
            result.errors.push(format!(
                "Bundle hash mismatch: expected {}, got {}",
                bundle.verification_manifest.bundle_hash,
                calculated_hash
            ));
        }

        // Verify artifact hashes
        for artifact in &bundle.artifacts {
            if let Some(expected_hash) = bundle.verification_manifest.artifact_hashes.get(&artifact.artifact_id) {
                if &artifact.content_hash != expected_hash {
                    result.artifacts_valid = false;
                    result.errors.push(format!(
                        "Artifact {} hash mismatch: expected {}, got {}",
                        artifact.artifact_id,
                        expected_hash,
                        artifact.content_hash
                    ));
                }
            } else {
                result.artifacts_valid = false;
                result.errors.push(format!(
                    "Artifact {} not found in verification manifest",
                    artifact.artifact_id
                ));
            }
        }

        // Verify signatures if public key provided
        if let Some(pub_key) = public_key {
            let signer = DilithiumSigner::new(pub_key.variant)?;
            if let Some(bundle_signature) = &bundle.signature {
                match base64::prelude::BASE64_STANDARD.decode(bundle_signature) {
                    Ok(signature_bytes) => {
                        let signature = ghost_pq::signatures::DilithiumSignature {
                            variant: pub_key.variant,
                            version: pub_key.version.clone(),
                            signature: signature_bytes,
                        };
                        match signer.verify(pub_key, bundle.verification_manifest.bundle_hash.as_bytes(), &signature) {
                            Ok(valid) => {
                                if !valid {
                                    result.signature_valid = false;
                                    result.errors.push("Bundle signature verification failed".to_string());
                                }
                            }
                            Err(e) => {
                                result.signature_valid = false;
                                result.errors.push(format!("Bundle signature verification error: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        result.signature_valid = false;
                        result.errors.push(format!("Bundle signature decode error: {}", e));
                    }
                }
            } else {
                result.warnings.push("Bundle signature not present".to_string());
            }

            // Verify artifact signatures
            for artifact in &bundle.artifacts {
                if let Some(artifact_signature) = bundle.verification_manifest.signatures.get(&artifact.artifact_id) {
                    match base64::prelude::BASE64_STANDARD.decode(artifact_signature) {
                        Ok(signature_bytes) => {
                            let signature = ghost_pq::signatures::DilithiumSignature {
                                variant: pub_key.variant,
                                version: pub_key.version.clone(),
                                signature: signature_bytes,
                            };
                            match signer.verify(pub_key, artifact.content_hash.as_bytes(), &signature) {
                                Ok(valid) => {
                                    if !valid {
                                        result.signature_valid = false;
                                        result.errors.push(format!(
                                            "Artifact {} signature verification failed",
                                            artifact.artifact_id
                                        ));
                                    }
                                }
                                Err(e) => {
                                    result.signature_valid = false;
                                    result.errors.push(format!(
                                        "Artifact {} signature verification error: {}",
                                        artifact.artifact_id, e
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            result.signature_valid = false;
                            result.errors.push(format!(
                                "Artifact {} signature decode error: {}",
                                artifact.artifact_id, e
                            ));
                        }
                    }
                } else {
                    result.warnings.push(format!(
                        "Artifact {} signature not present",
                        artifact.artifact_id
                    ));
                }
            }
        }

        Ok(result)
    }
}

/// Bundle verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub bundle_valid: bool,
    pub artifacts_valid: bool,
    pub signature_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        self.bundle_valid && self.artifacts_valid && self.signature_valid
    }
}
