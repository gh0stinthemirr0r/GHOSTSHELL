use anyhow::Result;
use std::path::Path;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn, error};
use sha3::{Digest, Sha3_256};

use ghost_pq::{signatures::DilithiumSigner, generate_dilithium_keypair};
use ghost_vault::Vault;

/// File sealer for secure downloads
pub struct FileSealer {
    pub signer: std::sync::Arc<DilithiumSigner>,
    private_key: ghost_pq::signatures::DilithiumPrivateKey,
    public_key: ghost_pq::signatures::DilithiumPublicKey,
}

impl FileSealer {
    /// Create a new file sealer
    pub fn new(signer: std::sync::Arc<DilithiumSigner>) -> Result<Self> {
        // Generate a key pair for this sealer
        let (public_key, private_key) = generate_dilithium_keypair()?;
        
        Ok(Self { 
            signer,
            private_key,
            public_key,
        })
    }

    /// Seal a downloaded file
    pub async fn seal_file(
        &self,
        source_path: &Path,
        vault_path: &str,
        vault_manager: &Vault,
    ) -> Result<(String, String)> {
        debug!("Sealing file: {} -> {}", source_path.display(), vault_path);

        // Read the source file
        let mut file_data = Vec::new();
        let mut file = fs::File::open(source_path).await?;
        file.read_to_end(&mut file_data).await?;

        // Calculate hash
        let hash = self.calculate_hash(&file_data);

        // Sign the file
        let signature = self.sign_file(&file_data, &hash).await?;

        // Create sealed file data
        let sealed_data = self.create_sealed_data(&file_data, &hash, &signature)?;

        // Store in vault (placeholder - would need actual vault file storage)
        // vault_manager.store_file(vault_path, &sealed_data).await?;
        // For now, just write to filesystem
        let vault_dir = std::path::Path::new("vault_files");
        tokio::fs::create_dir_all(vault_dir).await?;
        let vault_file_path = vault_dir.join(vault_path);
        if let Some(parent) = vault_file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(vault_file_path, &sealed_data).await?;

        // Clean up source file
        if let Err(e) = fs::remove_file(source_path).await {
            warn!("Failed to remove source file {}: {}", source_path.display(), e);
        }

        info!("File sealed successfully: {}", vault_path);
        Ok((hash, signature))
    }

    /// Unseal a file from vault
    pub async fn unseal_file(
        &self,
        vault_path: &str,
        output_path: &Path,
        vault_manager: &Vault,
    ) -> Result<bool> {
        debug!("Unsealing file: {} -> {}", vault_path, output_path.display());

        // Retrieve from vault (placeholder - would need actual vault file storage)
        // let sealed_data = vault_manager.retrieve_file(vault_path).await?;
        // For now, just read from filesystem
        let vault_dir = std::path::Path::new("vault_files");
        let vault_file_path = vault_dir.join(vault_path);
        let sealed_data = tokio::fs::read(vault_file_path).await?;

        // Parse sealed data
        let (file_data, hash, signature) = self.parse_sealed_data(&sealed_data)?;

        // Verify signature
        let is_valid = self.verify_signature(&file_data, &hash, &signature).await?;

        if !is_valid {
            error!("File signature verification failed: {}", vault_path);
            return Ok(false);
        }

        // Verify hash
        let calculated_hash = self.calculate_hash(&file_data);
        if calculated_hash != hash {
            error!("File hash verification failed: {}", vault_path);
            return Ok(false);
        }

        // Write unsealed file
        let mut output_file = fs::File::create(output_path).await?;
        output_file.write_all(&file_data).await?;

        info!("File unsealed successfully: {}", output_path.display());
        Ok(true)
    }

    /// Calculate SHA3-256 hash of file data
    fn calculate_hash(&self, data: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Sign file data and hash
    async fn sign_file(&self, data: &[u8], hash: &str) -> Result<String> {
        // Create signature payload (hash + data length)
        let payload = format!("{}:{}", hash, data.len());
        
        // Sign with Dilithium
        let signature = self.signer.sign(&self.private_key, payload.as_bytes())?;
        Ok(hex::encode(&signature.signature))
    }

    /// Verify file signature
    async fn verify_signature(&self, data: &[u8], hash: &str, signature: &str) -> Result<bool> {
        // Recreate signature payload
        let payload = format!("{}:{}", hash, data.len());
        
        // Decode signature
        let signature_bytes = hex::decode(signature)?;
        
        // Reconstruct DilithiumSignature
        let dilithium_signature = ghost_pq::signatures::DilithiumSignature {
            variant: ghost_pq::signatures::DilithiumVariant::Dilithium3,
            version: ghost_pq::CryptoVersion::default(),
            signature: signature_bytes,
        };
        
        // Verify with Dilithium
        Ok(self.signer.verify(&self.public_key, payload.as_bytes(), &dilithium_signature)?)
    }

    /// Create sealed file data (file + metadata)
    fn create_sealed_data(&self, file_data: &[u8], hash: &str, signature: &str) -> Result<Vec<u8>> {
        // Create metadata
        let metadata = serde_json::json!({
            "version": 1,
            "hash": hash,
            "signature": signature,
            "size": file_data.len(),
            "sealed_at": chrono::Utc::now(),
        });

        let metadata_bytes = serde_json::to_vec(&metadata)?;
        let metadata_len = metadata_bytes.len() as u32;

        // Create sealed format: [metadata_len][metadata][file_data]
        let mut sealed_data = Vec::new();
        sealed_data.extend_from_slice(&metadata_len.to_le_bytes());
        sealed_data.extend_from_slice(&metadata_bytes);
        sealed_data.extend_from_slice(file_data);

        Ok(sealed_data)
    }

    /// Parse sealed file data
    fn parse_sealed_data(&self, sealed_data: &[u8]) -> Result<(Vec<u8>, String, String)> {
        if sealed_data.len() < 4 {
            return Err(anyhow::anyhow!("Invalid sealed file format"));
        }

        // Read metadata length
        let metadata_len = u32::from_le_bytes([
            sealed_data[0], sealed_data[1], sealed_data[2], sealed_data[3]
        ]) as usize;

        if sealed_data.len() < 4 + metadata_len {
            return Err(anyhow::anyhow!("Invalid sealed file format"));
        }

        // Read metadata
        let metadata_bytes = &sealed_data[4..4 + metadata_len];
        let metadata: serde_json::Value = serde_json::from_slice(metadata_bytes)?;

        let hash = metadata["hash"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing hash in metadata"))?
            .to_string();
        
        let signature = metadata["signature"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing signature in metadata"))?
            .to_string();

        // Read file data
        let file_data = sealed_data[4 + metadata_len..].to_vec();

        Ok((file_data, hash, signature))
    }
}
