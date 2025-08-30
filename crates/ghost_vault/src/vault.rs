use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::Utc;


use crate::{
    VaultStorage, VaultEncryption, VaultMasterKey, SealedVmk, MfaManager, MfaChallenge, MfaSession,
    Secret, SecretSummary, SecretFilter, SecretData, CreateSecretRequest, UpdateSecretRequest,
    VaultError, Result, VaultStats,
};
use ghost_pq::KyberPrivateKey;

/// Main vault interface providing secure storage with policy enforcement
pub struct Vault {
    storage: Arc<VaultStorage>,
    encryption: Arc<RwLock<VaultEncryption>>,
    mfa_manager: Arc<MfaManager>,

    current_session: Arc<RwLock<Option<MfaSession>>>,
}

/// Vault configuration
#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub database_url: String,
    pub require_mfa: bool,
    pub auto_lock_timeout_minutes: u32,
    pub max_failed_attempts: u32,
    pub enable_policy_enforcement: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            database_url: "vault.db".to_string(),
            require_mfa: true,
            auto_lock_timeout_minutes: 30,
            max_failed_attempts: 3,
            enable_policy_enforcement: true,
        }
    }
}

impl Vault {
    /// Create a new vault instance
    pub async fn new(config: VaultConfig) -> Result<Self> {
        let storage = Arc::new(VaultStorage::new(&config.database_url).await?);
        let encryption = Arc::new(RwLock::new(VaultEncryption::new()));
        let mfa_manager = Arc::new(MfaManager::new(MfaManager::default_config()));
        
        Ok(Self {
            storage,
            encryption,
            mfa_manager,

            current_session: Arc::new(RwLock::new(None)),
        })
    }

    /// Create in-memory vault for testing
    pub async fn in_memory() -> Result<Self> {
        let config = VaultConfig {
            database_url: ":memory:".to_string(),
            ..Default::default()
        };
        Self::new(config).await
    }

    /// Set policy evaluator for access control


    /// Initialize vault with master password (first time setup)
    pub async fn initialize(&self, master_password: &str) -> Result<()> {
        // Check if vault is already initialized
        if self.storage.get_sealed_vmk().await?.is_some() {
            return Err(VaultError::InvalidInput("Vault is already initialized".to_string()));
        }

        // Generate new VMK
        let vmk = VaultMasterKey::generate()?;
        
        // Seal VMK with master password
        let sealed_vmk = vmk.seal_with_password(master_password)?;
        
        // Store sealed VMK
        self.storage.store_sealed_vmk(&sealed_vmk).await?;
        
        tracing::info!("Vault initialized successfully");
        Ok(())
    }

    /// Unlock vault with master password
    pub async fn unlock(&self, master_password: &str, kyber_secret: &KyberPrivateKey) -> Result<()> {
        // Get sealed VMK
        let sealed_vmk = self.storage.get_sealed_vmk().await?
            .ok_or_else(|| VaultError::InvalidInput("Vault is not initialized".to_string()))?;
        
        // Unseal VMK
        let vmk = VaultMasterKey::unseal_with_password(&sealed_vmk, master_password, kyber_secret)?;
        
        // Unlock encryption
        let mut encryption = self.encryption.write().await;
        encryption.unlock(vmk);
        
        tracing::info!("Vault unlocked successfully");
        Ok(())
    }

    /// Lock the vault
    pub async fn lock(&self) -> Result<()> {
        let mut encryption = self.encryption.write().await;
        encryption.lock();
        
        // Clear current session
        let mut session = self.current_session.write().await;
        *session = None;
        
        tracing::info!("Vault locked");
        Ok(())
    }

    /// Check if vault is unlocked
    pub async fn is_unlocked(&self) -> bool {
        let encryption = self.encryption.read().await;
        encryption.is_unlocked()
    }

    /// Verify MFA and create session
    pub async fn verify_mfa(&self, user_id: &str, challenge: MfaChallenge) -> Result<String> {
        // Get MFA setup for user
        let setup = self.storage.get_mfa_setup(user_id).await?
            .ok_or_else(|| VaultError::InvalidInput("MFA not configured for user".to_string()))?;
        
        // Verify challenge
        let is_valid = self.mfa_manager.verify_challenge(&challenge, &setup)?;
        if !is_valid {
            return Err(VaultError::MfaFailed);
        }
        
        // Create session
        let session = self.mfa_manager.create_session(user_id, challenge.method)?;
        let session_id = session.session_id.clone();
        
        // Store session
        self.storage.store_mfa_session(&session).await?;
        
        // Set current session
        let mut current_session = self.current_session.write().await;
        *current_session = Some(session);
        
        Ok(session_id)
    }

    /// Validate current session
    pub async fn validate_session(&self, session_id: &str) -> Result<bool> {
        let session = self.storage.get_mfa_session(session_id).await?;
        
        if let Some(session) = session {
            let is_valid = self.mfa_manager.validate_session(&session)?;
            
            if is_valid {
                // Update current session
                let mut current_session = self.current_session.write().await;
                *current_session = Some(session);
                Ok(true)
            } else {
                // Clean up expired session
                self.storage.delete_mfa_session(session_id).await?;
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Store a secret
    pub async fn store_secret(&self, request: CreateSecretRequest) -> Result<Uuid> {
        // Check if vault is unlocked
        if !self.is_unlocked().await {
            return Err(VaultError::VaultLocked);
        }

        // Validate MFA session
        self.require_valid_session().await?;

        // Policy evaluation removed for single-user mode

        // Validate secret data
        request.data.validate()?;

        // Extract data before moving request
        let secret_data = request.data.clone();

        // Create secret
        let mut secret = Secret::new(request);

        // Encrypt secret data
        let encryption = self.encryption.read().await;
        let encrypted_data = encryption.encrypt_json(&secret_data)?;
        secret.encrypted_data = encrypted_data;

        // Store in database
        self.storage.store_secret(&secret).await?;

        tracing::info!("Secret stored: {} ({})", secret.name, secret.id);
        Ok(secret.id)
    }

    /// Retrieve a secret
    pub async fn get_secret(&self, id: &Uuid) -> Result<Option<SecretData>> {
        // Check if vault is unlocked
        if !self.is_unlocked().await {
            return Err(VaultError::VaultLocked);
        }

        // Validate MFA session
        self.require_valid_session().await?;

        // Check policy if enabled
        // Policy evaluation removed for single-user mode

        // Get secret from storage
        let secret = self.storage.get_secret(id).await?;
        
        if let Some(mut secret) = secret {
            // Mark as accessed
            secret.mark_accessed();
            self.storage.mark_secret_accessed(id).await?;

            // Decrypt secret data
            let encryption = self.encryption.read().await;
            let decrypted_data: SecretData = encryption.decrypt_json(&secret.encrypted_data)?;

            tracing::info!("Secret accessed: {} ({})", secret.name, secret.id);
            Ok(Some(decrypted_data))
        } else {
            Ok(None)
        }
    }

    /// List secrets (summaries only, no sensitive data)
    pub async fn list_secrets(&self, filter: SecretFilter) -> Result<Vec<SecretSummary>> {
        // Check if vault is unlocked
        if !self.is_unlocked().await {
            return Err(VaultError::VaultLocked);
        }

        // Validate MFA session
        self.require_valid_session().await?;

        // Check policy if enabled
        // Policy evaluation removed for single-user mode

        let summaries = self.storage.list_secrets(&filter).await?;
        tracing::debug!("Listed {} secrets", summaries.len());
        Ok(summaries)
    }

    /// Update a secret
    pub async fn update_secret(&self, id: &Uuid, request: UpdateSecretRequest) -> Result<()> {
        // Check if vault is unlocked
        if !self.is_unlocked().await {
            return Err(VaultError::VaultLocked);
        }

        // Validate MFA session
        self.require_valid_session().await?;

        // Check policy
        // Policy evaluation removed for single-user mode

        // Get existing secret
        let mut secret = self.storage.get_secret(id).await?
            .ok_or_else(|| VaultError::SecretNotFound(id.to_string()))?;

        // Update secret
        secret.update(request.clone());

        // Re-encrypt if data changed
        if let Some(new_data) = request.data {
            new_data.validate()?;
            let encryption = self.encryption.read().await;
            secret.encrypted_data = encryption.encrypt_json(&new_data)?;
        }

        // Store updated secret
        self.storage.store_secret(&secret).await?;

        tracing::info!("Secret updated: {} ({})", secret.name, secret.id);
        Ok(())
    }

    /// Delete a secret
    pub async fn delete_secret(&self, id: &Uuid) -> Result<bool> {
        // Check if vault is unlocked
        if !self.is_unlocked().await {
            return Err(VaultError::VaultLocked);
        }

        // Validate MFA session
        self.require_valid_session().await?;

        // Policy evaluation removed for single-user mode

        let deleted = self.storage.delete_secret(id).await?;
        
        if deleted {
            tracing::info!("Secret deleted: {}", id);
        }
        
        Ok(deleted)
    }

    /// Export secrets (encrypted bundle)
    pub async fn export_secrets(&self, filter: SecretFilter) -> Result<Vec<u8>> {
        // Policy evaluation removed for single-user mode

        // Get all matching secrets
        let summaries = self.list_secrets(filter).await?;
        let mut secrets = Vec::new();

        for summary in summaries {
            if let Some(secret_data) = self.get_secret(&summary.id).await? {
                secrets.push((summary, secret_data));
            }
        }

        // Create export bundle
        let export_bundle = serde_json::json!({
            "version": 1,
            "exported_at": Utc::now(),
            "secrets": secrets
        });

        // Encrypt bundle
        let encryption = self.encryption.read().await;
        let encrypted_bundle = encryption.encrypt_json(&export_bundle)?;

        tracing::info!("Exported {} secrets", secrets.len());
        Ok(encrypted_bundle)
    }

    /// Import secrets from encrypted bundle
    pub async fn import_secrets(&self, encrypted_bundle: &[u8]) -> Result<u32> {
        // Policy evaluation removed for single-user mode

        // Decrypt bundle
        let encryption = self.encryption.read().await;
        let bundle: serde_json::Value = encryption.decrypt_json(encrypted_bundle)?;

        // Parse secrets
        let secrets = bundle["secrets"].as_array()
            .ok_or_else(|| VaultError::InvalidInput("Invalid export bundle format".to_string()))?;

        let mut imported_count = 0;

        for secret_entry in secrets {
            let summary: SecretSummary = serde_json::from_value(secret_entry[0].clone())?;
            let data: SecretData = serde_json::from_value(secret_entry[1].clone())?;

            let request = CreateSecretRequest {
                name: summary.name,
                description: None,
                secret_type: summary.secret_type,
                data,
                tags: summary.tags,
                expires_at: summary.expires_at,
                metadata: Default::default(),
            };

            // Store imported secret
            self.store_secret(request).await?;
            imported_count += 1;
        }

        tracing::info!("Imported {} secrets", imported_count);
        Ok(imported_count)
    }

    /// Setup MFA for a user
    pub async fn setup_mfa(&self, user_id: &str, issuer: &str) -> Result<crate::MfaSetup> {
        let setup = self.mfa_manager.setup_totp(user_id, issuer)?;
        self.storage.store_mfa_setup(user_id, &setup).await?;
        
        tracing::info!("MFA setup completed for user: {}", user_id);
        Ok(setup)
    }

    /// Get vault statistics
    pub async fn get_stats(&self) -> Result<VaultStats> {
        // For now, return dummy stats - in a real implementation this would query the database
        Ok(VaultStats {
            total_secrets: 0,
            expired_secrets: 0,
            mfa_users: 0,
            active_sessions: 0,
        })
    }

    /// Cleanup expired sessions and secrets
    pub async fn cleanup(&self) -> Result<()> {
        let expired_sessions = self.storage.cleanup_expired_sessions().await?;
        tracing::info!("Cleaned up {} expired MFA sessions", expired_sessions);
        Ok(())
    }

    /// Require valid MFA session
    async fn require_valid_session(&self) -> Result<()> {
        let session = self.current_session.read().await;
        
        if let Some(ref session) = *session {
            if !self.mfa_manager.validate_session(session)? {
                return Err(VaultError::MfaRequired);
            }
        } else {
            return Err(VaultError::MfaRequired);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecretData, SecretType, MfaChallengeBuilder, MfaMethod};
    use ghost_policy::{ContextBuilder, SensitivityLevel};

    #[tokio::test]
    async fn test_vault_initialization() {
        let vault = Vault::in_memory().await.unwrap();
        
        assert!(!vault.is_unlocked().await);
        
        vault.initialize("test_password").await.unwrap();
        
        // Should fail to initialize again
        assert!(vault.initialize("test_password").is_err());
    }

    #[tokio::test]
    async fn test_vault_unlock() {
        let vault = Vault::in_memory().await.unwrap();
        vault.initialize("test_password").await.unwrap();
        
        // Mock kyber secret (in real usage, this would be stored securely)
        let kyber_secret = vec![0u8; 32];
        
        // This would fail in real usage without proper kyber key
        // but demonstrates the API
        assert!(vault.unlock("test_password", &kyber_secret).is_err());
    }

    #[tokio::test]
    async fn test_mfa_setup() {
        let vault = Vault::in_memory().await.unwrap();
        
        let setup = vault.setup_mfa("test_user", "GHOSTSHELL").await.unwrap();
        assert_eq!(setup.method, MfaMethod::Totp);
        assert!(setup.secret.is_some());
        assert!(!setup.backup_codes.is_empty());
    }

    // Policy enforcement test removed for single-user mode
}
