//! Key Management System utilities

use crate::{
    CryptoError, Result, CryptoVersion,
    KyberKem, KyberKeyPair, KyberVariant,
    DilithiumSigner, DilithiumKeyPair, DilithiumVariant,
    VaultMasterKey, EnvelopeEncryption, SymmetricAlgorithm,
};
use serde::{Deserialize, Serialize};
use zeroize::DefaultIsZeroes;
use std::collections::HashMap;

/// Key usage types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUsage {
    /// Key encryption (Kyber KEM)
    KeyEncryption,
    /// Digital signatures (Dilithium)
    DigitalSignature,
    /// Vault master key
    VaultMaster,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self::KeyEncryption
    }
}

// Implement DefaultIsZeroes for KeyUsage to enable Zeroize derive
impl DefaultIsZeroes for KeyUsage {}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub id: String,
    pub usage: KeyUsage,
    pub version: CryptoVersion,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub tags: HashMap<String, String>,
}

/// Wrapped key for secure storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub metadata: KeyMetadata,
    pub algorithm: String,
    pub wrapped_data: Vec<u8>,
}

/// Key Management System
pub struct KeyManager {
    vault_keys: HashMap<String, KyberKeyPair>,
    signing_keys: HashMap<String, DilithiumKeyPair>,
    master_keys: HashMap<String, VaultMasterKey>,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new() -> Self {
        Self {
            vault_keys: HashMap::new(),
            signing_keys: HashMap::new(),
            master_keys: HashMap::new(),
        }
    }

    /// Generate a new Kyber key pair for vault encryption
    pub fn generate_vault_keypair(
        &mut self,
        id: String,
        variant: KyberVariant,
        tags: Option<HashMap<String, String>>,
    ) -> Result<&KyberKeyPair> {
        let kem = KyberKem::new(variant)?;
        let keypair = kem.generate_keypair()?;
        
        let metadata = KeyMetadata {
            id: id.clone(),
            usage: KeyUsage::KeyEncryption,
            version: CryptoVersion::default(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            tags: tags.unwrap_or_default(),
        };
        
        self.vault_keys.insert(id.clone(), keypair);
        Ok(self.vault_keys.get(&id).unwrap())
    }

    /// Generate a new Dilithium key pair for signing
    pub fn generate_signing_keypair(
        &mut self,
        id: String,
        variant: DilithiumVariant,
        tags: Option<HashMap<String, String>>,
    ) -> Result<&DilithiumKeyPair> {
        let signer = DilithiumSigner::new(variant)?;
        let keypair = signer.generate_keypair()?;
        
        let metadata = KeyMetadata {
            id: id.clone(),
            usage: KeyUsage::DigitalSignature,
            version: CryptoVersion::default(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            tags: tags.unwrap_or_default(),
        };
        
        self.signing_keys.insert(id.clone(), keypair);
        Ok(self.signing_keys.get(&id).unwrap())
    }

    /// Generate a new vault master key
    pub fn generate_master_key(
        &mut self,
        id: String,
        tags: Option<HashMap<String, String>>,
    ) -> Result<&VaultMasterKey> {
        let vmk = VaultMasterKey::generate();
        
        let metadata = KeyMetadata {
            id: id.clone(),
            usage: KeyUsage::VaultMaster,
            version: CryptoVersion::default(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            tags: tags.unwrap_or_default(),
        };
        
        self.master_keys.insert(id.clone(), vmk);
        Ok(self.master_keys.get(&id).unwrap())
    }

    /// Get vault key pair by ID
    pub fn get_vault_keypair(&self, id: &str) -> Option<&KyberKeyPair> {
        self.vault_keys.get(id)
    }

    /// Get signing key pair by ID
    pub fn get_signing_keypair(&self, id: &str) -> Option<&DilithiumKeyPair> {
        self.signing_keys.get(id)
    }

    /// Get master key by ID
    pub fn get_master_key(&self, id: &str) -> Option<&VaultMasterKey> {
        self.master_keys.get(id)
    }

    /// Wrap a key for secure storage using envelope encryption
    pub fn wrap_key<T: Serialize>(
        &self,
        key_data: &T,
        wrapping_key_id: &str,
        metadata: KeyMetadata,
    ) -> Result<WrappedKey> {
        let vault_keypair = self.get_vault_keypair(wrapping_key_id)
            .ok_or_else(|| CryptoError::InvalidKey(format!("Wrapping key not found: {}", wrapping_key_id)))?;

        let serialized = serde_json::to_vec(key_data)
            .map_err(|e| CryptoError::Encryption(format!("Key serialization failed: {}", e)))?;

        let envelope = EnvelopeEncryption::encrypt_envelope(
            &serialized,
            &vault_keypair.public_key,
            SymmetricAlgorithm::default(),
            None,
        )?;

        let wrapped_data = serde_json::to_vec(&envelope)
            .map_err(|e| CryptoError::Encryption(format!("Envelope serialization failed: {}", e)))?;

        Ok(WrappedKey {
            metadata,
            algorithm: format!("envelope-{:?}", envelope.header.algorithm),
            wrapped_data,
        })
    }

    /// Unwrap a key from secure storage
    pub fn unwrap_key<T: for<'de> Deserialize<'de>>(
        &self,
        wrapped_key: &WrappedKey,
        wrapping_key_id: &str,
    ) -> Result<T> {
        let vault_keypair = self.get_vault_keypair(wrapping_key_id)
            .ok_or_else(|| CryptoError::InvalidKey(format!("Wrapping key not found: {}", wrapping_key_id)))?;

        let envelope: crate::EncryptedEnvelope = serde_json::from_slice(&wrapped_key.wrapped_data)
            .map_err(|e| CryptoError::Decryption(format!("Envelope deserialization failed: {}", e)))?;

        let decrypted = EnvelopeEncryption::decrypt_envelope(&envelope, &vault_keypair.private_key)?;

        let key_data: T = serde_json::from_slice(&decrypted)
            .map_err(|e| CryptoError::Decryption(format!("Key deserialization failed: {}", e)))?;

        Ok(key_data)
    }

    /// List all key metadata
    pub fn list_keys(&self) -> Vec<KeyMetadata> {
        let mut keys = Vec::new();
        
        // Add vault keys
        for (id, _) in &self.vault_keys {
            keys.push(KeyMetadata {
                id: id.clone(),
                usage: KeyUsage::KeyEncryption,
                version: CryptoVersion::default(),
                created_at: chrono::Utc::now(), // TODO: Store actual creation time
                expires_at: None,
                tags: HashMap::new(),
            });
        }
        
        // Add signing keys
        for (id, _) in &self.signing_keys {
            keys.push(KeyMetadata {
                id: id.clone(),
                usage: KeyUsage::DigitalSignature,
                version: CryptoVersion::default(),
                created_at: chrono::Utc::now(), // TODO: Store actual creation time
                expires_at: None,
                tags: HashMap::new(),
            });
        }
        
        // Add master keys
        for (id, _) in &self.master_keys {
            keys.push(KeyMetadata {
                id: id.clone(),
                usage: KeyUsage::VaultMaster,
                version: CryptoVersion::default(),
                created_at: chrono::Utc::now(), // TODO: Store actual creation time
                expires_at: None,
                tags: HashMap::new(),
            });
        }
        
        keys
    }

    /// Remove a key by ID
    pub fn remove_key(&mut self, id: &str) -> Result<()> {
        let removed = self.vault_keys.remove(id).is_some()
            || self.signing_keys.remove(id).is_some()
            || self.master_keys.remove(id).is_some();
        
        if removed {
            Ok(())
        } else {
            Err(CryptoError::InvalidKey(format!("Key not found: {}", id)))
        }
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_vault_keys() {
        let mut km = KeyManager::new();
        
        // Generate vault keypair
        let keypair = km.generate_vault_keypair(
            "test-vault-key".to_string(),
            KyberVariant::Kyber768,
            None,
        ).unwrap();
        
        assert_eq!(keypair.public_key.variant, KyberVariant::Kyber768);
        
        // Retrieve keypair
        let retrieved = km.get_vault_keypair("test-vault-key").unwrap();
        assert_eq!(retrieved.public_key.variant, keypair.public_key.variant);
    }

    #[test]
    fn test_key_manager_signing_keys() {
        let mut km = KeyManager::new();
        
        // Generate signing keypair
        let keypair = km.generate_signing_keypair(
            "test-signing-key".to_string(),
            DilithiumVariant::Dilithium3,
            None,
        ).unwrap();
        
        assert_eq!(keypair.public_key.variant, DilithiumVariant::Dilithium3);
        
        // Retrieve keypair
        let retrieved = km.get_signing_keypair("test-signing-key").unwrap();
        assert_eq!(retrieved.public_key.variant, keypair.public_key.variant);
    }

    #[test]
    fn test_key_wrapping() {
        let mut km = KeyManager::new();
        
        // Generate wrapping key
        km.generate_vault_keypair(
            "wrapping-key".to_string(),
            KyberVariant::Kyber768,
            None,
        ).unwrap();
        
        // Generate key to wrap
        let signing_keypair = km.generate_signing_keypair(
            "key-to-wrap".to_string(),
            DilithiumVariant::Dilithium3,
            None,
        ).unwrap();
        
        let metadata = KeyMetadata {
            id: "wrapped-key".to_string(),
            usage: KeyUsage::DigitalSignature,
            version: CryptoVersion::default(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            tags: HashMap::new(),
        };
        
        // Wrap the key
        let wrapped = km.wrap_key(signing_keypair, "wrapping-key", metadata).unwrap();
        
        // Unwrap the key
        let unwrapped: DilithiumKeyPair = km.unwrap_key(&wrapped, "wrapping-key").unwrap();
        
        // Verify keys match
        assert_eq!(signing_keypair.public_key.key_data, unwrapped.public_key.key_data);
        assert_eq!(signing_keypair.private_key.key_data, unwrapped.private_key.key_data);
    }

    #[test]
    fn test_list_keys() {
        let mut km = KeyManager::new();
        
        km.generate_vault_keypair("vault1".to_string(), KyberVariant::Kyber768, None).unwrap();
        km.generate_signing_keypair("sign1".to_string(), DilithiumVariant::Dilithium3, None).unwrap();
        km.generate_master_key("master1".to_string(), None).unwrap();
        
        let keys = km.list_keys();
        assert_eq!(keys.len(), 3);
        
        let usages: std::collections::HashSet<_> = keys.iter().map(|k| k.usage).collect();
        assert!(usages.contains(&KeyUsage::KeyEncryption));
        assert!(usages.contains(&KeyUsage::DigitalSignature));
        assert!(usages.contains(&KeyUsage::VaultMaster));
    }
}
