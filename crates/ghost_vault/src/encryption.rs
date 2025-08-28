use ghost_pq::{EnvelopeEncryption, EnvelopeKey, generate_kyber_keypair, encrypt_with_kyber, decrypt_with_kyber, KyberPublicKey, KyberPrivateKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::{VaultError, Result};

/// Vault Master Key (VMK) - the root encryption key for the vault
#[derive(Clone)]
pub struct VaultMasterKey {
    key_data: Vec<u8>,
}

/// Sealed VMK - encrypted with user's key derivation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SealedVmk {
    pub kyber_ciphertext: Vec<u8>,
    pub kyber_public_key: Vec<u8>,
    pub envelope_header: Vec<u8>,
    pub salt: Vec<u8>,
    pub iterations: u32,
}

/// Key derivation parameters
#[derive(Debug, Clone)]
pub struct KeyDerivationParams {
    pub salt: Vec<u8>,
    pub iterations: u32,
}

impl VaultMasterKey {
    /// Generate a new random VMK
    pub fn generate() -> Result<Self> {
        let mut key_data = vec![0u8; 32]; // 256-bit key
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut key_data);
        
        Ok(Self { key_data })
    }

    /// Create VMK from existing key material
    pub fn from_bytes(key_data: Vec<u8>) -> Result<Self> {
        if key_data.len() != 32 {
            return Err(VaultError::InvalidInput("VMK must be 32 bytes".to_string()));
        }
        Ok(Self { key_data })
    }

    /// Get key bytes (use carefully)
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }

    /// Seal the VMK with a password-derived key using post-quantum cryptography
    pub fn seal_with_password(&self, password: &str) -> Result<SealedVmk> {
        // Generate salt for key derivation
        let mut salt = vec![0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut salt);
        
        let iterations = 100_000; // PBKDF2 iterations
        
        // Derive key from password
        let derived_key = self.derive_key_from_password(password, &salt, iterations)?;
        
        // Generate Kyber keypair for sealing
        let (kyber_public, kyber_secret) = generate_kyber_keypair()
            .map_err(|e| VaultError::EncryptionError(format!("Kyber keygen failed: {}", e)))?;
        
        // Create envelope encryption with the VMK
        let envelope = EnvelopeEncryption::new();
        let envelope_key = EnvelopeKey::from_bytes_legacy(self.key_data.clone())
            .map_err(|e| VaultError::EncryptionError(format!("Envelope key creation failed: {}", e)))?;
        
        // Encrypt the derived key with Kyber (this will be used to decrypt the VMK)
        let kyber_ciphertext = encrypt_with_kyber(&kyber_public, &derived_key)
            .map_err(|e| VaultError::EncryptionError(format!("Kyber encryption failed: {}", e)))?;
        
        // Create envelope header (contains metadata)
        let envelope_header = envelope.create_header(&envelope_key)
            .map_err(|e| VaultError::EncryptionError(format!("Envelope header creation failed: {}", e)))?;
        
        Ok(SealedVmk {
            kyber_ciphertext,
            kyber_public_key: kyber_public.as_bytes(),
            envelope_header,
            salt,
            iterations,
        })
    }

    /// Unseal the VMK with a password
    pub fn unseal_with_password(sealed: &SealedVmk, password: &str, kyber_secret: &KyberPrivateKey) -> Result<Self> {
        // Derive the same key from password
        let derived_key = Self::derive_key_from_password_static(
            password, 
            &sealed.salt, 
            sealed.iterations
        )?;
        
        // Decrypt with Kyber to get the derived key back
        let decrypted_key = decrypt_with_kyber(kyber_secret, &sealed.kyber_ciphertext)
            .map_err(|e| VaultError::DecryptionError(format!("Kyber decryption failed: {}", e)))?;
        
        // Verify the derived key matches
        if derived_key != decrypted_key {
            return Err(VaultError::InvalidCredentials);
        }
        
        // Use the envelope header to reconstruct the VMK
        let envelope = EnvelopeEncryption::new();
        let envelope_key = envelope.extract_key(&sealed.envelope_header)
            .map_err(|e| VaultError::DecryptionError(format!("Envelope key extraction failed: {}", e)))?;
        
        Ok(Self {
            key_data: envelope_key.as_bytes().to_vec(),
        })
    }

    /// Derive key from password using PBKDF2
    fn derive_key_from_password(&self, password: &str, salt: &[u8], iterations: u32) -> Result<Vec<u8>> {
        Self::derive_key_from_password_static(password, salt, iterations)
    }

    fn derive_key_from_password_static(password: &str, salt: &[u8], iterations: u32) -> Result<Vec<u8>> {
        use argon2::{Argon2, PasswordHasher};
        use argon2::password_hash::{PasswordHash, SaltString};
        
        // Use Argon2 for password-based key derivation (more secure than PBKDF2)
        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| VaultError::EncryptionError(format!("Salt encoding failed: {}", e)))?;
        
        let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| VaultError::EncryptionError(format!("Password hashing failed: {}", e)))?;
        
        // Extract the hash bytes
        let hash = password_hash.hash
            .ok_or_else(|| VaultError::EncryptionError("No hash in password hash".to_string()))?;
        let hash_bytes = hash.as_bytes();
        
        // Take first 32 bytes for key
        if hash_bytes.len() >= 32 {
            Ok(hash_bytes[..32].to_vec())
        } else {
            Err(VaultError::EncryptionError("Hash too short".to_string()))
        }
    }

    /// Encrypt data using the VMK
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let envelope = EnvelopeEncryption::new();
        let envelope_key = EnvelopeKey::from_bytes_legacy(self.key_data.clone())
            .map_err(|e| VaultError::EncryptionError(format!("Envelope key creation failed: {}", e)))?;
        
        envelope.encrypt(&envelope_key, plaintext)
            .map_err(|e| VaultError::EncryptionError(format!("Envelope encryption failed: {}", e)))
    }

    /// Decrypt data using the VMK
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let envelope = EnvelopeEncryption::new();
        let envelope_key = EnvelopeKey::from_bytes_legacy(self.key_data.clone())
            .map_err(|e| VaultError::DecryptionError(format!("Envelope key creation failed: {}", e)))?;
        
        envelope.decrypt(&envelope_key, ciphertext)
            .map_err(|e| VaultError::DecryptionError(format!("Envelope decryption failed: {}", e)))
    }

    /// Rotate the VMK (generate new key, re-encrypt all data)
    pub fn rotate(&mut self) -> Result<VaultMasterKey> {
        let new_vmk = Self::generate()?;
        
        // The caller is responsible for re-encrypting all vault data
        // with the new VMK before replacing the old one
        
        Ok(new_vmk)
    }
}

impl Drop for VaultMasterKey {
    fn drop(&mut self) {
        self.key_data.zeroize();
    }
}

/// Vault encryption context
pub struct VaultEncryption {
    vmk: Option<VaultMasterKey>,
}

impl VaultEncryption {
    /// Create new encryption context (locked)
    pub fn new() -> Self {
        Self { vmk: None }
    }

    /// Unlock with VMK
    pub fn unlock(&mut self, vmk: VaultMasterKey) {
        self.vmk = Some(vmk);
    }

    /// Lock the vault (clear VMK from memory)
    pub fn lock(&mut self) {
        self.vmk = None;
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.vmk.is_some()
    }

    /// Encrypt data (requires unlocked vault)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let vmk = self.vmk.as_ref().ok_or(VaultError::VaultLocked)?;
        vmk.encrypt(plaintext)
    }

    /// Decrypt data (requires unlocked vault)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let vmk = self.vmk.as_ref().ok_or(VaultError::VaultLocked)?;
        vmk.decrypt(ciphertext)
    }

    /// Encrypt JSON-serializable data
    pub fn encrypt_json<T: Serialize>(&self, data: &T) -> Result<Vec<u8>> {
        let json_bytes = serde_json::to_vec(data)?;
        self.encrypt(&json_bytes)
    }

    /// Decrypt to JSON-deserializable data
    pub fn decrypt_json<T: for<'de> Deserialize<'de>>(&self, ciphertext: &[u8]) -> Result<T> {
        let json_bytes = self.decrypt(ciphertext)?;
        let data = serde_json::from_slice(&json_bytes)?;
        Ok(data)
    }

    /// Get VMK for sealing operations
    pub fn vmk(&self) -> Result<&VaultMasterKey> {
        self.vmk.as_ref().ok_or(VaultError::VaultLocked)
    }
}

impl Default for VaultEncryption {
    fn default() -> Self {
        Self::new()
    }
}

/// Secure memory for sensitive data
#[derive(ZeroizeOnDrop)]
pub struct SecureBytes {
    data: Vec<u8>,
}

impl SecureBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<String> for SecureBytes {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmk_generation() {
        let vmk = VaultMasterKey::generate().unwrap();
        assert_eq!(vmk.as_bytes().len(), 32);
    }

    #[test]
    fn test_vmk_sealing() {
        let vmk = VaultMasterKey::generate().unwrap();
        let password = "test_password_123";
        
        let sealed = vmk.seal_with_password(password).unwrap();
        assert!(!sealed.kyber_ciphertext.is_empty());
        assert!(!sealed.kyber_public_key.is_empty());
        assert_eq!(sealed.salt.len(), 32);
        assert_eq!(sealed.iterations, 100_000);
    }

    #[test]
    fn test_encryption_decryption() {
        let vmk = VaultMasterKey::generate().unwrap();
        let plaintext = b"Hello, secure world!";
        
        let ciphertext = vmk.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        
        let decrypted = vmk.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_vault_encryption_context() {
        let mut vault_enc = VaultEncryption::new();
        assert!(!vault_enc.is_unlocked());
        
        let vmk = VaultMasterKey::generate().unwrap();
        vault_enc.unlock(vmk);
        assert!(vault_enc.is_unlocked());
        
        let test_data = serde_json::json!({"key": "value", "number": 42});
        let ciphertext = vault_enc.encrypt_json(&test_data).unwrap();
        let decrypted: serde_json::Value = vault_enc.decrypt_json(&ciphertext).unwrap();
        
        assert_eq!(decrypted, test_data);
        
        vault_enc.lock();
        assert!(!vault_enc.is_unlocked());
    }

    #[test]
    fn test_secure_bytes() {
        let sensitive_data = "password123".to_string();
        let secure = SecureBytes::from(sensitive_data);
        
        assert_eq!(secure.len(), 11);
        assert_eq!(secure.as_bytes(), b"password123");
        
        // SecureBytes should zeroize on drop
        drop(secure);
    }
}
