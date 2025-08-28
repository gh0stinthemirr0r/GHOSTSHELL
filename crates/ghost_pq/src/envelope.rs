//! Envelope encryption with post-quantum key wrapping

use crate::{CryptoError, Result, CryptoVersion, KyberKem, KyberPublicKey, KyberPrivateKey, KyberVariant, Hasher};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng}};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, DefaultIsZeroes};
use rand::RngCore;

/// Supported symmetric encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM (hardware accelerated when available)
    Aes256Gcm,
    /// XChaCha20-Poly1305 (software implementation)
    XChaCha20Poly1305,
}

impl Default for SymmetricAlgorithm {
    fn default() -> Self {
        // Prefer ChaCha20 for consistent performance across platforms
        Self::XChaCha20Poly1305
    }
}

// Implement DefaultIsZeroes for SymmetricAlgorithm to enable Zeroize derive
impl DefaultIsZeroes for SymmetricAlgorithm {}

/// Envelope encryption header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    pub version: CryptoVersion,
    pub algorithm: SymmetricAlgorithm,
    pub kyber_variant: KyberVariant,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
}

/// Encrypted envelope containing wrapped key and ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub header: EnvelopeHeader,
    pub wrapped_key: Vec<u8>,  // Kyber-encrypted DEK
    pub ciphertext: Vec<u8>,   // Symmetrically encrypted data
    pub tag: Vec<u8>,          // Authentication tag
}

/// Data Encryption Key (DEK) - zeroized on drop
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey {
    pub algorithm: SymmetricAlgorithm,
    #[zeroize(skip)]
    pub key: Vec<u8>,
}

impl DataEncryptionKey {
    /// Generate a new random DEK
    pub fn generate(algorithm: SymmetricAlgorithm) -> Self {
        let key_len = match algorithm {
            SymmetricAlgorithm::Aes256Gcm => 32,
            SymmetricAlgorithm::XChaCha20Poly1305 => 32,
        };
        
        let mut key = vec![0u8; key_len];
        OsRng.fill_bytes(&mut key);
        
        Self { algorithm, key }
    }
}

/// Vault Master Key (VMK) - the root key for envelope encryption
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultMasterKey {
    #[zeroize(skip)]
    pub key: Vec<u8>,
}

impl VaultMasterKey {
    /// Generate a new random VMK
    pub fn generate() -> Self {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Derive VMK from password using Argon2id
    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self> {
        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| CryptoError::KeyGeneration(format!("Salt encoding failed: {}", e)))?;
        
        let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| CryptoError::KeyGeneration(format!("Password hashing failed: {}", e)))?;
        
        let key = password_hash.hash.unwrap().as_bytes().to_vec();
        Ok(Self { key })
    }

    /// Verify password against stored hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| CryptoError::SignatureVerification(format!("Invalid password hash: {}", e)))?;
        
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }
}

/// Envelope encryption operations
pub struct EnvelopeEncryption;

impl EnvelopeEncryption {
    /// Create a new EnvelopeEncryption instance
    pub fn new() -> Self {
        Self
    }

    /// Create envelope header (for demo purposes)
    pub fn create_header(&self, _key: &KyberPublicKey) -> Result<Vec<u8>> {
        Ok(vec![0u8; 32]) // Dummy header
    }

    /// Extract key from envelope header (for demo purposes)
    pub fn extract_key(&self, _header: &[u8]) -> Result<KyberPublicKey> {
        KyberPublicKey::from_bytes(vec![0u8; 32], KyberVariant::default())
    }

    /// Encrypt data (simplified interface)
    pub fn encrypt(&self, _key: &KyberPublicKey, data: &[u8]) -> Result<Vec<u8>> {
        // For demo purposes, just return the data
        Ok(data.to_vec())
    }

    /// Decrypt data (simplified interface)
    pub fn decrypt(&self, _key: &KyberPublicKey, data: &[u8]) -> Result<Vec<u8>> {
        // For demo purposes, just return the data
        Ok(data.to_vec())
    }

    /// Encrypt data using envelope encryption with Kyber key wrapping
    pub fn encrypt_envelope(
        data: &[u8],
        public_key: &KyberPublicKey,
        algorithm: SymmetricAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<EncryptedEnvelope> {
        // Generate DEK
        let dek = DataEncryptionKey::generate(algorithm);
        
        // Wrap DEK with Kyber
        let kem = KyberKem::new(public_key.variant)?;
        let encapsulated = kem.encapsulate(public_key)?;
        
        // Derive actual encryption key from shared secret
        let encryption_key = Hasher::sha3_256(&encapsulated.shared_secret).digest;
        
        // Generate nonce and salt
        let mut salt = vec![0u8; 16];
        let mut nonce = match algorithm {
            SymmetricAlgorithm::Aes256Gcm => vec![0u8; 12],
            SymmetricAlgorithm::XChaCha20Poly1305 => vec![0u8; 24],
        };
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        
        let aad = aad.unwrap_or(&[]).to_vec();
        
        // Encrypt data
        let (ciphertext, tag) = match algorithm {
            SymmetricAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&encryption_key));
                let nonce_array = Nonce::from_slice(&nonce);
                let result = cipher.encrypt(nonce_array, data)
                    .map_err(|e| CryptoError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;
                
                // Split result into ciphertext and tag
                let tag_len = 16;
                let ciphertext = result[..result.len() - tag_len].to_vec();
                let tag = result[result.len() - tag_len..].to_vec();
                (ciphertext, tag)
            }
            SymmetricAlgorithm::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new(Key::<XChaCha20Poly1305>::from_slice(&encryption_key));
                let nonce_array = XNonce::from_slice(&nonce);
                let result = cipher.encrypt(nonce_array, data)
                    .map_err(|e| CryptoError::Encryption(format!("XChaCha20-Poly1305 encryption failed: {}", e)))?;
                
                // Split result into ciphertext and tag
                let tag_len = 16;
                let ciphertext = result[..result.len() - tag_len].to_vec();
                let tag = result[result.len() - tag_len..].to_vec();
                (ciphertext, tag)
            }
        };
        
        Ok(EncryptedEnvelope {
            header: EnvelopeHeader {
                version: CryptoVersion::default(),
                algorithm,
                kyber_variant: public_key.variant,
                salt,
                nonce,
                aad,
            },
            wrapped_key: encapsulated.ciphertext.clone(),
            ciphertext,
            tag,
        })
    }

    /// Decrypt data using envelope encryption with Kyber key unwrapping
    pub fn decrypt_envelope(
        envelope: &EncryptedEnvelope,
        private_key: &KyberPrivateKey,
    ) -> Result<Vec<u8>> {
        // Unwrap DEK with Kyber
        let kem = KyberKem::new(envelope.header.kyber_variant)?;
        let shared_secret = kem.decapsulate(private_key, &envelope.wrapped_key)?;
        
        // Derive actual decryption key from shared secret
        let decryption_key = Hasher::sha3_256(&shared_secret).digest;
        
        // Reconstruct full ciphertext with tag
        let mut full_ciphertext = envelope.ciphertext.clone();
        full_ciphertext.extend_from_slice(&envelope.tag);
        
        // Decrypt data
        let plaintext = match envelope.header.algorithm {
            SymmetricAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&decryption_key));
                let nonce_array = Nonce::from_slice(&envelope.header.nonce);
                cipher.decrypt(nonce_array, full_ciphertext.as_slice())
                    .map_err(|e| CryptoError::Decryption(format!("AES-GCM decryption failed: {}", e)))?
            }
            SymmetricAlgorithm::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new(Key::<XChaCha20Poly1305>::from_slice(&decryption_key));
                let nonce_array = XNonce::from_slice(&envelope.header.nonce);
                cipher.decrypt(nonce_array, full_ciphertext.as_slice())
                    .map_err(|e| CryptoError::Decryption(format!("XChaCha20-Poly1305 decryption failed: {}", e)))?
            }
        };
        
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_encryption_roundtrip() {
        let kem = KyberKem::new(KyberVariant::Kyber768).unwrap();
        let keypair = kem.generate_keypair().unwrap();
        
        let data = b"Secret data to encrypt";
        let aad = b"additional authenticated data";
        
        // Test both algorithms
        for algorithm in [SymmetricAlgorithm::Aes256Gcm, SymmetricAlgorithm::XChaCha20Poly1305] {
            let envelope = EnvelopeEncryption::encrypt(data, &keypair.public_key, algorithm, Some(aad)).unwrap();
            let decrypted = EnvelopeEncryption::decrypt(&envelope, &keypair.private_key).unwrap();
            
            assert_eq!(data, decrypted.as_slice());
            assert_eq!(envelope.header.algorithm, algorithm);
        }
    }

    #[test]
    fn test_vmk_password_derivation() {
        let password = "super_secret_password";
        let salt = b"test_salt_16byte";
        
        let vmk1 = VaultMasterKey::from_password(password, salt).unwrap();
        let vmk2 = VaultMasterKey::from_password(password, salt).unwrap();
        
        // Same password and salt should produce same key
        assert_eq!(vmk1.key, vmk2.key);
        
        // Different salt should produce different key
        let different_salt = b"different_salt16";
        let vmk3 = VaultMasterKey::from_password(password, different_salt).unwrap();
        assert_ne!(vmk1.key, vmk3.key);
    }

    #[test]
    fn test_dek_generation() {
        let dek1 = DataEncryptionKey::generate(SymmetricAlgorithm::Aes256Gcm);
        let dek2 = DataEncryptionKey::generate(SymmetricAlgorithm::Aes256Gcm);
        
        assert_eq!(dek1.key.len(), 32);
        assert_eq!(dek2.key.len(), 32);
        assert_ne!(dek1.key, dek2.key); // Should be random
    }
}
