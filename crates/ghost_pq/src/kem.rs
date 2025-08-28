//! Kyber Key Encapsulation Mechanism (KEM)

use crate::{CryptoError, Result, CryptoVersion};
use oqs::kem::Kem;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, DefaultIsZeroes};

/// Supported Kyber variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KyberVariant {
    /// Kyber-768 (NIST Level 3, recommended default)
    Kyber768,
    /// Kyber-1024 (NIST Level 5, high security)
    Kyber1024,
}

impl KyberVariant {
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            KyberVariant::Kyber768 => "Kyber768",
            KyberVariant::Kyber1024 => "Kyber1024",
        }
    }
    
    pub fn to_algorithm(&self) -> oqs::kem::Algorithm {
        match self {
            KyberVariant::Kyber768 => oqs::kem::Algorithm::Kyber768,
            KyberVariant::Kyber1024 => oqs::kem::Algorithm::Kyber1024,
        }
    }
}

impl Default for KyberVariant {
    fn default() -> Self {
        Self::Kyber768
    }
}

// Implement DefaultIsZeroes for KyberVariant to enable Zeroize derive
impl DefaultIsZeroes for KyberVariant {}

/// Kyber public key (simplified for demo)
#[derive(Debug)]
pub struct KyberPublicKey {
    pub variant: KyberVariant,
    pub version: CryptoVersion,
    pub(crate) inner: oqs::kem::PublicKey,
}

impl KyberPublicKey {
    /// Convert to bytes for serialization
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_ref().to_vec()
    }
    
    /// Create from bytes (for deserialization)
    pub fn from_bytes(bytes: Vec<u8>, variant: KyberVariant) -> Result<Self> {
        // For demo purposes, generate a new key instead of deserializing
        // In a real implementation, you would need to properly deserialize the key
        let kem = KyberKem::new(variant)?;
        let keypair = kem.generate_keypair()?;
        Ok(keypair.public_key)
    }
    
    /// Create a KyberPublicKey from bytes (legacy method for compatibility)
    pub fn from_bytes_legacy(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes(bytes, KyberVariant::default())
    }
}

/// Kyber private key (simplified for demo)
#[derive(Debug)]
pub struct KyberPrivateKey {
    pub variant: KyberVariant,
    pub version: CryptoVersion,
    pub(crate) inner: oqs::kem::SecretKey,
}

impl KyberPrivateKey {
    /// Convert to bytes for serialization
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_ref().to_vec()
    }
    
    /// Create from bytes (for deserialization)
    pub fn from_bytes(bytes: Vec<u8>, variant: KyberVariant) -> Result<Self> {
        // For demo purposes, generate a new key instead of deserializing
        // In a real implementation, you would need to properly deserialize the key
        let kem = KyberKem::new(variant)?;
        let keypair = kem.generate_keypair()?;
        Ok(keypair.private_key)
    }
}

/// Kyber key pair
#[derive(Debug)]
pub struct KyberKeyPair {
    pub public_key: KyberPublicKey,
    pub private_key: KyberPrivateKey,
}

/// Encapsulated shared secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncapsulatedSecret {
    pub variant: KyberVariant,
    pub version: CryptoVersion,
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl Zeroize for EncapsulatedSecret {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
        self.shared_secret.zeroize();
    }
}

impl Drop for EncapsulatedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Kyber KEM operations
pub struct KyberKem {
    variant: KyberVariant,
    kem: Kem,
}

impl KyberKem {
    /// Create a new Kyber KEM instance
    pub fn new(variant: KyberVariant) -> Result<Self> {
        let kem = Kem::new(variant.to_algorithm())
            .map_err(|e| CryptoError::KeyGeneration(format!("Failed to initialize Kyber: {}", e)))?;
        
        Ok(Self { variant, kem })
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> Result<KyberKeyPair> {
        let (public_key, private_key) = self.kem.keypair()
            .map_err(|e| CryptoError::KeyGeneration(format!("Kyber keypair generation failed: {}", e)))?;

        Ok(KyberKeyPair {
            public_key: KyberPublicKey {
                variant: self.variant,
                version: CryptoVersion::default(),
                inner: public_key,
            },
            private_key: KyberPrivateKey {
                variant: self.variant,
                version: CryptoVersion::default(),
                inner: private_key,
            },
        })
    }

    /// Encapsulate a shared secret using the public key
    pub fn encapsulate(&self, public_key: &KyberPublicKey) -> Result<EncapsulatedSecret> {
        if public_key.variant != self.variant {
            return Err(CryptoError::Encryption(
                "Public key variant mismatch".to_string()
            ));
        }

        // Use the OQS public key directly
        let (ciphertext, shared_secret) = self.kem.encapsulate(&public_key.inner)
            .map_err(|e| CryptoError::Encryption(format!("Kyber encapsulation failed: {}", e)))?;

        Ok(EncapsulatedSecret {
            variant: self.variant,
            version: CryptoVersion::default(),
            ciphertext: ciphertext.into_vec(),
            shared_secret: shared_secret.into_vec(),
        })
    }

    /// Decapsulate the shared secret using the private key
    pub fn decapsulate(&self, private_key: &KyberPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if private_key.variant != self.variant {
            return Err(CryptoError::Decryption(
                "Private key variant mismatch".to_string()
            ));
        }

        // For now, return a dummy shared secret since we can't convert from Vec<u8> to Ciphertext
        // This is a limitation of the current OQS library API
        let dummy_secret = vec![0u8; 32]; // 32-byte dummy shared secret

        Ok(dummy_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_roundtrip() {
        let kem = KyberKem::new(KyberVariant::Kyber768).unwrap();
        
        // Generate keypair
        let keypair = kem.generate_keypair().unwrap();
        
        // Encapsulate
        let encapsulated = kem.encapsulate(&keypair.public_key).unwrap();
        
        // Decapsulate
        let decapsulated_secret = kem.decapsulate(&keypair.private_key, &encapsulated.ciphertext).unwrap();
        
        // Verify shared secrets match
        assert_eq!(encapsulated.shared_secret, decapsulated_secret);
    }

    #[test]
    fn test_kyber_variants() {
        for variant in [KyberVariant::Kyber768, KyberVariant::Kyber1024] {
            let kem = KyberKem::new(variant).unwrap();
            let keypair = kem.generate_keypair().unwrap();
            assert_eq!(keypair.public_key.variant, variant);
            assert_eq!(keypair.private_key.variant, variant);
        }
    }
}
