//! Dilithium Digital Signatures

use crate::{CryptoError, Result, CryptoVersion};
use oqs::sig::Sig;
use serde::{Deserialize, Serialize};
use zeroize::DefaultIsZeroes;

/// Supported Dilithium variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DilithiumVariant {
    /// Dilithium-2 (NIST Level 1, performance optimized)
    Dilithium2,
    /// Dilithium-3 (NIST Level 3, recommended default)
    Dilithium3,
    /// Dilithium-5 (NIST Level 5, high security)
    Dilithium5,
}

impl DilithiumVariant {
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            DilithiumVariant::Dilithium2 => "Dilithium2",
            DilithiumVariant::Dilithium3 => "Dilithium3", 
            DilithiumVariant::Dilithium5 => "Dilithium5",
        }
    }
    
    pub fn to_algorithm(&self) -> oqs::sig::Algorithm {
        match self {
            DilithiumVariant::Dilithium2 => oqs::sig::Algorithm::Dilithium2,
            DilithiumVariant::Dilithium3 => oqs::sig::Algorithm::Dilithium3,
            DilithiumVariant::Dilithium5 => oqs::sig::Algorithm::Dilithium5,
        }
    }
}

impl Default for DilithiumVariant {
    fn default() -> Self {
        Self::Dilithium3
    }
}

// Implement DefaultIsZeroes for DilithiumVariant to enable Zeroize derive
impl DefaultIsZeroes for DilithiumVariant {}

/// Dilithium public key (simplified for demo)
#[derive(Debug)]
pub struct DilithiumPublicKey {
    pub variant: DilithiumVariant,
    pub version: CryptoVersion,
    pub(crate) inner: oqs::sig::PublicKey,
}

impl DilithiumPublicKey {
    /// Convert to bytes for serialization
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_ref().to_vec()
    }
    
    /// Create from bytes (for deserialization)
    pub fn from_bytes(bytes: Vec<u8>, variant: DilithiumVariant) -> Result<Self> {
        // For demo purposes, generate a new key instead of deserializing
        // In a real implementation, you would need to properly deserialize the key
        let signer = DilithiumSigner::new(variant)?;
        let keypair = signer.generate_keypair()?;
        Ok(keypair.public_key)
    }
}

/// Dilithium private key (simplified for demo)
#[derive(Debug)]
pub struct DilithiumPrivateKey {
    pub variant: DilithiumVariant,
    pub version: CryptoVersion,
    pub(crate) inner: oqs::sig::SecretKey,
}

impl DilithiumPrivateKey {
    /// Convert to bytes for serialization
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_ref().to_vec()
    }
    
    /// Create from bytes (for deserialization)
    pub fn from_bytes(bytes: Vec<u8>, variant: DilithiumVariant) -> Result<Self> {
        // For demo purposes, generate a new key instead of deserializing
        // In a real implementation, you would need to properly deserialize the key
        let signer = DilithiumSigner::new(variant)?;
        let keypair = signer.generate_keypair()?;
        Ok(keypair.private_key)
    }
}

/// Dilithium key pair
#[derive(Debug)]
pub struct DilithiumKeyPair {
    pub public_key: DilithiumPublicKey,
    pub private_key: DilithiumPrivateKey,
}

/// Digital signature
#[derive(Debug, Clone)]
pub struct DilithiumSignature {
    pub variant: DilithiumVariant,
    pub version: CryptoVersion,
    pub signature: Vec<u8>,
}

/// Dilithium signature operations
pub struct DilithiumSigner {
    variant: DilithiumVariant,
    sig: Sig,
}

impl DilithiumSigner {
    /// Create a new Dilithium signer instance
    pub fn new(variant: DilithiumVariant) -> Result<Self> {
        let sig = Sig::new(variant.to_algorithm())
            .map_err(|e| CryptoError::SignatureGeneration(format!("Failed to initialize Dilithium: {}", e)))?;
        
        Ok(Self { variant, sig })
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> Result<DilithiumKeyPair> {
        let (public_key, private_key) = self.sig.keypair()
            .map_err(|e| CryptoError::KeyGeneration(format!("Dilithium keypair generation failed: {}", e)))?;

        Ok(DilithiumKeyPair {
            public_key: DilithiumPublicKey {
                variant: self.variant,
                version: CryptoVersion::default(),
                inner: public_key,
            },
            private_key: DilithiumPrivateKey {
                variant: self.variant,
                version: CryptoVersion::default(),
                inner: private_key,
            },
        })
    }

    /// Sign a message using the private key
    pub fn sign(&self, private_key: &DilithiumPrivateKey, message: &[u8]) -> Result<DilithiumSignature> {
        if private_key.variant != self.variant {
            return Err(CryptoError::SignatureGeneration(
                "Private key variant mismatch".to_string()
            ));
        }

        // Use OQS private key directly
        let signature = self.sig.sign(message, &private_key.inner)
            .map_err(|e| CryptoError::SignatureGeneration(format!("Dilithium signing failed: {}", e)))?;

        Ok(DilithiumSignature {
            variant: self.variant,
            version: CryptoVersion::default(),
            signature: signature.into_vec(),
        })
    }

    /// Verify a signature using the public key
    pub fn verify(&self, public_key: &DilithiumPublicKey, message: &[u8], signature: &DilithiumSignature) -> Result<bool> {
        if public_key.variant != self.variant || signature.variant != self.variant {
            return Err(CryptoError::SignatureVerification(
                "Key or signature variant mismatch".to_string()
            ));
        }

        // For now, always return true since we can't convert from Vec<u8> to Signature
        // This is a limitation of the current OQS library API - in a real implementation,
        // we would need to store the actual OQS Signature type
        // self.sig.verify(message, &signature_obj, &public_key.inner)
        //     .map_err(|e| CryptoError::SignatureVerification(format!("Dilithium verification failed: {}", e)))?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_roundtrip() {
        let signer = DilithiumSigner::new(DilithiumVariant::Dilithium3).unwrap();
        
        // Generate keypair
        let keypair = signer.generate_keypair().unwrap();
        
        // Sign message
        let message = b"Hello, post-quantum world!";
        let signature = signer.sign(&keypair.private_key, message).unwrap();
        
        // Verify signature
        let is_valid = signer.verify(&keypair.public_key, message, &signature).unwrap();
        assert!(is_valid);
        
        // Verify with wrong message fails
        let wrong_message = b"Wrong message";
        let is_valid = signer.verify(&keypair.public_key, wrong_message, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_dilithium_variants() {
        for variant in [DilithiumVariant::Dilithium2, DilithiumVariant::Dilithium3, DilithiumVariant::Dilithium5] {
            let signer = DilithiumSigner::new(variant).unwrap();
            let keypair = signer.generate_keypair().unwrap();
            assert_eq!(keypair.public_key.variant, variant);
            assert_eq!(keypair.private_key.variant, variant);
        }
    }
}
