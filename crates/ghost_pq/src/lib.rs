//! GHOSTSHELL Post-Quantum Cryptography
//! 
//! This crate provides post-quantum cryptographic primitives including:
//! - Kyber KEM (Key Encapsulation Mechanism)
//! - Dilithium digital signatures
//! - SHA3/SHAKE hash functions
//! - Envelope encryption with PQ-safe key wrapping

pub mod kem;
pub mod signatures;
pub mod hash;
pub mod envelope;
pub mod kms;

pub use kem::*;
pub use signatures::*;
pub use hash::*;
pub use envelope::*;
pub use kms::*;

use thiserror::Error;
use zeroize::DefaultIsZeroes;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    #[error("Signature generation failed: {0}")]
    SignatureGeneration(String),
    
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),
    
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    
    #[error("OQS error: {0}")]
    Oqs(#[from] oqs::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Crypto algorithm versions for forward compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CryptoVersion {
    V1 = 1,
}

impl Default for CryptoVersion {
    fn default() -> Self {
        Self::V1
    }
}

// Implement DefaultIsZeroes for CryptoVersion to enable Zeroize derive
impl DefaultIsZeroes for CryptoVersion {}

// Convenience functions for backward compatibility
pub fn generate_kyber_keypair() -> Result<(KyberPublicKey, KyberPrivateKey)> {
    let kem = KyberKem::new(KyberVariant::default())?;
    let keypair = kem.generate_keypair()?;
    Ok((keypair.public_key, keypair.private_key))
}

pub fn encrypt_with_kyber(public_key: &KyberPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let kem = KyberKem::new(public_key.variant)?;
    let encapsulated = kem.encapsulate(public_key)?;
    // For demo purposes, return the ciphertext
    Ok(encapsulated.ciphertext.clone())
}

pub fn decrypt_with_kyber(private_key: &KyberPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let kem = KyberKem::new(private_key.variant)?;
    kem.decapsulate(private_key, ciphertext)
}

pub fn generate_dilithium_keypair() -> Result<(DilithiumPublicKey, DilithiumPrivateKey)> {
    let signer = DilithiumSigner::new(DilithiumVariant::default())?;
    let keypair = signer.generate_keypair()?;
    Ok((keypair.public_key, keypair.private_key))
}

pub fn sign_with_dilithium(private_key: &DilithiumPrivateKey, message: &[u8]) -> Result<Vec<u8>> {
    let signer = DilithiumSigner::new(private_key.variant)?;
    let signature = signer.sign(private_key, message)?;
    Ok(signature.signature)
}

pub fn verify_with_dilithium(public_key: &DilithiumPublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
    let signer = DilithiumSigner::new(public_key.variant)?;
    let sig = DilithiumSignature {
        variant: public_key.variant,
        version: CryptoVersion::default(),
        signature: signature.to_vec(),
    };
    signer.verify(public_key, message, &sig)
}

pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    let hash_digest = Hasher::sha3_256(data);
    hash_digest.digest
}

// Type alias for backward compatibility
pub type EnvelopeKey = KyberPublicKey;
