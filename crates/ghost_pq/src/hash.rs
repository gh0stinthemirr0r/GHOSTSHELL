//! SHA3 and SHAKE hash functions

use crate::{CryptoError, Result};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};
use serde::{Deserialize, Serialize};

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA3-256 (32-byte output)
    Sha3_256,
    /// SHA3-512 (64-byte output)
    Sha3_512,
    /// SHAKE128 (variable output)
    Shake128,
    /// SHAKE256 (variable output)
    Shake256,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha3_256
    }
}

/// Hash digest result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashDigest {
    pub algorithm: HashAlgorithm,
    pub digest: Vec<u8>,
}

impl HashDigest {
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.digest)
    }

    /// Create from hex string
    pub fn from_hex(algorithm: HashAlgorithm, hex_str: &str) -> Result<Self> {
        let digest = hex::decode(hex_str)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid hex: {}", e)))?;
        
        Ok(Self { algorithm, digest })
    }
}

/// Hash operations
pub struct Hasher;

impl Hasher {
    /// Compute SHA3-256 hash
    pub fn sha3_256(data: &[u8]) -> HashDigest {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let digest = hasher.finalize().to_vec();
        
        HashDigest {
            algorithm: HashAlgorithm::Sha3_256,
            digest,
        }
    }

    /// Compute SHA3-512 hash
    pub fn sha3_512(data: &[u8]) -> HashDigest {
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        let digest = hasher.finalize().to_vec();
        
        HashDigest {
            algorithm: HashAlgorithm::Sha3_512,
            digest,
        }
    }

    /// Compute SHAKE128 hash with specified output length
    pub fn shake128(data: &[u8], output_len: usize) -> HashDigest {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        
        let mut hasher = Shake128::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut digest = vec![0u8; output_len];
        reader.read(&mut digest);
        
        HashDigest {
            algorithm: HashAlgorithm::Shake128,
            digest,
        }
    }

    /// Compute SHAKE256 hash with specified output length
    pub fn shake256(data: &[u8], output_len: usize) -> HashDigest {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        
        let mut hasher = Shake256::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut digest = vec![0u8; output_len];
        reader.read(&mut digest);
        
        HashDigest {
            algorithm: HashAlgorithm::Shake256,
            digest,
        }
    }

    /// Generic hash function
    pub fn hash(algorithm: HashAlgorithm, data: &[u8], output_len: Option<usize>) -> Result<HashDigest> {
        match algorithm {
            HashAlgorithm::Sha3_256 => Ok(Self::sha3_256(data)),
            HashAlgorithm::Sha3_512 => Ok(Self::sha3_512(data)),
            HashAlgorithm::Shake128 => {
                let len = output_len.unwrap_or(32);
                Ok(Self::shake128(data, len))
            }
            HashAlgorithm::Shake256 => {
                let len = output_len.unwrap_or(64);
                Ok(Self::shake256(data, len))
            }
        }
    }

    /// Hash chain - compute hash of previous hash + new data
    pub fn chain(previous: &HashDigest, data: &[u8]) -> HashDigest {
        let mut combined = previous.digest.clone();
        combined.extend_from_slice(data);
        Self::sha3_256(&combined)
    }
}

/// HKDF-SHA3 key derivation
pub struct Hkdf;

impl Hkdf {
    /// Extract phase: compute PRK from input key material
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        let salt = salt.unwrap_or(&[0u8; 32]);
        let mut combined = salt.to_vec();
        combined.extend_from_slice(ikm);
        Hasher::sha3_256(&combined).digest
    }

    /// Expand phase: derive key material from PRK
    pub fn expand(prk: &[u8], info: Option<&[u8]>, length: usize) -> Vec<u8> {
        let info = info.unwrap_or(&[]);
        let mut output = Vec::new();
        let mut counter = 1u8;
        
        while output.len() < length {
            let mut t = prk.to_vec();
            if !output.is_empty() {
                t.extend_from_slice(&output[output.len().saturating_sub(32)..]);
            }
            t.extend_from_slice(info);
            t.push(counter);
            
            let hash = Hasher::sha3_256(&t);
            output.extend_from_slice(&hash.digest);
            counter += 1;
        }
        
        output.truncate(length);
        output
    }

    /// One-shot HKDF
    pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: Option<&[u8]>, length: usize) -> Vec<u8> {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let data = b"Hello, world!";
        let digest = Hasher::sha3_256(data);
        assert_eq!(digest.algorithm, HashAlgorithm::Sha3_256);
        assert_eq!(digest.digest.len(), 32);
        
        // Test hex conversion
        let hex = digest.to_hex();
        let from_hex = HashDigest::from_hex(HashAlgorithm::Sha3_256, &hex).unwrap();
        assert_eq!(digest, from_hex);
    }

    #[test]
    fn test_shake128() {
        let data = b"Hello, world!";
        let digest = Hasher::shake128(data, 64);
        assert_eq!(digest.algorithm, HashAlgorithm::Shake128);
        assert_eq!(digest.digest.len(), 64);
    }

    #[test]
    fn test_hash_chain() {
        let data1 = b"block1";
        let data2 = b"block2";
        
        let hash1 = Hasher::sha3_256(data1);
        let hash2 = Hasher::chain(&hash1, data2);
        
        // Verify chain property
        let mut combined = hash1.digest.clone();
        combined.extend_from_slice(data2);
        let expected = Hasher::sha3_256(&combined);
        
        assert_eq!(hash2, expected);
    }

    #[test]
    fn test_hkdf() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"application info";
        
        let derived = Hkdf::derive(Some(salt), ikm, Some(info), 32);
        assert_eq!(derived.len(), 32);
        
        // Test deterministic
        let derived2 = Hkdf::derive(Some(salt), ikm, Some(info), 32);
        assert_eq!(derived, derived2);
    }
}
