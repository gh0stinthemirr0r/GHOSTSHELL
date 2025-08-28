use ghost_pq::*;
use std::collections::HashMap;

#[tokio::test]
async fn test_kyber_kem_operations() {
    // Test Kyber KEM key generation and encapsulation
    let (public_key, secret_key) = kyber_keygen().expect("Failed to generate Kyber keypair");
    
    assert!(!public_key.is_empty(), "Public key should not be empty");
    assert!(!secret_key.is_empty(), "Secret key should not be empty");
    
    // Test encapsulation
    let (ciphertext, shared_secret) = kyber_encapsulate(&public_key)
        .expect("Failed to encapsulate with Kyber");
    
    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
    assert!(!shared_secret.is_empty(), "Shared secret should not be empty");
    assert_eq!(shared_secret.len(), 32, "Shared secret should be 32 bytes");
    
    // Test decapsulation
    let decapsulated_secret = kyber_decapsulate(&ciphertext, &secret_key)
        .expect("Failed to decapsulate with Kyber");
    
    assert_eq!(shared_secret, decapsulated_secret, "Shared secrets should match");
}

#[tokio::test]
async fn test_dilithium_signatures() {
    // Test Dilithium signature generation and verification
    let (public_key, secret_key) = dilithium_keygen().expect("Failed to generate Dilithium keypair");
    
    assert!(!public_key.is_empty(), "Public key should not be empty");
    assert!(!secret_key.is_empty(), "Secret key should not be empty");
    
    let message = b"Hello, post-quantum world!";
    
    // Test signing
    let signature = dilithium_sign(message, &secret_key)
        .expect("Failed to sign message");
    
    assert!(!signature.is_empty(), "Signature should not be empty");
    
    // Test verification
    let is_valid = dilithium_verify(message, &signature, &public_key)
        .expect("Failed to verify signature");
    
    assert!(is_valid, "Signature should be valid");
    
    // Test with tampered message
    let tampered_message = b"Hello, post-quantum world?";
    let is_invalid = dilithium_verify(tampered_message, &signature, &public_key)
        .expect("Failed to verify tampered signature");
    
    assert!(!is_invalid, "Tampered signature should be invalid");
}

#[tokio::test]
async fn test_sha3_hashing() {
    let data = b"Test data for SHA3 hashing";
    
    // Test SHA3-256
    let hash = sha3_256(data).expect("Failed to compute SHA3-256");
    assert_eq!(hash.len(), 32, "SHA3-256 hash should be 32 bytes");
    
    // Test consistency
    let hash2 = sha3_256(data).expect("Failed to compute SHA3-256 again");
    assert_eq!(hash, hash2, "SHA3-256 should be deterministic");
    
    // Test SHAKE-256
    let shake_output = shake256(data, 64).expect("Failed to compute SHAKE-256");
    assert_eq!(shake_output.len(), 64, "SHAKE-256 output should be 64 bytes");
}

#[tokio::test]
async fn test_envelope_encryption() {
    let plaintext = b"Secret data to encrypt";
    let aad = b"Additional authenticated data";
    
    // Test AES-GCM envelope encryption
    let encrypted = envelope_encrypt_aes(plaintext, aad)
        .expect("Failed to encrypt with AES-GCM");
    
    assert!(!encrypted.ciphertext.is_empty(), "Ciphertext should not be empty");
    assert!(!encrypted.sealed_key.is_empty(), "Sealed key should not be empty");
    assert!(!encrypted.nonce.is_empty(), "Nonce should not be empty");
    
    // Test decryption
    let decrypted = envelope_decrypt_aes(&encrypted, aad)
        .expect("Failed to decrypt with AES-GCM");
    
    assert_eq!(plaintext, decrypted.as_slice(), "Decrypted data should match original");
    
    // Test ChaCha20-Poly1305 envelope encryption
    let encrypted_chacha = envelope_encrypt_chacha(plaintext, aad)
        .expect("Failed to encrypt with ChaCha20-Poly1305");
    
    let decrypted_chacha = envelope_decrypt_chacha(&encrypted_chacha, aad)
        .expect("Failed to decrypt with ChaCha20-Poly1305");
    
    assert_eq!(plaintext, decrypted_chacha.as_slice(), "ChaCha20 decrypted data should match original");
}

#[tokio::test]
async fn test_key_management_system() {
    let mut kms = KeyManagementSystem::new();
    
    // Test key generation
    let key_id = kms.generate_key("test-key", KeyType::Symmetric)
        .expect("Failed to generate key");
    
    assert!(!key_id.is_empty(), "Key ID should not be empty");
    
    // Test key retrieval
    let key_material = kms.get_key(&key_id)
        .expect("Failed to get key");
    
    assert!(key_material.is_some(), "Key should exist");
    let key = key_material.unwrap();
    assert!(!key.is_empty(), "Key material should not be empty");
    
    // Test key rotation
    let new_key_id = kms.rotate_key(&key_id)
        .expect("Failed to rotate key");
    
    assert_ne!(key_id, new_key_id, "Rotated key should have different ID");
    
    // Test key deletion
    kms.delete_key(&key_id).expect("Failed to delete key");
    let deleted_key = kms.get_key(&key_id).expect("Failed to check deleted key");
    assert!(deleted_key.is_none(), "Deleted key should not exist");
}

#[tokio::test]
async fn test_crypto_error_handling() {
    // Test invalid key sizes
    let invalid_key = vec![0u8; 10]; // Too short
    let result = kyber_decapsulate(&[0u8; 100], &invalid_key);
    assert!(result.is_err(), "Should fail with invalid key");
    
    // Test invalid signature verification
    let (public_key, _) = dilithium_keygen().expect("Failed to generate keypair");
    let invalid_signature = vec![0u8; 10];
    let result = dilithium_verify(b"test", &invalid_signature, &public_key);
    assert!(result.is_err(), "Should fail with invalid signature");
}

#[tokio::test]
async fn test_performance_benchmarks() {
    use std::time::Instant;
    
    // Benchmark Kyber operations
    let start = Instant::now();
    let (pk, sk) = kyber_keygen().expect("Failed to generate Kyber keypair");
    let keygen_time = start.elapsed();
    
    let start = Instant::now();
    let (ct, ss) = kyber_encapsulate(&pk).expect("Failed to encapsulate");
    let encap_time = start.elapsed();
    
    let start = Instant::now();
    let _ss2 = kyber_decapsulate(&ct, &sk).expect("Failed to decapsulate");
    let decap_time = start.elapsed();
    
    println!("Kyber Performance:");
    println!("  Keygen: {:?}", keygen_time);
    println!("  Encapsulate: {:?}", encap_time);
    println!("  Decapsulate: {:?}", decap_time);
    
    // Benchmark Dilithium operations
    let start = Instant::now();
    let (pk, sk) = dilithium_keygen().expect("Failed to generate Dilithium keypair");
    let keygen_time = start.elapsed();
    
    let message = b"Performance test message";
    let start = Instant::now();
    let sig = dilithium_sign(message, &sk).expect("Failed to sign");
    let sign_time = start.elapsed();
    
    let start = Instant::now();
    let _valid = dilithium_verify(message, &sig, &pk).expect("Failed to verify");
    let verify_time = start.elapsed();
    
    println!("Dilithium Performance:");
    println!("  Keygen: {:?}", keygen_time);
    println!("  Sign: {:?}", sign_time);
    println!("  Verify: {:?}", verify_time);
    
    // Performance assertions (reasonable bounds)
    assert!(keygen_time.as_millis() < 100, "Keygen should be reasonably fast");
    assert!(sign_time.as_millis() < 50, "Signing should be reasonably fast");
    assert!(verify_time.as_millis() < 50, "Verification should be reasonably fast");
}
