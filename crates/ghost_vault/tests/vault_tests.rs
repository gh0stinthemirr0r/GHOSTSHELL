use ghost_vault::*;
use ghost_policy::{ContextBuilder, SensitivityLevel, NetworkTrust};
use std::collections::HashMap;
use tempfile::TempDir;

async fn create_test_vault() -> (Vault, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config = VaultConfig {
        database_url: temp_dir.path().join("test_vault.db").to_string_lossy().to_string(),
        require_mfa: false, // Disable MFA for testing
        auto_lock_timeout_minutes: 60,
        max_failed_attempts: 3,
        enable_policy_enforcement: false, // Disable policy for basic tests
    };
    
    let vault = Vault::new(config).await.expect("Failed to create vault");
    vault.initialize("test_master_password").await.expect("Failed to initialize vault");
    vault.unlock("test_master_password", &[0u8; 32]).await.expect("Failed to unlock vault");
    
    (vault, temp_dir)
}

fn create_test_context() -> ghost_policy::ExecutionContext {
    ContextBuilder::new()
        .user("test_user", "user")
        .pq_available(true)
        .network_trust(NetworkTrust::Trusted)
        .sensitivity(SensitivityLevel::Internal)
        .build()
}

#[tokio::test]
async fn test_vault_initialization_and_unlock() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config = VaultConfig {
        database_url: temp_dir.path().join("init_test.db").to_string_lossy().to_string(),
        require_mfa: false,
        auto_lock_timeout_minutes: 30,
        max_failed_attempts: 3,
        enable_policy_enforcement: false,
    };
    
    let vault = Vault::new(config).await.expect("Failed to create vault");
    
    // Test initialization
    vault.initialize("strong_master_password_123").await.expect("Failed to initialize vault");
    
    // Test unlock with correct password
    let kyber_secret = [1u8; 32]; // Mock Kyber secret
    vault.unlock("strong_master_password_123", &kyber_secret).await.expect("Failed to unlock vault");
    
    assert!(vault.is_unlocked().await, "Vault should be unlocked");
    
    // Test lock
    vault.lock().await.expect("Failed to lock vault");
    assert!(!vault.is_unlocked().await, "Vault should be locked");
    
    // Test unlock with wrong password
    let result = vault.unlock("wrong_password", &kyber_secret).await;
    assert!(result.is_err(), "Should fail with wrong password");
}

#[tokio::test]
async fn test_secret_storage_and_retrieval() {
    let (vault, _temp_dir) = create_test_vault().await;
    let context = create_test_context();
    
    // Create a password secret
    let password_request = CreateSecretRequest {
        name: "Test Login".to_string(),
        description: Some("Test website login".to_string()),
        secret_type: SecretType::Password,
        data: SecretData::Password {
            username: "testuser".to_string(),
            password: "secret123".to_string(),
            url: Some("https://example.com".to_string()),
            notes: Some("Test notes".to_string()),
        },
        tags: vec!["test".to_string(), "website".to_string()],
        expires_at: None,
        metadata: HashMap::new(),
    };
    
    // Store the secret
    let secret_id = vault.store_secret(password_request, context.clone()).await
        .expect("Failed to store secret");
    
    // Retrieve the secret
    let retrieved_secret = vault.get_secret(&secret_id, context.clone()).await
        .expect("Failed to retrieve secret")
        .expect("Secret should exist");
    
    // Verify the data
    match retrieved_secret.data {
        SecretData::Password { username, password, url, notes } => {
            assert_eq!(username, "testuser");
            assert_eq!(password, "secret123");
            assert_eq!(url, Some("https://example.com".to_string()));
            assert_eq!(notes, Some("Test notes".to_string()));
        }
        _ => panic!("Expected password secret type"),
    }
    
    assert_eq!(retrieved_secret.name, "Test Login");
    assert!(retrieved_secret.tags.contains(&"test".to_string()));
}

#[tokio::test]
async fn test_different_secret_types() {
    let (vault, _temp_dir) = create_test_vault().await;
    let context = create_test_context();
    
    // Test SSH Key
    let ssh_request = CreateSecretRequest {
        name: "SSH Key".to_string(),
        description: Some("Server SSH key".to_string()),
        secret_type: SecretType::SshKey,
        data: SecretData::SshKey {
            private_key: "-----BEGIN PRIVATE KEY-----\ntest_key\n-----END PRIVATE KEY-----".to_string(),
            public_key: Some("ssh-rsa AAAAB3...".to_string()),
            passphrase: Some("key_passphrase".to_string()),
            comment: Some("test@example.com".to_string()),
        },
        tags: vec!["ssh".to_string()],
        expires_at: None,
        metadata: HashMap::new(),
    };
    
    let ssh_id = vault.store_secret(ssh_request, context.clone()).await
        .expect("Failed to store SSH key");
    
    // Test API Token
    let api_request = CreateSecretRequest {
        name: "API Token".to_string(),
        description: Some("Service API token".to_string()),
        secret_type: SecretType::ApiToken,
        data: SecretData::ApiToken {
            token: "sk-1234567890abcdef".to_string(),
            service: "OpenAI".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            expires_at: None,
        },
        tags: vec!["api".to_string()],
        expires_at: None,
        metadata: HashMap::new(),
    };
    
    let api_id = vault.store_secret(api_request, context.clone()).await
        .expect("Failed to store API token");
    
    // Test Custom Secret
    let custom_request = CreateSecretRequest {
        name: "Custom Data".to_string(),
        description: Some("Custom secret data".to_string()),
        secret_type: SecretType::CustomSecret,
        data: SecretData::Custom {
            data: r#"{"custom": "data", "number": 42}"#.to_string(),
            content_type: Some("application/json".to_string()),
        },
        tags: vec!["custom".to_string()],
        expires_at: None,
        metadata: HashMap::new(),
    };
    
    let custom_id = vault.store_secret(custom_request, context.clone()).await
        .expect("Failed to store custom secret");
    
    // Verify all secrets exist
    let ssh_secret = vault.get_secret(&ssh_id, context.clone()).await.expect("Failed to get SSH secret");
    let api_secret = vault.get_secret(&api_id, context.clone()).await.expect("Failed to get API secret");
    let custom_secret = vault.get_secret(&custom_id, context.clone()).await.expect("Failed to get custom secret");
    
    assert!(ssh_secret.is_some());
    assert!(api_secret.is_some());
    assert!(custom_secret.is_some());
}

#[tokio::test]
async fn test_secret_filtering_and_search() {
    let (vault, _temp_dir) = create_test_vault().await;
    let context = create_test_context();
    
    // Store multiple secrets with different tags
    let secrets = vec![
        ("Website Login 1", vec!["website", "personal"]),
        ("Website Login 2", vec!["website", "work"]),
        ("Database Creds", vec!["database", "work"]),
        ("API Key", vec!["api", "development"]),
    ];
    
    for (name, tags) in secrets {
        let request = CreateSecretRequest {
            name: name.to_string(),
            description: Some(format!("Description for {}", name)),
            secret_type: SecretType::Password,
            data: SecretData::Password {
                username: "user".to_string(),
                password: "pass".to_string(),
                url: None,
                notes: None,
            },
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            expires_at: None,
            metadata: HashMap::new(),
        };
        
        vault.store_secret(request, context.clone()).await
            .expect("Failed to store secret");
    }
    
    // Test filtering by tags
    let work_filter = SecretFilter {
        tags: vec!["work".to_string()],
        ..Default::default()
    };
    
    let work_secrets = vault.list_secrets(work_filter, context.clone()).await
        .expect("Failed to list work secrets");
    
    assert_eq!(work_secrets.len(), 2, "Should find 2 work secrets");
    
    // Test filtering by secret type
    let password_filter = SecretFilter {
        secret_type: Some(SecretType::Password),
        ..Default::default()
    };
    
    let password_secrets = vault.list_secrets(password_filter, context.clone()).await
        .expect("Failed to list password secrets");
    
    assert_eq!(password_secrets.len(), 4, "Should find 4 password secrets");
    
    // Test name pattern matching
    let website_filter = SecretFilter {
        name_pattern: Some("Website".to_string()),
        ..Default::default()
    };
    
    let website_secrets = vault.list_secrets(website_filter, context.clone()).await
        .expect("Failed to list website secrets");
    
    assert_eq!(website_secrets.len(), 2, "Should find 2 website secrets");
}

#[tokio::test]
async fn test_secret_deletion() {
    let (vault, _temp_dir) = create_test_vault().await;
    let context = create_test_context();
    
    // Store a secret
    let request = CreateSecretRequest {
        name: "To Delete".to_string(),
        description: Some("Secret to be deleted".to_string()),
        secret_type: SecretType::SecureNote,
        data: SecretData::SecureNote {
            content: "This will be deleted".to_string(),
        },
        tags: vec!["temp".to_string()],
        expires_at: None,
        metadata: HashMap::new(),
    };
    
    let secret_id = vault.store_secret(request, context.clone()).await
        .expect("Failed to store secret");
    
    // Verify it exists
    let secret = vault.get_secret(&secret_id, context.clone()).await
        .expect("Failed to get secret");
    assert!(secret.is_some(), "Secret should exist before deletion");
    
    // Delete the secret
    let deleted = vault.delete_secret(&secret_id, context.clone()).await
        .expect("Failed to delete secret");
    assert!(deleted, "Secret should be successfully deleted");
    
    // Verify it's gone
    let secret = vault.get_secret(&secret_id, context.clone()).await
        .expect("Failed to check deleted secret");
    assert!(secret.is_none(), "Secret should not exist after deletion");
}

#[tokio::test]
async fn test_mfa_setup_and_verification() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config = VaultConfig {
        database_url: temp_dir.path().join("mfa_test.db").to_string_lossy().to_string(),
        require_mfa: true,
        auto_lock_timeout_minutes: 30,
        max_failed_attempts: 3,
        enable_policy_enforcement: false,
    };
    
    let vault = Vault::new(config).await.expect("Failed to create vault");
    vault.initialize("test_password").await.expect("Failed to initialize vault");
    
    // Setup MFA
    let mfa_setup = vault.setup_mfa("test_user", "GHOSTSHELL").await
        .expect("Failed to setup MFA");
    
    assert!(!mfa_setup.secret.is_empty(), "MFA secret should not be empty");
    assert!(!mfa_setup.backup_codes.is_empty(), "Should have backup codes");
    assert!(mfa_setup.qr_code.is_some(), "Should have QR code");
    
    // Test TOTP verification (we'll use a mock code since we can't generate real TOTP)
    let challenge = MfaChallengeBuilder::new()
        .method(MfaMethod::BackupCode)
        .code(mfa_setup.backup_codes[0].clone())
        .build()
        .expect("Failed to build MFA challenge");
    
    let session_id = vault.verify_mfa("test_user", challenge).await
        .expect("Failed to verify MFA with backup code");
    
    assert!(!session_id.is_empty(), "Should return valid session ID");
}

#[tokio::test]
async fn test_vault_statistics() {
    let (vault, _temp_dir) = create_test_vault().await;
    let context = create_test_context();
    
    // Store some secrets
    for i in 0..5 {
        let request = CreateSecretRequest {
            name: format!("Test Secret {}", i),
            description: Some(format!("Description {}", i)),
            secret_type: SecretType::Password,
            data: SecretData::Password {
                username: format!("user{}", i),
                password: format!("pass{}", i),
                url: None,
                notes: None,
            },
            tags: vec!["test".to_string()],
            expires_at: None,
            metadata: HashMap::new(),
        };
        
        vault.store_secret(request, context.clone()).await
            .expect("Failed to store secret");
    }
    
    // Get statistics
    let stats = vault.get_stats().await.expect("Failed to get vault stats");
    
    assert_eq!(stats.total_secrets, 5, "Should have 5 secrets");
    assert!(stats.total_batches > 0, "Should have audit batches");
    assert!(stats.latest_entry.is_some(), "Should have latest entry timestamp");
}

#[tokio::test]
async fn test_vault_encryption_integrity() {
    let (vault, _temp_dir) = create_test_vault().await;
    let context = create_test_context();
    
    let sensitive_data = "Very sensitive information that must be encrypted";
    
    let request = CreateSecretRequest {
        name: "Sensitive Data".to_string(),
        description: Some("Highly sensitive information".to_string()),
        secret_type: SecretType::SecureNote,
        data: SecretData::SecureNote {
            content: sensitive_data.to_string(),
        },
        tags: vec!["sensitive".to_string()],
        expires_at: None,
        metadata: HashMap::new(),
    };
    
    let secret_id = vault.store_secret(request, context.clone()).await
        .expect("Failed to store sensitive secret");
    
    // Lock and unlock the vault to test encryption/decryption
    vault.lock().await.expect("Failed to lock vault");
    assert!(!vault.is_unlocked().await, "Vault should be locked");
    
    vault.unlock("test_master_password", &[0u8; 32]).await
        .expect("Failed to unlock vault");
    
    // Retrieve and verify the data
    let retrieved = vault.get_secret(&secret_id, context).await
        .expect("Failed to retrieve secret after unlock")
        .expect("Secret should exist");
    
    match retrieved.data {
        SecretData::SecureNote { content } => {
            assert_eq!(content, sensitive_data, "Decrypted data should match original");
        }
        _ => panic!("Expected secure note type"),
    }
}

#[tokio::test]
async fn test_vault_error_handling() {
    let (vault, _temp_dir) = create_test_vault().await;
    let context = create_test_context();
    
    // Test retrieving non-existent secret
    let fake_id = uuid::Uuid::new_v4();
    let result = vault.get_secret(&fake_id, context.clone()).await;
    assert!(result.is_ok(), "Should not error for non-existent secret");
    assert!(result.unwrap().is_none(), "Should return None for non-existent secret");
    
    // Test deleting non-existent secret
    let deleted = vault.delete_secret(&fake_id, context.clone()).await
        .expect("Should not error when deleting non-existent secret");
    assert!(!deleted, "Should return false for non-existent secret");
    
    // Test operations on locked vault
    vault.lock().await.expect("Failed to lock vault");
    
    let request = CreateSecretRequest {
        name: "Test".to_string(),
        description: None,
        secret_type: SecretType::SecureNote,
        data: SecretData::SecureNote {
            content: "test".to_string(),
        },
        tags: vec![],
        expires_at: None,
        metadata: HashMap::new(),
    };
    
    let result = vault.store_secret(request, context).await;
    assert!(result.is_err(), "Should fail to store secret in locked vault");
}

#[tokio::test]
async fn test_vault_concurrent_access() {
    let (vault, _temp_dir) = create_test_vault().await;
    let vault = std::sync::Arc::new(vault);
    
    let mut handles = vec![];
    
    // Spawn multiple tasks to store secrets concurrently
    for i in 0..10 {
        let vault_clone = vault.clone();
        let handle = tokio::spawn(async move {
            let context = create_test_context();
            let request = CreateSecretRequest {
                name: format!("Concurrent Secret {}", i),
                description: Some(format!("Created by task {}", i)),
                secret_type: SecretType::Password,
                data: SecretData::Password {
                    username: format!("user{}", i),
                    password: format!("pass{}", i),
                    url: None,
                    notes: None,
                },
                tags: vec!["concurrent".to_string()],
                expires_at: None,
                metadata: HashMap::new(),
            };
            
            vault_clone.store_secret(request, context).await
        });
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    let mut secret_ids = vec![];
    for handle in handles {
        let secret_id = handle.await.expect("Task should complete")
            .expect("Should store secret successfully");
        secret_ids.push(secret_id);
    }
    
    // Verify all secrets were stored
    assert_eq!(secret_ids.len(), 10, "Should have 10 secret IDs");
    
    let context = create_test_context();
    let filter = SecretFilter {
        tags: vec!["concurrent".to_string()],
        ..Default::default()
    };
    
    let secrets = vault.list_secrets(filter, context).await
        .expect("Failed to list concurrent secrets");
    
    assert_eq!(secrets.len(), 10, "Should find all 10 concurrent secrets");
}
