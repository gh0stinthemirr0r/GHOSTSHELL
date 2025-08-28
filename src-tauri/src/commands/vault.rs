use std::collections::HashMap;
use tauri::{State, Window};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ghost_policy::{Resource, Action};
use ghost_vault::{
    Vault, VaultConfig, CreateSecretRequest, SecretData, SecretType, SecretSummary, SecretFilter,
    MfaChallenge, MfaChallengeBuilder, MfaMethod
};
use ghost_pq::{KyberPrivateKey, KyberVariant};
use crate::security::PepState;
use crate::enforce_policy;

/// Vault state for Tauri
pub type VaultState = std::sync::Arc<tokio::sync::RwLock<Option<Vault>>>;

/// Response for vault statistics
#[derive(Debug, Serialize)]
pub struct VaultStatsResponse {
    pub total_secrets: u64,
    pub expired_secrets: u64,
    pub mfa_users: u64,
    pub active_sessions: u64,
}

/// Initialize vault
#[tauri::command]
pub async fn vault_initialize(
    master_password: String,
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Enforce policy
    let _decision = enforce_policy!(pep, Resource::Vault, Action::Create, &window);

    // Create vault config
    let config = VaultConfig {
        database_url: "data/ghostshell_vault.db".to_string(),
        require_mfa: true,
        auto_lock_timeout_minutes: 30,
        max_failed_attempts: 3,
        enable_policy_enforcement: true,
    };

    // Create vault
    let vault = Vault::new(config).await.map_err(|e| e.to_string())?;
    
    // Initialize with master password
    vault.initialize(&master_password).await.map_err(|e| e.to_string())?;

    // Store the initialized vault in the state
    let mut vault_guard = vault_state.write().await;
    *vault_guard = Some(vault);

    Ok("Vault initialized successfully".to_string())
}

/// Unlock vault
#[tauri::command]
pub async fn vault_unlock(
    master_password: String,
    kyber_secret: Vec<u8>,
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Enforce policy
    let _decision = enforce_policy!(pep, Resource::Vault, Action::Read, &window);

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        // Convert bytes to KyberPrivateKey (for demo purposes, create a new key)
        let kyber_key = KyberPrivateKey::from_bytes(kyber_secret.clone(), KyberVariant::default())
            .map_err(|e| format!("Failed to create Kyber key: {}", e))?;
        vault.unlock(&master_password, &kyber_key).await.map_err(|e| e.to_string())?;
        Ok("Vault unlocked successfully".to_string())
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Lock vault
#[tauri::command]
pub async fn vault_lock(
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Enforce policy
    let _decision = enforce_policy!(pep, Resource::Vault, Action::Update, &window);

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        vault.lock().await.map_err(|e| e.to_string())?;
        Ok("Vault locked successfully".to_string())
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Check if vault is unlocked
#[tauri::command]
pub async fn vault_is_unlocked(
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<bool, String> {
    // Enforce policy
    let _decision = enforce_policy!(pep, Resource::Vault, Action::Read, &window);

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        Ok(vault.is_unlocked().await)
    } else {
        Ok(false)
    }
}

/// Setup MFA for vault
#[tauri::command]
pub async fn vault_setup_mfa(
    user_id: String,
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<MfaSetupResponse, String> {
    // Enforce policy
    let _decision = enforce_policy!(pep, Resource::Vault, Action::Update, &window);

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let setup = vault.setup_mfa(&user_id, "GHOSTSHELL").await.map_err(|e| e.to_string())?;
        
        Ok(MfaSetupResponse {
            secret: setup.secret.unwrap_or_default(),
            backup_codes: setup.backup_codes,
            qr_code: setup.qr_code.unwrap_or_default(),
        })
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Verify MFA challenge
#[tauri::command]
pub async fn vault_verify_mfa(
    user_id: String,
    method: String,
    code: String,
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Enforce policy
    let _decision = enforce_policy!(pep, Resource::Vault, Action::Update, &window);

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let mfa_method = match method.as_str() {
            "totp" => MfaMethod::Totp,
            "backup" => MfaMethod::BackupCode,
            _ => return Err("Invalid MFA method".to_string()),
        };

        let challenge = MfaChallengeBuilder::new()
            .method(mfa_method)
            .code(code)
            .build()
            .map_err(|e| e.to_string())?;

        let session_id = vault.verify_mfa(&user_id, challenge).await.map_err(|e| e.to_string())?;
        Ok(session_id)
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Store a secret
#[tauri::command]
pub async fn vault_store_secret(
    request: CreateSecretRequestDto,
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Enforce policy with context
    let mut context = HashMap::new();
    context.insert("secret_type".to_string(), format!("{:?}", request.secret_type));
    context.insert("sensitivity".to_string(), "confidential".to_string());
    
    let _decision = enforce_policy!(pep, Resource::Vault, Action::Write, context, &window);

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        // Convert DTO to vault request
        let vault_request = CreateSecretRequest {
            name: request.name,
            description: request.description,
            secret_type: request.secret_type,
            data: request.data,
            tags: request.tags,
            expires_at: request.expires_at,
            metadata: Default::default(),
        };

        // Create execution context for vault
        let exec_context = ghost_policy::ContextBuilder::new()
            .user("current_user", "user") // TODO: Get from session
            .pq_available(true)
            .sensitivity(ghost_policy::SensitivityLevel::Confidential)
            .build();

        let secret_id = vault.store_secret(vault_request, exec_context).await.map_err(|e| e.to_string())?;
        Ok(secret_id.to_string())
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// List secrets
#[tauri::command]
pub async fn vault_list_secrets(
    filter: Option<SecretFilterDto>,
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<Vec<SecretSummary>, String> {
    // Enforce policy
    let _decision = enforce_policy!(pep, Resource::Vault, Action::Read, &window);

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let vault_filter = filter.map(|f| SecretFilter {
            secret_type: f.secret_type,
            tags: f.tags.unwrap_or_default(),
            name_pattern: f.name_pattern,
            created_after: f.created_after,
            created_before: f.created_before,
            expires_after: f.expires_after,
            expires_before: f.expires_before,
            limit: f.limit,
            offset: f.offset,
        }).unwrap_or_default();

        // Create execution context
        let exec_context = ghost_policy::ContextBuilder::new()
            .user("current_user", "user")
            .pq_available(true)
            .build();

        let summaries = vault.list_secrets(vault_filter, exec_context).await.map_err(|e| e.to_string())?;
        Ok(summaries)
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Get a secret
#[tauri::command]
pub async fn vault_get_secret(
    secret_id: String,
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<Option<SecretData>, String> {
    // Enforce policy with high sensitivity
    let mut context = HashMap::new();
    context.insert("secret_id".to_string(), secret_id.clone());
    context.insert("sensitivity".to_string(), "secret".to_string());
    
    let decision = enforce_policy!(pep, Resource::Vault, Action::Read, context, &window);

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let uuid = Uuid::parse_str(&secret_id).map_err(|e| e.to_string())?;
        
        // Create execution context
        let exec_context = ghost_policy::ContextBuilder::new()
            .user("current_user", "user")
            .pq_available(true)
            .sensitivity(ghost_policy::SensitivityLevel::Secret)
            .build();

        let secret_data = vault.get_secret(&uuid, exec_context).await.map_err(|e| e.to_string())?;
        
        // Apply policy constraints
        if decision.mask_preview {
            // Return masked version if policy requires it
            if let Some(data) = &secret_data {
                return Ok(Some(data.masked()));
            }
        }
        
        Ok(secret_data)
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Delete a secret
#[tauri::command]
pub async fn vault_delete_secret(
    secret_id: String,
    justification: Option<String>,
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<bool, String> {
    // Enforce policy with context
    let mut context = HashMap::new();
    context.insert("secret_id".to_string(), secret_id.clone());
    context.insert("operation".to_string(), "delete".to_string());
    if let Some(ref just) = justification {
        context.insert("justification".to_string(), just.clone());
    }
    
    let decision = enforce_policy!(pep, Resource::Vault, Action::Delete, context, &window);
    
    // Check if justification is required
    if decision.requires_justification && justification.is_none() {
        return Err("Justification required for secret deletion".to_string());
    }

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let uuid = Uuid::parse_str(&secret_id).map_err(|e| e.to_string())?;
        
        // Create execution context
        let exec_context = ghost_policy::ContextBuilder::new()
            .user("current_user", "user")
            .pq_available(true)
            .build();

        let deleted = vault.delete_secret(&uuid, exec_context).await.map_err(|e| e.to_string())?;
        Ok(deleted)
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Get vault statistics
#[tauri::command]
pub async fn vault_get_stats(
    vault_state: State<'_, VaultState>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<VaultStatsResponse, String> {
    // Enforce policy
    let _decision = enforce_policy!(pep, Resource::Vault, Action::Read, &window);

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let stats = vault.get_stats().await.map_err(|e| e.to_string())?;
        
        Ok(VaultStatsResponse {
            total_secrets: stats.total_secrets,
            expired_secrets: stats.expired_secrets,
            mfa_users: stats.mfa_users,
            active_sessions: stats.active_sessions,
        })
    } else {
        Err("Vault not initialized".to_string())
    }
}

// DTOs for Tauri commands

#[derive(Debug, Deserialize)]
pub struct CreateSecretRequestDto {
    pub name: String,
    pub description: Option<String>,
    pub secret_type: SecretType,
    pub data: SecretData,
    pub tags: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct SecretFilterDto {
    pub secret_type: Option<SecretType>,
    pub tags: Option<Vec<String>>,
    pub name_pattern: Option<String>,
    pub created_after: Option<chrono::DateTime<chrono::Utc>>,
    pub created_before: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_after: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_before: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub backup_codes: Vec<String>,
    pub qr_code: Vec<u8>,
}



/// Initialize vault state for Tauri
pub fn create_vault_state() -> VaultState {
    std::sync::Arc::new(tokio::sync::RwLock::new(None))
}
