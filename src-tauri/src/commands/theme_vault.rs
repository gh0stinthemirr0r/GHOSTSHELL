use std::collections::HashMap;
use tauri::{State, Window};
use serde::{Deserialize, Serialize};
use uuid::Uuid;


use ghost_vault::{SecretData, SecretType, CreateSecretRequest, SecretMetadata};
// Policy enforcement removed for single-user mode
use crate::commands::vault::VaultState;
use crate::commands::theme::ThemeV1;

/// Theme stored in vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTheme {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub theme_data: ThemeV1,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub tags: Vec<String>,
    pub is_default: bool,
    pub author: Option<String>,
}

/// Theme metadata for listing
#[derive(Debug, Clone, Serialize)]
pub struct VaultThemeMetadata {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub tags: Vec<String>,
    pub is_default: bool,
    pub author: Option<String>,
}

/// Create theme request
#[derive(Debug, Deserialize)]
pub struct CreateThemeRequest {
    pub name: String,
    pub description: Option<String>,
    pub theme_data: ThemeV1,
    pub tags: Vec<String>,
    pub is_default: bool,
}

/// Update theme request
#[derive(Debug, Deserialize)]
pub struct UpdateThemeRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub theme_data: Option<ThemeV1>,
    pub tags: Option<Vec<String>>,
    pub is_default: Option<bool>,
}

/// Store theme in vault
#[tauri::command]
pub async fn vault_store_theme(
    request: CreateThemeRequest,
    vault_state: State<'_, VaultState>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<String, String> {
    // Enforce policy with context
    let mut context = HashMap::new();
    context.insert("resource_type".to_string(), "theme".to_string());
    context.insert("operation".to_string(), "store".to_string());
    
    // Policy enforcement removed for single-user mode

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let theme_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        
        let vault_theme = VaultTheme {
            id: theme_id.to_string(),
            name: request.name.clone(),
            description: request.description.clone(),
            theme_data: request.theme_data,
            created_at: now,
            updated_at: now,
            tags: request.tags,
            is_default: request.is_default,
            author: Some("current_user".to_string()), // TODO: Get from session
        };

        // Serialize theme as JSON
        let theme_json = serde_json::to_string(&vault_theme).map_err(|e| e.to_string())?;

        // Create vault secret request
        let mut secret_tags = vec!["theme".to_string(), "ui".to_string()];
        secret_tags.extend(vault_theme.tags.clone());
        
        let vault_request = CreateSecretRequest {
            name: format!("Theme: {}", request.name),
            description: request.description.or_else(|| Some("GHOSTSHELL UI Theme".to_string())),
            secret_type: SecretType::Custom("theme".to_string()),
            data: SecretData::Custom {
                data: serde_json::Value::String(theme_json),
            },
            tags: secret_tags,
            expires_at: None, // Themes don't expire
            metadata: SecretMetadata {
                notes: Some(format!("GHOSTSHELL Theme - Default: {}", vault_theme.is_default)),
                ..Default::default()
            },
        };

        // Simplified for single-user mode
        let secret_id = vault.store_secret(vault_request).await.map_err(|e| e.to_string())?;
        
        tracing::info!("Theme '{}' stored in vault with ID: {}", request.name, secret_id);
        Ok(secret_id.to_string())
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// List themes from vault
#[tauri::command]
pub async fn vault_list_themes(
    vault_state: State<'_, VaultState>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<Vec<VaultThemeMetadata>, String> {
    // Enforce policy
    // Policy enforcement removed for single-user mode

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        // Create filter for theme secrets
        let filter = ghost_vault::SecretFilter {
            secret_type: Some(SecretType::Custom("theme".to_string())),
            tags: vec!["theme".to_string()],
            name_pattern: Some("Theme:".to_string()),
            ..Default::default()
        };

        // Simplified for single-user mode
        let summaries = vault.list_secrets(filter).await.map_err(|e| e.to_string())?;
        
        let mut themes = Vec::new();
        
        for summary in summaries {
            // Get the full secret to extract theme metadata
            let secret_data = vault.get_secret(&summary.id).await.map_err(|e| e.to_string())?;
            
            if let Some(data) = secret_data {
                if let SecretData::Custom { data: json_data } = data {
                    match serde_json::from_value::<VaultTheme>(json_data) {
                        Ok(vault_theme) => {
                            themes.push(VaultThemeMetadata {
                                id: vault_theme.id,
                                name: vault_theme.name,
                                description: vault_theme.description,
                                created_at: vault_theme.created_at,
                                updated_at: vault_theme.updated_at,
                                tags: vault_theme.tags,
                                is_default: vault_theme.is_default,
                                author: vault_theme.author,
                            });
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse theme data for secret {}: {}", summary.id, e);
                        }
                    }
                }
            }
        }

        // Sort by updated_at descending
        themes.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        
        Ok(themes)
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Get theme from vault
#[tauri::command]
pub async fn vault_get_theme(
    theme_id: String,
    vault_state: State<'_, VaultState>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<Option<VaultTheme>, String> {
    // Enforce policy with context
    let mut context = HashMap::new();
    context.insert("theme_id".to_string(), theme_id.clone());
    
    // Policy enforcement removed for single-user mode

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let uuid = Uuid::parse_str(&theme_id).map_err(|e| e.to_string())?;
        
        // Create execution context
        // Simplified for single-user mode

        let secret_data = vault.get_secret(&uuid).await.map_err(|e| e.to_string())?;
        
        if let Some(data) = secret_data {
            if let SecretData::Custom { data: json_data } = data {
                match serde_json::from_value::<VaultTheme>(json_data) {
                    Ok(vault_theme) => Ok(Some(vault_theme)),
                    Err(e) => Err(format!("Failed to parse theme data: {}", e)),
                }
            } else {
                Err("Invalid secret type for theme".to_string())
            }
        } else {
            Ok(None)
        }
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Update theme in vault
#[tauri::command]
pub async fn vault_update_theme(
    theme_id: String,
    request: UpdateThemeRequest,
    vault_state: State<'_, VaultState>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<String, String> {
    // Enforce policy with context
    let mut context = HashMap::new();
    context.insert("theme_id".to_string(), theme_id.clone());
    context.insert("operation".to_string(), "update".to_string());
    
    // Policy enforcement removed for single-user mode

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        // First, get the existing theme
        let uuid = Uuid::parse_str(&theme_id).map_err(|e| e.to_string())?;
        
        // Simplified for single-user mode

        let secret_data = vault.get_secret(&uuid).await.map_err(|e| e.to_string())?;
        
        if let Some(data) = secret_data {
            if let SecretData::Custom { data: json_data } = data {
                let mut vault_theme: VaultTheme = serde_json::from_value(json_data).map_err(|e| e.to_string())?;
                
                // Update fields if provided
                if let Some(name) = request.name {
                    vault_theme.name = name;
                }
                if let Some(description) = request.description {
                    vault_theme.description = Some(description);
                }
                if let Some(theme_data) = request.theme_data {
                    vault_theme.theme_data = theme_data;
                }
                if let Some(tags) = request.tags {
                    vault_theme.tags = tags;
                }
                if let Some(is_default) = request.is_default {
                    vault_theme.is_default = is_default;
                }
                
                vault_theme.updated_at = chrono::Utc::now();

                // Serialize updated theme
                let updated_json = serde_json::to_string(&vault_theme).map_err(|e| e.to_string())?;

                // Update the secret (this would require implementing update in the vault)
                // For now, we'll delete and recreate
                vault.delete_secret(&uuid).await.map_err(|e| e.to_string())?;

                // Create new secret with updated data
                let mut secret_tags = vec!["theme".to_string(), "ui".to_string()];
                secret_tags.extend(vault_theme.tags.clone());
                
                let vault_request = CreateSecretRequest {
                    name: format!("Theme: {}", vault_theme.name),
                    description: vault_theme.description.clone(),
                    secret_type: SecretType::Custom("theme".to_string()),
                    data: SecretData::Custom {
                        data: serde_json::Value::String(updated_json),
                    },
                    tags: secret_tags,
                    expires_at: None,
                    metadata: SecretMetadata {
                        notes: Some(format!("Updated GHOSTSHELL Theme - Default: {}", vault_theme.is_default)),
                        ..Default::default()
                    },
                };

                let new_secret_id = vault.store_secret(vault_request).await.map_err(|e| e.to_string())?;
                
                tracing::info!("Theme '{}' updated in vault with new ID: {}", vault_theme.name, new_secret_id);
                Ok(new_secret_id.to_string())
            } else {
                Err("Invalid secret type for theme".to_string())
            }
        } else {
            Err("Theme not found".to_string())
        }
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Delete theme from vault
#[tauri::command]
pub async fn vault_delete_theme(
    theme_id: String,
    justification: Option<String>,
    vault_state: State<'_, VaultState>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<bool, String> {
    // Enforce policy with context
    let mut context = HashMap::new();
    context.insert("theme_id".to_string(), theme_id.clone());
    context.insert("operation".to_string(), "delete".to_string());
    if let Some(ref just) = justification {
        context.insert("justification".to_string(), just.clone());
    }
    
    // Policy enforcement removed for single-user mode
    
    // Policy enforcement removed for single-user mode

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let uuid = Uuid::parse_str(&theme_id).map_err(|e| e.to_string())?;
        
        // Simplified for single-user mode

        let deleted = vault.delete_secret(&uuid).await.map_err(|e| e.to_string())?;
        
        if deleted {
            tracing::info!("Theme deleted from vault: {}", theme_id);
        }
        
        Ok(deleted)
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Export theme from vault
#[tauri::command]
pub async fn vault_export_theme(
    theme_id: String,
    vault_state: State<'_, VaultState>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<String, String> {
    // Enforce policy with context
    let mut context = HashMap::new();
    context.insert("theme_id".to_string(), theme_id.clone());
    context.insert("operation".to_string(), "export".to_string());
    
    // Policy enforcement removed for single-user mode

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        let uuid = Uuid::parse_str(&theme_id).map_err(|e| e.to_string())?;
        
        // Simplified for single-user mode

        let secret_data = vault.get_secret(&uuid).await.map_err(|e| e.to_string())?;
        
        if let Some(data) = secret_data {
            if let SecretData::Custom { data: json_data } = data {
                let vault_theme: VaultTheme = serde_json::from_value(json_data).map_err(|e| e.to_string())?;
                
                // Export as JSON with metadata
                let export_data = serde_json::json!({
                    "format": "ghostshell_theme_export",
                    "version": "1.0",
                    "exported_at": chrono::Utc::now(),
                    "theme": vault_theme
                });
                
                serde_json::to_string_pretty(&export_data).map_err(|e| e.to_string())
            } else {
                Err("Invalid secret type for theme".to_string())
            }
        } else {
            Err("Theme not found".to_string())
        }
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Import theme to vault
#[tauri::command]
pub async fn vault_import_theme(
    theme_data: String,
    vault_state: State<'_, VaultState>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<String, String> {
    // Enforce policy with context
    let mut context = HashMap::new();
    context.insert("operation".to_string(), "import".to_string());
    
    // Policy enforcement removed for single-user mode

    let vault_guard = vault_state.read().await;
    if let Some(vault) = vault_guard.as_ref() {
        // Parse the import data
        let import_json: serde_json::Value = serde_json::from_str(&theme_data).map_err(|e| e.to_string())?;
        
        let vault_theme = if import_json.get("format").and_then(|f| f.as_str()) == Some("ghostshell_theme_export") {
            // New export format
            let theme_obj = import_json.get("theme").ok_or("Missing theme data in export")?;
            serde_json::from_value::<VaultTheme>(theme_obj.clone()).map_err(|e| e.to_string())?
        } else {
            // Legacy format - assume it's a direct ThemeV1 object
            let theme_v1: ThemeV1 = serde_json::from_str(&theme_data).map_err(|e| e.to_string())?;
            
            VaultTheme {
                id: Uuid::new_v4().to_string(),
                name: "Imported Theme".to_string(),
                description: Some("Imported from legacy format".to_string()),
                theme_data: theme_v1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                tags: vec!["imported".to_string()],
                is_default: false,
                author: Some("current_user".to_string()),
            }
        };

        // Store the imported theme
        let request = CreateThemeRequest {
            name: vault_theme.name.clone(),
            description: vault_theme.description.clone(),
            theme_data: vault_theme.theme_data,
            tags: vault_theme.tags,
            is_default: vault_theme.is_default,
        };

        drop(vault_guard);
        vault_store_theme(request, vault_state, window).await
    } else {
        Err("Vault not initialized".to_string())
    }
}

/// Migrate existing themes to vault
#[tauri::command]
pub async fn migrate_themes_to_vault(
    vault_state: State<'_, VaultState>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<MigrationResult, String> {
    // Enforce policy with context
    let mut context = HashMap::new();
    context.insert("operation".to_string(), "migration".to_string());
    
    // Policy enforcement removed for single-user mode

    let vault_guard = vault_state.read().await;
    if let Some(_vault) = vault_guard.as_ref() {
        // TODO: Load existing themes from the old storage system
        // For now, we'll create some default themes
        
        let default_themes = vec![
            ("Cyberpunk Neon", create_default_cyberpunk_theme()),
            ("Dark Matrix", create_default_matrix_theme()),
            ("Ghost Terminal", create_default_ghost_theme()),
        ];

        let mut migrated = 0;
        let mut failed = 0;
        let mut errors = Vec::new();

        for (name, theme_data) in default_themes {
            let request = CreateThemeRequest {
                name: name.to_string(),
                description: Some(format!("Default {} theme", name)),
                theme_data,
                tags: vec!["default".to_string(), "migrated".to_string()],
                is_default: name == "Cyberpunk Neon",
            };

            match vault_store_theme(request, vault_state.clone(), window.clone()).await {
                Ok(_) => migrated += 1,
                Err(e) => {
                    failed += 1;
                    errors.push(format!("Failed to migrate '{}': {}", name, e));
                }
            }
        }

        Ok(MigrationResult {
            migrated,
            failed,
            errors,
        })
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[derive(Debug, Serialize)]
pub struct MigrationResult {
    pub migrated: u32,
    pub failed: u32,
    pub errors: Vec<String>,
}

// Helper functions to create default themes
fn create_default_cyberpunk_theme() -> ThemeV1 {
    ThemeV1 {
        name: "Cyberpunk Neon".to_string(),
        version: 1,
        tokens: crate::commands::theme::ThemeTokens {
            bg_tint: "#0a0a0a".to_string(),
            fg: "#ffffff".to_string(),
            slate: "#1a1a1a".to_string(),
            accent_pink: "#ff00ff".to_string(),
            accent_cyan: "#00ffff".to_string(),
            accent_neon_green: "#ffff00".to_string(),
            glow_strength: 0.8,
            blur_px: 8,
            noise_opacity: 0.1,
            cursor_style: "block".to_string(),
            cursor_color: "#00ffff".to_string(),
            mono_font: "JetBrains Mono".to_string(),
            ui_font: "Space Grotesk".to_string(),
            radius: 8,
            border: "#333333".to_string(),
        },
    }
}

fn create_default_matrix_theme() -> ThemeV1 {
    ThemeV1 {
        name: "Dark Matrix".to_string(),
        version: 1,
        tokens: crate::commands::theme::ThemeTokens {
            bg_tint: "#000000".to_string(),
            fg: "#00ff00".to_string(),
            slate: "#001100".to_string(),
            accent_pink: "#008800".to_string(),
            accent_cyan: "#00aa00".to_string(),
            accent_neon_green: "#00ff00".to_string(),
            glow_strength: 0.6,
            blur_px: 4,
            noise_opacity: 0.05,
            cursor_style: "block".to_string(),
            cursor_color: "#00ff00".to_string(),
            mono_font: "Fira Code".to_string(),
            ui_font: "Roboto".to_string(),
            radius: 4,
            border: "#004400".to_string(),
        },
    }
}

fn create_default_ghost_theme() -> ThemeV1 {
    ThemeV1 {
        name: "Ghost Terminal".to_string(),
        version: 1,
        tokens: crate::commands::theme::ThemeTokens {
            bg_tint: "#0f0f23".to_string(),
            fg: "#e2e8f0".to_string(),
            slate: "#1e1e3f".to_string(),
            accent_pink: "#8b5cf6".to_string(),
            accent_cyan: "#06b6d4".to_string(),
            accent_neon_green: "#f59e0b".to_string(),
            glow_strength: 0.7,
            blur_px: 6,
            noise_opacity: 0.08,
            cursor_style: "block".to_string(),
            cursor_color: "#8b5cf6".to_string(),
            mono_font: "Cascadia Code".to_string(),
            ui_font: "Inter".to_string(),
            radius: 6,
            border: "#4c1d95".to_string(),
        },
    }
}
