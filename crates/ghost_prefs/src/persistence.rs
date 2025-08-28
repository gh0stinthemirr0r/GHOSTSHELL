use anyhow::Result;
use async_trait::async_trait;
use ghost_nav::{LayoutV2, WorkspaceMeta};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Trait for persisting navigation preferences and layouts
#[async_trait]
pub trait PersistenceProvider: Send + Sync {
    /// Save a layout to persistent storage
    async fn save_layout(&self, workspace_id: &str, layout: &LayoutV2) -> Result<String>;

    /// Load a layout from persistent storage
    async fn load_layout(&self, workspace_id: &str) -> Result<LayoutV2>;

    /// Save workspace metadata
    async fn save_workspace_meta(&self, workspace: &WorkspaceMeta) -> Result<()>;

    /// Load workspace metadata
    async fn load_workspace_meta(&self, workspace_id: &str) -> Result<WorkspaceMeta>;

    /// List all available workspaces
    async fn list_workspaces(&self) -> Result<Vec<WorkspaceMeta>>;

    /// Delete a workspace and its layout
    async fn delete_workspace(&self, workspace_id: &str) -> Result<()>;

    /// Save user preferences
    async fn save_preferences(&self, preferences: &crate::UserPreferences) -> Result<()>;

    /// Load user preferences
    async fn load_preferences(&self) -> Result<crate::UserPreferences>;
}

/// Vault-based persistence provider using GhostVault
pub struct VaultPersistenceProvider {
    vault: std::sync::Arc<ghost_vault::Vault>,
}

impl VaultPersistenceProvider {
    pub fn new(vault: std::sync::Arc<ghost_vault::Vault>) -> Self {
        Self { vault }
    }

    fn layout_key(workspace_id: &str) -> String {
        format!("nav_layout_{}", workspace_id)
    }

    fn workspace_meta_key(workspace_id: &str) -> String {
        format!("workspace_meta_{}", workspace_id)
    }

    fn preferences_key() -> String {
        "user_preferences".to_string()
    }
}

#[async_trait]
impl PersistenceProvider for VaultPersistenceProvider {
    async fn save_layout(&self, workspace_id: &str, layout: &LayoutV2) -> Result<String> {
        let key = Self::layout_key(workspace_id);
        let data = serde_json::to_string(layout)?;
        
        // Create a secret request for the layout
        let request = ghost_vault::CreateSecretRequest {
            name: key.clone(),
            description: Some(format!("Navigation layout for workspace: {}", workspace_id)),
            secret_type: ghost_vault::SecretType::ConfigProfile,
            data: ghost_vault::SecretData::ConfigProfile {
                config_data: serde_json::from_str(&data)?,
            },
            tags: vec!["navigation".to_string(), "layout".to_string()],
            expires_at: None,
            metadata: ghost_vault::SecretMetadata::default(),
        };
        
        // Store in vault
        let context = ghost_policy::ExecutionContext::for_user("system", "admin");
        let _secret_id = self.vault.store_secret(request, context).await?;
        
        Ok(key)
    }

    async fn load_layout(&self, workspace_id: &str) -> Result<LayoutV2> {
        let _key = Self::layout_key(workspace_id);
        
        // For now, return a default layout since we need to implement proper secret lookup by name
        // This would need to be implemented with a proper secret lookup mechanism
        Ok(LayoutV2::default_for_workspace(workspace_id))
    }

    async fn save_workspace_meta(&self, workspace: &WorkspaceMeta) -> Result<()> {
        let key = Self::workspace_meta_key(&workspace.id);
        let data = serde_json::to_string(workspace)?;
        
        let request = ghost_vault::CreateSecretRequest {
            name: key,
            description: Some(format!("Workspace metadata for: {}", workspace.name)),
            secret_type: ghost_vault::SecretType::ConfigProfile,
            data: ghost_vault::SecretData::ConfigProfile {
                config_data: serde_json::from_str(&data)?,
            },
            tags: vec!["navigation".to_string(), "workspace".to_string()],
            expires_at: None,
            metadata: ghost_vault::SecretMetadata::default(),
        };
        
        let context = ghost_policy::ExecutionContext::for_user("system", "admin");
        let _secret_id = self.vault.store_secret(request, context).await?;
        Ok(())
    }

    async fn load_workspace_meta(&self, workspace_id: &str) -> Result<WorkspaceMeta> {
        let _key = Self::workspace_meta_key(workspace_id);
        
        // Return default workspace metadata for now
        Ok(WorkspaceMeta::new(
            workspace_id.to_string(),
            workspace_id.to_string(),
            format!("Workspace: {}", workspace_id),
        ))
    }

    async fn list_workspaces(&self) -> Result<Vec<WorkspaceMeta>> {
        // This would need to be implemented based on vault's key listing capabilities
        // For now, return default workspaces
        let default_workspaces = vec![
            WorkspaceMeta::new(
                "default".to_string(),
                "Default".to_string(),
                "Default workspace configuration".to_string(),
            ),
            WorkspaceMeta::from_preset(
                "analyst".to_string(),
                "Analyst".to_string(),
                "Security analysis workspace".to_string(),
            ),
            WorkspaceMeta::from_preset(
                "ops".to_string(),
                "Operations".to_string(),
                "Operations workspace".to_string(),
            ),
        ];
        
        Ok(default_workspaces)
    }

    async fn delete_workspace(&self, workspace_id: &str) -> Result<()> {
        let _layout_key = Self::layout_key(workspace_id);
        let _meta_key = Self::workspace_meta_key(workspace_id);
        
        // For now, just return Ok since we need to implement proper secret deletion by name
        Ok(())
    }

    async fn save_preferences(&self, preferences: &crate::UserPreferences) -> Result<()> {
        let key = Self::preferences_key();
        let data = serde_json::to_string(preferences)?;
        
        let request = ghost_vault::CreateSecretRequest {
            name: key,
            description: Some("User navigation preferences".to_string()),
            secret_type: ghost_vault::SecretType::ConfigProfile,
            data: ghost_vault::SecretData::ConfigProfile {
                config_data: serde_json::from_str(&data)?,
            },
            tags: vec!["navigation".to_string(), "preferences".to_string()],
            expires_at: None,
            metadata: ghost_vault::SecretMetadata::default(),
        };
        
        let context = ghost_policy::ExecutionContext::for_user("system", "admin");
        let _secret_id = self.vault.store_secret(request, context).await?;
        Ok(())
    }

    async fn load_preferences(&self) -> Result<crate::UserPreferences> {
        let _key = Self::preferences_key();
        
        // Return default preferences for now
        Ok(crate::UserPreferences::default())
    }
}

/// File-based persistence provider for development/testing
pub struct FilePersistenceProvider {
    base_path: std::path::PathBuf,
}

impl FilePersistenceProvider {
    pub fn new<P: AsRef<Path>>(base_path: P) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();
        std::fs::create_dir_all(&base_path)?;
        Ok(Self { base_path })
    }

    fn layout_path(&self, workspace_id: &str) -> std::path::PathBuf {
        self.base_path.join(format!("layout_{}.json", workspace_id))
    }

    fn workspace_meta_path(&self, workspace_id: &str) -> std::path::PathBuf {
        self.base_path.join(format!("workspace_{}.json", workspace_id))
    }

    fn preferences_path(&self) -> std::path::PathBuf {
        self.base_path.join("preferences.json")
    }
}

#[async_trait]
impl PersistenceProvider for FilePersistenceProvider {
    async fn save_layout(&self, workspace_id: &str, layout: &LayoutV2) -> Result<String> {
        let path = self.layout_path(workspace_id);
        let data = serde_json::to_string_pretty(layout)?;
        tokio::fs::write(&path, data).await?;
        Ok(path.to_string_lossy().to_string())
    }

    async fn load_layout(&self, workspace_id: &str) -> Result<LayoutV2> {
        let path = self.layout_path(workspace_id);
        
        match tokio::fs::read_to_string(&path).await {
            Ok(data) => {
                let layout: LayoutV2 = serde_json::from_str(&data)?;
                Ok(layout)
            }
            Err(_) => {
                // Return default layout if file not found
                Ok(LayoutV2::default_for_workspace(workspace_id))
            }
        }
    }

    async fn save_workspace_meta(&self, workspace: &WorkspaceMeta) -> Result<()> {
        let path = self.workspace_meta_path(&workspace.id);
        let data = serde_json::to_string_pretty(workspace)?;
        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    async fn load_workspace_meta(&self, workspace_id: &str) -> Result<WorkspaceMeta> {
        let path = self.workspace_meta_path(workspace_id);
        let data = tokio::fs::read_to_string(&path).await?;
        let workspace: WorkspaceMeta = serde_json::from_str(&data)?;
        Ok(workspace)
    }

    async fn list_workspaces(&self) -> Result<Vec<WorkspaceMeta>> {
        let mut workspaces = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_path).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(file_name) = path.file_name() {
                let file_name = file_name.to_string_lossy();
                if file_name.starts_with("workspace_") && file_name.ends_with(".json") {
                    if let Ok(data) = tokio::fs::read_to_string(&path).await {
                        if let Ok(workspace) = serde_json::from_str::<WorkspaceMeta>(&data) {
                            workspaces.push(workspace);
                        }
                    }
                }
            }
        }
        
        // Sort by name
        workspaces.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(workspaces)
    }

    async fn delete_workspace(&self, workspace_id: &str) -> Result<()> {
        let layout_path = self.layout_path(workspace_id);
        let meta_path = self.workspace_meta_path(workspace_id);
        
        let _ = tokio::fs::remove_file(layout_path).await;
        let _ = tokio::fs::remove_file(meta_path).await;
        
        Ok(())
    }

    async fn save_preferences(&self, preferences: &crate::UserPreferences) -> Result<()> {
        let path = self.preferences_path();
        let data = serde_json::to_string_pretty(preferences)?;
        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    async fn load_preferences(&self) -> Result<crate::UserPreferences> {
        let path = self.preferences_path();
        
        match tokio::fs::read_to_string(&path).await {
            Ok(data) => {
                let preferences: crate::UserPreferences = serde_json::from_str(&data)?;
                Ok(preferences)
            }
            Err(_) => {
                // Return default preferences if file not found
                Ok(crate::UserPreferences::default())
            }
        }
    }
}
