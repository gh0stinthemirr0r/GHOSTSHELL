pub mod manager;
pub mod persistence;
pub mod export;
pub mod import;

pub use manager::*;
pub use persistence::*;
pub use export::*;
pub use import::*;

use anyhow::Result;
use ghost_nav::{LayoutV2, WorkspaceMeta, NavigationManager};
use std::sync::Arc;
use crate::persistence::PersistenceProvider;

/// Preferences manager for GHOSTSHELL navigation and workspace settings
pub struct PreferencesManager {
    nav_manager: Arc<NavigationManager>,
    persistence: Arc<VaultPersistenceProvider>,
    current_workspace: String,
}

impl PreferencesManager {
    pub fn new(
        nav_manager: Arc<NavigationManager>,
        persistence: Arc<VaultPersistenceProvider>,
    ) -> Self {
        Self {
            nav_manager,
            persistence,
            current_workspace: "default".to_string(),
        }
    }

    /// Get current workspace layout
    pub async fn get_current_layout(&self) -> Result<LayoutV2> {
        self.nav_manager.get_layout(Some(&self.current_workspace)).await
    }

    /// Save current layout
    pub async fn save_current_layout(&self, layout: LayoutV2) -> Result<String> {
        let layout_id = self.nav_manager.save_layout(layout).await?;
        
        // Log the save operation
        self.log_preference_change("layout_save", &layout_id).await?;
        
        Ok(layout_id)
    }

    /// Switch to a different workspace
    pub async fn switch_workspace(&mut self, workspace_id: String) -> Result<()> {
        // Validate workspace exists
        let _workspace = self.get_workspace(&workspace_id).await?;
        
        let old_workspace = self.current_workspace.clone();
        self.current_workspace = workspace_id.clone();
        
        // Log the workspace switch
        self.log_workspace_switch(&old_workspace, &workspace_id).await?;
        
        Ok(())
    }

    /// Get workspace metadata
    pub async fn get_workspace(&self, workspace_id: &str) -> Result<WorkspaceMeta> {
        self.persistence.load_workspace_meta(workspace_id).await
    }

    /// List all available workspaces
    pub async fn list_workspaces(&self) -> Result<Vec<WorkspaceMeta>> {
        self.persistence.list_workspaces().await
    }

    /// Create a new workspace from a preset
    pub async fn create_workspace_from_preset(
        &self,
        preset_id: &str,
        workspace_name: String,
        workspace_description: String,
    ) -> Result<String> {
        let preset = ghost_nav::NavPreset::get_by_id(preset_id)
            .ok_or_else(|| anyhow::anyhow!("Preset '{}' not found", preset_id))?;

        let workspace_id = uuid::Uuid::new_v4().to_string();
        let workspace = WorkspaceMeta::from_preset(
            workspace_id.clone(),
            workspace_name,
            workspace_description,
        );

        // Save workspace metadata
        self.persistence.save_workspace_meta(&workspace).await?;

        // Save layout
        let layout_id = self.nav_manager.save_layout(preset.layout).await?;

        // Log the creation
        self.log_workspace_creation(&workspace_id, preset_id).await?;

        Ok(workspace_id)
    }

    /// Export workspace to file
    pub async fn export_workspace(&self, workspace_id: &str, export_path: &str) -> Result<()> {
        let exporter = WorkspaceExporter::new(
            self.nav_manager.clone(),
            self.persistence.clone(),
        );

        exporter.export_workspace(workspace_id, export_path).await?;

        // Log the export
        self.log_workspace_export(workspace_id, export_path).await?;

        Ok(())
    }

    /// Import workspace from file
    pub async fn import_workspace(&self, import_path: &str, mode: ImportMode) -> Result<ImportResult> {
        let importer = WorkspaceImporter::new(
            self.nav_manager.clone(),
            self.persistence.clone(),
        );

        let result = importer.import_workspace(import_path, mode).await?;

        // Log the import
        self.log_workspace_import(import_path, &result).await?;

        Ok(result)
    }

    async fn log_preference_change(&self, action: &str, target: &str) -> Result<()> {
        tracing::info!("Preference change: {} - {}", action, target);
        // TODO: Integrate with GhostLog
        Ok(())
    }

    async fn log_workspace_switch(&self, from: &str, to: &str) -> Result<()> {
        tracing::info!("Workspace switch: {} -> {}", from, to);
        // TODO: Integrate with GhostLog
        Ok(())
    }

    async fn log_workspace_creation(&self, workspace_id: &str, preset_id: &str) -> Result<()> {
        tracing::info!("Workspace created: {} from preset {}", workspace_id, preset_id);
        // TODO: Integrate with GhostLog
        Ok(())
    }

    async fn log_workspace_export(&self, workspace_id: &str, export_path: &str) -> Result<()> {
        tracing::info!("Workspace exported: {} to {}", workspace_id, export_path);
        // TODO: Integrate with GhostLog
        Ok(())
    }

    async fn log_workspace_import(&self, import_path: &str, result: &ImportResult) -> Result<()> {
        tracing::info!("Workspace imported: {} - {:?}", import_path, result.status);
        // TODO: Integrate with GhostLog
        Ok(())
    }
}
