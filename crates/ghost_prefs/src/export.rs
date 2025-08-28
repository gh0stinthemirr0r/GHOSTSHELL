use anyhow::Result;
use ghost_nav::{LayoutV2, NavigationManager, WorkspaceExport};
use std::path::Path;
use std::sync::Arc;
use crate::persistence::PersistenceProvider;

/// Workspace exporter for creating PQ-signed .ghostnav.json files
pub struct WorkspaceExporter {
    nav_manager: Arc<NavigationManager>,
    persistence: Arc<crate::VaultPersistenceProvider>,
}

impl WorkspaceExporter {
    pub fn new(
        nav_manager: Arc<NavigationManager>,
        persistence: Arc<crate::VaultPersistenceProvider>,
    ) -> Self {
        Self {
            nav_manager,
            persistence,
        }
    }

    /// Export a workspace to a .ghostnav.json file
    pub async fn export_workspace(&self, workspace_id: &str, export_path: &str) -> Result<()> {
        // Load workspace metadata
        let workspace = self.persistence.load_workspace_meta(workspace_id).await?;

        // Load workspace layout
        let layout = self.persistence.load_layout(workspace_id).await?;

        // Create export structure
        let export = WorkspaceExport::new(
            workspace,
            layout,
            "ghostshell_user".to_string(), // TODO: Get actual user ID
        );

        // Sign the export
        let signed_export = self.sign_export(export).await?;

        // Write to file
        self.write_export_file(&signed_export, export_path).await?;

        Ok(())
    }

    /// Export multiple workspaces to a single file
    pub async fn export_multiple_workspaces(
        &self,
        workspace_ids: &[String],
        export_path: &str,
    ) -> Result<()> {
        let mut exports = Vec::new();

        for workspace_id in workspace_ids {
            let workspace = self.persistence.load_workspace_meta(workspace_id).await?;
            let layout = self.persistence.load_layout(workspace_id).await?;

            let export = WorkspaceExport::new(
                workspace,
                layout,
                "ghostshell_user".to_string(),
            );

            exports.push(export);
        }

        let multi_export = MultiWorkspaceExport {
            version: 2,
            exports,
            exported_at: chrono::Utc::now(),
            exported_by: "ghostshell_user".to_string(),
            signature: "dilithium-multi-export".to_string(),
        };

        let signed_export = self.sign_multi_export(multi_export).await?;
        self.write_multi_export_file(&signed_export, export_path).await?;

        Ok(())
    }

    /// Export workspace as a preset template
    pub async fn export_as_preset(
        &self,
        workspace_id: &str,
        preset_name: String,
        preset_description: String,
        export_path: &str,
    ) -> Result<()> {
        let layout = self.persistence.load_layout(workspace_id).await?;

        let preset = ghost_nav::NavPreset {
            id: preset_name.to_lowercase().replace(' ', "_"),
            name: preset_name,
            description: preset_description,
            layout,
            signature: "dilithium-custom-preset".to_string(),
        };

        let signed_preset = self.sign_preset(preset).await?;
        self.write_preset_file(&signed_preset, export_path).await?;

        Ok(())
    }

    async fn sign_export(&self, export: WorkspaceExport) -> Result<SignedWorkspaceExport> {
        // TODO: Implement actual PQ signing
        let signature = format!("dilithium-{}-{}", export.workspace.id, export.exported_at.timestamp());
        
        Ok(SignedWorkspaceExport {
            export,
            signature,
            signature_algorithm: "dilithium3".to_string(),
            signature_timestamp: chrono::Utc::now(),
        })
    }

    async fn sign_multi_export(&self, export: MultiWorkspaceExport) -> Result<SignedMultiWorkspaceExport> {
        // TODO: Implement actual PQ signing
        let signature = format!("dilithium-multi-{}", export.exported_at.timestamp());
        
        Ok(SignedMultiWorkspaceExport {
            export,
            signature,
            signature_algorithm: "dilithium3".to_string(),
            signature_timestamp: chrono::Utc::now(),
        })
    }

    async fn sign_preset(&self, preset: ghost_nav::NavPreset) -> Result<SignedPreset> {
        // TODO: Implement actual PQ signing
        let signature = format!("dilithium-preset-{}", preset.id);
        
        Ok(SignedPreset {
            preset,
            signature,
            signature_algorithm: "dilithium3".to_string(),
            signature_timestamp: chrono::Utc::now(),
        })
    }

    async fn write_export_file(&self, export: &SignedWorkspaceExport, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(export)?;
        tokio::fs::write(path, json).await?;
        Ok(())
    }

    async fn write_multi_export_file(&self, export: &SignedMultiWorkspaceExport, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(export)?;
        tokio::fs::write(path, json).await?;
        Ok(())
    }

    async fn write_preset_file(&self, preset: &SignedPreset, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(preset)?;
        tokio::fs::write(path, json).await?;
        Ok(())
    }

    /// Validate export path and create directories if needed
    pub fn validate_export_path(&self, path: &str) -> Result<()> {
        let path = Path::new(path);
        
        // Check if parent directory exists, create if not
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Check file extension
        if let Some(extension) = path.extension() {
            if extension != "json" && extension != "ghostnav" {
                return Err(anyhow::anyhow!(
                    "Invalid file extension. Use .json or .ghostnav"
                ));
            }
        } else {
            return Err(anyhow::anyhow!("File must have an extension"));
        }

        Ok(())
    }
}

/// Signed workspace export with PQ signature
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedWorkspaceExport {
    pub export: WorkspaceExport,
    pub signature: String,
    pub signature_algorithm: String,
    pub signature_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Multi-workspace export container
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MultiWorkspaceExport {
    pub version: u32,
    pub exports: Vec<WorkspaceExport>,
    pub exported_at: chrono::DateTime<chrono::Utc>,
    pub exported_by: String,
    pub signature: String,
}

/// Signed multi-workspace export
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedMultiWorkspaceExport {
    pub export: MultiWorkspaceExport,
    pub signature: String,
    pub signature_algorithm: String,
    pub signature_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Signed preset export
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedPreset {
    pub preset: ghost_nav::NavPreset,
    pub signature: String,
    pub signature_algorithm: String,
    pub signature_timestamp: chrono::DateTime<chrono::Utc>,
}
