use anyhow::Result;
use ghost_nav::{LayoutV2, NavigationManager, WorkspaceExport, LayoutValidator, WorkspaceMeta};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use crate::persistence::PersistenceProvider;

/// Import mode for workspace imports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportMode {
    /// Replace existing workspace completely
    Replace,
    /// Merge with existing workspace (keep existing settings where possible)
    Merge,
    /// Create new workspace with imported settings
    CreateNew,
}

/// Result of a workspace import operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub status: ImportStatus,
    pub workspace_id: String,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub changes_summary: ChangesSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportStatus {
    Success,
    SuccessWithWarnings,
    Failed,
}

/// Summary of changes made during import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesSummary {
    pub modules_added: Vec<String>,
    pub modules_removed: Vec<String>,
    pub modules_modified: Vec<String>,
    pub groups_added: Vec<String>,
    pub groups_removed: Vec<String>,
    pub groups_modified: Vec<String>,
}

impl Default for ChangesSummary {
    fn default() -> Self {
        Self {
            modules_added: Vec::new(),
            modules_removed: Vec::new(),
            modules_modified: Vec::new(),
            groups_added: Vec::new(),
            groups_removed: Vec::new(),
            groups_modified: Vec::new(),
        }
    }
}

/// Workspace importer for processing .ghostnav.json files
pub struct WorkspaceImporter {
    nav_manager: Arc<NavigationManager>,
    persistence: Arc<crate::VaultPersistenceProvider>,
    validator: LayoutValidator,
}

impl WorkspaceImporter {
    pub fn new(
        nav_manager: Arc<NavigationManager>,
        persistence: Arc<crate::VaultPersistenceProvider>,
    ) -> Self {
        Self {
            nav_manager,
            persistence,
            validator: LayoutValidator::new(),
        }
    }

    /// Import a workspace from a .ghostnav.json file
    pub async fn import_workspace(&self, import_path: &str, mode: ImportMode) -> Result<ImportResult> {
        // Read and parse the import file
        let import_data = self.read_import_file(import_path).await?;

        // Validate signature
        self.validate_signature(&import_data)?;

        // Validate layout structure
        let validation_result = self.validator.validate(&import_data.export.layout);
        if let Err(e) = validation_result {
            return Ok(ImportResult {
                status: ImportStatus::Failed,
                workspace_id: import_data.export.workspace.id.clone(),
                warnings: Vec::new(),
                errors: vec![format!("Layout validation failed: {}", e)],
                changes_summary: ChangesSummary::default(),
            });
        }

        // Process the import based on mode
        match mode {
            ImportMode::Replace => self.import_replace(import_data).await,
            ImportMode::Merge => self.import_merge(import_data).await,
            ImportMode::CreateNew => self.import_create_new(import_data).await,
        }
    }

    /// Import multiple workspaces from a multi-workspace export file
    pub async fn import_multiple_workspaces(&self, import_path: &str, mode: ImportMode) -> Result<Vec<ImportResult>> {
        let multi_import = self.read_multi_import_file(import_path).await?;
        let mut results = Vec::new();

        for export in multi_import.export.exports {
            let single_import = crate::SignedWorkspaceExport {
                export,
                signature: multi_import.signature.clone(),
                signature_algorithm: multi_import.signature_algorithm.clone(),
                signature_timestamp: multi_import.signature_timestamp,
            };

            let result = self.process_single_import(single_import, mode.clone()).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Import a preset from a preset file
    pub async fn import_preset(&self, import_path: &str) -> Result<ImportResult> {
        let preset_import = self.read_preset_file(import_path).await?;

        // Validate signature
        self.validate_preset_signature(&preset_import)?;

        // Create workspace from preset
        let workspace_id = uuid::Uuid::new_v4().to_string();
        let workspace = ghost_nav::WorkspaceMeta::from_preset(
            workspace_id.clone(),
            preset_import.preset.name.clone(),
            preset_import.preset.description.clone(),
        );

        // Save workspace and layout
        self.persistence.save_workspace_meta(&workspace).await?;
        let _layout_id = self.persistence.save_layout(&workspace_id, &preset_import.preset.layout).await?;

        Ok(ImportResult {
            status: ImportStatus::Success,
            workspace_id,
            warnings: Vec::new(),
            errors: Vec::new(),
            changes_summary: ChangesSummary::default(),
        })
    }

    async fn import_replace(&self, import_data: crate::SignedWorkspaceExport) -> Result<ImportResult> {
        let workspace_id = import_data.export.workspace.id.clone();
        let mut warnings = Vec::new();

        // Load existing layout for comparison
        let existing_layout = self.persistence.load_layout(&workspace_id).await.ok();
        let changes_summary = if let Some(existing) = existing_layout {
            self.calculate_changes(&existing, &import_data.export.layout)
        } else {
            ChangesSummary::default()
        };

        // Replace workspace metadata
        self.persistence.save_workspace_meta(&import_data.export.workspace).await?;

        // Replace layout
        self.persistence.save_layout(&workspace_id, &import_data.export.layout).await?;

        // Apply policy overlay and check for conflicts
        let final_layout = self.nav_manager.preview_layout(import_data.export.layout).await?;
        if self.has_policy_conflicts(&final_layout) {
            warnings.push("Some imported settings conflict with current policy and have been overridden".to_string());
        }

        Ok(ImportResult {
            status: if warnings.is_empty() { ImportStatus::Success } else { ImportStatus::SuccessWithWarnings },
            workspace_id,
            warnings,
            errors: Vec::new(),
            changes_summary,
        })
    }

    async fn import_merge(&self, import_data: crate::SignedWorkspaceExport) -> Result<ImportResult> {
        let workspace_id = import_data.export.workspace.id.clone();
        let mut warnings = Vec::new();

        // Load existing layout
        let existing_layout = self.persistence.load_layout(&workspace_id).await
            .unwrap_or_else(|_| LayoutV2::default_for_workspace(&workspace_id));

        // Merge layouts
        let merged_layout = self.merge_layouts(existing_layout.clone(), import_data.export.layout)?;
        let changes_summary = self.calculate_changes(&existing_layout, &merged_layout);

        // Update workspace metadata (merge approach)
        let mut existing_workspace = self.persistence.load_workspace_meta(&workspace_id).await
            .unwrap_or_else(|_| import_data.export.workspace.clone());
        
        existing_workspace.updated_at = chrono::Utc::now();
        if existing_workspace.description.is_empty() {
            existing_workspace.description = import_data.export.workspace.description;
        }

        // Save merged results
        self.persistence.save_workspace_meta(&existing_workspace).await?;
        self.persistence.save_layout(&workspace_id, &merged_layout).await?;

        // Check for policy conflicts
        let final_layout = self.nav_manager.preview_layout(merged_layout).await?;
        if self.has_policy_conflicts(&final_layout) {
            warnings.push("Some merged settings conflict with current policy".to_string());
        }

        Ok(ImportResult {
            status: if warnings.is_empty() { ImportStatus::Success } else { ImportStatus::SuccessWithWarnings },
            workspace_id,
            warnings,
            errors: Vec::new(),
            changes_summary,
        })
    }

    async fn import_create_new(&self, import_data: crate::SignedWorkspaceExport) -> Result<ImportResult> {
        let new_workspace_id = uuid::Uuid::new_v4().to_string();
        let mut new_workspace = import_data.export.workspace.clone();
        
        // Update workspace with new ID and timestamp
        new_workspace.id = new_workspace_id.clone();
        new_workspace.name = format!("{} (Imported)", new_workspace.name);
        new_workspace.created_at = chrono::Utc::now();
        new_workspace.updated_at = chrono::Utc::now();

        // Save new workspace
        self.persistence.save_workspace_meta(&new_workspace).await?;
        self.persistence.save_layout(&new_workspace_id, &import_data.export.layout).await?;

        Ok(ImportResult {
            status: ImportStatus::Success,
            workspace_id: new_workspace_id,
            warnings: Vec::new(),
            errors: Vec::new(),
            changes_summary: ChangesSummary::default(),
        })
    }

    async fn process_single_import(&self, import_data: crate::SignedWorkspaceExport, mode: ImportMode) -> Result<ImportResult> {
        match mode {
            ImportMode::Replace => self.import_replace(import_data).await,
            ImportMode::Merge => self.import_merge(import_data).await,
            ImportMode::CreateNew => self.import_create_new(import_data).await,
        }
    }

    fn merge_layouts(&self, existing: LayoutV2, imported: LayoutV2) -> Result<LayoutV2> {
        let mut merged = existing;

        // Merge groups (add new ones, keep existing)
        for imported_group in imported.groups {
            if !merged.groups.iter().any(|g| g.id == imported_group.id) {
                merged.groups.push(imported_group);
            }
        }

        // Merge modules (add new ones, update existing)
        for imported_module in imported.modules {
            if let Some(existing_module) = merged.modules.iter_mut().find(|m| m.id == imported_module.id) {
                // Update existing module (but preserve locked state)
                if !existing_module.locked {
                    existing_module.visible = imported_module.visible;
                    existing_module.pinned = imported_module.pinned;
                    existing_module.group_id = imported_module.group_id;
                    existing_module.order = imported_module.order;
                    existing_module.icon_variant = imported_module.icon_variant;
                }
            } else {
                // Add new module
                merged.modules.push(imported_module);
            }
        }

        // Update theme hints
        merged.theme_hints = imported.theme_hints;

        Ok(merged)
    }

    fn calculate_changes(&self, old_layout: &LayoutV2, new_layout: &LayoutV2) -> ChangesSummary {
        let mut summary = ChangesSummary::default();

        // Calculate module changes
        let old_modules: std::collections::HashMap<_, _> = old_layout.modules.iter()
            .map(|m| (&m.id, m)).collect();
        let new_modules: std::collections::HashMap<_, _> = new_layout.modules.iter()
            .map(|m| (&m.id, m)).collect();

        for (id, new_module) in &new_modules {
            if let Some(old_module) = old_modules.get(id) {
                if old_module != new_module {
                    summary.modules_modified.push(id.to_string());
                }
            } else {
                summary.modules_added.push(id.to_string());
            }
        }

        for (id, _) in &old_modules {
            if !new_modules.contains_key(id) {
                summary.modules_removed.push(id.to_string());
            }
        }

        // Calculate group changes (similar logic)
        let old_groups: std::collections::HashMap<_, _> = old_layout.groups.iter()
            .map(|g| (&g.id, g)).collect();
        let new_groups: std::collections::HashMap<_, _> = new_layout.groups.iter()
            .map(|g| (&g.id, g)).collect();

        for (id, new_group) in &new_groups {
            if let Some(old_group) = old_groups.get(id) {
                if old_group != new_group {
                    summary.groups_modified.push(id.to_string());
                }
            } else {
                summary.groups_added.push(id.to_string());
            }
        }

        for (id, _) in &old_groups {
            if !new_groups.contains_key(id) {
                summary.groups_removed.push(id.to_string());
            }
        }

        summary
    }

    fn has_policy_conflicts(&self, layout: &LayoutV2) -> bool {
        layout.modules.iter().any(|m| m.locked && m.lock_reason.is_some())
    }

    async fn read_import_file(&self, path: &str) -> Result<crate::SignedWorkspaceExport> {
        let content = tokio::fs::read_to_string(path).await?;
        let import_data: crate::SignedWorkspaceExport = serde_json::from_str(&content)?;
        Ok(import_data)
    }

    async fn read_multi_import_file(&self, path: &str) -> Result<crate::SignedMultiWorkspaceExport> {
        let content = tokio::fs::read_to_string(path).await?;
        let import_data: crate::SignedMultiWorkspaceExport = serde_json::from_str(&content)?;
        Ok(import_data)
    }

    async fn read_preset_file(&self, path: &str) -> Result<crate::SignedPreset> {
        let content = tokio::fs::read_to_string(path).await?;
        let import_data: crate::SignedPreset = serde_json::from_str(&content)?;
        Ok(import_data)
    }

    fn validate_signature(&self, import_data: &crate::SignedWorkspaceExport) -> Result<()> {
        // TODO: Implement actual signature validation
        if !import_data.signature.starts_with("dilithium-") {
            return Err(anyhow::anyhow!("Invalid signature format"));
        }
        Ok(())
    }

    fn validate_preset_signature(&self, import_data: &crate::SignedPreset) -> Result<()> {
        // TODO: Implement actual signature validation
        if !import_data.signature.starts_with("dilithium-") {
            return Err(anyhow::anyhow!("Invalid preset signature format"));
        }
        Ok(())
    }
}
