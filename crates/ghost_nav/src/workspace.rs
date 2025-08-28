use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Workspace metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMeta {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub is_default: bool,
    pub preset_id: Option<String>,
}

impl WorkspaceMeta {
    pub fn new(id: String, name: String, description: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            id,
            name,
            description,
            created_at: now,
            updated_at: now,
            is_default: false,
            preset_id: None,
        }
    }

    pub fn from_preset(preset_id: String, name: String, description: String) -> Self {
        let mut workspace = Self::new(preset_id.clone(), name, description);
        workspace.preset_id = Some(preset_id);
        workspace
    }
}

/// Workspace manager for handling multiple navigation layouts
pub struct WorkspaceManager {
    workspaces: HashMap<String, WorkspaceMeta>,
    current_workspace: String,
}

impl WorkspaceManager {
    pub fn new() -> Self {
        let mut manager = Self {
            workspaces: HashMap::new(),
            current_workspace: "default".to_string(),
        };

        // Add default workspace
        manager.add_default_workspaces();
        manager
    }

    fn add_default_workspaces(&mut self) {
        // Default workspace
        let default_workspace = WorkspaceMeta {
            id: "default".to_string(),
            name: "Default".to_string(),
            description: "Default workspace configuration".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_default: true,
            preset_id: None,
        };
        self.workspaces.insert("default".to_string(), default_workspace);

        // Preset-based workspaces
        let preset_workspaces = vec![
            ("analyst", "Analyst Workspace", "Security analysis and investigation"),
            ("ops", "Operations Workspace", "System operations and monitoring"),
            ("auditor", "Auditor Workspace", "Compliance and audit tools"),
            ("minimal", "Minimal Workspace", "Essential tools only"),
            ("exec", "Executive Workspace", "High-level overview and reporting"),
        ];

        for (id, name, description) in preset_workspaces {
            let workspace = WorkspaceMeta::from_preset(
                id.to_string(),
                name.to_string(),
                description.to_string(),
            );
            self.workspaces.insert(id.to_string(), workspace);
        }
    }

    /// Get all workspaces
    pub fn list_workspaces(&self) -> Vec<&WorkspaceMeta> {
        let mut workspaces: Vec<&WorkspaceMeta> = self.workspaces.values().collect();
        workspaces.sort_by(|a, b| {
            // Default first, then by name
            if a.is_default {
                std::cmp::Ordering::Less
            } else if b.is_default {
                std::cmp::Ordering::Greater
            } else {
                a.name.cmp(&b.name)
            }
        });
        workspaces
    }

    /// Get workspace by ID
    pub fn get_workspace(&self, id: &str) -> Option<&WorkspaceMeta> {
        self.workspaces.get(id)
    }

    /// Get current workspace
    pub fn get_current_workspace(&self) -> &WorkspaceMeta {
        self.workspaces
            .get(&self.current_workspace)
            .expect("Current workspace should always exist")
    }

    /// Set current workspace
    pub fn set_current_workspace(&mut self, id: String) -> Result<(), String> {
        if !self.workspaces.contains_key(&id) {
            return Err(format!("Workspace '{}' does not exist", id));
        }
        self.current_workspace = id;
        Ok(())
    }

    /// Create a new workspace
    pub fn create_workspace(
        &mut self,
        id: String,
        name: String,
        description: String,
    ) -> Result<(), String> {
        if self.workspaces.contains_key(&id) {
            return Err(format!("Workspace '{}' already exists", id));
        }

        let workspace = WorkspaceMeta::new(id.clone(), name, description);
        self.workspaces.insert(id, workspace);
        Ok(())
    }

    /// Update workspace metadata
    pub fn update_workspace(
        &mut self,
        id: &str,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<(), String> {
        let workspace = self
            .workspaces
            .get_mut(id)
            .ok_or_else(|| format!("Workspace '{}' does not exist", id))?;

        if let Some(name) = name {
            workspace.name = name;
        }
        if let Some(description) = description {
            workspace.description = description;
        }
        workspace.updated_at = chrono::Utc::now();

        Ok(())
    }

    /// Delete a workspace
    pub fn delete_workspace(&mut self, id: &str) -> Result<(), String> {
        if id == "default" {
            return Err("Cannot delete the default workspace".to_string());
        }

        if !self.workspaces.contains_key(id) {
            return Err(format!("Workspace '{}' does not exist", id));
        }

        // If deleting current workspace, switch to default
        if self.current_workspace == id {
            self.current_workspace = "default".to_string();
        }

        self.workspaces.remove(id);
        Ok(())
    }

    /// Clone a workspace
    pub fn clone_workspace(
        &mut self,
        source_id: &str,
        new_id: String,
        new_name: String,
    ) -> Result<(), String> {
        if self.workspaces.contains_key(&new_id) {
            return Err(format!("Workspace '{}' already exists", new_id));
        }

        let source = self
            .workspaces
            .get(source_id)
            .ok_or_else(|| format!("Source workspace '{}' does not exist", source_id))?;

        let mut cloned = source.clone();
        cloned.id = new_id.clone();
        cloned.name = new_name;
        cloned.created_at = chrono::Utc::now();
        cloned.updated_at = chrono::Utc::now();
        cloned.is_default = false;
        cloned.preset_id = None; // Cloned workspaces are not preset-based

        self.workspaces.insert(new_id, cloned);
        Ok(())
    }

    /// Get workspace suggestions based on current context
    pub fn get_workspace_suggestions(&self, context: &WorkspaceContext) -> Vec<String> {
        let mut suggestions = Vec::new();

        match context.activity_type.as_str() {
            "incident_response" => {
                suggestions.push("analyst".to_string());
                suggestions.push("ops".to_string());
            }
            "compliance_audit" => {
                suggestions.push("auditor".to_string());
                suggestions.push("exec".to_string());
            }
            "daily_ops" => {
                suggestions.push("ops".to_string());
                suggestions.push("minimal".to_string());
            }
            "security_analysis" => {
                suggestions.push("analyst".to_string());
            }
            _ => {
                suggestions.push("default".to_string());
            }
        }

        suggestions
    }
}

/// Context for workspace suggestions
#[derive(Debug, Clone)]
pub struct WorkspaceContext {
    pub activity_type: String,
    pub user_role: String,
    pub environment: String,
    pub time_of_day: chrono::NaiveTime,
}

impl Default for WorkspaceContext {
    fn default() -> Self {
        Self {
            activity_type: "general".to_string(),
            user_role: "user".to_string(),
            environment: "dev".to_string(),
            time_of_day: chrono::Utc::now().time(),
        }
    }
}

/// Workspace export/import functionality
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceExport {
    pub version: u32,
    pub workspace: WorkspaceMeta,
    pub layout: crate::LayoutV2,
    pub exported_at: chrono::DateTime<chrono::Utc>,
    pub exported_by: String,
    pub signature: String,
}

impl WorkspaceExport {
    pub fn new(
        workspace: WorkspaceMeta,
        layout: crate::LayoutV2,
        exported_by: String,
    ) -> Self {
        Self {
            version: 2,
            workspace,
            layout,
            exported_at: chrono::Utc::now(),
            exported_by,
            signature: "dilithium-placeholder".to_string(),
        }
    }

    /// Validate the export signature
    pub fn validate_signature(&self) -> Result<bool, String> {
        // TODO: Implement actual signature validation
        Ok(self.signature.starts_with("dilithium-"))
    }

    /// Get export filename
    pub fn get_filename(&self) -> String {
        let timestamp = self.exported_at.format("%Y%m%d_%H%M%S");
        format!("{}_workspace_{}.ghostnav.json", self.workspace.id, timestamp)
    }
}
