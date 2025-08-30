pub mod layout;
// Policy module removed for single-user mode
pub mod presets;
pub mod validator;
pub mod workspace;

pub use layout::*;
// Policy module removed for single-user mode
pub use presets::*;
pub use validator::*;
pub use workspace::*;

use anyhow::Result;

/// Navigation management system for GHOSTSHELL
/// Handles sidebar layout, policy enforcement, and workspace management
pub struct NavigationManager {
    vault: std::sync::Arc<ghost_vault::Vault>,
    // Policy evaluator removed for single-user mode
}

impl NavigationManager {
    pub fn new(
        vault: std::sync::Arc<ghost_vault::Vault>,
        // Policy evaluator removed for single-user mode
    ) -> Self {
        Self { vault }
    }

    /// Get the current layout for a workspace, with policy overlay applied
    pub async fn get_layout(&self, workspace: Option<&str>) -> Result<LayoutV2> {
        let workspace_name = workspace.unwrap_or("default");
        
        // Load base layout from vault
        let base_layout = self.load_layout_from_vault(workspace_name).await?;
        
        // Apply policy overlay
        // Policy overlay removed for single-user mode
        let final_layout = base_layout;
        
        Ok(final_layout)
    }

    /// Preview a layout draft with policy overlay applied
    pub async fn preview_layout(&self, draft: LayoutV2) -> Result<LayoutV2> {
        // Policy overlay removed for single-user mode
        Ok(draft)
    }

    /// Save a layout to the vault
    pub async fn save_layout(&self, layout: LayoutV2) -> Result<String> {
        // Validate the layout
        let validator = LayoutValidator::new();
        validator.validate(&layout)?;

        // Sign the layout
        let signed_layout = self.sign_layout(layout).await?;

        // Store in vault
        let layout_id = self.store_layout_in_vault(signed_layout).await?;

        // Log the change
        self.log_layout_change("save", &layout_id).await?;

        Ok(layout_id)
    }

    async fn load_layout_from_vault(&self, workspace: &str) -> Result<LayoutV2> {
        // Implementation will load from vault
        // For now, return a default layout
        Ok(LayoutV2::default_for_workspace(workspace))
    }

    // Policy overlay functions removed for single-user mode

    async fn sign_layout(&self, layout: LayoutV2) -> Result<SignedLayout> {
        // Implementation will use PQ signatures
        Ok(SignedLayout {
            layout,
            signature: "dilithium-placeholder".to_string(),
            timestamp: chrono::Utc::now(),
        })
    }

    async fn store_layout_in_vault(&self, signed_layout: SignedLayout) -> Result<String> {
        // Implementation will store in vault
        Ok(uuid::Uuid::new_v4().to_string())
    }

    async fn log_layout_change(&self, action: &str, layout_id: &str) -> Result<()> {
        tracing::info!("Layout change: {} - {}", action, layout_id);
        // Implementation will log to GhostLog
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedLayout {
    pub layout: LayoutV2,
    pub signature: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
