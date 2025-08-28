pub mod layout;
pub mod policy;
pub mod presets;
pub mod validator;
pub mod workspace;

pub use layout::*;
pub use policy::*;
pub use presets::*;
pub use validator::*;
pub use workspace::*;

use anyhow::Result;

/// Navigation management system for GHOSTSHELL
/// Handles sidebar layout, policy enforcement, and workspace management
pub struct NavigationManager {
    vault: std::sync::Arc<ghost_vault::Vault>,
    policy: std::sync::Arc<ghost_policy::PolicyEvaluator>,
}

impl NavigationManager {
    pub fn new(
        vault: std::sync::Arc<ghost_vault::Vault>,
        policy: std::sync::Arc<ghost_policy::PolicyEvaluator>,
    ) -> Self {
        Self { vault, policy }
    }

    /// Get the current layout for a workspace, with policy overlay applied
    pub async fn get_layout(&self, workspace: Option<&str>) -> Result<LayoutV2> {
        let workspace_name = workspace.unwrap_or("default");
        
        // Load base layout from vault
        let base_layout = self.load_layout_from_vault(workspace_name).await?;
        
        // Apply policy overlay
        let policy_overlay = self.compute_policy_overlay().await?;
        let final_layout = self.apply_policy_overlay(base_layout, policy_overlay)?;
        
        Ok(final_layout)
    }

    /// Preview a layout draft with policy overlay applied
    pub async fn preview_layout(&self, draft: LayoutV2) -> Result<LayoutV2> {
        let policy_overlay = self.compute_policy_overlay().await?;
        self.apply_policy_overlay(draft, policy_overlay)
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

    async fn compute_policy_overlay(&self) -> Result<PolicyOverlay> {
        // Implementation will compute policy based on current user/role/environment
        Ok(PolicyOverlay::default())
    }

    fn apply_policy_overlay(&self, mut layout: LayoutV2, overlay: PolicyOverlay) -> Result<LayoutV2> {
        // Apply force show/hide rules
        for module_id in &overlay.force_hide {
            if let Some(module) = layout.modules.iter_mut().find(|m| &m.id == module_id) {
                module.visible = false;
                module.locked = true;
                module.lock_reason = Some("policy:force_hide".to_string());
            }
        }

        for module_id in &overlay.force_show {
            if let Some(module) = layout.modules.iter_mut().find(|m| &m.id == module_id) {
                module.visible = true;
                module.locked = true;
                module.lock_reason = Some("policy:force_show".to_string());
            }
        }

        // Apply specific locks
        for (module_id, reason) in &overlay.locks {
            if let Some(module) = layout.modules.iter_mut().find(|m| &m.id == module_id) {
                module.locked = true;
                module.lock_reason = Some(reason.clone());
            }
        }

        Ok(layout)
    }

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
