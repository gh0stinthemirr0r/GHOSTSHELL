use anyhow::Result;
use ghost_nav::{LayoutV2, WorkspaceMeta, NavPreset, ModuleMeta};
use ghost_prefs::{ImportMode, ImportResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

/// Navigation manager state for Tauri
pub struct NavigationState {
    pub nav_manager: Arc<ghost_nav::NavigationManager>,
    pub prefs_manager: Arc<ghost_prefs::PreferencesManager>,
}

/// Get the current navigation layout for a workspace
#[tauri::command]
pub async fn nav_get_layout(
    workspace: Option<String>,
    state: State<'_, NavigationState>,
) -> Result<LayoutV2, String> {
    state
        .nav_manager
        .get_layout(workspace.as_deref())
        .await
        .map_err(|e| e.to_string())
}

/// Preview a layout draft with policy overlay applied
#[tauri::command]
pub async fn nav_preview_layout(
    layout_draft: LayoutV2,
    state: State<'_, NavigationState>,
) -> Result<LayoutV2, String> {
    state
        .nav_manager
        .preview_layout(layout_draft)
        .await
        .map_err(|e| e.to_string())
}

/// Save a navigation layout
#[tauri::command]
pub async fn nav_save_layout(
    layout: LayoutV2,
    state: State<'_, NavigationState>,
) -> Result<String, String> {
    state
        .prefs_manager
        .save_current_layout(layout)
        .await
        .map_err(|e| e.to_string())
}

/// List all available workspaces
#[tauri::command]
pub async fn nav_list_workspaces(
    state: State<'_, NavigationState>,
) -> Result<Vec<WorkspaceMeta>, String> {
    state
        .prefs_manager
        .list_workspaces()
        .await
        .map_err(|e| e.to_string())
}

/// Set the current workspace
#[tauri::command]
pub async fn nav_set_workspace(
    workspace_id: String,
    state: State<'_, NavigationState>,
) -> Result<(), String> {
    // Note: This would need to be implemented with proper state management
    // For now, we'll just validate the workspace exists
    state
        .prefs_manager
        .get_workspace(&workspace_id)
        .await
        .map_err(|e| e.to_string())?;
    
    Ok(())
}

/// Export a workspace layout to a file
#[tauri::command]
pub async fn nav_export_layout(
    workspace_id: String,
    export_path: String,
    state: State<'_, NavigationState>,
) -> Result<String, String> {
    state
        .prefs_manager
        .export_workspace(&workspace_id, &export_path)
        .await
        .map_err(|e| e.to_string())?;
    
    Ok(export_path)
}

/// Import a workspace layout from a file
#[tauri::command]
pub async fn nav_import_layout(
    import_path: String,
    mode: String, // "merge" | "replace" | "create_new"
    state: State<'_, NavigationState>,
) -> Result<ImportResult, String> {
    let import_mode = match mode.as_str() {
        "merge" => ImportMode::Merge,
        "replace" => ImportMode::Replace,
        "create_new" => ImportMode::CreateNew,
        _ => return Err("Invalid import mode. Use 'merge', 'replace', or 'create_new'".to_string()),
    };

    state
        .prefs_manager
        .import_workspace(&import_path, import_mode)
        .await
        .map_err(|e| e.to_string())
}

/// Create a new workspace from a preset
#[tauri::command]
pub async fn nav_create_workspace_from_preset(
    preset_id: String,
    workspace_name: String,
    workspace_description: String,
    state: State<'_, NavigationState>,
) -> Result<String, String> {
    state
        .prefs_manager
        .create_workspace_from_preset(&preset_id, workspace_name, workspace_description)
        .await
        .map_err(|e| e.to_string())
}

/// Get all available navigation presets
#[tauri::command]
pub async fn nav_get_presets() -> Result<Vec<NavPreset>, String> {
    Ok(NavPreset::get_all_presets())
}

/// Get metadata for all available modules
#[tauri::command]
pub async fn nav_get_module_metadata() -> Result<Vec<ModuleMeta>, String> {
    Ok(ModuleMeta::get_all_modules())
}

/// Validate a layout structure
#[tauri::command]
pub async fn nav_validate_layout(layout: LayoutV2) -> Result<ValidationResponse, String> {
    let validator = ghost_nav::LayoutValidator::new();
    
    match validator.validate(&layout) {
        Ok(()) => Ok(ValidationResponse {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }),
        Err(e) => Ok(ValidationResponse {
            is_valid: false,
            errors: vec![e.to_string()],
            warnings: Vec::new(),
        }),
    }
}

/// Get workspace suggestions based on context
#[tauri::command]
pub async fn nav_get_workspace_suggestions(
    context: WorkspaceContextRequest,
) -> Result<Vec<String>, String> {
    let workspace_context = ghost_nav::WorkspaceContext {
        activity_type: context.activity_type,
        user_role: context.user_role,
        environment: context.environment,
        time_of_day: chrono::Utc::now().time(),
    };

    let manager = ghost_nav::WorkspaceManager::new();
    Ok(manager.get_workspace_suggestions(&workspace_context))
}

/// Reorder modules within a group
#[tauri::command]
pub async fn nav_reorder_modules(
    workspace_id: String,
    group_id: String,
    module_orders: Vec<ModuleOrder>,
    state: State<'_, NavigationState>,
) -> Result<LayoutV2, String> {
    // Load current layout
    let mut layout = state
        .nav_manager
        .get_layout(Some(&workspace_id))
        .await
        .map_err(|e| e.to_string())?;

    // Update module orders
    for module_order in module_orders {
        if let Some(module) = layout.modules.iter_mut().find(|m| m.id == module_order.module_id) {
            if module.group_id == group_id && !module.locked {
                module.order = module_order.order;
            }
        }
    }

    // Save updated layout
    state
        .nav_manager
        .save_layout(layout.clone())
        .await
        .map_err(|e| e.to_string())?;

    Ok(layout)
}

/// Toggle module visibility
#[tauri::command]
pub async fn nav_toggle_module_visibility(
    workspace_id: String,
    module_id: String,
    visible: bool,
    state: State<'_, NavigationState>,
) -> Result<LayoutV2, String> {
    // Load current layout
    let mut layout = state
        .nav_manager
        .get_layout(Some(&workspace_id))
        .await
        .map_err(|e| e.to_string())?;

    // Update module visibility
    if let Some(module) = layout.modules.iter_mut().find(|m| m.id == module_id) {
        if !module.locked {
            module.visible = visible;
        } else {
            return Err("Module is locked by policy and cannot be modified".to_string());
        }
    } else {
        return Err("Module not found".to_string());
    }

    // Save updated layout
    state
        .nav_manager
        .save_layout(layout.clone())
        .await
        .map_err(|e| e.to_string())?;

    Ok(layout)
}

/// Pin/unpin a module
#[tauri::command]
pub async fn nav_toggle_module_pin(
    workspace_id: String,
    module_id: String,
    pinned: bool,
    state: State<'_, NavigationState>,
) -> Result<LayoutV2, String> {
    // Load current layout
    let mut layout = state
        .nav_manager
        .get_layout(Some(&workspace_id))
        .await
        .map_err(|e| e.to_string())?;

    // Update module pin status
    if let Some(module) = layout.modules.iter_mut().find(|m| m.id == module_id) {
        if !module.locked {
            module.pinned = pinned;
            // If pinning, move to pinned group
            if pinned {
                module.group_id = "grp-pinned".to_string();
            }
        } else {
            return Err("Module is locked by policy and cannot be modified".to_string());
        }
    } else {
        return Err("Module not found".to_string());
    }

    // Save updated layout
    state
        .nav_manager
        .save_layout(layout.clone())
        .await
        .map_err(|e| e.to_string())?;

    Ok(layout)
}

/// Move a module to a different group
#[tauri::command]
pub async fn nav_move_module_to_group(
    workspace_id: String,
    module_id: String,
    target_group_id: String,
    state: State<'_, NavigationState>,
) -> Result<LayoutV2, String> {
    // Load current layout
    let mut layout = state
        .nav_manager
        .get_layout(Some(&workspace_id))
        .await
        .map_err(|e| e.to_string())?;

    // Validate target group exists
    if !layout.groups.iter().any(|g| g.id == target_group_id) {
        return Err("Target group does not exist".to_string());
    }

    // Update module group
    if let Some(module) = layout.modules.iter_mut().find(|m| m.id == module_id) {
        if !module.locked {
            module.group_id = target_group_id;
            // Reset order when moving to new group
            module.order = 0;
        } else {
            return Err("Module is locked by policy and cannot be moved".to_string());
        }
    } else {
        return Err("Module not found".to_string());
    }

    // Save updated layout
    state
        .nav_manager
        .save_layout(layout.clone())
        .await
        .map_err(|e| e.to_string())?;

    Ok(layout)
}

// Request/Response types for Tauri commands

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationResponse {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceContextRequest {
    pub activity_type: String,
    pub user_role: String,
    pub environment: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleOrder {
    pub module_id: String,
    pub order: u32,
}
