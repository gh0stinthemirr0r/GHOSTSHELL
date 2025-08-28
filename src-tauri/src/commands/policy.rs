use std::collections::HashMap;
use tauri::{State, Window};
use serde::{Deserialize, Serialize};

use ghost_policy::{Resource, Action, Policy};
use crate::security::{PepState, PolicyStats, DryRunResult};

/// Load policy from content
#[tauri::command]
pub async fn policy_load(
    policy_content: String,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Check if user has permission to manage policies
    let decision = pep.evaluate_access(
        Resource::Policy,
        Action::Update,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Insufficient permissions to manage policies".to_string());
    }

    // Load the policy
    pep.load_policy(&policy_content).await.map_err(|e| e.to_string())?;
    
    Ok("Policy loaded successfully".to_string())
}

/// Get policy statistics
#[tauri::command]
pub async fn policy_get_stats(
    pep: State<'_, PepState>,
    window: Window,
) -> Result<PolicyStats, String> {
    // Check read permission
    let decision = pep.evaluate_access(
        Resource::Policy,
        Action::Read,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Insufficient permissions to view policy stats".to_string());
    }

    let stats = pep.get_policy_stats().await
        .ok_or_else(|| "Failed to get policy statistics".to_string())?;
    
    Ok(stats)
}

/// Dry run policy evaluation
#[tauri::command]
pub async fn policy_dry_run(
    resource: String,
    action: String,
    context: HashMap<String, String>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<DryRunResult, String> {
    // Check if user can test policies
    let decision = pep.evaluate_access(
        Resource::Policy,
        Action::Query,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Insufficient permissions to test policies".to_string());
    }

    // Parse resource and action
    let policy_resource = parse_resource(&resource)?;
    let policy_action = parse_action(&action)?;

    // Run dry evaluation
    let result = pep.dry_run_policy(policy_resource, policy_action, context).await
        .map_err(|e| e.to_string())?;
    
    Ok(result)
}

/// Set user context for policy evaluation
#[tauri::command]
pub async fn policy_set_user(
    user_id: String,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Check if user can manage sessions
    let decision = pep.evaluate_access(
        Resource::Policy,
        Action::Update,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Insufficient permissions to set user context".to_string());
    }

    pep.set_user(user_id.clone()).await;
    Ok(format!("User context set to: {}", user_id))
}

/// Update session context
#[tauri::command]
pub async fn policy_update_context(
    key: String,
    value: String,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Check if user can update context
    let decision = pep.evaluate_access(
        Resource::Policy,
        Action::Update,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Insufficient permissions to update context".to_string());
    }

    pep.update_session_context(key.clone(), value.clone()).await;
    Ok(format!("Context updated: {} = {}", key, value))
}

/// Test access to a resource/action combination
#[tauri::command]
pub async fn policy_test_access(
    resource: String,
    action: String,
    context: Option<HashMap<String, String>>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<AccessTestResult, String> {
    // Check if user can test access
    let decision = pep.evaluate_access(
        Resource::Policy,
        Action::Query,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Insufficient permissions to test access".to_string());
    }

    // Parse resource and action
    let policy_resource = parse_resource(&resource)?;
    let policy_action = parse_action(&action)?;

    // Test access
    let test_decision = pep.evaluate_access(
        policy_resource,
        policy_action,
        context,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    Ok(AccessTestResult {
        allowed: test_decision.allowed,
        requires_justification: test_decision.requires_justification,
        justification_prompt: test_decision.justification_prompt,
        auto_clear_clipboard_ms: test_decision.auto_clear_clipboard_ms,
        mask_preview: test_decision.mask_preview,
        quarantine_file: test_decision.quarantine_file,
        time_limit_ms: test_decision.time_limit_ms,
        size_limit_mb: test_decision.size_limit_mb,
        warning_message: test_decision.warning_message,
        audit_required: test_decision.audit_required,
        policy_rule_id: test_decision.policy_rule_id,
    })
}

/// Get default policies for common scenarios
#[tauri::command]
pub async fn policy_get_defaults(
    scenario: String,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Check read permission
    let decision = pep.evaluate_access(
        Resource::Policy,
        Action::Read,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Insufficient permissions to view default policies".to_string());
    }

    let policy = match scenario.as_str() {
        "restrictive" => Policy::restrictive_default(),
        "development" => Policy::development_default(),
        _ => return Err("Unknown policy scenario".to_string()),
    };

    policy.to_toml().map_err(|e| e.to_string())
}

// Helper functions

fn parse_resource(resource_str: &str) -> Result<Resource, String> {
    match resource_str.to_lowercase().as_str() {
        "terminal" => Ok(Resource::Terminal),
        "ssh" => Ok(Resource::Ssh),
        "vault" => Ok(Resource::Vault),
        "vpn" => Ok(Resource::Vpn),
        "browser" => Ok(Resource::Browser),
        "files" => Ok(Resource::Files),
        "clipboard" => Ok(Resource::Clipboard),
        "network" => Ok(Resource::Network),
        "theme" => Ok(Resource::Theme),
        "settings" => Ok(Resource::Settings),
        "logs" => Ok(Resource::Logs),
        "policy" => Ok(Resource::Policy),
        _ => Err(format!("Unknown resource: {}", resource_str)),
    }
}

fn parse_action(action_str: &str) -> Result<Action, String> {
    match action_str.to_lowercase().as_str() {
        "read" => Ok(Action::Read),
        "write" => Ok(Action::Write),
        "exec" | "execute" => Ok(Action::Exec),
        "connect" => Ok(Action::Connect),
        "download" => Ok(Action::Download),
        "upload" => Ok(Action::Upload),
        "autofill" => Ok(Action::Autofill),
        "copy" => Ok(Action::Copy),
        "paste" => Ok(Action::Paste),
        "delete" => Ok(Action::Delete),
        "create" => Ok(Action::Create),
        "update" => Ok(Action::Update),
        "export" => Ok(Action::Export),
        "import" => Ok(Action::Import),
        "switch" => Ok(Action::Switch),
        "apply" => Ok(Action::Apply),
        "reload" => Ok(Action::Reload),
        "query" => Ok(Action::Query),
        "browse" => Ok(Action::Browse),
        "search" => Ok(Action::Search),
        _ => Err(format!("Unknown action: {}", action_str)),
    }
}

// DTOs

#[derive(Debug, Serialize)]
pub struct AccessTestResult {
    pub allowed: bool,
    pub requires_justification: bool,
    pub justification_prompt: Option<String>,
    pub auto_clear_clipboard_ms: Option<u64>,
    pub mask_preview: bool,
    pub quarantine_file: bool,
    pub time_limit_ms: Option<u64>,
    pub size_limit_mb: Option<u64>,
    pub warning_message: Option<String>,
    pub audit_required: bool,
    pub policy_rule_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyTestRequest {
    pub resource: String,
    pub action: String,
    pub context: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct PolicyValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validate policy content without loading it
#[tauri::command]
pub async fn policy_validate(
    policy_content: String,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<PolicyValidationResult, String> {
    // Check read permission
    let decision = pep.evaluate_access(
        Resource::Policy,
        Action::Read,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Insufficient permissions to validate policies".to_string());
    }

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Try to parse the policy
    match Policy::from_string(&policy_content) {
        Ok(policy) => {
            // Validate the policy structure
            match policy.validate() {
                Ok(_) => {
                    // Policy is valid
                    if policy.rules.is_empty() {
                        warnings.push("Policy has no rules defined".to_string());
                    }
                    
                    if policy.defaults.is_none() {
                        warnings.push("Policy has no default settings".to_string());
                    }
                }
                Err(e) => {
                    errors.push(format!("Policy validation failed: {}", e));
                }
            }
        }
        Err(e) => {
            errors.push(format!("Policy parsing failed: {}", e));
        }
    }

    Ok(PolicyValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    })
}
