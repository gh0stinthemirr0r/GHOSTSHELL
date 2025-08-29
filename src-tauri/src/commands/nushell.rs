use crate::embedded_nushell::{EmbeddedNushellManager, NushellResult};
use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

/// Create a new Nushell session
#[tauri::command]
pub async fn nushell_create_session(
    manager: State<'_, EmbeddedNushellManager>,
) -> Result<String, String> {
    let session_id = Uuid::new_v4().to_string();
    
    manager
        .create_session(session_id.clone())
        .await
        .map_err(|e| e.to_string())?;
    
    Ok(session_id)
}

/// Execute a command in a Nushell session
#[tauri::command]
pub async fn nushell_execute_command(
    manager: State<'_, EmbeddedNushellManager>,
    session_id: String,
    command: String,
) -> Result<NushellResult, String> {
    manager
        .execute_command(&session_id, &command)
        .await
        .map_err(|e| e.to_string())
}

/// Close a Nushell session
#[tauri::command]
pub async fn nushell_close_session(
    manager: State<'_, EmbeddedNushellManager>,
    session_id: String,
) -> Result<(), String> {
    manager
        .close_session(&session_id)
        .await
        .map_err(|e| e.to_string())
}

/// List all active Nushell sessions
#[tauri::command]
pub async fn nushell_list_sessions(
    manager: State<'_, EmbeddedNushellManager>,
) -> Result<Vec<String>, String> {
    Ok(manager.list_sessions().await)
}

/// Check if a Nushell session exists
#[tauri::command]
pub async fn nushell_session_exists(
    manager: State<'_, EmbeddedNushellManager>,
    session_id: String,
) -> Result<bool, String> {
    Ok(manager.session_exists(&session_id).await)
}

/// Get Nushell information
#[tauri::command]
pub async fn nushell_get_info() -> Result<NushellInfo, String> {
    Ok(NushellInfo {
        name: "Nushell".to_string(),
        version: "0.105.1 (Embedded)".to_string(),
        description: "A new type of shell - embedded in GhostShell".to_string(),
        features: vec![
            "Structured data pipelines".to_string(),
            "Built-in JSON/YAML/CSV support".to_string(),
            "Type-safe operations".to_string(),
            "Cross-platform compatibility".to_string(),
            "Modern syntax".to_string(),
            "No console windows".to_string(),
        ],
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NushellInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub features: Vec<String>,
}
