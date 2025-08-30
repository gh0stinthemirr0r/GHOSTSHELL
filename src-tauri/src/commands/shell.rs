//! # Shell Commands - Enterprise Integration
//! 
//! Tauri command handlers for shell operations using the GhostShell enterprise system.
//! This module provides the frontend interface to the comprehensive shell management system.

use crate::ghost_shell::{GhostShell, ShellType as GhostShellType};
use anyhow::Result;
use serde::{Deserialize, Serialize};
// use std::sync::Arc; // Not used in this module
// use tauri::State; // Not used in this module
use tracing::{debug, error};

// ============================================================================
// Legacy Shell Types (for backward compatibility)
// ============================================================================

/// Legacy shell type for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ShellType {
    PowerShell,
    PowerShellCore,
    Cmd,
    WSL,
    WSLDistro(String),
    GitBash,
    Custom(String),
}

/// Shell option for frontend
#[derive(Debug, Serialize, Deserialize)]
pub struct ShellOption {
    pub shell_type: ShellType,
    pub display_name: String,
    pub icon: String,
    pub is_available: bool,
}

/// Terminal session info
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub shell_type: ShellType,
    pub pid: Option<u32>,
    pub working_directory: Option<String>,
}

/// Command execution result
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
}

// ============================================================================
// Type Conversion Utilities
// ============================================================================

// Helper functions removed - were unused

// ============================================================================
// Tauri Commands - Enterprise Shell Integration
// ============================================================================

// Unused shell management functions removed - functionality available through simple_execute_command

/// Execute a command directly using GhostShell enterprise system (replaces simple_execute_command)
#[tauri::command]
pub async fn simple_execute_command(
    shell_type: String,
    command: String,
) -> Result<CommandResult, String> {
    debug!("Executing command with GhostShell enterprise system - {}: '{}'", shell_type, command);
    
    let ghost_shell = GhostShell::new();
    
    // Map shell type strings to profile names
    let profile_id = match shell_type.as_str() {
        "PowerShellCore" | "PowerShell" | "WindowsPowerShell" => "powershell",
        "Cmd" | "CommandPrompt" | "Command Prompt" => "cmd",
        "WSL" | "WSL2" => "wsl",
        "Ubuntu" | "Ubuntu-24.04" => "ubuntu",
        _ if shell_type.starts_with("WSL:") => {
            if shell_type.contains("Ubuntu") {
                "ubuntu"
            } else {
                "wsl"
            }
        },
        "GitBash" => "cmd", // Fallback to CMD
        _ => {
            error!("Unknown shell type: {}", shell_type);
            return Err(format!("Unknown shell type: {}", shell_type));
        }
    };
    
    // For WSL distro-specific commands, modify the command
    let final_command = if shell_type.starts_with("WSL:") && !shell_type.contains("Ubuntu") {
        let distro = shell_type.strip_prefix("WSL:").unwrap_or("Ubuntu");
        format!("-d {} {}", distro, command)
    } else {
        command
    };
    
    let result = ghost_shell.execute_command(profile_id, &final_command).await
        .map_err(|e| {
            error!("GhostShell enterprise execution failed: {}", e);
            e.to_string()
        })?;
    
    Ok(CommandResult {
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        success: result.success,
    })
}