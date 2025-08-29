use crate::shell_integration::{TerminalShellIntegration, ShellType};
// use crate::pty_shell::PtyShellManager; // Removed - using simple_shell instead
use crate::simple_shell::SimpleShellManager;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;
use tracing::{debug, error};
use tokio::sync::Mutex;

/// Shell integration state for Tauri
pub struct ShellState {
    pub integration: Arc<Mutex<TerminalShellIntegration>>,
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

/// Get available shell options
#[tauri::command]
pub async fn shell_get_available_shells(
    state: State<'_, ShellState>,
) -> Result<Vec<ShellOption>, String> {
    let integration = state.integration.lock().await;
    let options = integration.get_shell_options();
    
    Ok(options
        .into_iter()
        .map(|(shell_type, display_name, icon)| ShellOption {
            shell_type,
            display_name,
            icon,
            is_available: true,
        })
        .collect())
}

/// Get the default shell type
#[tauri::command]
pub async fn shell_get_default_shell(
    state: State<'_, ShellState>,
) -> Result<ShellType, String> {
    let integration = state.integration.lock().await;
    Ok(integration.get_default_shell_type())
}

/// Create a new terminal session with specified shell
#[tauri::command]
pub async fn shell_create_session(
    session_id: String,
    shell_type: ShellType,
    working_directory: Option<String>,
    state: State<'_, ShellState>,
) -> Result<SessionInfo, String> {
    let mut integration = state.integration.lock().await;
    
    integration
        .create_session(session_id.clone(), shell_type.clone(), working_directory.clone())
        .await
        .map_err(|e| e.to_string())?;

    let pid = integration.get_session_pid(&session_id);

    Ok(SessionInfo {
        session_id,
        shell_type,
        pid,
        working_directory,
    })
}

/// Close a terminal session
#[tauri::command]
pub async fn shell_close_session(
    session_id: String,
    state: State<'_, ShellState>,
) -> Result<(), String> {
    let mut integration = state.integration.lock().await;
    integration
        .close_session(&session_id)
        .map_err(|e| e.to_string())
}

/// Get session information
#[tauri::command]
pub async fn shell_get_session_info(
    session_id: String,
    state: State<'_, ShellState>,
) -> Result<Option<SessionInfo>, String> {
    let integration = state.integration.lock().await;
    
    if let Some(pid) = integration.get_session_pid(&session_id) {
        Ok(Some(SessionInfo {
            session_id,
            shell_type: integration.get_default_shell_type(), // This would need to be stored per session
            pid: Some(pid),
            working_directory: None, // This would need to be stored per session
        }))
    } else {
        Ok(None)
    }
}

/// Launch PowerShell with specific script
#[tauri::command]
pub async fn shell_launch_powershell_script(
    script_content: String,
    use_core: Option<bool>,
    state: State<'_, ShellState>,
) -> Result<String, String> {
    let shell_type = if use_core.unwrap_or(false) {
        ShellType::PowerShellCore
    } else {
        ShellType::PowerShell
    };

    let session_id = format!("ps_script_{}", uuid::Uuid::new_v4());
    let mut integration = state.integration.lock().await;
    
    integration
        .create_session(session_id.clone(), shell_type, None)
        .await
        .map_err(|e| e.to_string())?;

    // TODO: Execute the script content in the session
    // This would require PTY integration for proper script execution
    
    Ok(session_id)
}

/// Launch WSL with specific distribution
#[tauri::command]
pub async fn shell_launch_wsl_distro(
    distro_name: Option<String>,
    working_directory: Option<String>,
    state: State<'_, ShellState>,
) -> Result<String, String> {
    let shell_type = if let Some(distro) = distro_name {
        ShellType::WSLDistro(distro)
    } else {
        ShellType::WSL
    };

    let session_id = format!("wsl_{}", uuid::Uuid::new_v4());
    let mut integration = state.integration.lock().await;
    
    integration
        .create_session(session_id.clone(), shell_type, working_directory)
        .await
        .map_err(|e| e.to_string())?;

    Ok(session_id)
}

/// Execute a command in a specific shell type
#[tauri::command]
pub async fn shell_execute_command(
    command: String,
    shell_type: ShellType,
    working_directory: Option<String>,
    _state: State<'_, ShellState>,
) -> Result<CommandResult, String> {
    use std::process::{Command, Stdio};

    // Determine executable and args based on shell type
    let (executable, args) = match shell_type {
        ShellType::PowerShell => ("powershell".to_string(), vec!["-Command".to_string(), command]),
        ShellType::PowerShellCore => ("pwsh".to_string(), vec!["-Command".to_string(), command]),
        ShellType::Cmd => ("cmd".to_string(), vec!["/C".to_string(), command]),
        ShellType::WSL => ("wsl".to_string(), vec![command]),
        ShellType::WSLDistro(distro) => ("wsl".to_string(), vec!["-d".to_string(), distro, command]),
        ShellType::GitBash => ("bash".to_string(), vec!["-c".to_string(), command]),
        ShellType::Custom(exe) => (exe, vec![command]),
    };

    debug!("Executing command: {} with args: {:?}", executable, args);
    
    let console_manager = crate::console_manager::ConsoleManager::new();
    let (stdout, stderr, exit_code) = console_manager.execute_hidden_command(&executable, &args.iter().map(|s| s.as_str()).collect::<Vec<_>>(), working_directory.as_deref()).await.map_err(|e| {
        error!("Failed to execute command '{}': {}", executable, e);
        e.to_string()
    })?;

    debug!("Command output - stdout: '{}', stderr: '{}', exit_code: {}", 
           stdout, stderr, exit_code);

    Ok(CommandResult {
        stdout,
        stderr,
        exit_code,
        success: exit_code == 0,
    })
}

/// Test if a shell is available and working
#[tauri::command]
pub async fn shell_test_availability(
    shell_type: ShellType,
    _state: State<'_, ShellState>,
) -> Result<bool, String> {
    use std::process::Command;

    let executable = match shell_type {
        ShellType::PowerShell => "powershell",
        ShellType::PowerShellCore => "pwsh",
        ShellType::Cmd => "cmd",
        ShellType::WSL | ShellType::WSLDistro(_) => "wsl",
        ShellType::GitBash => "bash",
        ShellType::Custom(ref exe) => exe,
    };

    let windows_discovery = crate::windows_api_shell::WindowsShellDiscovery::new();
    
    // First try to find the executable
    match windows_discovery.find_executable(executable).await {
        Ok(exe_path) => {
            // Then test if it's available
            let available = windows_discovery.test_shell_availability(&exe_path).await;
            Ok(available)
        }
        Err(_) => Ok(false),
    }
}

/// Command execution result
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
}

// PTY-based persistent shell commands

// Simple Shell Commands - Direct execution without persistent sessions
// (PTY commands removed to eliminate console window popups)

/// Execute a command directly (no persistent session)
#[tauri::command]
pub async fn simple_execute_command(
    shell_type: String,
    command: String,
) -> Result<crate::simple_shell::CommandResult, String> {
    debug!("Executing simple command with {}: '{}'", shell_type, command);
    
    let shell_type_enum = match shell_type.as_str() {
        "PowerShellCore" => ShellType::PowerShellCore,
        "PowerShell" => ShellType::PowerShell,
        "WindowsPowerShell" => ShellType::PowerShell,
        "Cmd" => ShellType::Cmd,
        "GitBash" => ShellType::GitBash,
        "WSL" => ShellType::WSL,
        distro if distro.starts_with("WSL:") => {
            let distro_name = distro.strip_prefix("WSL:").unwrap_or("Ubuntu").to_string();
            ShellType::WSLDistro(distro_name)
        },
        _ => {
            error!("Unknown shell type: {}", shell_type);
            return Err(format!("Unknown shell type: {}", shell_type));
        }
    };
    
    // Create a temporary session and execute the command
    let mut session = crate::simple_shell::SimpleShellSession::new(
        "temp".to_string(), 
        shell_type_enum
    );
    
    session.execute_command(&command).await
        .map_err(|e| {
            error!("Failed to execute command: {}", e);
            e.to_string()
        })
}
