use crate::shell_integration::{TerminalShellIntegration, ShellType};
use crate::pty_shell::PtyShellManager;
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

    let mut cmd = Command::new(&executable);
    cmd.args(&args);

    if let Some(dir) = working_directory {
        cmd.current_dir(dir);
    }

    cmd.stdout(Stdio::piped())
       .stderr(Stdio::piped());

    debug!("Executing command: {} with args: {:?}", executable, args);
    
    let output = cmd.output().map_err(|e| {
        error!("Failed to execute command '{}': {}", executable, e);
        e.to_string()
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    debug!("Command output - stdout: '{}', stderr: '{}', exit_code: {:?}", 
           stdout, stderr, output.status.code());

    Ok(CommandResult {
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
        exit_code: output.status.code().unwrap_or(-1),
        success: output.status.success(),
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

    match Command::new(executable).arg("--version").output() {
        Ok(output) => Ok(output.status.success()),
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

/// Create a persistent PTY shell session
#[tauri::command]
pub async fn pty_create_session(
    session_id: String,
    shell_type: String,
    pty_manager: State<'_, Arc<PtyShellManager>>,
) -> Result<String, String> {
    // Convert string to ShellType
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
        // Handle serialized enum variants (from serde)
        s if s.contains("PowerShellCore") => ShellType::PowerShellCore,
        s if s.contains("PowerShell") => ShellType::PowerShell,
        s if s.contains("Cmd") => ShellType::Cmd,
        s if s.contains("GitBash") => ShellType::GitBash,
        s if s.contains("WSL") => ShellType::WSL,
        _ => {
            error!("Unknown shell type: {}", shell_type);
            return Err(format!("Unknown shell type: {}", shell_type));
        }
    };

    debug!("Creating PTY session: {} with shell type: {:?}", session_id, shell_type_enum);
    
    pty_manager.create_session(session_id.clone(), shell_type_enum).await
        .map_err(|e| {
            error!("Failed to create PTY session {}: {}", session_id, e);
            e.to_string()
        })?;
    
    Ok(session_id)
}

/// Write input to a PTY shell session
#[tauri::command]
pub async fn pty_write_input(
    session_id: String,
    input: String,
    pty_manager: State<'_, Arc<PtyShellManager>>,
) -> Result<(), String> {
    debug!("Writing input to PTY session {}: '{}'", session_id, input);
    
    pty_manager.write_to_session(&session_id, &input).await
        .map_err(|e| {
            error!("Failed to write to PTY session {}: {}", session_id, e);
            e.to_string()
        })
}

/// Get output from a PTY shell session
#[tauri::command]
pub async fn pty_get_output(
    session_id: String,
    pty_manager: State<'_, Arc<PtyShellManager>>,
) -> Result<Option<String>, String> {
    let output = pty_manager.get_output(&session_id).await;
    debug!("Getting output for session {}: {:?}", session_id, output.as_ref().map(|s| format!("{}...", &s[..s.len().min(100)])));
    Ok(output)
}

/// Get full output from a PTY shell session (for debugging)
#[tauri::command]
pub async fn pty_get_full_output(
    session_id: String,
    pty_manager: State<'_, Arc<PtyShellManager>>,
) -> Result<Option<String>, String> {
    let output = pty_manager.get_full_output(&session_id).await;
    debug!("Getting full output for session {}: {} chars", session_id, output.as_ref().map(|s| s.len()).unwrap_or(0));
    Ok(output)
}

/// Resize a PTY shell session (simplified - no-op for now)
#[tauri::command]
pub async fn pty_resize_session(
    session_id: String,
    rows: u16,
    cols: u16,
    _pty_manager: State<'_, Arc<PtyShellManager>>,
) -> Result<(), String> {
    debug!("Resize request for PTY session {} to {}x{} (not implemented in simplified version)", session_id, cols, rows);
    // For now, we'll just acknowledge the resize request but not actually resize
    // This can be implemented later if needed
    Ok(())
}

/// Close a PTY shell session
#[tauri::command]
pub async fn pty_close_session(
    session_id: String,
    pty_manager: State<'_, Arc<PtyShellManager>>,
) -> Result<(), String> {
    debug!("Closing PTY session: {}", session_id);
    
    pty_manager.close_session(&session_id).await
        .map_err(|e| {
            error!("Failed to close PTY session {}: {}", session_id, e);
            e.to_string()
        })
}

/// List all active PTY shell sessions
#[tauri::command]
pub async fn pty_list_sessions(
    pty_manager: State<'_, Arc<PtyShellManager>>,
) -> Result<Vec<String>, String> {
    let sessions = pty_manager.list_sessions().await;
    Ok(sessions)
}

// Simple Shell Commands - Direct execution without persistent sessions

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
