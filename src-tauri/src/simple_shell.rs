use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
use crate::shell_integration::ShellType;
use crate::console_manager::ConsoleManager;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct SimpleShellSession {
    pub session_id: String,
    pub shell_type: ShellType,
    pub working_directory: String,
    pub environment: HashMap<String, String>,
    pub console_manager: Arc<ConsoleManager>,
}

impl SimpleShellSession {
    pub fn new(session_id: String, shell_type: ShellType) -> Self {
        let working_directory = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("C:\\Users"))
            .to_string_lossy()
            .to_string();

        let mut console_manager = ConsoleManager::new();
        let _ = console_manager.initialize(); // Initialize console suppression

        Self {
            session_id,
            shell_type,
            working_directory,
            environment: std::env::vars().collect(),
            console_manager: Arc::new(console_manager),
        }
    }

    pub async fn execute_command(&mut self, command: &str) -> Result<CommandResult> {
        debug!("Executing command in session {}: '{}'", self.session_id, command);

        if command.trim().is_empty() {
            return Ok(CommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
                success: true,
            });
        }

        // Handle built-in commands
        if let Some(result) = self.handle_builtin_command(command).await? {
            return Ok(result);
        }

        // Execute the command based on shell type
        let result = match &self.shell_type {
            ShellType::PowerShell | ShellType::PowerShellCore => {
                self.execute_powershell_command(command).await
            }
            ShellType::Cmd => {
                self.execute_cmd_command(command).await
            }
            ShellType::WSL | ShellType::WSLDistro(_) => {
                self.execute_wsl_command(command).await
            }
            ShellType::GitBash => {
                self.execute_bash_command(command).await
            }
            ShellType::Custom(_) => {
                self.execute_cmd_command(command).await // Fallback to CMD
            }
        };

        match result {
            Ok(cmd_result) => {
                debug!("Command executed successfully in session {}", self.session_id);
                Ok(cmd_result)
            }
            Err(e) => {
                error!("Command execution failed in session {}: {}", self.session_id, e);
                Ok(CommandResult {
                    stdout: String::new(),
                    stderr: format!("Command execution failed: {}", e),
                    exit_code: 1,
                    success: false,
                })
            }
        }
    }

    async fn handle_builtin_command(&mut self, command: &str) -> Result<Option<CommandResult>> {
        let cmd_lower = command.trim().to_lowercase();
        
        // Handle cd command
        if cmd_lower.starts_with("cd ") || cmd_lower == "cd" {
            let path = if cmd_lower == "cd" {
                // cd with no arguments goes to home directory
                std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users".to_string())
            } else {
                command.trim()[3..].trim().to_string()
            };

            match std::env::set_current_dir(&path) {
                Ok(_) => {
                    self.working_directory = std::env::current_dir()
                        .unwrap_or_else(|_| std::path::PathBuf::from(&path))
                        .to_string_lossy()
                        .to_string();
                    
                    return Ok(Some(CommandResult {
                        stdout: format!("Changed directory to: {}\n", self.working_directory),
                        stderr: String::new(),
                        exit_code: 0,
                        success: true,
                    }));
                }
                Err(e) => {
                    return Ok(Some(CommandResult {
                        stdout: String::new(),
                        stderr: format!("Failed to change directory: {}\n", e),
                        exit_code: 1,
                        success: false,
                    }));
                }
            }
        }

        // Handle pwd/echo %cd% commands
        if cmd_lower == "pwd" || cmd_lower == "echo %cd%" {
            return Ok(Some(CommandResult {
                stdout: format!("{}\n", self.working_directory),
                stderr: String::new(),
                exit_code: 0,
                success: true,
            }));
        }

        Ok(None)
    }

    async fn execute_powershell_command(&self, command: &str) -> Result<CommandResult> {
        let executable = match &self.shell_type {
            ShellType::PowerShellCore => "pwsh.exe",
            _ => "powershell.exe",
        };

        let args = vec!["-NoProfile", "-NoLogo", "-Command", command];
        
        let (stdout, stderr, exit_code) = self.console_manager
            .execute_hidden_command(executable, &args, Some(&self.working_directory))
            .await?;

        Ok(CommandResult {
            stdout,
            stderr,
            exit_code,
            success: exit_code == 0,
        })
    }

    async fn execute_cmd_command(&self, command: &str) -> Result<CommandResult> {
        let args = vec!["/C", command];
        
        let (stdout, stderr, exit_code) = self.console_manager
            .execute_hidden_command("cmd.exe", &args, Some(&self.working_directory))
            .await?;

        Ok(CommandResult {
            stdout,
            stderr,
            exit_code,
            success: exit_code == 0,
        })
    }

    async fn execute_wsl_command(&self, command: &str) -> Result<CommandResult> {
        // First test if WSL is available and working
        let test_result = self.console_manager
            .execute_hidden_command("wsl.exe", &["--status"], None)
            .await;
            
        if let Err(_) = test_result {
            return Ok(CommandResult {
                stdout: String::new(),
                stderr: "WSL is not available or not properly configured. Please check your WSL installation.".to_string(),
                exit_code: 1,
                success: false,
            });
        }
        
        let mut args = Vec::new();
        
        // For WSL, we need to handle it differently
        match &self.shell_type {
            ShellType::WSLDistro(distro) => {
                // Specific WSL distribution
                args.push("-d");
                args.push(distro);
                
                // Test if the specific distribution exists
                let distro_test = self.console_manager
                    .execute_hidden_command("wsl.exe", &["-d", distro, "--", "echo", "test"], None)
                    .await;
                    
                if let Err(_) = distro_test {
                    return Ok(CommandResult {
                        stdout: String::new(),
                        stderr: format!("WSL distribution '{}' is not available or not properly configured.", distro),
                        exit_code: 1,
                        success: false,
                    });
                }
            }
            ShellType::WSL => {
                // Default WSL distribution - no extra args needed
            }
            _ => {}
        }

        // Change to the correct directory in WSL first
        let wsl_home_cmd = if args.is_empty() {
            vec!["--", "cd", "~", "&&", command]
        } else {
            let mut cmd = args.clone();
            cmd.extend_from_slice(&["--", "cd", "~", "&&", command]);
            cmd
        };
        
        let (stdout, stderr, exit_code) = self.console_manager
            .execute_hidden_command("wsl.exe", &wsl_home_cmd, None)
            .await?;

        Ok(CommandResult {
            stdout,
            stderr,
            exit_code,
            success: exit_code == 0,
        })
    }

    async fn execute_bash_command(&self, command: &str) -> Result<CommandResult> {
        // Try to find Git Bash
        let bash_paths = [
            "C:\\Program Files\\Git\\bin\\bash.exe",
            "C:\\Program Files (x86)\\Git\\bin\\bash.exe",
            "bash.exe", // If it's in PATH
        ];

        let mut bash_exe = None;
        for path in &bash_paths {
            if std::path::Path::new(path).exists() || path == &"bash.exe" {
                bash_exe = Some(*path);
                break;
            }
        }

        let bash_exe = bash_exe.ok_or_else(|| anyhow::anyhow!("Git Bash not found"))?;

        let args = vec!["-c", command];
        
        let (stdout, stderr, exit_code) = self.console_manager
            .execute_hidden_command(bash_exe, &args, Some(&self.working_directory))
            .await?;

        Ok(CommandResult {
            stdout,
            stderr,
            exit_code,
            success: exit_code == 0,
        })
    }
}

pub struct SimpleShellManager {
    sessions: Arc<RwLock<HashMap<String, Arc<Mutex<SimpleShellSession>>>>>,
}

impl SimpleShellManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_session(&self, session_id: String, shell_type: ShellType) -> Result<()> {
        debug!("Creating simple shell session: {} with type: {:?}", session_id, shell_type);
        
        let session = SimpleShellSession::new(session_id.clone(), shell_type);
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), Arc::new(Mutex::new(session)));
        
        info!("Created simple shell session: {}", session_id);
        Ok(())
    }

    pub async fn execute_command(&self, session_id: &str, command: &str) -> Result<CommandResult> {
        debug!("Executing command in session {}: '{}'", session_id, command);
        
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;
        
        let mut session = session.lock().await;
        session.execute_command(command).await
    }

    pub async fn close_session(&self, session_id: &str) -> Result<()> {
        debug!("Closing simple shell session: {}", session_id);
        
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        
        info!("Closed simple shell session: {}", session_id);
        Ok(())
    }

    pub async fn list_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }

    pub async fn session_exists(&self, session_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(session_id)
    }
}
