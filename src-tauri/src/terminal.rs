use anyhow::{Result, anyhow};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{State, Window};
use tokio::sync::{mpsc, RwLock};
use tracing::{info, error, debug};
use uuid::Uuid;
// Console manager replaced by GhostShell enterprise system
// use crate::console_manager::ConsoleManager;

#[cfg(windows)]
// use std::os::windows::process::CommandExt; // Not used

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSession {
    pub id: String,
    pub title: String,
    pub cwd: String,
    pub shell: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalOutput {
    pub session_id: String,
    pub data: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalInput {
    pub session_id: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalResize {
    pub session_id: String,
    pub cols: u16,
    pub rows: u16,
}

pub struct TerminalManager {
    sessions: Arc<RwLock<HashMap<String, TerminalSession>>>,
    session_channels: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<TerminalCommand>>>>,
}

#[derive(Debug)]
enum TerminalCommand {
    Input(String),
    Resize(u16, u16),
    Close,
}

impl TerminalManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_channels: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn create_session(&self, window: Window, title: Option<String>, cwd: Option<String>) -> Result<TerminalSession> {
        let session_id = Uuid::new_v4().to_string();
        let session_count = self.sessions.read().await.len();
        let title = title.unwrap_or_else(|| format!("Shell {}", session_count + 1));
        
        // Determine shell and working directory
        let shell = self.get_default_shell().await;
        let cwd = cwd.unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("/"))
                .to_string_lossy()
                .to_string()
        });

        // Create session
        let session = TerminalSession {
            id: session_id.clone(),
            title: title.clone(),
            cwd: cwd.clone(),
            shell: shell.clone(),
            created_at: chrono::Utc::now(),
            active: true,
        };

        // Set up communication channels
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<TerminalCommand>();
        
        // Clone necessary data for the task
        let session_id_clone = session_id.clone();
        let window_clone = window.clone();
        let shell_clone = shell.clone();
        let cwd_clone = cwd.clone();
        
        // Spawn task to handle PTY I/O using blocking I/O in a separate thread
        tokio::task::spawn_blocking(move || {
            // Create PTY system inside the task to avoid Send/Sync issues
            let pty_system = native_pty_system();
            
            let pty_size = PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            };

            let pty_pair = match pty_system.openpty(pty_size) {
                Ok(pair) => pair,
                Err(e) => {
                    error!("Failed to create PTY: {}", e);
                    return;
                }
            };
            
            // Create command
            let mut cmd = CommandBuilder::new(&shell_clone);
            cmd.cwd(&cwd_clone);
            
            // Add environment variables for better terminal experience
            cmd.env("TERM", "xterm-256color");
            cmd.env("COLORTERM", "truecolor");
            cmd.env("GHOSTSHELL", "1");
            
            let _child = match pty_pair.slave.spawn_command(cmd) {
                Ok(child) => child,
                Err(e) => {
                    error!("Failed to spawn command: {}", e);
                    return;
                }
            };
            
            let mut reader = match pty_pair.master.try_clone_reader() {
                Ok(reader) => reader,
                Err(e) => {
                    error!("Failed to clone reader: {}", e);
                    return;
                }
            };
            
            let mut writer = match pty_pair.master.take_writer() {
                Ok(writer) => writer,
                Err(e) => {
                    error!("Failed to take writer: {}", e);
                    return;
                }
            };
            let mut buffer = [0u8; 8192];
            
            // Use blocking I/O with timeouts
            use std::io::{Read, Write};
            use std::time::Duration;
            
            loop {
                // Check for commands (non-blocking)
                if let Ok(cmd) = cmd_rx.try_recv() {
                    match cmd {
                        TerminalCommand::Input(data) => {
                            if let Err(e) = writer.write_all(data.as_bytes()) {
                                error!("Failed to write to PTY: {}", e);
                                break;
                            }
                            if let Err(e) = writer.flush() {
                                error!("Failed to flush PTY writer: {}", e);
                                break;
                            }
                        }
                        TerminalCommand::Resize(cols, rows) => {
                            let size = PtySize {
                                rows,
                                cols,
                                pixel_width: 0,
                                pixel_height: 0,
                            };
                            if let Err(e) = pty_pair.master.resize(size) {
                                error!("Failed to resize PTY: {}", e);
                            }
                        }
                        TerminalCommand::Close => {
                            debug!("Terminal session {} closing", session_id_clone);
                            break;
                        }
                    }
                }
                
                // Try to read from PTY (non-blocking)
                match reader.read(&mut buffer) {
                    Ok(size) if size > 0 => {
                        let data = String::from_utf8_lossy(&buffer[..size]).to_string();
                        let output = TerminalOutput {
                            session_id: session_id_clone.clone(),
                            data,
                            timestamp: chrono::Utc::now(),
                        };
                        
                        if let Err(e) = window_clone.emit("terminal-output", &output) {
                            error!("Failed to emit terminal output: {}", e);
                        }
                    }
                    Ok(_) => {
                        // No data available, sleep briefly
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available, sleep briefly
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        error!("Failed to read from PTY: {}", e);
                        break;
                    }
                }
            }
            
            info!("Terminal session {} ended", session_id_clone);
            
            // Emit session closed event
            if let Err(e) = window_clone.emit("terminal-session-closed", &session_id_clone) {
                error!("Failed to emit session closed event: {}", e);
            }
        });

        // Store session and command channel
        self.sessions.write().await.insert(session_id.clone(), session.clone());
        self.session_channels.write().await.insert(session_id.clone(), cmd_tx);
        
        info!("Created terminal session: {} ({})", title, session_id);
        Ok(session)
    }

    pub async fn send_input(&self, session_id: &str, data: &str) -> Result<()> {
        let channels = self.session_channels.read().await;
        if let Some(cmd_tx) = channels.get(session_id) {
            cmd_tx.send(TerminalCommand::Input(data.to_string()))
                .map_err(|e| anyhow!("Failed to send input: {}", e))?;
            Ok(())
        } else {
            Err(anyhow!("Session not found: {}", session_id))
        }
    }

    pub async fn resize_session(&self, session_id: &str, cols: u16, rows: u16) -> Result<()> {
        let channels = self.session_channels.read().await;
        if let Some(cmd_tx) = channels.get(session_id) {
            cmd_tx.send(TerminalCommand::Resize(cols, rows))
                .map_err(|e| anyhow!("Failed to send resize command: {}", e))?;
            debug!("Resized session {} to {}x{}", session_id, cols, rows);
            Ok(())
        } else {
            Err(anyhow!("Session not found: {}", session_id))
        }
    }

    pub async fn close_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let mut channels = self.session_channels.write().await;
        
        if let Some(cmd_tx) = channels.remove(session_id) {
            let _ = cmd_tx.send(TerminalCommand::Close);
        }
        
        if sessions.remove(session_id).is_some() {
            info!("Closed terminal session: {}", session_id);
            Ok(())
        } else {
            Err(anyhow!("Session not found: {}", session_id))
        }
    }

    pub async fn list_sessions(&self) -> Vec<TerminalSession> {
        self.sessions.read().await
            .values()
            .cloned()
            .collect()
    }

    async fn get_default_shell(&self) -> String {
        #[cfg(windows)]
        {
            // Use static default to prevent console windows during startup
            "pwsh".to_string() // Default to PowerShell Core, fallback handled in simple_shell
        }
        
        #[cfg(unix)]
        {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string())
        }
    }
}

// Tauri commands
#[tauri::command]
pub async fn create_terminal_session(
    terminal_manager: State<'_, TerminalManager>,
    window: Window,
    title: Option<String>,
    cwd: Option<String>,
) -> Result<TerminalSession, String> {
    terminal_manager
        .create_session(window, title, cwd)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn send_terminal_input(
    terminal_manager: State<'_, TerminalManager>,
    input: TerminalInput,
) -> Result<(), String> {
    terminal_manager
        .send_input(&input.session_id, &input.data)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn resize_terminal(
    terminal_manager: State<'_, TerminalManager>,
    resize: TerminalResize,
) -> Result<(), String> {
    terminal_manager
        .resize_session(&resize.session_id, resize.cols, resize.rows)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn close_terminal_session(
    terminal_manager: State<'_, TerminalManager>,
    session_id: String,
) -> Result<(), String> {
    terminal_manager
        .close_session(&session_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_terminal_sessions(
    terminal_manager: State<'_, TerminalManager>,
) -> Result<Vec<TerminalSession>, String> {
    Ok(terminal_manager.list_sessions().await)
}
