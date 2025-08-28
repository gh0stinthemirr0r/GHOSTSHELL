use anyhow::Result;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use crate::shell_integration::ShellType;

/// Represents a persistent shell session using PTY
pub struct PtyShellSession {
    pub session_id: String,
    pub shell_type: ShellType,
    pub writer: Arc<Mutex<Box<dyn Write + Send>>>,
    pub output_buffer: Arc<Mutex<String>>,
    pub reader_handle: Option<tokio::task::JoinHandle<()>>,
    pub is_active: Arc<Mutex<bool>>,
}

impl PtyShellSession {
    pub async fn new(
        session_id: String,
        shell_type: ShellType,
    ) -> Result<Self> {
        let pty_system = native_pty_system();
        
        // Create PTY with appropriate size
        let pty_pair = pty_system.openpty(PtySize {
            rows: 30,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        // Build command based on shell type
        let mut cmd = CommandBuilder::new(Self::get_shell_executable(&shell_type)?);
        Self::configure_shell_command(&mut cmd, &shell_type)?;

        // Spawn the shell process
        let child = pty_pair.slave.spawn_command(cmd)?;
        debug!("Spawned shell process with PID: {:?}", child.process_id());

        // Get reader and writer
        let reader = pty_pair.master.try_clone_reader()?;
        let writer = pty_pair.master.take_writer()?;

        let writer = Arc::new(Mutex::new(writer));
        let output_buffer = Arc::new(Mutex::new(String::new()));
        let is_active = Arc::new(Mutex::new(true));

        // Start reading output in background
        let output_buffer_clone = output_buffer.clone();
        let is_active_clone = is_active.clone();
        let session_id_clone = session_id.clone();
        
        let reader_handle = tokio::spawn(async move {
            Self::read_output_loop(reader, output_buffer_clone, is_active_clone, session_id_clone).await;
        });

        // Give the shell a moment to initialize before sending any commands
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        Ok(Self {
            session_id,
            shell_type,
            writer,
            output_buffer,
            reader_handle: Some(reader_handle),
            is_active,
        })
    }

    fn get_shell_executable(shell_type: &ShellType) -> Result<String> {
        match shell_type {
            ShellType::PowerShell => {
                // Use the exact path that Windows Terminal uses
                Ok("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string())
            }
            ShellType::PowerShellCore => {
                // Try to find PowerShell Core using Windows Terminal's method
                let wt_paths = [
                    // Windows Terminal default paths
                    "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
                    "C:\\Program Files (x86)\\PowerShell\\7\\pwsh.exe",
                    // Microsoft Store version
                    "C:\\Program Files\\WindowsApps\\Microsoft.PowerShell_7.5.2.0_x64__8wekyb3d8bbwe\\pwsh.exe",
                    // Scoop installation
                    &format!("{}\\scoop\\apps\\powershell\\current\\pwsh.exe", std::env::var("USERPROFILE").unwrap_or_default()),
                ];
                
                for path in &wt_paths {
                    if std::path::Path::new(path).exists() {
                        return Ok(path.to_string());
                    }
                }
                
                // Try to find via registry (Windows Terminal method)
                if let Ok(path) = Self::find_pwsh_via_registry() {
                    return Ok(path);
                }
                
                // Fallback to PATH
                Ok("pwsh.exe".to_string())
            }
            ShellType::Cmd => Ok("C:\\Windows\\System32\\cmd.exe".to_string()),
            ShellType::WSL => Ok("C:\\Windows\\System32\\wsl.exe".to_string()),
            ShellType::WSLDistro(_distro) => Ok("C:\\Windows\\System32\\wsl.exe".to_string()),
            ShellType::GitBash => {
                // Use Windows Terminal's Git Bash detection method
                let wt_paths = [
                    "C:\\Program Files\\Git\\bin\\bash.exe",
                    "C:\\Program Files (x86)\\Git\\bin\\bash.exe",
                    &format!("{}\\AppData\\Local\\Programs\\Git\\bin\\bash.exe", std::env::var("USERPROFILE").unwrap_or_default()),
                ];
                
                for path in &wt_paths {
                    if std::path::Path::new(path).exists() {
                        return Ok(path.to_string());
                    }
                }
                
                Ok("bash.exe".to_string())
            }
            ShellType::Custom(exe) => Ok(exe.clone()),
        }
    }

    fn find_pwsh_via_registry() -> Result<String> {
        // This is a simplified version - in a real implementation,
        // you'd query the Windows registry to find PowerShell Core installations
        // For now, return a common path
        Ok("pwsh.exe".to_string())
    }

    fn clean_terminal_output(output: &str) -> String {
        let mut result = String::new();
        let mut chars = output.chars().peekable();
        
        while let Some(ch) = chars.next() {
            match ch {
                // Handle ANSI escape sequences starting with ESC [
                '\x1b' => {
                    if chars.peek() == Some(&'[') {
                        chars.next(); // consume '['
                        // Skip until we find a letter (end of ANSI sequence)
                        while let Some(next_ch) = chars.next() {
                            if next_ch.is_ascii_alphabetic() {
                                break;
                            }
                        }
                    } else if chars.peek() == Some(&']') {
                        chars.next(); // consume ']'
                        // Skip until we find a control character or specific end
                        while let Some(next_ch) = chars.next() {
                            if next_ch == '\x07' || next_ch == '\x1b' {
                                break;
                            }
                        }
                    }
                    // Skip other escape sequences
                }
                // Handle other control characters
                '\x07' | '\x08' | '\x0c' => {
                    // Skip bell, backspace, form feed
                }
                // Convert carriage return + newline to just newline
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next(); // consume the \n
                        result.push('\n');
                    }
                    // Otherwise skip standalone \r
                }
                // Keep printable characters and newlines/tabs
                c if c >= ' ' || c == '\n' || c == '\t' => {
                    result.push(c);
                }
                // Skip other control characters
                _ => {}
            }
        }
        
        // Clean up multiple consecutive newlines
        while result.contains("\n\n\n") {
            result = result.replace("\n\n\n", "\n\n");
        }
        
        result
    }

    fn configure_shell_command(cmd: &mut CommandBuilder, shell_type: &ShellType) -> Result<()> {
        match shell_type {
            ShellType::PowerShell => {
                // Minimal args to keep PowerShell stable
                cmd.arg("-NoLogo");
            }
            ShellType::PowerShellCore => {
                // Minimal args to keep PowerShell Core stable
                cmd.arg("-NoLogo");
            }
            ShellType::Cmd => {
                // No arguments for CMD to keep it simple
            }
            ShellType::WSL => {
                // Just run WSL with default distro
            }
            ShellType::WSLDistro(distro) => {
                cmd.arg("-d");
                cmd.arg(distro);
            }
            ShellType::GitBash => {
                // Minimal args for Git Bash
                cmd.arg("--login");
            }
            ShellType::Custom(_) => {
                // Custom shells - assume they work interactively by default
            }
        }
        Ok(())
    }

    async fn read_output_loop(
        reader: Box<dyn std::io::Read + Send>,
        output_buffer: Arc<Mutex<String>>,
        is_active: Arc<Mutex<bool>>,
        session_id: String,
    ) {
        let mut buf_reader = BufReader::new(reader);
        let mut line_buffer = String::new();
        
        info!("Starting output loop for session {}", session_id);
        
        loop {
            // Check if session is still active
            {
                let active = is_active.lock().await;
                if !*active {
                    debug!("Session {} marked inactive, stopping output loop", session_id);
                    break;
                }
            }
            
            // Try to read a line with timeout
            let read_result = tokio::task::spawn_blocking({
                let mut buf_reader = buf_reader;
                let mut line_buffer = line_buffer;
                move || {
                    line_buffer.clear();
                    match buf_reader.read_line(&mut line_buffer) {
                        Ok(0) => {
                            debug!("PTY reader reached EOF for session");
                            (buf_reader, line_buffer, None)
                        }
                        Ok(_) => {
                            let output = line_buffer.clone();
                            (buf_reader, line_buffer, Some(output))
                        }
                        Err(e) => {
                            error!("Error reading from PTY: {}", e);
                            (buf_reader, line_buffer, None)
                        }
                    }
                }
            }).await;
            
            match read_result {
                Ok((new_buf_reader, new_line_buffer, Some(output))) => {
                    buf_reader = new_buf_reader;
                    line_buffer = new_line_buffer;
                    
                    // Add to output buffer with cleaning
                    {
                        let mut buffer = output_buffer.lock().await;
                        let cleaned_output = Self::clean_terminal_output(&output);
                        buffer.push_str(&cleaned_output);
                        
                        // Keep buffer size reasonable (last 50KB)
                        if buffer.len() > 51200 {
                            let start = buffer.len() - 40960;
                            *buffer = buffer[start..].to_string();
                        }
                    }
                    
                    debug!("Added output to session {}: {}", session_id, output.trim());
                }
                Ok((new_buf_reader, new_line_buffer, None)) => {
                    buf_reader = new_buf_reader;
                    line_buffer = new_line_buffer;
                    break;
                }
                Err(e) => {
                    error!("Task error in output loop for session {}: {}", session_id, e);
                    break;
                }
            }
            
            // Small delay to prevent busy waiting
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        info!("Output loop ended for session {}", session_id);
    }

    pub async fn write_input(&self, input: &str) -> Result<()> {
        debug!("Writing input to session {}: '{}'", self.session_id, input.trim());
        
        // Check if session is still active
        {
            let active = self.is_active.lock().await;
            if !*active {
                return Err(anyhow::anyhow!("Session {} is not active", self.session_id));
            }
        }
        
        let mut writer = self.writer.lock().await;
        
        // Use simple newline for all shells to avoid encoding issues
        let input_with_newline = if input.ends_with('\n') {
            input.to_string()
        } else {
            format!("{}\n", input)
        };
        
        match writer.write_all(input_with_newline.as_bytes()) {
            Ok(_) => {
                match writer.flush() {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        warn!("Failed to flush writer for session {}: {}", self.session_id, e);
                        // Mark session as inactive
                        let mut active = self.is_active.lock().await;
                        *active = false;
                        Err(anyhow::anyhow!("Session pipe closed: {}", e))
                    }
                }
            }
            Err(e) => {
                warn!("Failed to write to session {}: {}", self.session_id, e);
                // Mark session as inactive
                let mut active = self.is_active.lock().await;
                *active = false;
                Err(anyhow::anyhow!("Session pipe closed: {}", e))
            }
        }
    }

    pub async fn get_output(&self) -> String {
        let buffer = self.output_buffer.lock().await;
        buffer.clone()
    }

    pub async fn get_new_output(&self) -> String {
        let mut buffer = self.output_buffer.lock().await;
        let output = buffer.clone();
        buffer.clear();
        output
    }

    pub async fn close(&self) -> Result<()> {
        // Mark session as inactive
        {
            let mut active = self.is_active.lock().await;
            *active = false;
        }
        
        debug!("Closed PTY session: {}", self.session_id);
        Ok(())
    }
}

impl Drop for PtyShellSession {
    fn drop(&mut self) {
        if let Some(handle) = self.reader_handle.take() {
            handle.abort();
        }
    }
}

/// Manager for persistent shell sessions
pub struct PtyShellManager {
    sessions: Arc<RwLock<HashMap<String, Arc<PtyShellSession>>>>,
}

impl PtyShellManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_session(
        &self,
        session_id: String,
        shell_type: ShellType,
    ) -> Result<()> {
        info!("Creating PTY session: {} with shell type: {:?}", session_id, shell_type);
        
        let session = PtyShellSession::new(
            session_id.clone(),
            shell_type,
        ).await?;

        let session = Arc::new(session);
        
        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session);
        }

        info!("Created PTY shell session: {}", session_id);
        Ok(())
    }

    pub async fn write_to_session(&self, session_id: &str, input: &str) -> Result<()> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            session.write_input(input).await?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Session not found: {}", session_id))
        }
    }



    pub async fn close_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get(session_id) {
            session.close().await?;
        }
        
        sessions.remove(session_id);
        
        info!("Closed PTY shell session: {}", session_id);
        Ok(())
    }

    pub async fn get_output(&self, session_id: &str) -> Option<String> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            let output = session.get_new_output().await;
            if !output.is_empty() {
                Some(output)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub async fn get_full_output(&self, session_id: &str) -> Option<String> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            let output = session.get_output().await;
            if !output.is_empty() {
                Some(output)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub async fn list_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }
}
