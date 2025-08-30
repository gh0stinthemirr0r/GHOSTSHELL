use anyhow::Result;
use nu_engine::eval_block;
use nu_protocol::debugger::WithoutDebug;
use nu_parser::parse;
use nu_protocol::{
    engine::{EngineState, Stack, StateWorkingSet},
    PipelineData, Value,
};
use nu_command::add_shell_command_context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info};
// use uuid::Uuid; // Not used directly

/// Result of executing a Nushell command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NushellResult {
    pub output: String,
    pub error: Option<String>,
    pub exit_code: i32,
    pub success: bool,
}

/// Embedded Nushell session
pub struct NushellSession {
    pub session_id: String,
    pub engine_state: EngineState,
    pub stack: Stack,
    pub working_directory: String,
    pub environment: HashMap<String, String>,
}

impl NushellSession {
    /// Create a new Nushell session
    pub fn new(session_id: String) -> Result<Self> {
        info!("Creating new Nushell session: {}", session_id);
        
        // Initialize Nushell engine state with default context
        let engine_state = add_shell_command_context(EngineState::new());
        
        // Create a new stack for this session
        let mut stack = Stack::new();
        
        // Initialize essential environment variables
        let working_directory = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .to_string_lossy()
            .to_string();
            
        // Set PWD environment variable
        stack.add_env_var("PWD".to_string(), Value::string(working_directory.clone(), nu_protocol::Span::unknown()));
        
        // Set other essential environment variables
        if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
            stack.add_env_var("HOME".to_string(), Value::string(home, nu_protocol::Span::unknown()));
        }
        
        if let Ok(user) = std::env::var("USERNAME").or_else(|_| std::env::var("USER")) {
            stack.add_env_var("USER".to_string(), Value::string(user, nu_protocol::Span::unknown()));
        }
        
        // Set PATH from system environment
        if let Ok(path) = std::env::var("PATH") {
            stack.add_env_var("PATH".to_string(), Value::string(path, nu_protocol::Span::unknown()));
        }

        Ok(Self {
            session_id,
            engine_state,
            stack,
            working_directory,
            environment: HashMap::new(),
        })
    }

        /// Execute a command in this Nushell session
    pub fn execute_command(&mut self, command: &str) -> Result<NushellResult> {
        debug!("Executing Nushell command in session {}: {}", self.session_id, command);

        // Handle built-in commands first
        if let Some(result) = self.handle_builtin_command(command)? {
            return Ok(result);
        }

        // Check if this is an external command that needs special handling
        let is_external_command = self.is_external_command(command);
        debug!("Command '{}' is external: {}", command, is_external_command);

        // Parse the command
        let mut working_set = StateWorkingSet::new(&self.engine_state);
        let output = parse(&mut working_set, None, command.as_bytes(), false);

        if let Some(err) = working_set.parse_errors.first() {
            return Ok(NushellResult {
                output: String::new(),
                error: Some(format!("Parse error: {}", err)),
                exit_code: 1,
                success: false,
            });
        }

        // Merge the working set changes
        self.engine_state.merge_delta(working_set.render())?;

        // Execute the parsed block
        match eval_block::<WithoutDebug>(
            &self.engine_state,
            &mut self.stack,
            &output,
            PipelineData::empty(),
        ) {
            Ok(pipeline_data) => {
                debug!("Pipeline data type: {:?}", std::mem::discriminant(&pipeline_data));
                
                // Convert pipeline data to string
                let output_string = self.pipeline_to_string(pipeline_data)?;

                debug!("Command executed successfully in session {}, output length: {}", self.session_id, output_string.len());
                Ok(NushellResult {
                    output: if output_string.is_empty() { 
                        String::new() 
                    } else { 
                        format!("{}\n", output_string) 
                    },
                    error: None,
                    exit_code: 0,
                    success: true,
                })
            }
            Err(e) => {
                error!("Command execution failed in session {}: {}", self.session_id, e);
                Ok(NushellResult {
                    output: String::new(),
                    error: Some(format!("Execution error: {}", e)),
                    exit_code: 1,
                    success: false,
                })
            }
        }
    }

    /// Check if a command is an external command
    fn is_external_command(&self, command: &str) -> bool {
        let cmd = command.trim().split_whitespace().next().unwrap_or("");
        matches!(cmd, "ping" | "nslookup" | "tracert" | "route" | "ipconfig" | "netstat" | "arp" | "whoami" | "hostname")
    }

    /// Execute external commands directly using Windows API
    fn execute_external_command(&self, command: &str) -> Result<Option<NushellResult>> {
        debug!("Executing external command directly: {}", command);
        
        use std::process::{Command, Stdio};
        use std::os::windows::process::CommandExt;
        
        // Parse command and arguments
        let parts: Vec<&str> = command.trim().split_whitespace().collect();
        if parts.is_empty() {
            return Ok(Some(NushellResult {
                output: String::new(),
                error: Some("Empty command".to_string()),
                exit_code: 1,
                success: false,
            }));
        }
        
        let cmd_name = parts[0];
        let args = &parts[1..];
        
        debug!("Executing: {} with args: {:?}", cmd_name, args);
        
        // Execute the command with console window suppression
        let mut cmd = Command::new(cmd_name);
        cmd.args(args)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped())
           .creation_flags(0x08000000); // CREATE_NO_WINDOW
        
        // Set working directory
        cmd.current_dir(&self.working_directory);
        
        match cmd.output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let exit_code = output.status.code().unwrap_or(-1);
                
                debug!("Command completed with exit code: {}, stdout: {} chars, stderr: {} chars", 
                       exit_code, stdout.len(), stderr.len());
                
                let result_output = if !stdout.trim().is_empty() {
                    stdout.trim().to_string()
                } else if !stderr.trim().is_empty() {
                    format!("Error: {}", stderr.trim())
                } else {
                    "(no output)".to_string()
                };
                
                Ok(Some(NushellResult {
                    output: if result_output == "(no output)" { 
                        String::new() 
                    } else { 
                        format!("{}\n", result_output) 
                    },
                    error: if !stderr.trim().is_empty() && !stdout.trim().is_empty() { 
                        Some(stderr.trim().to_string()) 
                    } else { 
                        None 
                    },
                    exit_code,
                    success: exit_code == 0,
                }))
            }
            Err(e) => {
                error!("Failed to execute external command '{}': {}", command, e);
                Ok(Some(NushellResult {
                    output: String::new(),
                    error: Some(format!("Failed to execute command: {}", e)),
                    exit_code: 1,
                    success: false,
                }))
            }
        }
    }

    /// Convert pipeline data to string
    fn pipeline_to_string(&self, pipeline_data: PipelineData) -> Result<String> {
        use nu_protocol::PipelineData;
        
        debug!("Converting pipeline data to string");
        
        match pipeline_data {
            PipelineData::Value(value, _) => {
                debug!("Processing Value pipeline data");
                Ok(self.value_to_string(&value))
            }
            PipelineData::ListStream(stream, _) => {
                debug!("Processing ListStream pipeline data");
                // Convert stream to iterator and collect values
                let values: Vec<Value> = stream.into_iter().collect();
                if values.is_empty() {
                    return Ok(String::new());
                }
                
                // Format as a table-like output for structured data
                let strings: Vec<String> = values.iter()
                    .map(|v| self.value_to_string(v))
                    .collect();
                Ok(strings.join("\n"))
            }
            // Handle ByteStream data (external command output)
            PipelineData::ByteStream(byte_stream, _) => {
                debug!("Processing ByteStream pipeline data from external command");
                match byte_stream.into_bytes() {
                    Ok(bytes) => {
                        debug!("Successfully read {} bytes from byte stream", bytes.len());
                        let output = String::from_utf8_lossy(&bytes).to_string();
                        if output.trim().is_empty() {
                            debug!("Byte stream output was empty");
                            Ok("(no output)".to_string())
                        } else {
                            debug!("Byte stream output: {} characters", output.len());
                            Ok(output.trim().to_string())
                        }
                    }
                    Err(e) => {
                        error!("Failed to read byte stream: {}", e);
                        Ok("(external command output unavailable)".to_string())
                    }
                }
            }
            PipelineData::Empty => {
                debug!("Processing Empty pipeline data");
                Ok(String::new())
            }
        }
    }
    
    /// Convert a Nushell Value to a readable string
    fn value_to_string(&self, value: &Value) -> std::string::String {
        use nu_protocol::Value;
        
        match value {
            Value::String { val, .. } => val.clone(),
            Value::Int { val, .. } => val.to_string(),
            Value::Float { val, .. } => val.to_string(),
            Value::Bool { val, .. } => val.to_string(),
            Value::Nothing { .. } => std::string::String::new(),
            Value::List { vals, .. } => {
                let items: Vec<std::string::String> = vals.iter()
                    .map(|v| self.value_to_string(v))
                    .collect();
                items.join("\n")
            }
            Value::Record { val, .. } => {
                // Format record as key-value pairs
                let mut output = Vec::new();
                for (key, value) in val.iter() {
                    let value_str = self.value_to_string(value);
                    if !value_str.is_empty() {
                        output.push(format!("{}: {}", key, value_str));
                    } else {
                        output.push(key.clone());
                    }
                }
                output.join("  ")
            }
            Value::Filesize { val, .. } => {
                // Format file size in human readable format
                // Convert Filesize to i64 using into()
                let bytes: i64 = (*val).into();
                if bytes < 1024 {
                    format!("{} B", bytes)
                } else if bytes < 1024 * 1024 {
                    format!("{:.1} KB", bytes as f64 / 1024.0)
                } else if bytes < 1024 * 1024 * 1024 {
                    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
                } else {
                    format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
                }
            }
            Value::Date { val, .. } => {
                // Format datetime in readable format
                val.format("%Y-%m-%d %H:%M:%S").to_string()
            }
            _ => {
                // For other types, try to get string representation
                match value.as_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => format!("({})", value.get_type()),
                }
            }
        }
    }

    /// Handle built-in commands that need special processing
    fn handle_builtin_command(&mut self, command: &str) -> Result<Option<NushellResult>> {
        let cmd_lower = command.trim().to_lowercase();
        
        // Handle external commands directly since Nushell embedded isn't executing them properly
        if self.is_external_command(command) {
            return self.execute_external_command(command);
        }
        
        // Handle cd command
        if cmd_lower.starts_with("cd ") || cmd_lower == "cd" {
            let path = if cmd_lower == "cd" {
                // cd with no arguments goes to home directory
                std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_else(|_| ".".to_string())
            } else {
                command.trim()[3..].trim().to_string()
            };

            match std::env::set_current_dir(&path) {
                Ok(_) => {
                    self.working_directory = std::env::current_dir()
                        .unwrap_or_else(|_| std::path::PathBuf::from(&path))
                        .to_string_lossy()
                        .to_string();
                    
                    // Update PWD environment variable in Nushell stack
                    self.stack.add_env_var("PWD".to_string(), Value::string(self.working_directory.clone(), nu_protocol::Span::unknown()));
                    
                    return Ok(Some(NushellResult {
                        output: format!("Changed directory to: {}\n", self.working_directory),
                        error: None,
                        exit_code: 0,
                        success: true,
                    }));
                }
                Err(e) => {
                    return Ok(Some(NushellResult {
                        output: String::new(),
                        error: Some(format!("Failed to change directory: {}", e)),
                        exit_code: 1,
                        success: false,
                    }));
                }
            }
        }

        // Let Nushell handle pwd and other standard commands

        Ok(None)
    }
}

/// Manager for embedded Nushell sessions
pub struct EmbeddedNushellManager {
    sessions: Arc<Mutex<HashMap<String, Arc<Mutex<NushellSession>>>>>,
}

impl std::fmt::Debug for EmbeddedNushellManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedNushellManager")
            .field("sessions", &"<sessions>")
            .finish()
    }
}

impl EmbeddedNushellManager {
    /// Create a new Nushell manager
    pub fn new() -> Self {
        info!("Initializing Embedded Nushell Manager");
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new Nushell session
    pub async fn create_session(&self, session_id: String) -> Result<()> {
        info!("Creating Nushell session: {}", session_id);
        
        let session = NushellSession::new(session_id.clone())?;
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id, Arc::new(Mutex::new(session)));
        
        Ok(())
    }

    /// Execute a command in a specific session
    pub async fn execute_command(&self, session_id: &str, command: &str) -> Result<NushellResult> {
        // Get the session arc without holding the sessions lock
        let session_arc = {
            let sessions = self.sessions.lock().unwrap();
            sessions.get(session_id).cloned()
        };
        
        if let Some(session_arc) = session_arc {
            // Clone the necessary data to avoid holding the lock across await
            let command_str = command.to_string();
            let mut session = session_arc.lock().unwrap();
            session.execute_command(&command_str)
        } else {
            error!("Session not found: {}", session_id);
            Ok(NushellResult {
                output: String::new(),
                error: Some(format!("Session '{}' not found", session_id)),
                exit_code: 1,
                success: false,
            })
        }
    }

    /// Close a session
    pub async fn close_session(&self, session_id: &str) -> Result<()> {
        info!("Closing Nushell session: {}", session_id);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
        Ok(())
    }

    /// List all active sessions
    pub async fn list_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.lock().unwrap();
        sessions.keys().cloned().collect()
    }

    /// Check if a session exists
    pub async fn session_exists(&self, session_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        sessions.contains_key(session_id)
    }
}

impl Default for EmbeddedNushellManager {
    fn default() -> Self {
        Self::new()
    }
}
