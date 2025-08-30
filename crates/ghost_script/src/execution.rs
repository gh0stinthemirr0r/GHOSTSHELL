//! Script execution engine with sandboxing and policy enforcement

use crate::{
    ScriptLanguage, ExecutionRecord, ExecutionStatus, ExecutionConfig, ExecutionEvent,
    ScriptError, ScriptResult, ExecutionStats,
};
use chrono::{DateTime, Utc};

use ghost_log::{GhostLogDaemon, Resource, Action};
use rusqlite::{Connection, params};
use r2d2_sqlite::SqliteConnectionManager;
use r2d2::Pool;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command as TokioCommand};
use tokio::sync::{mpsc, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Script execution engine
pub struct ExecutionEngine {
    /// Database connection pool for execution records
    db_pool: Pool<SqliteConnectionManager>,
    /// Policy evaluator for security checks
    // Policy evaluator removed for single-user mode
    /// Ghost log daemon for audit logging
    ghost_log: Option<Arc<GhostLogDaemon>>,
    /// Active executions
    active_executions: Arc<RwLock<HashMap<String, ActiveExecution>>>,
}

/// Active execution tracking
struct ActiveExecution {
    id: String,
    script_id: String,
    executor: String,
    started: Instant,
    process: Option<Child>,
    event_sender: Option<mpsc::UnboundedSender<ExecutionEvent>>,
}

impl ExecutionEngine {
    /// Create a new execution engine
    pub fn new(db_path: PathBuf) -> ScriptResult<Self> {
        // Initialize connection pool
        let manager = SqliteConnectionManager::file(&db_path);
        let db_pool = Pool::new(manager)
            .map_err(|e| ScriptError::Database(format!("Failed to create connection pool: {}", e)))?;
        
        let engine = Self {
            db_pool,
            // Policy evaluator removed
            ghost_log: None,
            active_executions: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Initialize database
        engine.initialize_database()?;
        
        Ok(engine)
    }
    
    /// Set policy evaluator for security checks
    // Policy evaluator setter removed for single-user mode
    
    /// Set ghost log daemon for audit logging
    pub fn set_ghost_log(&mut self, ghost_log: Arc<GhostLogDaemon>) {
        self.ghost_log = Some(ghost_log);
    }
    
    /// Initialize execution records database
    fn initialize_database(&self) -> ScriptResult<()> {
        let conn = self.db_pool.get()
            .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS executions (
                id TEXT PRIMARY KEY,
                script_id TEXT NOT NULL,
                script_name TEXT NOT NULL,
                executor TEXT NOT NULL,
                parameters TEXT NOT NULL,
                stdout TEXT,
                stderr TEXT,
                exit_code INTEGER,
                runtime_ms INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                signature TEXT,
                status TEXT NOT NULL
            )",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_executions_script_id ON executions(script_id)",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_executions_executor ON executions(executor)",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_executions_timestamp ON executions(timestamp)",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        info!("Initialized execution records database with connection pool");
        Ok(())
    }
    
    /// Execute a script with the given parameters
    pub async fn execute_script(
        &self,
        script_id: String,
        script_name: String,
        script_path: PathBuf,
        language: ScriptLanguage,
        executor: String,
        parameters: HashMap<String, String>,
        config: ExecutionConfig,
    ) -> ScriptResult<mpsc::UnboundedReceiver<ExecutionEvent>> {
        let execution_id = Uuid::new_v4().to_string();
        
        // Policy check
        if false { // Policy evaluation removed for single-user mode
            let mut subject = HashMap::new();
            subject.insert("user_id".to_string(), executor.clone());
            subject.insert("role".to_string(), "script_executor".to_string());
            
            let mut context_attrs = HashMap::new();
            context_attrs.insert("script_id".to_string(), script_id.clone());
            context_attrs.insert("language".to_string(), format!("{:?}", language));
            context_attrs.insert("executor".to_string(), executor.clone());
            
            // Policy evaluation removed for single-user mode
        }
        
        // Create event channel
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        // Send start event
        event_sender.send(ExecutionEvent::Started { 
            execution_id: execution_id.clone() 
        }).map_err(|_| ScriptError::Execution("Failed to send start event".to_string()))?;
        
        // Create execution record
        let active_execution = ActiveExecution {
            id: execution_id.clone(),
            script_id: script_id.clone(),
            executor: executor.clone(),
            started: Instant::now(),
            process: None,
            event_sender: Some(event_sender.clone()),
        };
        
        // Store active execution
        {
            let mut active = self.active_executions.write().await;
            active.insert(execution_id.clone(), active_execution);
        }
        
        // Spawn execution task
        let engine_clone = self.clone_for_task();
        let execution_id_clone = execution_id.clone();
        
        tokio::spawn(async move {
            let result = engine_clone.run_script_process(
                execution_id_clone.clone(),
                script_id,
                script_name,
                script_path,
                language,
                executor,
                parameters,
                config,
                event_sender,
            ).await;
            
            // Clean up active execution
            let mut active = engine_clone.active_executions.write().await;
            active.remove(&execution_id_clone);
            
            if let Err(e) = result {
                error!("Script execution failed: {}", e);
            }
        });
        
        Ok(event_receiver)
    }
    
    /// Cancel a running script execution
    pub async fn cancel_execution(&self, execution_id: &str) -> ScriptResult<()> {
        let mut active = self.active_executions.write().await;
        
        if let Some(mut execution) = active.remove(execution_id) {
            // Kill the process if it's running
            if let Some(mut process) = execution.process.take() {
                let _ = process.kill().await;
            }
            
            // Send cancellation event
            if let Some(sender) = &execution.event_sender {
                let _ = sender.send(ExecutionEvent::Error { 
                    message: "Execution cancelled by user".to_string() 
                });
            }
            
            info!("Cancelled execution: {}", execution_id);
            Ok(())
        } else {
            Err(ScriptError::Execution(format!("Execution not found: {}", execution_id)))
        }
    }
    
    /// Get execution record by ID
    pub async fn get_execution_record(&self, execution_id: &str) -> ScriptResult<Option<ExecutionRecord>> {
        let conn = self.db_pool.get()
            .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
        
        let result = conn.query_row(
            "SELECT id, script_id, script_name, executor, parameters, stdout, stderr, 
                    exit_code, runtime_ms, timestamp, signature, status
             FROM executions WHERE id = ?1",
            params![execution_id],
            |row| {
                let parameters_json: String = row.get(4)?;
                let parameters: HashMap<String, String> = serde_json::from_str(&parameters_json)
                    .unwrap_or_default();
                
                let status_str: String = row.get(11)?;
                let status = match status_str.as_str() {
                    "Running" => ExecutionStatus::Running,
                    "Success" => ExecutionStatus::Success,
                    "Failed" => ExecutionStatus::Failed,
                    "Cancelled" => ExecutionStatus::Cancelled,
                    "TimedOut" => ExecutionStatus::TimedOut,
                    _ => ExecutionStatus::Failed,
                };
                
                Ok(ExecutionRecord {
                    id: row.get(0)?,
                    script_id: row.get(1)?,
                    script_name: row.get(2)?,
                    executor: row.get(3)?,
                    parameters,
                    stdout: row.get(5)?,
                    stderr: row.get(6)?,
                    exit_code: row.get(7)?,
                    runtime_ms: row.get::<_, i64>(8)? as u64,
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                        .unwrap().with_timezone(&Utc),
                    signature: row.get(10)?,
                    status,
                })
            }
        );
        
        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ScriptError::Database(e.to_string())),
        }
    }
    
    /// Get execution statistics
    pub async fn get_execution_stats(&self) -> ScriptResult<ExecutionStats> {
        let conn = self.db_pool.get()
            .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
        
        // Total runs
        let total_runs: usize = conn.query_row(
            "SELECT COUNT(*) FROM executions",
            [],
            |row| row.get(0)
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        // Successful runs
        let successful_runs: usize = conn.query_row(
            "SELECT COUNT(*) FROM executions WHERE status = 'Success'",
            [],
            |row| row.get(0)
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        // Failed runs
        let failed_runs: usize = conn.query_row(
            "SELECT COUNT(*) FROM executions WHERE status = 'Failed'",
            [],
            |row| row.get(0)
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        // Average runtime
        let average_runtime_ms: f64 = conn.query_row(
            "SELECT AVG(runtime_ms) FROM executions WHERE status = 'Success'",
            [],
            |row| row.get(0)
        ).unwrap_or(0.0);
        
        // Recent activity (last 10 executions)
        let mut stmt = conn.prepare(
            "SELECT id, script_id, script_name, executor, parameters, stdout, stderr, 
                    exit_code, runtime_ms, timestamp, signature, status
             FROM executions ORDER BY timestamp DESC LIMIT 10"
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        let rows = stmt.query_map([], |row| {
            let parameters_json: String = row.get(4)?;
            let parameters: HashMap<String, String> = serde_json::from_str(&parameters_json)
                .unwrap_or_default();
            
            let status_str: String = row.get(11)?;
            let status = match status_str.as_str() {
                "Running" => ExecutionStatus::Running,
                "Success" => ExecutionStatus::Success,
                "Failed" => ExecutionStatus::Failed,
                "Cancelled" => ExecutionStatus::Cancelled,
                "TimedOut" => ExecutionStatus::TimedOut,
                _ => ExecutionStatus::Failed,
            };
            
            Ok(ExecutionRecord {
                id: row.get(0)?,
                script_id: row.get(1)?,
                script_name: row.get(2)?,
                executor: row.get(3)?,
                parameters,
                stdout: row.get(5)?,
                stderr: row.get(6)?,
                exit_code: row.get(7)?,
                runtime_ms: row.get::<_, i64>(8)? as u64,
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap().with_timezone(&Utc),
                signature: row.get(10)?,
                status,
            })
        }).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        let mut recent_activity = Vec::new();
        for row in rows {
            recent_activity.push(row.map_err(|e| ScriptError::Database(e.to_string()))?);
        }
        
        Ok(ExecutionStats {
            total_runs,
            successful_runs,
            failed_runs,
            average_runtime_ms,
            runs_by_language: HashMap::new(), // TODO: Implement
            runs_by_user: HashMap::new(), // TODO: Implement
            recent_activity,
        })
    }
    
    /// Internal method to run script process
    async fn run_script_process(
        &self,
        execution_id: String,
        script_id: String,
        script_name: String,
        script_path: PathBuf,
        language: ScriptLanguage,
        executor: String,
        parameters: HashMap<String, String>,
        config: ExecutionConfig,
        event_sender: mpsc::UnboundedSender<ExecutionEvent>,
    ) -> ScriptResult<()> {
        let start_time = Instant::now();
        let timestamp = Utc::now();
        
        // Build command based on language
        let mut cmd = self.build_command(&language, &script_path, &parameters, &config)?;
        
        // Configure process
        cmd.stdout(Stdio::piped())
           .stderr(Stdio::piped())
           .stdin(Stdio::null());
        
        if let Some(working_dir) = &config.working_directory {
            cmd.current_dir(working_dir);
        }
        
        // Set environment variables
        for (key, value) in &config.environment {
            cmd.env(key, value);
        }
        
        // Spawn process
        let mut child = cmd.spawn()
            .map_err(|e| ScriptError::Execution(format!("Failed to spawn process: {}", e)))?;
        
        // Get stdout and stderr handles before moving child
        let stdout = child.stdout.take()
            .ok_or_else(|| ScriptError::Execution("Failed to get stdout".to_string()))?;
        let stderr = child.stderr.take()
            .ok_or_else(|| ScriptError::Execution("Failed to get stderr".to_string()))?;
        
        // Store child reference for waiting, but keep it for process management
        // Note: We'll need to handle the process waiting differently since we can't move and store
        
        // Spawn tasks to read output
        let event_sender_stdout = event_sender.clone();
        let stdout_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let mut full_output = String::new();
            
            while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                full_output.push_str(&line);
                let _ = event_sender_stdout.send(ExecutionEvent::Stdout { 
                    data: line.clone() 
                });
                line.clear();
            }
            
            full_output
        });
        
        let event_sender_stderr = event_sender.clone();
        let stderr_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            let mut full_output = String::new();
            
            while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                full_output.push_str(&line);
                let _ = event_sender_stderr.send(ExecutionEvent::Stderr { 
                    data: line.clone() 
                });
                line.clear();
            }
            
            full_output
        });
        
        // Wait for process with timeout
        let wait_result = if let Some(timeout_secs) = config.timeout {
            timeout(Duration::from_secs(timeout_secs), child.wait()).await
        } else {
            Ok(child.wait().await)
        };
        
        let (exit_status, status) = match wait_result {
            Ok(Ok(exit_status)) => {
                let status = if exit_status.success() {
                    ExecutionStatus::Success
                } else {
                    ExecutionStatus::Failed
                };
                (exit_status.code(), status)
            },
            Ok(Err(e)) => {
                error!("Process wait error: {}", e);
                (None, ExecutionStatus::Failed)
            },
            Err(_) => {
                // Timeout occurred
                warn!("Script execution timed out: {}", execution_id);
                (None, ExecutionStatus::TimedOut)
            },
        };
        
        // Collect output
        let stdout_output = stdout_task.await.unwrap_or_default();
        let stderr_output = stderr_task.await.unwrap_or_default();
        
        let runtime_ms = start_time.elapsed().as_millis() as u64;
        
        // Send completion event
        let _ = event_sender.send(ExecutionEvent::Finished { 
            exit_code: exit_status, 
            runtime_ms 
        });
        
        // Create execution record
        let record = ExecutionRecord {
            id: execution_id,
            script_id,
            script_name,
            executor,
            parameters,
            stdout: stdout_output,
            stderr: stderr_output,
            exit_code: exit_status,
            runtime_ms,
            timestamp,
            signature: None, // TODO: Sign execution record
            status,
        };
        
        // Store execution record
        self.store_execution_record(&record).await?;
        
        // Log to GhostLog if available
        if let Some(ghost_log) = &self.ghost_log {
            // TODO: Log execution to GhostLog
        }
        
        Ok(())
    }
    
    /// Build command for script execution
    fn build_command(
        &self,
        language: &ScriptLanguage,
        script_path: &Path,
        parameters: &HashMap<String, String>,
        _config: &ExecutionConfig,
    ) -> ScriptResult<TokioCommand> {
        let mut cmd = match language {
            ScriptLanguage::Python => {
                let mut cmd = TokioCommand::new("python");
                cmd.arg(script_path);
                
                // Add parameters as command line arguments
                for (key, value) in parameters {
                    cmd.arg(format!("--{}", key));
                    cmd.arg(value);
                }
                
                cmd
            },
            ScriptLanguage::PowerShell => {
                let mut cmd = TokioCommand::new("powershell");
                cmd.arg("-ExecutionPolicy").arg("Bypass");
                cmd.arg("-File").arg(script_path);
                
                // Add parameters
                for (key, value) in parameters {
                    cmd.arg(format!("-{}", key));
                    cmd.arg(value);
                }
                
                cmd
            },
            ScriptLanguage::Batch => {
                let mut cmd = TokioCommand::new("cmd");
                cmd.arg("/C").arg(script_path);
                
                // Add parameters as environment variables for batch scripts
                for (key, value) in parameters {
                    cmd.env(format!("PARAM_{}", key.to_uppercase()), value);
                }
                
                cmd
            },
        };
        
        Ok(cmd)
    }
    
    /// Store execution record in database
    async fn store_execution_record(&self, record: &ExecutionRecord) -> ScriptResult<()> {
        let conn = self.db_pool.get()
            .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
        
        let parameters_json = serde_json::to_string(&record.parameters)?;
        
        conn.execute(
            "INSERT INTO executions 
             (id, script_id, script_name, executor, parameters, stdout, stderr, 
              exit_code, runtime_ms, timestamp, signature, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                record.id,
                record.script_id,
                record.script_name,
                record.executor,
                parameters_json,
                record.stdout,
                record.stderr,
                record.exit_code,
                record.runtime_ms as i64,
                record.timestamp.to_rfc3339(),
                record.signature,
                format!("{:?}", record.status),
            ]
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        Ok(())
    }
    
    /// Clone for async task (simplified clone)
    fn clone_for_task(&self) -> Self {
        Self {
            db_pool: self.db_pool.clone(),
            // Policy evaluator removed
            ghost_log: self.ghost_log.clone(),
            active_executions: self.active_executions.clone(),
        }
    }
}
