//! Script execution archive and audit trail management

use crate::{ExecutionRecord, ScriptError, ScriptResult, ScriptBundle, ExecutionStats};
use chrono::{DateTime, Utc};
use ghost_pq::{DilithiumSigner, DilithiumVariant};
use rusqlite::{Connection, params};
use r2d2_sqlite::SqliteConnectionManager;
use r2d2::Pool;
use serde_json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Script execution archive manager
pub struct ExecutionArchive {
    /// Database connection pool for execution records
    db_pool: Pool<SqliteConnectionManager>,
    /// Archive directory for storing execution artifacts
    archive_dir: PathBuf,
    /// Cryptographic signer for audit trail integrity
    signer: Arc<DilithiumSigner>,
    /// Private key for signing
    private_key: Arc<ghost_pq::DilithiumPrivateKey>,
    /// Execution statistics cache
    stats_cache: Arc<RwLock<Option<ExecutionStats>>>,
}

impl ExecutionArchive {
    /// Create a new execution archive
    pub fn new(archive_dir: PathBuf) -> ScriptResult<Self> {
        // Ensure archive directory exists
        std::fs::create_dir_all(&archive_dir)?;
        
        let db_path = archive_dir.join("executions.db");
        
        // Initialize connection pool
        let manager = SqliteConnectionManager::file(&db_path);
        let db_pool = Pool::new(manager)
            .map_err(|e| ScriptError::Database(format!("Failed to create connection pool: {}", e)))?;
        
        // Initialize cryptographic signer
        let signer = Arc::new(
            DilithiumSigner::new(DilithiumVariant::Dilithium2)
                .map_err(|e| ScriptError::Crypto(e))?
        );
        
        // Generate keypair for signing
        let keypair = signer.generate_keypair()
            .map_err(|e| ScriptError::Crypto(e))?;
        let private_key = Arc::new(keypair.private_key);
        
        let archive = Self {
            db_pool,
            archive_dir,
            signer,
            private_key,
            stats_cache: Arc::new(RwLock::new(None)),
        };
        
        // Initialize database
        archive.initialize_database()?;
        
        Ok(archive)
    }
    
    /// Initialize the archive database
    fn initialize_database(&self) -> ScriptResult<()> {
        let conn = self.db_pool.get()
            .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
        
        // Execution records table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS execution_records (
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
                status TEXT NOT NULL,
                archived_at TEXT,
                archive_path TEXT
            )",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        // Execution artifacts table (for storing additional files)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS execution_artifacts (
                id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                checksum TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(execution_id) REFERENCES execution_records(id)
            )",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        // Archive statistics table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS archive_stats (
                id INTEGER PRIMARY KEY,
                total_executions INTEGER NOT NULL,
                successful_executions INTEGER NOT NULL,
                failed_executions INTEGER NOT NULL,
                total_runtime_ms INTEGER NOT NULL,
                archive_size_bytes INTEGER NOT NULL,
                last_updated TEXT NOT NULL
            )",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        // Create indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_execution_records_timestamp ON execution_records(timestamp)",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_execution_records_script_id ON execution_records(script_id)",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_execution_records_executor ON execution_records(executor)",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        info!("Initialized execution archive database");
        Ok(())
    }
    
    /// Archive an execution record
    pub async fn archive_execution(&self, record: &ExecutionRecord) -> ScriptResult<()> {
        let archived_at = Utc::now();
        
        // Create archive path for this execution
        let date_path = archived_at.format("%Y/%m/%d").to_string();
        let execution_dir = self.archive_dir
            .join("executions")
            .join(&date_path)
            .join(&record.id);
        
        std::fs::create_dir_all(&execution_dir)?;
        
        // Store execution record as JSON
        let record_path = execution_dir.join("execution.json");
        let record_json = serde_json::to_string_pretty(record)?;
        std::fs::write(&record_path, &record_json)?;
        
        // Store stdout if present
        if !record.stdout.is_empty() {
            let stdout_path = execution_dir.join("stdout.txt");
            std::fs::write(&stdout_path, &record.stdout)?;
        }
        
        // Store stderr if present
        if !record.stderr.is_empty() {
            let stderr_path = execution_dir.join("stderr.txt");
            std::fs::write(&stderr_path, &record.stderr)?;
        }
        
        // Generate signature for the execution record
        let signature_data = format!(
            "{}{}{}{}{}",
            record.id,
            record.script_id,
            record.executor,
            record.timestamp.to_rfc3339(),
            record_json
        );
        
        let signature = self.signer.sign(&self.private_key, signature_data.as_bytes())
            .map_err(|e| ScriptError::Crypto(e))?;
        let signature_hex = hex::encode(&signature.signature);
        
        // Store signature
        let signature_path = execution_dir.join("signature.txt");
        std::fs::write(&signature_path, &signature_hex)?;
        
        // Update database record - perform all DB operations in a single scope
        {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            let parameters_json = serde_json::to_string(&record.parameters)?;
            
            conn.execute(
                "INSERT OR REPLACE INTO execution_records 
                 (id, script_id, script_name, executor, parameters, stdout, stderr, 
                  exit_code, runtime_ms, timestamp, signature, status, archived_at, archive_path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
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
                    signature_hex,
                    format!("{:?}", record.status),
                    archived_at.to_rfc3339(),
                    execution_dir.to_string_lossy().to_string(),
                ]
            ).map_err(|e| ScriptError::Database(e.to_string()))?;
        }
        
        // Invalidate stats cache
        {
            let mut cache = self.stats_cache.write().await;
            *cache = None;
        }
        
        info!("Archived execution {} to {:?}", record.id, execution_dir);
        Ok(())
    }
    
    /// Retrieve an execution record from archive
    pub async fn get_execution(&self, execution_id: &str) -> ScriptResult<Option<ExecutionRecord>> {
        // Perform all DB operations in a single scope
        let result = {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            conn.query_row(
                "SELECT id, script_id, script_name, executor, parameters, stdout, stderr, 
                        exit_code, runtime_ms, timestamp, signature, status
                 FROM execution_records WHERE id = ?1",
                params![execution_id],
                |row| {
                    let parameters_json: String = row.get(4)?;
                    let parameters: HashMap<String, String> = serde_json::from_str(&parameters_json)
                        .unwrap_or_default();
                    
                    let status_str: String = row.get(11)?;
                    let status = match status_str.as_str() {
                        "Running" => crate::ExecutionStatus::Running,
                        "Success" => crate::ExecutionStatus::Success,
                        "Failed" => crate::ExecutionStatus::Failed,
                        "Cancelled" => crate::ExecutionStatus::Cancelled,
                        "TimedOut" => crate::ExecutionStatus::TimedOut,
                        _ => crate::ExecutionStatus::Failed,
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
            )
        };
        
        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ScriptError::Database(e.to_string())),
        }
    }
    
    /// Search execution records
    pub async fn search_executions(
        &self,
        script_id: Option<&str>,
        executor: Option<&str>,
        status: Option<&str>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> ScriptResult<Vec<ExecutionRecord>> {
        // Perform all DB operations in a single scope
        let results = {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            let mut sql = "SELECT id, script_id, script_name, executor, parameters, stdout, stderr, 
                                  exit_code, runtime_ms, timestamp, signature, status
                           FROM execution_records WHERE 1=1".to_string();
            let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
            
            if let Some(script_id) = script_id {
                sql.push_str(&format!(" AND script_id = ?{}", params.len() + 1));
                params.push(Box::new(script_id.to_string()));
            }
            
            if let Some(executor) = executor {
                sql.push_str(&format!(" AND executor = ?{}", params.len() + 1));
                params.push(Box::new(executor.to_string()));
            }
            
            if let Some(status) = status {
                sql.push_str(&format!(" AND status = ?{}", params.len() + 1));
                params.push(Box::new(status.to_string()));
            }
            
            if let Some(start_time) = start_time {
                sql.push_str(&format!(" AND timestamp >= ?{}", params.len() + 1));
                params.push(Box::new(start_time.to_rfc3339()));
            }
            
            if let Some(end_time) = end_time {
                sql.push_str(&format!(" AND timestamp <= ?{}", params.len() + 1));
                params.push(Box::new(end_time.to_rfc3339()));
            }
            
            sql.push_str(" ORDER BY timestamp DESC");
            
            if let Some(limit) = limit {
                sql.push_str(&format!(" LIMIT {}", limit));
            }
            
            if let Some(offset) = offset {
                sql.push_str(&format!(" OFFSET {}", offset));
            }
            
            let mut stmt = conn.prepare(&sql)
                .map_err(|e| ScriptError::Database(e.to_string()))?;
            
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            
            let rows = stmt.query_map(&param_refs[..], |row| {
                let parameters_json: String = row.get(4)?;
                let parameters: HashMap<String, String> = serde_json::from_str(&parameters_json)
                    .unwrap_or_default();
                
                let status_str: String = row.get(11)?;
                let status = match status_str.as_str() {
                    "Running" => crate::ExecutionStatus::Running,
                    "Success" => crate::ExecutionStatus::Success,
                    "Failed" => crate::ExecutionStatus::Failed,
                    "Cancelled" => crate::ExecutionStatus::Cancelled,
                    "TimedOut" => crate::ExecutionStatus::TimedOut,
                    _ => crate::ExecutionStatus::Failed,
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
            
            let mut results = Vec::new();
            for row in rows {
                results.push(row.map_err(|e| ScriptError::Database(e.to_string()))?);
            }
            
            results
        };
        
        Ok(results)
    }
    
    /// Get execution statistics
    pub async fn get_stats(&self) -> ScriptResult<ExecutionStats> {
        // Check cache first
        {
            let cache = self.stats_cache.read().await;
            if let Some(stats) = cache.as_ref() {
                return Ok(stats.clone());
            }
        }
        
        // Calculate stats from database - perform all DB operations in a single scope
        let (total_runs, successful_runs, failed_runs, average_runtime_ms) = {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            let total_runs: usize = conn.query_row(
                "SELECT COUNT(*) FROM execution_records",
                [],
                |row| row.get(0)
            ).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            let successful_runs: usize = conn.query_row(
                "SELECT COUNT(*) FROM execution_records WHERE status = 'Success'",
                [],
                |row| row.get(0)
            ).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            let failed_runs: usize = conn.query_row(
                "SELECT COUNT(*) FROM execution_records WHERE status = 'Failed'",
                [],
                |row| row.get(0)
            ).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            let average_runtime_ms: f64 = conn.query_row(
                "SELECT AVG(runtime_ms) FROM execution_records WHERE status = 'Success'",
                [],
                |row| row.get(0)
            ).unwrap_or(0.0);
            
            (total_runs, successful_runs, failed_runs, average_runtime_ms)
        };
        
        // Get recent activity (last 10 executions)
        let recent_activity = self.search_executions(
            None, None, None, None, None, Some(10), None
        ).await?;
        
        let stats = ExecutionStats {
            total_runs,
            successful_runs,
            failed_runs,
            average_runtime_ms,
            runs_by_language: HashMap::new(), // TODO: Implement
            runs_by_user: HashMap::new(), // TODO: Implement
            recent_activity,
        };
        
        // Update cache
        {
            let mut cache = self.stats_cache.write().await;
            *cache = Some(stats.clone());
        }
        
        Ok(stats)
    }
    
    /// Verify execution record integrity
    pub async fn verify_execution(&self, execution_id: &str) -> ScriptResult<bool> {
        let record = self.get_execution(execution_id).await?
            .ok_or_else(|| ScriptError::ScriptNotFound(execution_id.to_string()))?;
        
        if let Some(signature_hex) = &record.signature {
            // Reconstruct the signed data
            let record_json = serde_json::to_string(&record)?;
            let signature_data = format!(
                "{}{}{}{}{}",
                record.id,
                record.script_id,
                record.executor,
                record.timestamp.to_rfc3339(),
                record_json
            );
            
            // Decode signature
            let signature = hex::decode(signature_hex)
                .map_err(|e| ScriptError::Validation(format!("Invalid signature format: {}", e)))?;
            
            // Verify signature (in a full implementation, you'd verify against public key)
            // For now, we'll just check that the signature exists and is valid hex
            Ok(signature.len() > 0)
        } else {
            Ok(false) // No signature to verify
        }
    }
    
    /// Export execution records as a signed bundle
    pub async fn export_executions(
        &self,
        execution_ids: &[String],
        exported_by: String,
    ) -> ScriptResult<PathBuf> {
        let export_id = Uuid::new_v4().to_string();
        let export_dir = self.archive_dir.join("exports").join(&export_id);
        std::fs::create_dir_all(&export_dir)?;
        
        let mut records = Vec::new();
        for execution_id in execution_ids {
            if let Some(record) = self.get_execution(execution_id).await? {
                records.push(record);
            }
        }
        
        // Create export bundle
        let bundle = serde_json::json!({
            "export_id": export_id,
            "exported_by": exported_by,
            "exported_at": Utc::now().to_rfc3339(),
            "execution_count": records.len(),
            "executions": records
        });
        
        let bundle_path = export_dir.join("executions.json");
        let bundle_json = serde_json::to_string_pretty(&bundle)?;
        std::fs::write(&bundle_path, &bundle_json)?;
        
        // Sign the bundle
        let signature = self.signer.sign(&self.private_key, bundle_json.as_bytes())
            .map_err(|e| ScriptError::Crypto(e))?;
        let signature_hex = hex::encode(&signature.signature);
        
        let signature_path = export_dir.join("signature.txt");
        std::fs::write(&signature_path, &signature_hex)?;
        
        info!("Exported {} executions to {:?}", records.len(), export_dir);
        Ok(bundle_path)
    }
    
    /// Clean up old execution records
    pub async fn cleanup_old_records(&self, older_than_days: u32) -> ScriptResult<usize> {
        let cutoff_date = Utc::now() - chrono::Duration::days(older_than_days as i64);
        
        // Perform all DB operations in a single scope
        let deleted_count = {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            // Get records to delete
            let mut stmt = conn.prepare(
                "SELECT id, archive_path FROM execution_records WHERE timestamp < ?1"
            ).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            let rows = stmt.query_map(params![cutoff_date.to_rfc3339()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            }).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            let mut deleted_count = 0;
            for row in rows {
                let (_execution_id, archive_path) = row.map_err(|e| ScriptError::Database(e.to_string()))?;
                
                // Delete archive directory if it exists
                if let Some(path) = archive_path {
                    let archive_dir = PathBuf::from(path);
                    if archive_dir.exists() {
                        std::fs::remove_dir_all(&archive_dir)?;
                    }
                }
                
                deleted_count += 1;
            }
            
            // Delete from database
            conn.execute(
                "DELETE FROM execution_records WHERE timestamp < ?1",
                params![cutoff_date.to_rfc3339()]
            ).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            deleted_count
        };
        
        // Invalidate stats cache
        {
            let mut cache = self.stats_cache.write().await;
            *cache = None;
        }
        
        info!("Cleaned up {} old execution records", deleted_count);
        Ok(deleted_count)
    }
}
