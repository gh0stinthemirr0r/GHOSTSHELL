//! Main GhostScript engine that orchestrates all components

use crate::{
    ScriptRepository, ExecutionEngine, ExecutionArchive, ScriptEditor,
    ScriptRepositoryConfig, EditorConfig, ScriptLanguage, ScriptMetadata,
    ExecutionRecord, ExecutionConfig, ExecutionEvent, ScriptSearchQuery, RepositoryStats,
    ExecutionStats, ScriptError, ScriptResult, ScriptSchedule, ValidationResult,
};
use chrono::{DateTime, Utc};
use ghost_log::GhostLogDaemon;

use ghost_vault::Vault;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Main GhostScript engine
pub struct GhostScriptEngine {
    /// Script repository for managing scripts
    repository: ScriptRepository,
    /// Execution engine for running scripts
    execution_engine: ExecutionEngine,
    /// Execution archive for audit trails
    archive: ExecutionArchive,
    /// Policy enforcer for security
    // Policy enforcer removed for single-user mode
    /// Script editor functionality
    editor: ScriptEditor,
    /// Active schedules
    schedules: Arc<RwLock<HashMap<String, ScriptSchedule>>>,
    /// Integration components
    vault: Option<Arc<RwLock<Vault>>>,
    ghost_log: Option<Arc<GhostLogDaemon>>,
    // Policy evaluator removed for single-user mode
}

impl GhostScriptEngine {
    /// Create a new GhostScript engine
    pub fn new(
        scripts_directory: PathBuf,
        archive_directory: PathBuf,
    ) -> ScriptResult<Self> {
        // Create repository configuration
        let repo_config = ScriptRepositoryConfig {
            scripts_directory,
            ..Default::default()
        };
        
        // Initialize components
        let repository = ScriptRepository::new(repo_config)?;
        let execution_engine = ExecutionEngine::new(archive_directory.join("executions.db"))?;
        let archive = ExecutionArchive::new(archive_directory)?;
        // Policy enforcer removed for single-user mode
        let editor = ScriptEditor::new(EditorConfig::default());
        
        Ok(Self {
            repository,
            execution_engine,
            archive,
            // Policy enforcer removed
            editor,
            schedules: Arc::new(RwLock::new(HashMap::new())),
            vault: None,
            ghost_log: None,
            // Policy evaluator removed
        })
    }
    
    /// Initialize the engine with integrations
    pub async fn initialize(
        &mut self,
        vault: Option<Arc<RwLock<Vault>>>,
        ghost_log: Option<Arc<GhostLogDaemon>>,
        // Policy evaluator removed for single-user mode
    ) -> ScriptResult<()> {
        // Set integrations
        if let Some(vault) = vault.clone() {
            self.repository.set_vault(vault.clone());
            self.vault = Some(vault);
        }
        
        if let Some(ghost_log) = ghost_log.clone() {
            self.execution_engine.set_ghost_log(ghost_log.clone());
            self.ghost_log = Some(ghost_log);
        }
        
        // Policy evaluator initialization removed for single-user mode
        
        info!("GhostScript engine initialized successfully");
        Ok(())
    }
    
    /// Get repository configuration
    pub fn get_repository_config(&self) -> &ScriptRepositoryConfig {
        self.repository.config()
    }
    
    /// Get scripts directory path
    pub fn get_scripts_directory(&self) -> &Path {
        self.repository.scripts_directory()
    }
    
    /// Store a new script
    pub async fn store_script(
        &self,
        name: String,
        description: Option<String>,
        language: ScriptLanguage,
        content: String,
        tags: Vec<String>,
        created_by: String,
        parameters: Vec<crate::ScriptParameter>,
    ) -> ScriptResult<String> {
        // Validate script content
        let validation = self.editor.validate_content(&content, &language)?;
        if !validation.is_valid {
            return Err(ScriptError::Validation(
                format!("Script validation failed: {}", validation.errors.join(", "))
            ));
        }
        
        // Store in repository
        let script_id = self.repository.store_script(
            name,
            description,
            language,
            content,
            tags,
            created_by,
            parameters,
        ).await?;
        
        // Log to GhostLog if available
        if let Some(ghost_log) = &self.ghost_log {
            // TODO: Log script creation
        }
        
        Ok(script_id)
    }
    
    /// Update an existing script
    pub async fn update_script(
        &self,
        id: String,
        name: Option<String>,
        description: Option<String>,
        content: Option<String>,
        tags: Option<Vec<String>>,
        modified_by: String,
        parameters: Option<Vec<crate::ScriptParameter>>,
    ) -> ScriptResult<()> {
        // Validate content if provided
        if let Some(content) = &content {
            let metadata = self.repository.get_script_metadata(&id).await?
                .ok_or_else(|| ScriptError::ScriptNotFound(id.clone()))?;
            
            let validation = self.editor.validate_content(content, &metadata.language)?;
            if !validation.is_valid {
                return Err(ScriptError::Validation(
                    format!("Script validation failed: {}", validation.errors.join(", "))
                ));
            }
        }
        
        // Update in repository
        self.repository.update_script(
            id.clone(),
            name,
            description,
            content,
            tags,
            modified_by,
            parameters,
        ).await?;
        
        // Log to GhostLog if available
        if let Some(ghost_log) = &self.ghost_log {
            // TODO: Log script update
        }
        
        Ok(())
    }
    
    /// Get script metadata
    pub async fn get_script_metadata(&self, id: &str) -> ScriptResult<Option<ScriptMetadata>> {
        self.repository.get_script_metadata(id).await
    }
    
    /// Get script content
    pub async fn get_script_content(&self, id: &str) -> ScriptResult<Option<String>> {
        self.repository.get_script_content(id).await
    }
    
    /// Search scripts
    pub async fn search_scripts(&self, query: ScriptSearchQuery) -> ScriptResult<Vec<ScriptMetadata>> {
        self.repository.search_scripts(query).await
    }
    
    /// Delete a script
    pub async fn delete_script(&self, id: &str) -> ScriptResult<()> {
        self.repository.delete_script(id).await?;
        
        // Log to GhostLog if available
        if let Some(ghost_log) = &self.ghost_log {
            // TODO: Log script deletion
        }
        
        Ok(())
    }
    
    /// Execute a script
    pub async fn execute_script(
        &self,
        script_id: String,
        executor: String,
        parameters: HashMap<String, String>,
        config: Option<ExecutionConfig>,
    ) -> ScriptResult<mpsc::UnboundedReceiver<ExecutionEvent>> {
        // Get script metadata and content
        let metadata = self.repository.get_script_metadata(&script_id).await?
            .ok_or_else(|| ScriptError::ScriptNotFound(script_id.clone()))?;
        
        let content = self.repository.get_script_content(&script_id).await?
            .ok_or_else(|| ScriptError::ScriptNotFound(script_id.clone()))?;
        
        // Policy evaluation
        // Policy evaluation removed for single-user mode
        let mut exec_config = config.unwrap_or_default();
        
        // Execute the script
        let event_receiver = self.execution_engine.execute_script(
            script_id,
            metadata.name.clone(),
            metadata.file_path,
            metadata.language,
            executor,
            parameters,
            exec_config,
        ).await?;
        
        Ok(event_receiver)
    }
    
    /// Cancel a running script execution
    pub async fn cancel_execution(&self, execution_id: &str) -> ScriptResult<()> {
        self.execution_engine.cancel_execution(execution_id).await
    }
    
    /// Get execution record
    pub async fn get_execution_record(&self, execution_id: &str) -> ScriptResult<Option<ExecutionRecord>> {
        // Try execution engine first (for recent executions)
        if let Some(record) = self.execution_engine.get_execution_record(execution_id).await? {
            return Ok(Some(record));
        }
        
        // Fall back to archive
        self.archive.get_execution(execution_id).await
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
        self.archive.search_executions(
            script_id,
            executor,
            status,
            start_time,
            end_time,
            limit,
            offset,
        ).await
    }
    
    /// Get repository statistics
    pub async fn get_repository_stats(&self) -> ScriptResult<RepositoryStats> {
        let mut stats = self.repository.get_stats().await?;
        
        // Enhance with execution statistics
        let exec_stats = self.execution_engine.get_execution_stats().await?;
        stats.total_executions = exec_stats.total_runs;
        stats.recent_executions = exec_stats.recent_activity.len();
        
        if exec_stats.total_runs > 0 {
            stats.success_rate = exec_stats.successful_runs as f64 / exec_stats.total_runs as f64 * 100.0;
        }
        stats.average_runtime_ms = exec_stats.average_runtime_ms;
        
        Ok(stats)
    }
    
    /// Get execution statistics
    pub async fn get_execution_stats(&self) -> ScriptResult<ExecutionStats> {
        self.archive.get_stats().await
    }
    
    /// Validate script content
    pub fn validate_script(&self, content: &str, language: &ScriptLanguage) -> ScriptResult<ValidationResult> {
        self.editor.validate_content(content, language)
    }
    
    /// Format script content
    pub fn format_script(&self, content: &str, language: &ScriptLanguage) -> ScriptResult<String> {
        self.editor.format_content(content, language)
    }
    
    /// Get syntax highlighting tokens
    pub fn get_syntax_tokens(&self, content: &str, language: &ScriptLanguage) -> Vec<crate::editor::SyntaxToken> {
        self.editor.get_syntax_tokens(content, language)
    }
    
    /// Schedule a script for automated execution
    pub async fn schedule_script(
        &self,
        script_id: String,
        name: String,
        cron_expression: String,
        timezone: Option<String>,
        parameters: HashMap<String, String>,
        created_by: String,
    ) -> ScriptResult<String> {
        // Validate that the script exists
        self.repository.get_script_metadata(&script_id).await?
            .ok_or_else(|| ScriptError::ScriptNotFound(script_id.clone()))?;
        
        // Create schedule
        let schedule_id = Uuid::new_v4().to_string();
        let schedule = ScriptSchedule {
            id: schedule_id.clone(),
            script_id,
            name,
            cron_expression,
            timezone,
            parameters,
            enabled: true,
            created_by,
            created: Utc::now(),
            last_run: None,
            next_run: Utc::now(), // TODO: Calculate from cron expression
        };
        
        // Store schedule
        let mut schedules = self.schedules.write().await;
        schedules.insert(schedule_id.clone(), schedule);
        
        info!("Created script schedule: {}", schedule_id);
        Ok(schedule_id)
    }
    
    /// Get scheduled scripts
    pub async fn get_scheduled_scripts(&self) -> ScriptResult<Vec<ScriptSchedule>> {
        let schedules = self.schedules.read().await;
        Ok(schedules.values().cloned().collect())
    }
    
    /// Cancel a scheduled script
    pub async fn cancel_schedule(&self, schedule_id: &str) -> ScriptResult<()> {
        let mut schedules = self.schedules.write().await;
        schedules.remove(schedule_id)
            .ok_or_else(|| ScriptError::ScriptNotFound(schedule_id.to_string()))?;
        
        info!("Cancelled script schedule: {}", schedule_id);
        Ok(())
    }
    
    /// Archive execution records
    pub async fn archive_execution(&self, record: &ExecutionRecord) -> ScriptResult<()> {
        self.archive.archive_execution(record).await
    }
    
    /// Verify execution record integrity
    pub async fn verify_execution(&self, execution_id: &str) -> ScriptResult<bool> {
        self.archive.verify_execution(execution_id).await
    }
    
    /// Export execution records
    pub async fn export_executions(
        &self,
        execution_ids: &[String],
        exported_by: String,
    ) -> ScriptResult<PathBuf> {
        self.archive.export_executions(execution_ids, exported_by).await
    }
    
    /// Clean up old execution records
    pub async fn cleanup_old_records(&self, older_than_days: u32) -> ScriptResult<usize> {
        self.archive.cleanup_old_records(older_than_days).await
    }
    
    // Policy methods removed for single-user mode
    
    /// Update editor configuration
    pub fn update_editor_config(&mut self, config: EditorConfig) {
        self.editor.set_config(config);
    }
    
    /// Get editor configuration
    pub fn get_editor_config(&self) -> &EditorConfig {
        self.editor.config()
    }
}
