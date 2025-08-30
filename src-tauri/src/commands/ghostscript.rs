//! Tauri commands for GhostScript functionality

use ghost_script::{
    GhostScriptEngine, ScriptLanguage, ScriptMetadata, ExecutionRecord, ExecutionEvent,
    ScriptSearchQuery, RepositoryStats, ExecutionStats, ScriptRepositoryConfig,
    EditorConfig, ExecutionConfig, ValidationResult, ScriptSchedule,
    ScriptParameter, ParameterType,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info};

/// Repository configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryConfig {
    pub id: String,
    pub name: String,
    pub path: String,
    pub is_active: bool,
    pub created_at: String,
}

/// GhostScript state for Tauri
pub struct GhostScriptState {
    pub engine: Arc<RwLock<Option<GhostScriptEngine>>>,
    pub repositories: Arc<RwLock<Vec<RepositoryConfig>>>,
    pub active_repo_id: Arc<RwLock<Option<String>>>,
}

impl GhostScriptState {
    pub fn new() -> Self {
        Self {
            engine: Arc::new(RwLock::new(None)),
            repositories: Arc::new(RwLock::new(Vec::new())),
            active_repo_id: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Load repositories from config file
    pub async fn load_repositories(&self) -> Result<(), String> {
        let config_path = std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join("ghostscript_repos.json");
        
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)
                .map_err(|e| e.to_string())?;
            let repos: Vec<RepositoryConfig> = serde_json::from_str(&content)
                .map_err(|e| e.to_string())?;
            
            let mut repositories = self.repositories.write().await;
            *repositories = repos;
        }
        
        Ok(())
    }
    
    /// Save repositories to config file
    pub async fn save_repositories(&self) -> Result<(), String> {
        let config_path = std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join("ghostscript_repos.json");
        
        let repositories = self.repositories.read().await;
        let content = serde_json::to_string_pretty(&*repositories)
            .map_err(|e| e.to_string())?;
        
        std::fs::write(&config_path, content)
            .map_err(|e| e.to_string())?;
        
        Ok(())
    }
}

/// Prompt user to select scripts directory
#[tauri::command]
pub async fn ghostscript_select_directory() -> Result<Option<String>, String> {
    // For now, return a placeholder path until we can fix the dialog API
    Ok(Some("C:\\Scripts".to_string()))
}

/// Get all configured repositories
#[tauri::command]
pub async fn ghostscript_get_repositories(
    state: State<'_, GhostScriptState>,
) -> Result<Vec<RepositoryConfig>, String> {
    state.load_repositories().await?;
    let repositories = state.repositories.read().await;
    Ok(repositories.clone())
}

/// Add a new repository
#[tauri::command]
pub async fn ghostscript_add_repository(
    name: String,
    path: Option<String>,
    state: State<'_, GhostScriptState>,
) -> Result<String, String> {
    let repo_path = match path {
        Some(p) => p,
        None => {
            match ghostscript_select_directory().await? {
                Some(dir) => dir,
                None => return Err("No directory selected".to_string()),
            }
        }
    };
    
    // Validate path exists and is accessible
    let path_buf = PathBuf::from(&repo_path);
    if !path_buf.exists() {
        std::fs::create_dir_all(&path_buf).map_err(|e| e.to_string())?;
    }
    
    // Create archive subdirectory
    let archive_path = path_buf.join("archive");
    std::fs::create_dir_all(&archive_path).map_err(|e| e.to_string())?;
    
    let repo_id = uuid::Uuid::new_v4().to_string();
    let repo_config = RepositoryConfig {
        id: repo_id.clone(),
        name,
        path: repo_path,
        is_active: false,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    
    let mut repositories = state.repositories.write().await;
    repositories.push(repo_config);
    drop(repositories);
    
    state.save_repositories().await?;
    
    info!("Added new GhostScript repository: {}", repo_id);
    Ok(repo_id)
}

/// Set active repository
#[tauri::command]
pub async fn ghostscript_set_active_repository(
    repo_id: String,
    state: State<'_, GhostScriptState>,
) -> Result<String, String> {
    state.load_repositories().await?;
    
    let mut repositories = state.repositories.write().await;
    let mut found = false;
    
    // Set all repositories to inactive, then activate the selected one
    for repo in repositories.iter_mut() {
        repo.is_active = repo.id == repo_id;
        if repo.id == repo_id {
            found = true;
        }
    }
    
    if !found {
        return Err("Repository not found".to_string());
    }
    
    drop(repositories);
    state.save_repositories().await?;
    
    // Update active repo ID
    {
        let mut active_repo = state.active_repo_id.write().await;
        *active_repo = Some(repo_id.clone());
    }
    
    // Initialize engine with the new repository
    ghostscript_initialize_with_repo(repo_id.clone(), state).await?;
    
    Ok(repo_id)
}

/// Remove a repository
#[tauri::command]
pub async fn ghostscript_remove_repository(
    repo_id: String,
    state: State<'_, GhostScriptState>,
) -> Result<(), String> {
    let mut repositories = state.repositories.write().await;
    repositories.retain(|repo| repo.id != repo_id);
    drop(repositories);
    
    state.save_repositories().await?;
    
    // If this was the active repository, clear the engine
    let active_repo = state.active_repo_id.read().await;
    if active_repo.as_ref() == Some(&repo_id) {
        drop(active_repo);
        let mut active_repo = state.active_repo_id.write().await;
        *active_repo = None;
        
        let mut engine_guard = state.engine.write().await;
        *engine_guard = None;
    }
    
    info!("Removed GhostScript repository: {}", repo_id);
    Ok(())
}

/// Initialize GhostScript engine with a specific repository
async fn ghostscript_initialize_with_repo(
    repo_id: String,
    state: State<'_, GhostScriptState>,
) -> Result<String, String> {
    let repositories = state.repositories.read().await;
    let repo = repositories.iter()
        .find(|r| r.id == repo_id)
        .ok_or("Repository not found")?;
    
    let scripts_path = PathBuf::from(&repo.path);
    let archive_path = scripts_path.join("archive");
    
    // Ensure directories exist
    std::fs::create_dir_all(&scripts_path).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&archive_path).map_err(|e| e.to_string())?;
    
    let engine = GhostScriptEngine::new(scripts_path, archive_path)
        .map_err(|e| e.to_string())?;
    
    let mut engine_guard = state.engine.write().await;
    *engine_guard = Some(engine);
    
    info!("GhostScript engine initialized with repository: {}", repo.name);
    Ok(format!("Initialized with repository: {}", repo.name))
}

/// Initialize GhostScript engine (legacy compatibility)
#[tauri::command]
pub async fn ghostscript_initialize(
    state: State<'_, GhostScriptState>,
) -> Result<String, String> {
    // Load existing repositories
    state.load_repositories().await?;
    
    let repositories = state.repositories.read().await;
    
    // Check if there's an active repository
    if let Some(active_repo) = repositories.iter().find(|r| r.is_active) {
        let active_repo_id = active_repo.id.clone();
        drop(repositories);
        return ghostscript_initialize_with_repo(active_repo_id, state).await;
    }
    
    // If no repositories exist, prompt to add one
    if repositories.is_empty() {
        drop(repositories);
        return Err("No repositories configured. Please add a repository first.".to_string());
    }
    
    // If repositories exist but none are active, return list for user to choose
    drop(repositories);
    Err("Multiple repositories available. Please select an active repository.".to_string())
}

/// Store a new script
#[tauri::command]
pub async fn ghostscript_store_script(
    state: State<'_, GhostScriptState>,
    name: String,
    description: Option<String>,
    language: String,
    content: String,
    tags: Vec<String>,
    created_by: String,
    parameters: Vec<ScriptParameterDto>,
) -> Result<String, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let script_language = parse_language(&language)?;
        let script_params = parameters.into_iter().map(|p| p.into()).collect();
        
        engine.store_script(
            name,
            description,
            script_language,
            content,
            tags,
            created_by,
            script_params,
        ).await.map_err(|e| e.to_string())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Update an existing script
#[tauri::command]
pub async fn ghostscript_update_script(
    state: State<'_, GhostScriptState>,
    id: String,
    name: Option<String>,
    description: Option<String>,
    content: Option<String>,
    tags: Option<Vec<String>>,
    modified_by: String,
    parameters: Option<Vec<ScriptParameterDto>>,
) -> Result<(), String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let script_params = parameters.map(|params| 
            params.into_iter().map(|p| p.into()).collect()
        );
        
        engine.update_script(
            id,
            name,
            description,
            content,
            tags,
            modified_by,
            script_params,
        ).await.map_err(|e| e.to_string())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Get script metadata
#[tauri::command]
pub async fn ghostscript_get_script_metadata(
    state: State<'_, GhostScriptState>,
    id: String,
) -> Result<Option<ScriptMetadataDto>, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let metadata = engine.get_script_metadata(&id).await.map_err(|e| e.to_string())?;
        Ok(metadata.map(|m| m.into()))
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Get script content
#[tauri::command]
pub async fn ghostscript_get_script_content(
    state: State<'_, GhostScriptState>,
    id: String,
) -> Result<Option<String>, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        engine.get_script_content(&id).await.map_err(|e| e.to_string())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Search scripts
#[tauri::command]
pub async fn ghostscript_search_scripts(
    state: State<'_, GhostScriptState>,
    query: ScriptSearchQueryDto,
) -> Result<Vec<ScriptMetadataDto>, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let search_query = query.try_into()?;
        let results = engine.search_scripts(search_query).await.map_err(|e| e.to_string())?;
        Ok(results.into_iter().map(|m| m.into()).collect())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Delete a script
#[tauri::command]
pub async fn ghostscript_delete_script(
    state: State<'_, GhostScriptState>,
    id: String,
) -> Result<(), String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        engine.delete_script(&id).await.map_err(|e| e.to_string())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Execute a script
#[tauri::command]
pub async fn ghostscript_execute_script(
    state: State<'_, GhostScriptState>,
    script_id: String,
    executor: String,
    parameters: HashMap<String, String>,
    config: Option<ExecutionConfigDto>,
) -> Result<String, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let exec_config = config.map(|c| c.into());
        let mut receiver = engine.execute_script(
            script_id,
            executor,
            parameters,
            exec_config,
        ).await.map_err(|e| e.to_string())?;
        
        // For now, return execution ID from the first event
        if let Some(event) = receiver.recv().await {
            match event {
                ExecutionEvent::Started { execution_id } => Ok(execution_id),
                _ => Err("Unexpected first event".to_string()),
            }
        } else {
            Err("No execution events received".to_string())
        }
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Cancel script execution
#[tauri::command]
pub async fn ghostscript_cancel_execution(
    state: State<'_, GhostScriptState>,
    execution_id: String,
) -> Result<(), String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        engine.cancel_execution(&execution_id).await.map_err(|e| e.to_string())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Get execution record
#[tauri::command]
pub async fn ghostscript_get_execution_record(
    state: State<'_, GhostScriptState>,
    execution_id: String,
) -> Result<Option<ExecutionRecordDto>, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let record = engine.get_execution_record(&execution_id).await.map_err(|e| e.to_string())?;
        Ok(record.map(|r| r.into()))
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Search execution records
#[tauri::command]
pub async fn ghostscript_search_executions(
    state: State<'_, GhostScriptState>,
    script_id: Option<String>,
    executor: Option<String>,
    status: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<Vec<ExecutionRecordDto>, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let results = engine.search_executions(
            script_id.as_deref(),
            executor.as_deref(),
            status.as_deref(),
            None, // start_time
            None, // end_time
            limit,
            offset,
        ).await.map_err(|e| e.to_string())?;
        
        Ok(results.into_iter().map(|r| r.into()).collect())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Get repository statistics
#[tauri::command]
pub async fn ghostscript_get_repository_stats(
    state: State<'_, GhostScriptState>,
) -> Result<RepositoryStatsDto, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let stats = engine.get_repository_stats().await.map_err(|e| e.to_string())?;
        Ok(stats.into())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Get execution statistics
#[tauri::command]
pub async fn ghostscript_get_execution_stats(
    state: State<'_, GhostScriptState>,
) -> Result<ExecutionStatsDto, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let stats = engine.get_execution_stats().await.map_err(|e| e.to_string())?;
        Ok(stats.into())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Validate script content
#[tauri::command]
pub async fn ghostscript_validate_script(
    state: State<'_, GhostScriptState>,
    content: String,
    language: String,
) -> Result<ValidationResultDto, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let script_language = parse_language(&language)?;
        let result = engine.validate_script(&content, &script_language).map_err(|e| e.to_string())?;
        Ok(result.into())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Format script content
#[tauri::command]
pub async fn ghostscript_format_script(
    state: State<'_, GhostScriptState>,
    content: String,
    language: String,
) -> Result<String, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let script_language = parse_language(&language)?;
        engine.format_script(&content, &script_language).map_err(|e| e.to_string())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Schedule a script
#[tauri::command]
pub async fn ghostscript_schedule_script(
    state: State<'_, GhostScriptState>,
    script_id: String,
    name: String,
    cron_expression: String,
    timezone: Option<String>,
    parameters: HashMap<String, String>,
    created_by: String,
) -> Result<String, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        engine.schedule_script(
            script_id,
            name,
            cron_expression,
            timezone,
            parameters,
            created_by,
        ).await.map_err(|e| e.to_string())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Get scheduled scripts
#[tauri::command]
pub async fn ghostscript_get_scheduled_scripts(
    state: State<'_, GhostScriptState>,
) -> Result<Vec<ScriptScheduleDto>, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        let schedules = engine.get_scheduled_scripts().await.map_err(|e| e.to_string())?;
        Ok(schedules.into_iter().map(|s| s.into()).collect())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Cancel a scheduled script
#[tauri::command]
pub async fn ghostscript_cancel_schedule(
    state: State<'_, GhostScriptState>,
    schedule_id: String,
) -> Result<(), String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        engine.cancel_schedule(&schedule_id).await.map_err(|e| e.to_string())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

/// Verify execution integrity
#[tauri::command]
pub async fn ghostscript_verify_execution(
    state: State<'_, GhostScriptState>,
    execution_id: String,
) -> Result<bool, String> {
    let engine_guard = state.engine.read().await;
    if let Some(engine) = engine_guard.as_ref() {
        engine.verify_execution(&execution_id).await.map_err(|e| e.to_string())
    } else {
        Err("GhostScript engine not initialized".to_string())
    }
}

// Helper functions and DTOs

fn parse_language(language: &str) -> Result<ScriptLanguage, String> {
    match language.to_lowercase().as_str() {
        "python" => Ok(ScriptLanguage::Python),
        "powershell" => Ok(ScriptLanguage::PowerShell),
        "batch" => Ok(ScriptLanguage::Batch),
        _ => Err(format!("Unsupported language: {}", language)),
    }
}

// Data Transfer Objects (DTOs) for Tauri serialization

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptMetadataDto {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub language: String,
    pub tags: Vec<String>,
    pub created_by: String,
    pub modified_by: String,
    pub created: String,
    pub modified: String,
    pub hash: String,
    pub parameters: Vec<ScriptParameterDto>,
    pub rollback_script_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptParameterDto {
    pub name: String,
    pub description: Option<String>,
    pub param_type: String,
    pub required: bool,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecordDto {
    pub id: String,
    pub script_id: String,
    pub script_name: String,
    pub executor: String,
    pub parameters: HashMap<String, String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub runtime_ms: u64,
    pub timestamp: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptSearchQueryDto {
    pub text: Option<String>,
    pub language: Option<String>,
    pub tags: Option<Vec<String>>,
    pub author: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfigDto {
    pub working_directory: Option<String>,
    pub environment: HashMap<String, String>,
    pub capture_output: bool,
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResultDto {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryStatsDto {
    pub total_scripts: usize,
    pub scripts_by_language: HashMap<String, usize>,
    pub total_executions: usize,
    pub recent_executions: usize,
    pub success_rate: f64,
    pub average_runtime_ms: f64,
    pub storage_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStatsDto {
    pub total_runs: usize,
    pub successful_runs: usize,
    pub failed_runs: usize,
    pub average_runtime_ms: f64,
    pub recent_activity: Vec<ExecutionRecordDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptScheduleDto {
    pub id: String,
    pub script_id: String,
    pub name: String,
    pub cron_expression: String,
    pub timezone: Option<String>,
    pub parameters: HashMap<String, String>,
    pub enabled: bool,
    pub created_by: String,
    pub created: String,
    pub last_run: Option<String>,
    pub next_run: String,
}

// Conversion implementations

impl From<ScriptMetadata> for ScriptMetadataDto {
    fn from(metadata: ScriptMetadata) -> Self {
        Self {
            id: metadata.id,
            name: metadata.name,
            description: metadata.description,
            language: format!("{:?}", metadata.language),
            tags: metadata.tags,
            created_by: metadata.created_by,
            modified_by: metadata.modified_by,
            created: metadata.created.to_rfc3339(),
            modified: metadata.modified.to_rfc3339(),
            hash: metadata.hash,
            parameters: metadata.parameters.into_iter().map(|p| p.into()).collect(),
            rollback_script_id: metadata.rollback_script_id,
        }
    }
}

impl From<ScriptParameter> for ScriptParameterDto {
    fn from(param: ScriptParameter) -> Self {
        Self {
            name: param.name,
            description: param.description,
            param_type: match param.param_type {
                ParameterType::String => "string".to_string(),
                ParameterType::Integer => "integer".to_string(),
                ParameterType::Float => "float".to_string(),
                ParameterType::Boolean => "boolean".to_string(),
                ParameterType::Path => "path".to_string(),
                ParameterType::Enum { .. } => "enum".to_string(),
            },
            required: param.required,
            default_value: param.default_value,
        }
    }
}

impl From<ScriptParameterDto> for ScriptParameter {
    fn from(dto: ScriptParameterDto) -> Self {
        Self {
            name: dto.name,
            description: dto.description,
            param_type: match dto.param_type.as_str() {
                "string" => ParameterType::String,
                "integer" => ParameterType::Integer,
                "float" => ParameterType::Float,
                "boolean" => ParameterType::Boolean,
                "path" => ParameterType::Path,
                _ => ParameterType::String, // Default fallback
            },
            required: dto.required,
            default_value: dto.default_value,
        }
    }
}

impl From<ExecutionRecord> for ExecutionRecordDto {
    fn from(record: ExecutionRecord) -> Self {
        Self {
            id: record.id,
            script_id: record.script_id,
            script_name: record.script_name,
            executor: record.executor,
            parameters: record.parameters,
            stdout: record.stdout,
            stderr: record.stderr,
            exit_code: record.exit_code,
            runtime_ms: record.runtime_ms,
            timestamp: record.timestamp.to_rfc3339(),
            status: format!("{:?}", record.status),
        }
    }
}

impl TryFrom<ScriptSearchQueryDto> for ScriptSearchQuery {
    type Error = String;
    
    fn try_from(dto: ScriptSearchQueryDto) -> Result<Self, Self::Error> {
        let language = if let Some(lang_str) = dto.language {
            Some(parse_language(&lang_str)?)
        } else {
            None
        };
        
        Ok(Self {
            text: dto.text,
            language,
            tags: dto.tags,
            author: dto.author,
            date_range: None, // TODO: Add date range support
            limit: dto.limit,
            offset: dto.offset,
        })
    }
}

impl From<ExecutionConfigDto> for ExecutionConfig {
    fn from(dto: ExecutionConfigDto) -> Self {
        Self {
            working_directory: dto.working_directory.map(PathBuf::from),
            environment: dto.environment,
            limits: Default::default(), // Use default limits
            capture_output: dto.capture_output,
            timeout: dto.timeout,
        }
    }
}

impl From<ValidationResult> for ValidationResultDto {
    fn from(result: ValidationResult) -> Self {
        Self {
            is_valid: result.is_valid,
            errors: result.errors,
            warnings: result.warnings,
            suggestions: result.suggestions,
        }
    }
}

impl From<RepositoryStats> for RepositoryStatsDto {
    fn from(stats: RepositoryStats) -> Self {
        let scripts_by_language = stats.scripts_by_language
            .into_iter()
            .map(|(lang, count)| (format!("{:?}", lang), count))
            .collect();
        
        Self {
            total_scripts: stats.total_scripts,
            scripts_by_language,
            total_executions: stats.total_executions,
            recent_executions: stats.recent_executions,
            success_rate: stats.success_rate,
            average_runtime_ms: stats.average_runtime_ms,
            storage_size_bytes: stats.storage_size_bytes,
        }
    }
}

impl From<ExecutionStats> for ExecutionStatsDto {
    fn from(stats: ExecutionStats) -> Self {
        Self {
            total_runs: stats.total_runs,
            successful_runs: stats.successful_runs,
            failed_runs: stats.failed_runs,
            average_runtime_ms: stats.average_runtime_ms,
            recent_activity: stats.recent_activity.into_iter().map(|r| r.into()).collect(),
        }
    }
}

impl From<ScriptSchedule> for ScriptScheduleDto {
    fn from(schedule: ScriptSchedule) -> Self {
        Self {
            id: schedule.id,
            script_id: schedule.script_id,
            name: schedule.name,
            cron_expression: schedule.cron_expression,
            timezone: schedule.timezone,
            parameters: schedule.parameters,
            enabled: schedule.enabled,
            created_by: schedule.created_by,
            created: schedule.created.to_rfc3339(),
            last_run: schedule.last_run.map(|dt| dt.to_rfc3339()),
            next_run: schedule.next_run.to_rfc3339(),
        }
    }
}
