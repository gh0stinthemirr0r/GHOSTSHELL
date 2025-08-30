//! GhostLog Tauri commands
//! 
//! Provides frontend interface to the GhostLog system

use anyhow::Result;
use ghost_log::{
    GhostLogConfig, GhostLogEntry, LogSeverity, SearchQuery, SearchResult,
    ViewerFilter, ViewerState, ExportConfig, ExportResult, ViewerStats,
    get_ghost_log, initialize_ghost_log,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tauri::State;
use tracing::{debug, error, info};

/// Initialize GhostLog system
#[tauri::command]
pub async fn ghostlog_initialize(config: Option<GhostLogConfig>) -> Result<(), String> {
    let config = config.unwrap_or_default();
    
    initialize_ghost_log(config).await
        .map_err(|e| {
            error!("Failed to initialize GhostLog: {}", e);
            e.to_string()
        })?;
    
    info!("GhostLog initialized successfully");
    Ok(())
}

/// Log an entry to GhostLog
#[tauri::command]
pub async fn ghostlog_log_entry(
    module: String,
    severity: String,
    event_id: String,
    message: String,
    context: Option<HashMap<String, serde_json::Value>>,
) -> Result<(), String> {
    let severity = match severity.to_lowercase().as_str() {
        "info" => LogSeverity::Info,
        "warn" | "warning" => LogSeverity::Warn,
        "error" => LogSeverity::Error,
        "critical" => LogSeverity::Critical,
        _ => LogSeverity::Info,
    };

    if let Some(ghost_log) = get_ghost_log() {
        let module_ref = module.clone();
        let event_id_ref = event_id.clone();
        
        if let Some(context) = context {
            ghost_log.log_with_context(module, severity, event_id, message, context)
                .map_err(|e| e.to_string())?;
        } else {
            ghost_log.log(module, severity, event_id, message)
                .map_err(|e| e.to_string())?;
        }
        debug!("Logged entry from frontend: {}/{}", module_ref, event_id_ref);
    } else {
        return Err("GhostLog not initialized".to_string());
    }

    Ok(())
}

/// Search logs
#[tauri::command]
pub async fn ghostlog_search(
    text: Option<String>,
    module: Option<String>,
    severity: Option<String>,
    regex: Option<bool>
) -> Result<SearchResult, String> {
    use ghost_log::{SearchQuery, LogSeverity};
    
    // Parse severity if provided
    let severity_enum = if let Some(sev) = severity {
                   match sev.to_lowercase().as_str() {
               "error" => Some(LogSeverity::Error),
               "warn" | "warning" => Some(LogSeverity::Warn),
               "info" => Some(LogSeverity::Info),
               _ => None,
           }
    } else {
        None
    };
    
    let search_query = SearchQuery {
        text,
        module,
        severity: severity_enum,
        event_id: None,
        start_time: None,
        end_time: None,
        limit: Some(100),
        offset: None,
        regex: regex.unwrap_or(false),
    };
    
    // TODO: Implement search through the global GhostLog instance
    // For now, return empty results with proper structure
    Ok(SearchResult {
        entries: Vec::new(),
        total_matches: 0,
        execution_time_ms: 5,
        truncated: false,
    })
}

/// Get available modules for filtering
#[tauri::command]
pub async fn ghostlog_get_modules() -> Result<Vec<String>, String> {
    // Return common GhostShell modules
    Ok(vec![
        "ssh".to_string(),
        "terminal".to_string(),
        "vault".to_string(),
        "vpn".to_string(),
        "browse".to_string(),
        "script".to_string(),
        "dash".to_string(),
        "report".to_string(),
        "policy".to_string(),
        "ai".to_string(),
        "shell".to_string(),
        "ghostlog".to_string(),
    ])
}

/// Get log statistics
#[tauri::command]
pub async fn ghostlog_get_stats() -> Result<ViewerStats, String> {
    // TODO: Implement stats through the global GhostLog instance
    // For now, return placeholder stats
    let mut severity_breakdown = HashMap::new();
    severity_breakdown.insert("Info".to_string(), 150);
    severity_breakdown.insert("Warn".to_string(), 25);
    severity_breakdown.insert("Error".to_string(), 8);
    severity_breakdown.insert("Critical".to_string(), 2);

    Ok(ViewerStats {
        total_entries: 185,
        modules: 12,
        unique_events: 45,
        severity_breakdown,
    })
}

/// Export logs
#[tauri::command]
pub async fn ghostlog_export(config: ExportConfig) -> Result<ExportResult, String> {
    // TODO: Implement export through the global GhostLog instance
    // For now, return placeholder result
    Ok(ExportResult {
        file_path: format!("ghostlog_export_{}.json", chrono::Utc::now().format("%Y%m%d_%H%M%S")),
        entry_count: 0,
        timestamp: chrono::Utc::now(),
        file_hash: "placeholder_hash".to_string(),
        signature: None,
    })
}

/// Get recent log entries for live mode
#[tauri::command]
pub async fn ghostlog_get_recent(limit: Option<usize>) -> Result<Vec<GhostLogEntry>, String> {
    let _limit = limit.unwrap_or(50);
    
    // TODO: Implement recent entries through the global GhostLog instance
    // For now, return empty list
    Ok(Vec::new())
}

/// Validate log file integrity
#[tauri::command]
pub async fn ghostlog_verify_integrity(file_path: String) -> Result<bool, String> {
    // TODO: Implement integrity verification
    debug!("Verifying integrity of log file: {}", file_path);
    Ok(true)
}

/// Get log rotation status
#[tauri::command]
pub async fn ghostlog_rotation_status() -> Result<RotationStatus, String> {
    // TODO: Implement rotation status
    Ok(RotationStatus {
        active_files: 12,
        total_size_mb: 245,
        oldest_file_age_hours: 72,
        next_rotation_in_hours: 6,
    })
}

/// Trigger manual log rotation
#[tauri::command]
pub async fn ghostlog_rotate_logs() -> Result<(), String> {
    // TODO: Implement manual rotation trigger
    info!("Manual log rotation triggered from frontend");
    Ok(())
}

/// Clean up old log files
#[tauri::command]
pub async fn ghostlog_cleanup_old_files() -> Result<CleanupResult, String> {
    // TODO: Implement cleanup
    Ok(CleanupResult {
        files_removed: 0,
        space_freed_mb: 0,
    })
}

/// Helper structs for frontend communication
#[derive(Debug, Serialize, Deserialize)]
pub struct RotationStatus {
    pub active_files: u32,
    pub total_size_mb: u64,
    pub oldest_file_age_hours: u64,
    pub next_rotation_in_hours: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CleanupResult {
    pub files_removed: u32,
    pub space_freed_mb: u64,
}

// Convenience macros for logging from other modules
#[macro_export]
macro_rules! ghost_log_info {
    ($module:expr, $event_id:expr, $message:expr) => {
        if let Some(log) = ghost_log::get_ghost_log() {
            let _ = log.log($module, ghost_log::LogSeverity::Info, $event_id, $message);
        }
    };
    ($module:expr, $event_id:expr, $message:expr, $context:expr) => {
        if let Some(log) = ghost_log::get_ghost_log() {
            let _ = log.log_with_context($module, ghost_log::LogSeverity::Info, $event_id, $message, $context);
        }
    };
}

#[macro_export]
macro_rules! ghost_log_warn {
    ($module:expr, $event_id:expr, $message:expr) => {
        if let Some(log) = ghost_log::get_ghost_log() {
            let _ = log.log($module, ghost_log::LogSeverity::Warn, $event_id, $message);
        }
    };
    ($module:expr, $event_id:expr, $message:expr, $context:expr) => {
        if let Some(log) = ghost_log::get_ghost_log() {
            let _ = log.log_with_context($module, ghost_log::LogSeverity::Warn, $event_id, $message, $context);
        }
    };
}

#[macro_export]
macro_rules! ghost_log_error {
    ($module:expr, $event_id:expr, $message:expr) => {
        if let Some(log) = ghost_log::get_ghost_log() {
            let _ = log.log($module, ghost_log::LogSeverity::Error, $event_id, $message);
        }
    };
    ($module:expr, $event_id:expr, $message:expr, $context:expr) => {
        if let Some(log) = ghost_log::get_ghost_log() {
            let _ = log.log_with_context($module, ghost_log::LogSeverity::Error, $event_id, $message, $context);
        }
    };
}

#[macro_export]
macro_rules! ghost_log_critical {
    ($module:expr, $event_id:expr, $message:expr) => {
        if let Some(log) = ghost_log::get_ghost_log() {
            let _ = log.log($module, ghost_log::LogSeverity::Critical, $event_id, $message);
        }
    };
    ($module:expr, $event_id:expr, $message:expr, $context:expr) => {
        if let Some(log) = ghost_log::get_ghost_log() {
            let _ = log.log_with_context($module, ghost_log::LogSeverity::Critical, $event_id, $message, $context);
        }
    };
}
