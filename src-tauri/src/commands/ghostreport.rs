//! GhostReport Tauri commands
//! 
//! Provides frontend interface to the GhostReport system

use anyhow::Result;
use ghost_report::{
    ReportEngine, ReportJob, ReportArtifact, ReportPreview, ReportStats, ReportSource,
    ReportFilters, ReportFormat, ReportSchedule, ScheduleFrequency, ReportBuilder,
    ReportTemplates, TemplateManager, TemplateCategory, ReportTemplate, ArchiveQuery,
    ArchiveStats, SchedulerStats,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use uuid::Uuid;

/// GhostReport state for Tauri
pub struct GhostReportState {
    pub engine: Arc<RwLock<Option<ReportEngine>>>,
    pub template_manager: Arc<RwLock<TemplateManager>>,
}

impl GhostReportState {
    pub fn new() -> Self {
        Self {
            engine: Arc::new(RwLock::new(None)),
            template_manager: Arc::new(RwLock::new(TemplateManager::new())),
        }
    }
}

/// Initialize GhostReport system
#[tauri::command]
pub async fn ghostreport_initialize(
    output_dir: Option<String>,
    state: State<'_, GhostReportState>,
) -> Result<(), String> {
    let output_path = output_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("reports"));
    
    info!("Initializing GhostReport with output directory: {:?}", output_path);
    
    let engine = ReportEngine::new(output_path)
        .map_err(|e| e.to_string())?;
    
    engine.initialize(None).await
        .map_err(|e| e.to_string())?;
    
    let mut engine_guard = state.engine.write().await;
    *engine_guard = Some(engine);
    
    info!("GhostReport initialized successfully");
    Ok(())
}

/// Generate a report from a job configuration
#[tauri::command]
pub async fn ghostreport_generate_report(
    job: ReportJob,
    state: State<'_, GhostReportState>,
) -> Result<Vec<ReportArtifact>, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    info!("Generating report: {}", job.name);
    
    let artifacts = engine.generate_report(job).await
        .map_err(|e| e.to_string())?;
    
    debug!("Generated {} artifacts", artifacts.len());
    Ok(artifacts)
}

/// Generate a preview of what a report would contain
#[tauri::command]
pub async fn ghostreport_generate_preview(
    job: ReportJob,
    state: State<'_, GhostReportState>,
) -> Result<ReportPreview, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    debug!("Generating preview for report: {}", job.name);
    
    let preview = engine.generate_preview(&job).await
        .map_err(|e| e.to_string())?;
    
    Ok(preview)
}

/// Schedule a report job
#[tauri::command]
pub async fn ghostreport_schedule_report(
    job: ReportJob,
    state: State<'_, GhostReportState>,
) -> Result<String, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    info!("Scheduling report: {}", job.name);
    
    let job_id = engine.schedule_report(job).await
        .map_err(|e| e.to_string())?;
    
    Ok(job_id)
}

/// Get all scheduled reports
#[tauri::command]
pub async fn ghostreport_get_scheduled_reports(
    state: State<'_, GhostReportState>,
) -> Result<Vec<ReportJob>, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    let jobs = engine.get_scheduled_reports().await
        .map_err(|e| e.to_string())?;
    
    Ok(jobs)
}

/// Cancel a scheduled report
#[tauri::command]
pub async fn ghostreport_cancel_scheduled_report(
    job_id: String,
    state: State<'_, GhostReportState>,
) -> Result<(), String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    engine.cancel_scheduled_report(&job_id).await
        .map_err(|e| e.to_string())?;
    
    info!("Cancelled scheduled report: {}", job_id);
    Ok(())
}

/// Get report engine statistics
#[tauri::command]
pub async fn ghostreport_get_stats(
    state: State<'_, GhostReportState>,
) -> Result<ReportStats, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    let stats = engine.get_stats().await;
    Ok(stats)
}

/// Search the report archive
#[tauri::command]
pub async fn ghostreport_search_archive(
    query: ArchiveQuery,
    state: State<'_, GhostReportState>,
) -> Result<Vec<ReportArtifact>, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    let archive = engine.get_archive().await;
    let artifacts = archive.search(&query).await
        .map_err(|e| e.to_string())?;
    
    debug!("Found {} artifacts matching query", artifacts.len());
    Ok(artifacts)
}

/// Get archive statistics
#[tauri::command]
pub async fn ghostreport_get_archive_stats(
    state: State<'_, GhostReportState>,
) -> Result<ArchiveStats, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    let archive = engine.get_archive().await;
    let stats = archive.get_stats().await
        .map_err(|e| e.to_string())?;
    
    Ok(stats)
}

/// Verify a report artifact signature
#[tauri::command]
pub async fn ghostreport_verify_artifact(
    artifact: ReportArtifact,
    state: State<'_, GhostReportState>,
) -> Result<bool, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    let is_valid = engine.verify_artifact(&artifact).await
        .map_err(|e| e.to_string())?;
    
    debug!("Artifact verification result: {}", is_valid);
    Ok(is_valid)
}

/// Get all available report templates
#[tauri::command]
pub async fn ghostreport_get_templates(
    state: State<'_, GhostReportState>,
) -> Result<Vec<ReportTemplate>, String> {
    let template_manager = state.template_manager.read().await;
    let templates = template_manager.get_templates()
        .into_iter()
        .cloned()
        .collect();
    
    Ok(templates)
}

/// Get templates by category
#[tauri::command]
pub async fn ghostreport_get_templates_by_category(
    category: TemplateCategory,
    state: State<'_, GhostReportState>,
) -> Result<Vec<ReportTemplate>, String> {
    let template_manager = state.template_manager.read().await;
    let templates = template_manager.get_templates_by_category(&category)
        .into_iter()
        .cloned()
        .collect();
    
    Ok(templates)
}

/// Get a specific template
#[tauri::command]
pub async fn ghostreport_get_template(
    template_id: String,
    state: State<'_, GhostReportState>,
) -> Result<Option<ReportTemplate>, String> {
    let template_manager = state.template_manager.read().await;
    let template = template_manager.get_template(&template_id)
        .cloned();
    
    Ok(template)
}

/// Create a security audit report using template
#[tauri::command]
pub async fn ghostreport_create_security_audit(
    created_by: String,
) -> Result<ReportJob, String> {
    let job = ReportTemplates::security_audit(created_by)
        .build()
        .map_err(|e| e.to_string())?;
    
    Ok(job)
}

/// Create a network activity report using template
#[tauri::command]
pub async fn ghostreport_create_network_activity(
    created_by: String,
) -> Result<ReportJob, String> {
    let job = ReportTemplates::network_activity(created_by)
        .build()
        .map_err(|e| e.to_string())?;
    
    Ok(job)
}

/// Create a system health report using template
#[tauri::command]
pub async fn ghostreport_create_system_health(
    created_by: String,
) -> Result<ReportJob, String> {
    let job = ReportTemplates::system_health(created_by)
        .build()
        .map_err(|e| e.to_string())?;
    
    Ok(job)
}

/// Create a compliance report using template
#[tauri::command]
pub async fn ghostreport_create_compliance_report(
    created_by: String,
    framework: String,
) -> Result<ReportJob, String> {
    let job = ReportTemplates::compliance_report(created_by, framework)
        .build()
        .map_err(|e| e.to_string())?;
    
    Ok(job)
}

/// Create an incident response report using template
#[tauri::command]
pub async fn ghostreport_create_incident_response(
    created_by: String,
    incident_id: String,
) -> Result<ReportJob, String> {
    let job = ReportTemplates::incident_response(created_by, incident_id)
        .build()
        .map_err(|e| e.to_string())?;
    
    Ok(job)
}

/// Create a daily operations report using template
#[tauri::command]
pub async fn ghostreport_create_daily_operations(
    created_by: String,
) -> Result<ReportJob, String> {
    let job = ReportTemplates::daily_operations(created_by)
        .build()
        .map_err(|e| e.to_string())?;
    
    Ok(job)
}

/// Build a custom report using the builder API
#[tauri::command]
pub async fn ghostreport_build_custom_report(
    name: String,
    created_by: String,
    sources: Vec<ReportSource>,
    filters: ReportFilters,
    formats: Vec<ReportFormat>,
    schedule: Option<ReportSchedule>,
) -> Result<ReportJob, String> {
    let mut builder = ReportBuilder::new(name, created_by);
    
    // Add sources
    for source in sources {
        match source {
            ReportSource::GhostLog { modules } => {
                builder = builder.add_ghostlog_source(modules);
            }
            ReportSource::GhostDashSystem => {
                builder = builder.add_ghostdash_system_source();
            }
            ReportSource::GhostDashNetwork => {
                builder = builder.add_ghostdash_network_source();
            }
            ReportSource::GhostDashInterfaces => {
                builder = builder.add_ghostdash_interfaces_source();
            }
            ReportSource::GhostDashDns => {
                builder = builder.add_ghostdash_dns_source();
            }
            ReportSource::GhostDashRoutes => {
                builder = builder.add_ghostdash_routes_source();
            }
            ReportSource::GhostDashConnections => {
                builder = builder.add_ghostdash_connections_source();
            }
        }
    }
    
    // Apply filters
    builder = builder.with_filters(filters);
    
    // Set formats
    builder = builder.with_formats(formats);
    
    // Set schedule if provided
    if let Some(sched) = schedule {
        builder = builder.with_schedule(sched);
    }
    
    let job = builder.build()
        .map_err(|e| e.to_string())?;
    
    Ok(job)
}

/// Get available report formats
#[tauri::command]
pub async fn ghostreport_get_formats() -> Result<Vec<ReportFormat>, String> {
    Ok(vec![
        ReportFormat::Csv,
        ReportFormat::Xlsx,
        ReportFormat::Pdf,
    ])
}

/// Get available schedule frequencies
#[tauri::command]
pub async fn ghostreport_get_schedule_frequencies() -> Result<Vec<ScheduleFrequency>, String> {
    Ok(vec![
        ScheduleFrequency::Once,
        ScheduleFrequency::Daily,
        ScheduleFrequency::Weekly,
        ScheduleFrequency::Monthly,
    ])
}

/// Delete an artifact from the archive
#[tauri::command]
pub async fn ghostreport_delete_artifact(
    report_id: String,
    format: ReportFormat,
    state: State<'_, GhostReportState>,
) -> Result<(), String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    let archive = engine.get_archive().await;
    archive.delete_artifact(&report_id, &format).await
        .map_err(|e| e.to_string())?;
    
    info!("Deleted artifact: {} ({})", report_id, format);
    Ok(())
}

/// Clean up old artifacts
#[tauri::command]
pub async fn ghostreport_cleanup_old_artifacts(
    retention_days: u32,
    state: State<'_, GhostReportState>,
) -> Result<u32, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    let archive = engine.get_archive().await;
    let deleted_count = archive.cleanup_old_artifacts(retention_days).await
        .map_err(|e| e.to_string())?;
    
    info!("Cleaned up {} old artifacts", deleted_count);
    Ok(deleted_count)
}

/// Export archive index
#[tauri::command]
pub async fn ghostreport_export_archive_index(
    state: State<'_, GhostReportState>,
) -> Result<String, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    let archive = engine.get_archive().await;
    let index_json = archive.export_index().await
        .map_err(|e| e.to_string())?;
    
    Ok(index_json)
}

/// Get all report jobs
#[tauri::command]
pub async fn ghostreport_get_jobs(
    state: State<'_, GhostReportState>,
) -> Result<Vec<ReportJob>, String> {
    let engine_guard = state.engine.read().await;
    let engine = engine_guard.as_ref()
        .ok_or("GhostReport not initialized")?;
    
    // Use get_scheduled_reports as a placeholder for jobs
    engine.get_scheduled_reports().await.map_err(|e| e.to_string())
}

// Removed duplicate functions - they already exist earlier in the file

/// Create a new report job
#[tauri::command]
pub async fn ghostreport_create_job(
    job: ReportJob,
    _state: State<'_, GhostReportState>,
) -> Result<String, String> {
    // TODO: Implement job creation - for now return a placeholder ID
    Ok(format!("job_{}", Uuid::new_v4()))
}

/// Run a report job
#[tauri::command]
pub async fn ghostreport_run_job(
    job_id: String,
    _state: State<'_, GhostReportState>,
) -> Result<String, String> {
    // TODO: Implement job execution - for now return success message
    Ok(format!("Job {} started successfully", job_id))
}

/// Delete a report job
#[tauri::command]
pub async fn ghostreport_delete_job(
    job_id: String,
    _state: State<'_, GhostReportState>,
) -> Result<(), String> {
    // TODO: Implement job deletion - for now return success
    info!("Deleting job: {}", job_id);
    Ok(())
}
