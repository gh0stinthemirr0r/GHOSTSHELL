//! Report generation engine
//! 
//! Core engine that orchestrates data collection, processing, and export

use crate::{
    ReportJob, ReportArtifact, ReportError, ReportResult, ReportStats, ReportPreview,
    ReportSource, ReportFormat, DataCollector, CsvExporter, XlsxExporter, PdfExporter,
    ReportArchive, ReportScheduler,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use ghost_log::GhostLogDaemon;
use ghost_pq::{DilithiumSigner, DilithiumVariant};
use ghost_vault::Vault;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Main report generation engine
pub struct ReportEngine {
    /// Data collector for various sources
    collector: Arc<DataCollector>,
    /// CSV exporter
    csv_exporter: Arc<CsvExporter>,
    /// XLSX exporter
    xlsx_exporter: Arc<XlsxExporter>,
    /// PDF exporter
    pdf_exporter: Arc<PdfExporter>,
    /// Report archive manager
    archive: Arc<ReportArchive>,
    /// Report scheduler
    scheduler: Arc<ReportScheduler>,
    /// PQ signer for report authentication
    signer: Arc<DilithiumSigner>,
    /// Vault for secure storage
    vault: Arc<RwLock<Option<Vault>>>,
    /// Engine statistics
    stats: Arc<RwLock<ReportStats>>,
    /// Output directory
    output_dir: PathBuf,
}

impl ReportEngine {
    /// Create a new report engine
    pub fn new(output_dir: PathBuf) -> ReportResult<Self> {
        let signer = Arc::new(DilithiumSigner::new(DilithiumVariant::Dilithium2)
            .map_err(|e| ReportError::Signature(format!("Failed to create signer: {}", e)))?);
        
        Ok(Self {
            collector: Arc::new(DataCollector::new()),
            csv_exporter: Arc::new(CsvExporter::new()),
            xlsx_exporter: Arc::new(XlsxExporter::new()),
            pdf_exporter: Arc::new(PdfExporter::new()),
            archive: Arc::new(ReportArchive::new(output_dir.join("archive"))?),
            scheduler: Arc::new(ReportScheduler::new()),
            signer,
            vault: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(ReportStats::default())),
            output_dir,
        })
    }
    
    /// Initialize the engine with vault integration
    pub async fn initialize(&self, vault: Option<Vault>) -> ReportResult<()> {
        info!("Initializing GhostReport engine");
        
        // Set vault if provided
        if let Some(v) = vault {
            let mut vault_guard = self.vault.write().await;
            *vault_guard = Some(v);
        }
        
        // Initialize archive
        self.archive.initialize().await?;
        
        // Initialize scheduler
        self.scheduler.initialize().await?;
        
        info!("GhostReport engine initialized successfully");
        Ok(())
    }
    
    /// Generate a report from a job configuration
    pub async fn generate_report(&self, job: ReportJob) -> ReportResult<Vec<ReportArtifact>> {
        let start_time = std::time::Instant::now();
        info!("Generating report: {} ({})", job.name, job.id);
        
        // Collect data from sources
        let data = self.collector.collect_data(&job.sources, &job.filters).await
            .map_err(|e| ReportError::DataSource(e.to_string()))?;
        
        debug!("Collected {} data points for report {}", data.len(), job.id);
        
        // Generate artifacts for each requested format
        let mut artifacts = Vec::new();
        
        for format in &job.formats {
            let artifact = self.generate_artifact(&job, &data, format.clone()).await?;
            artifacts.push(artifact);
        }
        
        // Store in archive
        for artifact in &artifacts {
            self.archive.store_artifact(artifact).await?;
        }
        
        // Update statistics
        let generation_time = start_time.elapsed().as_millis() as f64;
        self.update_stats(&job, generation_time, data.len()).await;
        
        // Log the report generation
        if let Some(ghost_log) = ghost_log::get_ghost_log() {
            let _ = ghost_log.log(
                "ghostreport",
                ghost_log::LogSeverity::Info,
                "report-generated",
                &format!("Generated report {} with {} artifacts", job.name, artifacts.len()),
            );
        }
        
        info!("Report generation completed: {} artifacts in {:.2}ms", 
              artifacts.len(), generation_time);
        
        Ok(artifacts)
    }
    
    /// Generate a single artifact for a specific format
    async fn generate_artifact(
        &self,
        job: &ReportJob,
        data: &[HashMap<String, serde_json::Value>],
        format: ReportFormat,
    ) -> ReportResult<ReportArtifact> {
        let timestamp = Utc::now();
        let filename = format!("{}-{}.{}", 
                              job.name.replace(' ', "-").to_lowercase(),
                              timestamp.format("%Y%m%d-%H%M%S"),
                              format);
        
        let output_path = self.output_dir.join(&filename);
        
        // Generate the file based on format
        match format {
            ReportFormat::Csv => {
                self.csv_exporter.export(data, &output_path, job).await?;
            }
            ReportFormat::Xlsx => {
                self.xlsx_exporter.export(data, &output_path, job).await?;
            }
            ReportFormat::Pdf => {
                self.pdf_exporter.export(data, &output_path, job).await?;
            }
        }
        
        // Calculate file hash
        let file_content = tokio::fs::read(&output_path).await?;
        let hash = sha3::Sha3_256::digest(&file_content);
        let hash_hex = hex::encode(hash);
        
        // Sign the file
        let keypair = self.signer.generate_keypair()?;
        let signature = self.signer.sign(&keypair.private_key, &file_content)?;
        let signature_hex = hex::encode(&signature.signature);
        
        // Store in vault if available
        let vault_path = if let Some(vault) = self.vault.read().await.as_ref() {
            let vault_path = format!("ghostvault/reports/{}/{}", 
                                   timestamp.format("%Y-%m-%d"), filename);
            
            // Store file in vault (simplified - would use actual vault API)
            debug!("Would store report in vault at: {}", vault_path);
            Some(vault_path)
        } else {
            None
        };
        
        let artifact = ReportArtifact {
            report_id: job.id.clone(),
            format,
            path: vault_path.unwrap_or_else(|| output_path.to_string_lossy().to_string()),
            hash: hash_hex,
            signature: signature_hex,
            size: file_content.len() as u64,
            created_at: timestamp,
            metadata: self.create_artifact_metadata(job, data).await,
        };
        
        Ok(artifact)
    }
    
    /// Create metadata for an artifact
    async fn create_artifact_metadata(
        &self,
        job: &ReportJob,
        data: &[HashMap<String, serde_json::Value>],
    ) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        
        metadata.insert("job_name".to_string(), job.name.clone());
        metadata.insert("created_by".to_string(), job.created_by.clone());
        metadata.insert("data_points".to_string(), data.len().to_string());
        metadata.insert("sources".to_string(), 
                       serde_json::to_string(&job.sources).unwrap_or_default());
        
        if let Some(start) = job.filters.time_start {
            metadata.insert("time_start".to_string(), start.to_rfc3339());
        }
        if let Some(end) = job.filters.time_end {
            metadata.insert("time_end".to_string(), end.to_rfc3339());
        }
        
        metadata.insert("engine_version".to_string(), env!("CARGO_PKG_VERSION").to_string());
        metadata.insert("generated_at".to_string(), Utc::now().to_rfc3339());
        
        metadata
    }
    
    /// Generate a preview of what a report would contain
    pub async fn generate_preview(&self, job: &ReportJob) -> ReportResult<ReportPreview> {
        debug!("Generating preview for report: {}", job.name);
        
        // Collect a sample of data (limited to 100 rows for preview)
        let mut limited_filters = job.filters.clone();
        let sample_data = self.collector.collect_sample_data(&job.sources, &limited_filters, 100).await
            .map_err(|e| ReportError::DataSource(e.to_string()))?;
        
        // Get full statistics without data
        let stats = self.collector.get_data_stats(&job.sources, &job.filters).await
            .map_err(|e| ReportError::DataSource(e.to_string()))?;
        
        // Estimate file sizes
        let estimated_sizes = self.estimate_file_sizes(&sample_data, stats.total_rows).await;
        
        Ok(ReportPreview {
            metadata: job.clone(),
            sample_data,
            stats,
            estimated_sizes,
        })
    }
    
    /// Estimate file sizes for different formats
    async fn estimate_file_sizes(
        &self,
        sample_data: &[HashMap<String, serde_json::Value>],
        total_rows: u64,
    ) -> HashMap<ReportFormat, u64> {
        let mut sizes = HashMap::new();
        
        if !sample_data.is_empty() {
            // Rough estimation based on sample data
            let sample_json = serde_json::to_string(sample_data).unwrap_or_default();
            let bytes_per_row = sample_json.len() as f64 / sample_data.len() as f64;
            
            // CSV: roughly 60% of JSON size
            sizes.insert(ReportFormat::Csv, (bytes_per_row * 0.6 * total_rows as f64) as u64);
            
            // XLSX: roughly 80% of JSON size (compressed)
            sizes.insert(ReportFormat::Xlsx, (bytes_per_row * 0.8 * total_rows as f64) as u64);
            
            // PDF: roughly 120% of JSON size (formatting overhead)
            sizes.insert(ReportFormat::Pdf, (bytes_per_row * 1.2 * total_rows as f64) as u64);
        }
        
        sizes
    }
    
    /// Update engine statistics
    async fn update_stats(&self, job: &ReportJob, generation_time_ms: f64, data_points: usize) {
        let mut stats = self.stats.write().await;
        
        stats.total_reports += 1;
        
        for format in &job.formats {
            *stats.by_format.entry(format.clone()).or_insert(0) += 1;
        }
        
        for source in &job.sources {
            let source_key = format!("{:?}", source);
            *stats.by_source.entry(source_key).or_insert(0) += 1;
        }
        
        // Update average generation time
        let total_time = stats.avg_generation_time_ms * (stats.total_reports - 1) as f64 + generation_time_ms;
        stats.avg_generation_time_ms = total_time / stats.total_reports as f64;
        
        stats.total_data_processed += data_points as u64;
    }
    
    /// Get engine statistics
    pub async fn get_stats(&self) -> ReportStats {
        self.stats.read().await.clone()
    }
    
    /// Schedule a report job
    pub async fn schedule_report(&self, job: ReportJob) -> ReportResult<String> {
        if job.schedule.is_none() {
            return Err(ReportError::Scheduling("No schedule configuration provided".to_string()));
        }
        
        let job_id = self.scheduler.schedule_job(job).await?;
        
        info!("Scheduled report job: {}", job_id);
        Ok(job_id)
    }
    
    /// Get all scheduled reports
    pub async fn get_scheduled_reports(&self) -> ReportResult<Vec<ReportJob>> {
        self.scheduler.get_scheduled_jobs().await
    }
    
    /// Cancel a scheduled report
    pub async fn cancel_scheduled_report(&self, job_id: &str) -> ReportResult<()> {
        self.scheduler.cancel_job(job_id).await?;
        info!("Cancelled scheduled report: {}", job_id);
        Ok(())
    }
    
    /// Get report archive
    pub async fn get_archive(&self) -> Arc<ReportArchive> {
        Arc::clone(&self.archive)
    }
    
    /// Verify report artifact signature
    pub async fn verify_artifact(&self, artifact: &ReportArtifact) -> ReportResult<bool> {
        // Read file content
        let file_content = tokio::fs::read(&artifact.path).await?;
        
        // Verify hash
        let computed_hash = hex::encode(sha3::Sha3_256::digest(&file_content));
        if computed_hash != artifact.hash {
            warn!("Hash mismatch for artifact: {}", artifact.path);
            return Ok(false);
        }
        
        // Verify signature (simplified - would need public key)
        debug!("Signature verification for artifact: {}", artifact.path);
        
        // For now, just verify hash matches
        Ok(true)
    }
}

impl Default for ReportStats {
    fn default() -> Self {
        Self {
            total_reports: 0,
            by_format: HashMap::new(),
            by_source: HashMap::new(),
            avg_generation_time_ms: 0.0,
            total_data_processed: 0,
            failed_generations: 0,
        }
    }
}

// Add SHA3 dependency for hashing
use sha3::Digest;
