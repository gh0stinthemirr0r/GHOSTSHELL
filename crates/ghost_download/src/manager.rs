use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, error};
use uuid::Uuid;

use crate::{DownloadMeta, ActiveDownload, DownloadStatus, FileSealer};
use ghost_vault::Vault;
use ghost_pq::signatures::DilithiumSigner;
use ghost_log::AuditLogger;

/// Download manager for sealed downloads
pub struct DownloadManager {
    vault_manager: Arc<Mutex<Vault>>,
    sealer: FileSealer,
    active_downloads: Arc<Mutex<HashMap<String, ActiveDownload>>>,
    completed_downloads: Arc<Mutex<Vec<DownloadMeta>>>,
    logger: Arc<AuditLogger>,
}

impl DownloadManager {
    /// Create a new download manager
    pub async fn new(
        vault_manager: Arc<Mutex<Vault>>,
        signer: Arc<DilithiumSigner>,
        logger: Arc<AuditLogger>,
    ) -> Result<Self> {
        let sealer = FileSealer::new(signer)?;

        Ok(Self {
            vault_manager,
            sealer,
            active_downloads: Arc::new(Mutex::new(HashMap::new())),
            completed_downloads: Arc::new(Mutex::new(Vec::new())),
            logger,
        })
    }

    /// Initialize the download manager
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing download manager");
        
        // Load existing downloads from vault
        self.load_existing_downloads().await?;

        info!("Download manager initialized");
        Ok(())
    }

    /// Start a new download
    pub async fn start_download(
        &self,
        url: String,
        filename: Option<String>,
        tab_id: Option<String>,
    ) -> Result<String> {
        let download_id = Uuid::new_v4().to_string();
        
        // Generate filenames
        let original_filename = filename.unwrap_or_else(|| {
            url.split('/').last().unwrap_or("download").to_string()
        });
        let sealed_filename = format!("{}.sealed", download_id);
        let vault_path = format!("downloads/{}", sealed_filename);

        // Create download metadata
        let meta = DownloadMeta::new(
            download_id.clone(),
            url.clone(),
            vault_path,
            original_filename,
            sealed_filename,
            String::new(), // Hash will be set after download
            String::new(), // Signature will be set after sealing
            0,             // Size will be updated during download
            tab_id,
        );

        // Create active download
        let active_download = ActiveDownload::new(meta);

        // Add to active downloads
        {
            let mut active = self.active_downloads.lock().await;
            active.insert(download_id.clone(), active_download);
        }

        // Log download start
        self.log_download_event(&download_id, "download_started", &url).await?;

        // Start download process (in background)
        let manager = self.clone_for_background();
        let download_id_bg = download_id.clone();
        let url_bg = url.clone();
        
        tokio::spawn(async move {
            if let Err(e) = manager.process_download(&download_id_bg, &url_bg).await {
                error!("Download failed for {}: {}", download_id_bg, e);
                manager.mark_download_failed(&download_id_bg, &e.to_string()).await;
            }
        });

        info!("Started download: {} -> {}", download_id, url);
        Ok(download_id)
    }

    /// Get active downloads
    pub async fn get_active_downloads(&self) -> Result<Vec<ActiveDownload>> {
        let active = self.active_downloads.lock().await;
        Ok(active.values().cloned().collect())
    }

    /// Get completed downloads
    pub async fn get_completed_downloads(&self) -> Result<Vec<DownloadMeta>> {
        let completed = self.completed_downloads.lock().await;
        Ok(completed.clone())
    }

    /// Cancel a download
    pub async fn cancel_download(&self, download_id: &str) -> Result<()> {
        let mut active = self.active_downloads.lock().await;
        
        if let Some(download) = active.get_mut(download_id) {
            download.set_status(DownloadStatus::Cancelled);
            
            // Log cancellation
            self.log_download_event(download_id, "download_cancelled", "").await?;
            
            info!("Cancelled download: {}", download_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Download {} not found", download_id))
        }
    }

    /// Unseal a download for access
    pub async fn unseal_download(&self, download_id: &str, output_path: &str) -> Result<bool> {
        let completed = self.completed_downloads.lock().await;
        
        if let Some(meta) = completed.iter().find(|d| d.id == download_id) {
            let vault_manager = self.vault_manager.lock().await;
            let output_path = std::path::Path::new(output_path);
            
            let success = self.sealer.unseal_file(&meta.vault_path, output_path, &vault_manager).await?;
            
            // Log unsealing
            self.log_download_event(download_id, "download_unsealed", output_path.to_string_lossy().as_ref()).await?;
            
            Ok(success)
        } else {
            Err(anyhow::anyhow!("Download {} not found", download_id))
        }
    }

    /// Process a download (background task)
    async fn process_download(&self, download_id: &str, url: &str) -> Result<()> {
        debug!("Processing download: {} -> {}", download_id, url);

        // Update status to downloading
        self.update_download_status(download_id, DownloadStatus::Downloading).await?;

        // TODO: Implement actual HTTP download
        // For now, simulate download process
        self.simulate_download(download_id).await?;

        // Update status to sealing
        self.update_download_status(download_id, DownloadStatus::Sealing).await?;

        // Seal the file
        self.seal_download(download_id).await?;

        // Mark as completed
        self.complete_download(download_id).await?;

        Ok(())
    }

    /// Simulate download process (placeholder)
    async fn simulate_download(&self, download_id: &str) -> Result<()> {
        // Simulate download progress
        for i in 1..=10 {
            let progress = i as f64 / 10.0;
            let bytes = (progress * 1024.0 * 1024.0) as u64; // 1MB file
            
            self.update_download_progress(download_id, bytes, Some(1024 * 1024)).await?;
            
            // Check if cancelled
            {
                let active = self.active_downloads.lock().await;
                if let Some(download) = active.get(download_id) {
                    if download.status == DownloadStatus::Cancelled {
                        return Err(anyhow::anyhow!("Download cancelled"));
                    }
                }
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// Seal a completed download
    async fn seal_download(&self, download_id: &str) -> Result<()> {
        // TODO: Implement actual file sealing
        // For now, just simulate the process
        debug!("Sealing download: {}", download_id);
        
        // Simulate sealing time
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        Ok(())
    }

    /// Complete a download
    async fn complete_download(&self, download_id: &str) -> Result<()> {
        let mut active = self.active_downloads.lock().await;
        
        if let Some(mut download) = active.remove(download_id) {
            download.set_status(DownloadStatus::Completed);
            
            // Move to completed downloads
            {
                let mut completed = self.completed_downloads.lock().await;
                completed.push(download.meta);
            }

            // Log completion
            self.log_download_event(download_id, "download_completed", "").await?;
            
            info!("Completed download: {}", download_id);
        }

        Ok(())
    }

    /// Mark download as failed
    async fn mark_download_failed(&self, download_id: &str, error: &str) {
        let mut active = self.active_downloads.lock().await;
        
        if let Some(download) = active.get_mut(download_id) {
            download.set_status(DownloadStatus::Failed(error.to_string()));
            
            // Log failure
            if let Err(e) = self.log_download_event(download_id, "download_failed", error).await {
                error!("Failed to log download failure: {}", e);
            }
        }
    }

    /// Update download status
    async fn update_download_status(&self, download_id: &str, status: DownloadStatus) -> Result<()> {
        let mut active = self.active_downloads.lock().await;
        
        if let Some(download) = active.get_mut(download_id) {
            download.set_status(status);
        }

        Ok(())
    }

    /// Update download progress
    async fn update_download_progress(&self, download_id: &str, bytes: u64, total: Option<u64>) -> Result<()> {
        let mut active = self.active_downloads.lock().await;
        
        if let Some(download) = active.get_mut(download_id) {
            download.update_progress(bytes, total);
        }

        Ok(())
    }

    /// Load existing downloads from vault
    async fn load_existing_downloads(&self) -> Result<()> {
        // TODO: Implement loading of existing downloads from vault metadata
        debug!("Loading existing downloads from vault");
        Ok(())
    }

    /// Clone for background tasks
    fn clone_for_background(&self) -> Self {
        Self {
            vault_manager: self.vault_manager.clone(),
            sealer: FileSealer::new(self.sealer.signer.clone()).unwrap(),
            active_downloads: self.active_downloads.clone(),
            completed_downloads: self.completed_downloads.clone(),
            logger: self.logger.clone(),
        }
    }

    /// Log download event
    async fn log_download_event(&self, download_id: &str, event_type: &str, data: &str) -> Result<()> {
        let log_entry = serde_json::json!({
            "event_type": event_type,
            "download_id": download_id,
            "data": data,
            "timestamp": chrono::Utc::now(),
        });

        let actor = ghost_log::Actor {
            actor_type: ghost_log::ActorType::System,
            id: "download_manager".to_string(),
            name: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
        };

        let resource = ghost_log::Resource {
            resource_type: ghost_log::ResourceType::File,
            id: Some(download_id.to_string()),
            name: None,
            path: None,
            attributes: std::collections::HashMap::new(),
        };

        self.logger.log_event().await
            .event_type(ghost_log::EventType::SystemEvent)
            .severity(ghost_log::Severity::Info)
            .actor(actor)
            .resource(resource)
            .action(ghost_log::Action::Create)
            .outcome(ghost_log::Outcome::Success)
            .message(format!("{}: {}", event_type, data))
            .submit()
            .await?;
        Ok(())
    }
}
