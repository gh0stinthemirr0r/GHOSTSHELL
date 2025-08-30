//! GhostLog Daemon - Central logging coordinator
//! 
//! Receives log events from all modules via IPC and manages
//! per-module log streams with rotation and PQ signing.

use crate::{LogError, Result, LogManifest};
// anyhow::Context removed - not needed
use chrono::{DateTime, Utc};
use ghost_pq::{DilithiumSigner, DilithiumVariant, DilithiumKeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};
use uuid::Uuid;

/// Configuration for the GhostLog daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostLogConfig {
    /// Base directory for log storage
    pub log_directory: PathBuf,
    /// Maximum size per log file before rotation (bytes)
    pub max_file_size: u64,
    /// Maximum age before rotation (hours)
    pub max_file_age_hours: u64,
    /// Maximum number of log events per second
    pub max_events_per_second: u32,
    /// Enable real-time indexing for search
    pub enable_search_indexing: bool,
    /// Retention period in days
    pub retention_days: u32,
}

impl Default for GhostLogConfig {
    fn default() -> Self {
        Self {
            log_directory: PathBuf::from("ghostlog"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_file_age_hours: 24, // Daily rotation
            max_events_per_second: 10000,
            enable_search_indexing: true,
            retention_days: 90,
        }
    }
}

/// Log event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogSeverity {
    Info,
    Warn,
    Error,
    Critical,
}

/// Standardized log entry for all GhostShell modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostLogEntry {
    /// Timestamp (ISO 8601)
    pub timestamp: DateTime<Utc>,
    /// Module name (ssh, terminal, vault, etc.)
    pub module: String,
    /// Severity level
    pub severity: LogSeverity,
    /// Event identifier for categorization
    pub event_id: String,
    /// Human-readable message
    pub message: String,
    /// Additional context data
    pub context: HashMap<String, serde_json::Value>,
    /// PQ signature of the entry
    pub signature: Option<String>,
    /// Entry UUID
    pub id: Uuid,
}

impl GhostLogEntry {
    pub fn new(
        module: impl Into<String>,
        severity: LogSeverity,
        event_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            module: module.into(),
            severity,
            event_id: event_id.into(),
            message: message.into(),
            context: HashMap::new(),
            signature: None,
            id: Uuid::new_v4(),
        }
    }

    pub fn with_context(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.context.insert(key.into(), value);
        self
    }

    pub fn sign(&mut self, signer: &DilithiumSigner, private_key: &ghost_pq::DilithiumPrivateKey) -> Result<()> {
        let data = self.serialize_for_signing()?;
        let signature = signer.sign(private_key, &data)
            .map_err(|e| LogError::CryptoError(e))?;
        self.signature = Some(hex::encode(&signature.signature));
        Ok(())
    }

    fn serialize_for_signing(&self) -> Result<Vec<u8>> {
        let mut entry_copy = self.clone();
        entry_copy.signature = None; // Don't include signature in signing data
        serde_json::to_vec(&entry_copy)
            .map_err(|e| LogError::SerializationError(e))
    }
}

/// Per-module log stream manager
#[derive(Debug)]
struct ModuleLogStream {
    module: String,
    current_file: Option<PathBuf>,
    current_size: u64,
    entry_count: u64,
    sequence: u32,
    last_rotation: DateTime<Utc>,
}

impl ModuleLogStream {
    fn new(module: String) -> Self {
        Self {
            module,
            current_file: None,
            current_size: 0,
            entry_count: 0,
            sequence: 1,
            last_rotation: Utc::now(),
        }
    }

    fn should_rotate(&self, config: &GhostLogConfig) -> bool {
        self.current_size >= config.max_file_size ||
        Utc::now().signed_duration_since(self.last_rotation).num_hours() >= config.max_file_age_hours as i64
    }

    fn get_log_file_path(&self, base_dir: &Path, date: DateTime<Utc>) -> PathBuf {
        let date_str = date.format("%Y-%m-%d").to_string();
        let filename = format!("{}-{}-{:03}.log", date_str, self.module, self.sequence);
        base_dir.join(&self.module).join(filename)
    }

    fn get_manifest_path(&self, log_file: &Path) -> PathBuf {
        log_file.with_extension("manifest.json")
    }
}

/// Main GhostLog daemon
pub struct GhostLogDaemon {
    config: GhostLogConfig,
    streams: Arc<RwLock<HashMap<String, ModuleLogStream>>>,
    signer: Arc<DilithiumSigner>,
    private_key: Arc<ghost_pq::DilithiumPrivateKey>,
    event_sender: mpsc::UnboundedSender<GhostLogEntry>,
    event_receiver: Arc<Mutex<mpsc::UnboundedReceiver<GhostLogEntry>>>,
    search_indexer: Option<Arc<crate::search::SearchIndexer>>,
}

impl GhostLogDaemon {
    /// Create a new GhostLog daemon
    pub async fn new(config: GhostLogConfig) -> Result<Self> {
        // Ensure log directory exists
        fs::create_dir_all(&config.log_directory).await
            .map_err(|e| LogError::IoError(e))?;

        // Initialize PQ signer with key pair
        let signer_instance = DilithiumSigner::new(DilithiumVariant::Dilithium2)
            .map_err(|e| LogError::CryptoError(e))?;
        let keypair = signer_instance.generate_keypair()
            .map_err(|e| LogError::CryptoError(e))?;
        let signer = Arc::new(signer_instance);

        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        // Initialize search indexer if enabled
        let search_indexer = if config.enable_search_indexing {
            Some(Arc::new(crate::search::SearchIndexer::new(&config.log_directory).await?))
        } else {
            None
        };

        Ok(Self {
            config,
            streams: Arc::new(RwLock::new(HashMap::new())),
            signer,
            private_key: Arc::new(keypair.private_key),
            event_sender,
            event_receiver: Arc::new(Mutex::new(event_receiver)),
            search_indexer,
        })
    }

    /// Get a handle to send log events to the daemon
    pub fn get_sender(&self) -> mpsc::UnboundedSender<GhostLogEntry> {
        self.event_sender.clone()
    }

    /// Start the daemon (runs indefinitely)
    pub async fn run(&self) -> Result<()> {
        info!("Starting GhostLog daemon");

        // Start rotation timer
        let rotation_streams = Arc::clone(&self.streams);
        let rotation_config = self.config.clone();
        let rotation_signer = Arc::clone(&self.signer);
        let rotation_indexer = self.search_indexer.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // Check every 5 minutes
            loop {
                interval.tick().await;
                if let Err(e) = Self::check_rotations(
                    &rotation_streams,
                    &rotation_config,
                    &rotation_signer,
                    &rotation_indexer,
                ).await {
                    error!("Rotation check failed: {}", e);
                }
            }
        });

        // Main event processing loop
        let mut receiver = self.event_receiver.lock().await;
        while let Some(mut entry) = receiver.recv().await {
            if let Err(e) = self.process_entry(&mut entry).await {
                error!("Failed to process log entry: {}", e);
            }
        }

        Ok(())
    }

    async fn process_entry(&self, entry: &mut GhostLogEntry) -> Result<()> {
        // Sign the entry
        entry.sign(&self.signer, &self.private_key)?;

        // Get or create stream for this module
        let mut streams = self.streams.write().await;
        let stream = streams.entry(entry.module.clone())
            .or_insert_with(|| ModuleLogStream::new(entry.module.clone()));

        // Check if rotation is needed
        if stream.should_rotate(&self.config) {
            self.rotate_stream(stream).await?;
        }

        // Ensure current file exists
        if stream.current_file.is_none() {
            let log_file = stream.get_log_file_path(&self.config.log_directory, entry.timestamp);
            fs::create_dir_all(log_file.parent().unwrap()).await?;
            stream.current_file = Some(log_file);
            stream.current_size = 0;
            stream.entry_count = 0;
        }

        // Append entry to log file
        let log_file = stream.current_file.as_ref().unwrap();
        let entry_json = serde_json::to_string(entry)?;
        let entry_line = format!("{}\n", entry_json);
        
        fs::write(log_file, entry_line.as_bytes()).await?;
        stream.current_size += entry_line.len() as u64;
        stream.entry_count += 1;

        // Update search index if enabled
        if let Some(ref indexer) = self.search_indexer {
            indexer.index_entry(entry).await?;
        }

        debug!("Logged entry to {}: {}", entry.module, entry.message);
        Ok(())
    }

    async fn rotate_stream(&self, stream: &mut ModuleLogStream) -> Result<()> {
        if let Some(ref current_file) = stream.current_file {
            info!("Rotating log file: {:?}", current_file);

            // Create manifest for the completed log file
            let manifest = LogManifest {
                file_path: current_file.clone(),
                entries: stream.entry_count,
                start_time: stream.last_rotation,
                end_time: Utc::now(),
                signature: None,
            };

            // Sign and save manifest
            let manifest_path = stream.get_manifest_path(current_file);
            let manifest_data = serde_json::to_vec(&manifest)?;
            let signature = self.signer.sign(&self.private_key, &manifest_data)
                .map_err(|e| LogError::CryptoError(e))?;
            
            let signed_manifest = LogManifest {
                signature: Some(hex::encode(&signature.signature)),
                ..manifest
            };

            let manifest_json = serde_json::to_string_pretty(&signed_manifest)?;
            fs::write(&manifest_path, manifest_json).await?;

            info!("Created manifest: {:?}", manifest_path);
        }

        // Reset stream for new file
        stream.current_file = None;
        stream.current_size = 0;
        stream.entry_count = 0;
        stream.sequence += 1;
        stream.last_rotation = Utc::now();

        Ok(())
    }

    async fn check_rotations(
        streams: &Arc<RwLock<HashMap<String, ModuleLogStream>>>,
        config: &GhostLogConfig,
        signer: &Arc<DilithiumSigner>,
        _indexer: &Option<Arc<crate::search::SearchIndexer>>,
    ) -> Result<()> {
        let mut streams_guard = streams.write().await;
        for (_, stream) in streams_guard.iter_mut() {
            if stream.should_rotate(config) {
                // Note: This is a simplified rotation check
                // In practice, we'd need to handle the rotation more carefully
                debug!("Stream {} needs rotation", stream.module);
            }
        }
        Ok(())
    }

    /// Create a log entry for a module
    pub fn log(
        &self,
        module: impl Into<String>,
        severity: LogSeverity,
        event_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<()> {
        let entry = GhostLogEntry::new(module, severity, event_id, message);
        self.event_sender.send(entry)
            .map_err(|_| LogError::InvalidInput("Failed to send log entry".to_string()))?;
        Ok(())
    }

    /// Create a log entry with context
    pub fn log_with_context(
        &self,
        module: impl Into<String>,
        severity: LogSeverity,
        event_id: impl Into<String>,
        message: impl Into<String>,
        context: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        let mut entry = GhostLogEntry::new(module, severity, event_id, message);
        entry.context = context;
        self.event_sender.send(entry)
            .map_err(|_| LogError::InvalidInput("Failed to send log entry".to_string()))?;
        Ok(())
    }
}

/// Global GhostLog instance
static GHOST_LOG: once_cell::sync::OnceCell<Arc<GhostLogDaemon>> = once_cell::sync::OnceCell::new();

/// Initialize the global GhostLog daemon
pub async fn initialize_ghost_log(config: GhostLogConfig) -> Result<()> {
    let daemon = Arc::new(GhostLogDaemon::new(config).await?);
    
    // Allow reinitialization - if already set, just update the reference
    if GHOST_LOG.get().is_some() {
        info!("GhostLog already initialized, skipping reinitialization");
        return Ok(());
    }
    
    GHOST_LOG.set(daemon.clone())
        .map_err(|_| LogError::InvalidInput("Failed to initialize GhostLog".to_string()))?;

    // Start the daemon in a background task
    let daemon_clone = daemon.clone();
    tokio::spawn(async move {
        if let Err(e) = daemon_clone.run().await {
            error!("GhostLog daemon error: {}", e);
        }
    });

    Ok(())
}

/// Get the global GhostLog instance
pub fn get_ghost_log() -> Option<&'static Arc<GhostLogDaemon>> {
    GHOST_LOG.get()
}

/// Convenience macro for logging
#[macro_export]
macro_rules! ghost_log {
    ($module:expr, $severity:expr, $event_id:expr, $message:expr) => {
        if let Some(log) = $crate::get_ghost_log() {
            let _ = log.log($module, $severity, $event_id, $message);
        }
    };
    ($module:expr, $severity:expr, $event_id:expr, $message:expr, $context:expr) => {
        if let Some(log) = $crate::get_ghost_log() {
            let _ = log.log_with_context($module, $severity, $event_id, $message, $context);
        }
    };
}
