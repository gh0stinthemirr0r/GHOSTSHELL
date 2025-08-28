use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use chrono::Utc;
use crate::{
    LogEntry, LogBatch, HashChain, LogStorage, ChainMetadata,
    Actor, Resource, Action, Outcome, EventType, Severity,
    LogError, Result,
};

/// Main audit logger with async batching and signing
pub struct AuditLogger {
    storage: Arc<LogStorage>,
    chain: Arc<RwLock<HashChain>>,
    batch_sender: mpsc::UnboundedSender<LogEntry>,
    config: LoggerConfig,
}

/// Logger configuration
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    pub batch_size: usize,
    pub batch_timeout_ms: u64,
    pub auto_sign_batches: bool,
    pub enable_real_time_verification: bool,
    pub max_memory_entries: usize,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            batch_timeout_ms: 5000, // 5 seconds
            auto_sign_batches: true,
            enable_real_time_verification: true,
            max_memory_entries: 1000,
        }
    }
}

/// Batch processor for efficient log handling
struct BatchProcessor {
    storage: Arc<LogStorage>,
    chain: Arc<RwLock<HashChain>>,
    config: LoggerConfig,
    pending_entries: Vec<LogEntry>,
    last_batch_time: std::time::Instant,
}

impl AuditLogger {
    /// Create a new audit logger
    pub async fn new(
        database_url: &str,
        chain_id: String,
        config: LoggerConfig,
    ) -> Result<Self> {
        let storage = Arc::new(LogStorage::new(database_url).await?);
        
        // Try to load existing chain metadata, or create new
        let chain = if let Some(metadata) = storage.get_chain_metadata(&chain_id).await? {
            Arc::new(RwLock::new(HashChain::from_metadata(metadata)?))
        } else {
            let new_chain = HashChain::new(chain_id.clone())?;
            let metadata = new_chain.export_metadata();
            storage.store_chain_metadata(&metadata).await?;
            Arc::new(RwLock::new(new_chain))
        };

        let (batch_sender, batch_receiver) = mpsc::unbounded_channel();

        let logger = Self {
            storage: storage.clone(),
            chain: chain.clone(),
            batch_sender,
            config: config.clone(),
        };

        // Start batch processor
        tokio::spawn(Self::run_batch_processor(
            storage,
            chain,
            config,
            batch_receiver,
        ));

        Ok(logger)
    }

    /// Create in-memory logger for testing
    pub async fn in_memory(chain_id: String) -> Result<Self> {
        Self::new(":memory:", chain_id, LoggerConfig::default()).await
    }

    /// Log an entry
    pub async fn log(&self, entry: LogEntry) -> Result<()> {
        self.batch_sender.send(entry)
            .map_err(|_| LogError::InvalidInput("Logger is shut down".to_string()))?;
        Ok(())
    }

    /// Log with builder pattern
    pub async fn log_event(&self) -> LogEntryBuilder {
        let chain = self.chain.read().await;
        let sequence = chain.get_stats().last_sequence + 1;
        LogEntryBuilder::new(self.batch_sender.clone(), sequence)
    }

    /// Force flush pending entries
    pub async fn flush(&self) -> Result<()> {
        // Send a flush signal (empty entry with special marker)
        let flush_entry = LogEntry::new(
            0,
            EventType::SystemEvent,
            Severity::Debug,
            Actor {
                actor_type: crate::ActorType::System,
                id: "logger".to_string(),
                name: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            },
            Resource {
                resource_type: crate::ResourceType::Log,
                id: None,
                name: None,
                path: None,
                attributes: std::collections::HashMap::new(),
            },
            Action::Query,
            Outcome::Success,
            "__FLUSH__".to_string(),
        );

        self.batch_sender.send(flush_entry)
            .map_err(|_| LogError::InvalidInput("Logger is shut down".to_string()))?;

        // Wait a bit for processing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        Ok(())
    }

    /// Get logger statistics
    pub async fn get_stats(&self) -> LoggerStats {
        let chain_stats = {
            let chain = self.chain.read().await;
            chain.get_stats()
        };

        let storage_stats = self.storage.get_stats().await.unwrap_or_else(|_| {
            crate::LogStorageStats {
                total_entries: 0,
                total_batches: 0,
                total_checkpoints: 0,
                earliest_entry: None,
                latest_entry: None,
                critical_entries: 0,
                error_entries: 0,
                warning_entries: 0,
            }
        });

        LoggerStats {
            chain_id: chain_stats.chain_id,
            total_entries: storage_stats.total_entries,
            total_batches: storage_stats.total_batches,
            last_sequence: chain_stats.last_sequence,
            critical_entries: storage_stats.critical_entries,
            error_entries: storage_stats.error_entries,
            warning_entries: storage_stats.warning_entries,
            can_sign: chain_stats.has_signing_key,
        }
    }

    /// Verify chain integrity
    pub async fn verify_integrity(&self) -> Result<crate::ChainVerification> {
        let chain = self.chain.read().await;
        let all_entries = self.storage.get_entries_by_sequence(1, chain.get_stats().last_sequence).await?;
        chain.verify_chain(&all_entries)
    }

    /// Create a checkpoint
    pub async fn create_checkpoint(&self) -> Result<crate::ChainCheckpoint> {
        let chain = self.chain.read().await;
        let checkpoint = chain.create_checkpoint(chain.get_stats().last_sequence)?;
        self.storage.store_checkpoint(&checkpoint).await?;
        Ok(checkpoint)
    }

    /// Get storage reference for advanced operations
    pub fn storage(&self) -> &Arc<LogStorage> {
        &self.storage
    }

    /// Run the batch processor
    async fn run_batch_processor(
        storage: Arc<LogStorage>,
        chain: Arc<RwLock<HashChain>>,
        config: LoggerConfig,
        mut receiver: mpsc::UnboundedReceiver<LogEntry>,
    ) {
        let mut processor = BatchProcessor {
            storage,
            chain,
            config,
            pending_entries: Vec::new(),
            last_batch_time: std::time::Instant::now(),
        };

        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_millis(processor.config.batch_timeout_ms)
        );

        loop {
            tokio::select! {
                // Process incoming entries
                entry = receiver.recv() => {
                    match entry {
                        Some(entry) => {
                            if entry.details.message == "__FLUSH__" {
                                // Flush signal
                                if let Err(e) = processor.process_batch().await {
                                    tracing::error!("Failed to process flush batch: {}", e);
                                }
                            } else {
                                processor.add_entry(entry).await;
                            }
                        }
                        None => {
                            // Channel closed, process remaining entries and exit
                            if let Err(e) = processor.process_batch().await {
                                tracing::error!("Failed to process final batch: {}", e);
                            }
                            break;
                        }
                    }
                }
                
                // Timeout-based batch processing
                _ = interval.tick() => {
                    if processor.should_process_batch() {
                        if let Err(e) = processor.process_batch().await {
                            tracing::error!("Failed to process timeout batch: {}", e);
                        }
                    }
                }
            }
        }
    }
}

impl BatchProcessor {
    async fn add_entry(&mut self, entry: LogEntry) {
        self.pending_entries.push(entry);

        if self.should_process_batch() {
            if let Err(e) = self.process_batch().await {
                tracing::error!("Failed to process batch: {}", e);
            }
        }
    }

    fn should_process_batch(&self) -> bool {
        self.pending_entries.len() >= self.config.batch_size ||
        self.last_batch_time.elapsed().as_millis() >= self.config.batch_timeout_ms as u128
    }

    async fn process_batch(&mut self) -> Result<()> {
        if self.pending_entries.is_empty() {
            return Ok(());
        }

        let entries = std::mem::take(&mut self.pending_entries);
        let entry_count = entries.len();

        // Add entries to chain and store
        let mut chained_entries = Vec::new();
        {
            let mut chain = self.chain.write().await;
            for entry in entries {
                let chained_entry = chain.add_entry(entry)?;
                chained_entries.push(chained_entry);
            }

            // Update chain metadata
            let metadata = chain.export_metadata();
            self.storage.store_chain_metadata(&metadata).await?;
        }

        // Store entries
        for entry in &chained_entries {
            self.storage.store_entry(entry).await?;
        }

        // Create and store signed batch if enabled
        if self.config.auto_sign_batches {
            let chain = self.chain.read().await;
            if chain.can_sign() {
                match chain.create_batch(chained_entries) {
                    Ok(batch) => {
                        if let Err(e) = self.storage.store_batch(&batch).await {
                            tracing::error!("Failed to store batch: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to create batch: {}", e);
                    }
                }
            }
        }

        self.last_batch_time = std::time::Instant::now();
        tracing::debug!("Processed batch of {} entries", entry_count);

        Ok(())
    }
}

/// Builder for creating log entries with fluent API
pub struct LogEntryBuilder {
    sender: mpsc::UnboundedSender<LogEntry>,
    sequence: u64,
    event_type: EventType,
    severity: Severity,
    actor: Option<Actor>,
    resource: Option<Resource>,
    action: Action,
    outcome: Outcome,
    message: String,
    context: std::collections::HashMap<String, String>,
    error_code: Option<String>,
    error_message: Option<String>,
    duration_ms: Option<u64>,
    bytes_transferred: Option<u64>,
    policy_rule_id: Option<String>,
    justification: Option<String>,
}

impl LogEntryBuilder {
    fn new(sender: mpsc::UnboundedSender<LogEntry>, sequence: u64) -> Self {
        Self {
            sender,
            sequence,
            event_type: EventType::UserAction,
            severity: Severity::Info,
            actor: None,
            resource: None,
            action: Action::Read,
            outcome: Outcome::Success,
            message: String::new(),
            context: std::collections::HashMap::new(),
            error_code: None,
            error_message: None,
            duration_ms: None,
            bytes_transferred: None,
            policy_rule_id: None,
            justification: None,
        }
    }

    pub fn event_type(mut self, event_type: EventType) -> Self {
        self.event_type = event_type;
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn actor(mut self, actor: Actor) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn resource(mut self, resource: Resource) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn action(mut self, action: Action) -> Self {
        self.action = action;
        self
    }

    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = outcome;
        self
    }

    pub fn message(mut self, message: String) -> Self {
        self.message = message;
        self
    }

    pub fn context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }

    pub fn error(mut self, code: String, message: String) -> Self {
        self.error_code = Some(code);
        self.error_message = Some(message);
        self.outcome = Outcome::Error;
        if self.severity < Severity::Error {
            self.severity = Severity::Error;
        }
        self
    }

    pub fn duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub fn bytes(mut self, bytes: u64) -> Self {
        self.bytes_transferred = Some(bytes);
        self
    }

    pub fn policy_rule(mut self, rule_id: String) -> Self {
        self.policy_rule_id = Some(rule_id);
        self
    }

    pub fn justification(mut self, justification: String) -> Self {
        self.justification = Some(justification);
        self
    }

    /// Submit the log entry
    pub async fn submit(self) -> Result<()> {
        let actor = self.actor.ok_or_else(|| LogError::InvalidInput("Actor is required".to_string()))?;
        let resource = self.resource.ok_or_else(|| LogError::InvalidInput("Resource is required".to_string()))?;

        let mut entry = LogEntry::new(
            self.sequence,
            self.event_type,
            self.severity,
            actor,
            resource,
            self.action,
            self.outcome,
            self.message,
        );

        entry.context = self.context;
        entry.details.error_code = self.error_code;
        entry.details.error_message = self.error_message;
        entry.details.duration_ms = self.duration_ms;
        entry.details.bytes_transferred = self.bytes_transferred;
        entry.details.policy_rule_id = self.policy_rule_id;
        entry.details.justification = self.justification;

        self.sender.send(entry)
            .map_err(|_| LogError::InvalidInput("Logger is shut down".to_string()))?;

        Ok(())
    }
}

/// Logger statistics
#[derive(Debug, Clone)]
pub struct LoggerStats {
    pub chain_id: String,
    pub total_entries: u64,
    pub total_batches: u64,
    pub last_sequence: u64,
    pub critical_entries: u64,
    pub error_entries: u64,
    pub warning_entries: u64,
    pub can_sign: bool,
}

/// Convenience macros for common log operations
#[macro_export]
macro_rules! log_user_action {
    ($logger:expr, $user_id:expr, $resource_type:expr, $action:expr, $message:expr) => {
        $logger.log_event().await
            .event_type(EventType::UserAction)
            .actor(Actor {
                actor_type: ActorType::User,
                id: $user_id.to_string(),
                name: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            })
            .resource(Resource {
                resource_type: $resource_type,
                id: None,
                name: None,
                path: None,
                attributes: std::collections::HashMap::new(),
            })
            .action($action)
            .message($message.to_string())
            .submit().await
    };
}

#[macro_export]
macro_rules! log_security_alert {
    ($logger:expr, $message:expr) => {
        $logger.log_event().await
            .event_type(EventType::SecurityAlert)
            .severity(Severity::Critical)
            .actor(Actor {
                actor_type: ActorType::System,
                id: "security_monitor".to_string(),
                name: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            })
            .resource(Resource {
                resource_type: ResourceType::Log,
                id: None,
                name: None,
                path: None,
                attributes: std::collections::HashMap::new(),
            })
            .action(Action::Create)
            .message($message.to_string())
            .submit().await
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActorType, ResourceType};

    #[tokio::test]
    async fn test_logger_creation() {
        let logger = AuditLogger::in_memory("test_chain".to_string()).await.unwrap();
        let stats = logger.get_stats().await;
        
        assert_eq!(stats.chain_id, "test_chain");
        assert_eq!(stats.total_entries, 0);
        assert!(stats.can_sign);
    }

    #[tokio::test]
    async fn test_log_entry_builder() {
        let logger = AuditLogger::in_memory("test_chain".to_string()).await.unwrap();
        
        let actor = Actor {
            actor_type: ActorType::User,
            id: "test_user".to_string(),
            name: Some("Test User".to_string()),
            session_id: None,
            ip_address: None,
            user_agent: None,
        };

        let resource = Resource {
            resource_type: ResourceType::Vault,
            id: Some("vault123".to_string()),
            name: None,
            path: None,
            attributes: std::collections::HashMap::new(),
        };

        logger.log_event().await
            .event_type(EventType::DataAccess)
            .severity(Severity::Info)
            .actor(actor)
            .resource(resource)
            .action(Action::Read)
            .outcome(Outcome::Success)
            .message("User accessed vault".to_string())
            .context("ip".to_string(), "192.168.1.100".to_string())
            .submit().await.unwrap();

        // Flush to ensure processing
        logger.flush().await.unwrap();

        let stats = logger.get_stats().await;
        assert_eq!(stats.total_entries, 1);
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let mut config = LoggerConfig::default();
        config.batch_size = 3; // Small batch for testing
        
        let logger = AuditLogger::new(":memory:", "test_chain".to_string(), config).await.unwrap();
        
        // Log multiple entries
        for i in 0..5 {
            let actor = Actor {
                actor_type: ActorType::User,
                id: format!("user{}", i),
                name: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            };

            let resource = Resource {
                resource_type: ResourceType::Log,
                id: None,
                name: None,
                path: None,
                attributes: std::collections::HashMap::new(),
            };

            logger.log_event().await
                .actor(actor)
                .resource(resource)
                .message(format!("Entry {}", i))
                .submit().await.unwrap();
        }

        // Flush to ensure all entries are processed
        logger.flush().await.unwrap();

        let stats = logger.get_stats().await;
        assert_eq!(stats.total_entries, 5);
        assert!(stats.total_batches > 0);
    }

    #[tokio::test]
    async fn test_integrity_verification() {
        let logger = AuditLogger::in_memory("test_chain".to_string()).await.unwrap();
        
        // Log some entries
        for i in 0..3 {
            let actor = Actor {
                actor_type: ActorType::System,
                id: "system".to_string(),
                name: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            };

            let resource = Resource {
                resource_type: ResourceType::Log,
                id: None,
                name: None,
                path: None,
                attributes: std::collections::HashMap::new(),
            };

            logger.log_event().await
                .actor(actor)
                .resource(resource)
                .message(format!("System entry {}", i))
                .submit().await.unwrap();
        }

        logger.flush().await.unwrap();

        let verification = logger.verify_integrity().await.unwrap();
        assert!(verification.is_valid);
        assert_eq!(verification.verified_entries, 3);
        assert!(verification.broken_links.is_empty());
    }
}
