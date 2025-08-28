use sqlx::{SqlitePool, Row};
use serde_json;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::{
    LogEntry, CompactLogEntry, LogBatch, ChainMetadata, ChainCheckpoint,
    EventType, Severity, ResourceType, Action, Outcome,
    LogError, Result,
};

/// SQLite-based storage backend for audit logs
pub struct LogStorage {
    pool: SqlitePool,
}

impl LogStorage {
    /// Create new storage instance
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;
        let storage = Self { pool };
        storage.initialize().await?;
        Ok(storage)
    }

    /// Create in-memory storage for testing
    pub async fn in_memory() -> Result<Self> {
        Self::new(":memory:").await
    }

    /// Initialize database schema
    async fn initialize(&self) -> Result<()> {
        // Create log entries table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS log_entries (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                sequence_number INTEGER NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_session_id TEXT,
                actor_ip TEXT,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                resource_name TEXT,
                resource_path TEXT,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                message TEXT NOT NULL,
                error_code TEXT,
                error_message TEXT,
                duration_ms INTEGER,
                bytes_transferred INTEGER,
                policy_rule_id TEXT,
                justification TEXT,
                context TEXT NOT NULL, -- JSON
                metadata TEXT NOT NULL, -- JSON
                hash TEXT NOT NULL,
                previous_hash TEXT,
                signature TEXT
            )
        "#).execute(&self.pool).await?;

        // Create batches table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS log_batches (
                batch_id TEXT PRIMARY KEY,
                sequence_start INTEGER NOT NULL,
                sequence_end INTEGER NOT NULL,
                batch_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                entry_count INTEGER NOT NULL
            )
        "#).execute(&self.pool).await?;

        // Create chain metadata table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS chain_metadata (
                chain_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                last_sequence INTEGER NOT NULL DEFAULT 0,
                last_hash TEXT,
                total_entries INTEGER NOT NULL DEFAULT 0,
                verification_key TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        "#).execute(&self.pool).await?;

        // Create checkpoints table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS chain_checkpoints (
                id TEXT PRIMARY KEY,
                chain_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                hash TEXT NOT NULL,
                signature TEXT,
                timestamp TEXT NOT NULL,
                metadata TEXT NOT NULL, -- JSON
                FOREIGN KEY (chain_id) REFERENCES chain_metadata(chain_id)
            )
        "#).execute(&self.pool).await?;

        // Create indexes for better performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_log_entries_sequence ON log_entries(sequence_number)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_log_entries_event_type ON log_entries(event_type)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_log_entries_severity ON log_entries(severity)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_log_entries_actor ON log_entries(actor_id)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_log_entries_resource ON log_entries(resource_type, resource_id)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_log_batches_sequence ON log_batches(sequence_start, sequence_end)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_checkpoints_chain ON chain_checkpoints(chain_id, sequence_number)")
            .execute(&self.pool).await?;

        Ok(())
    }

    /// Store a log entry
    pub async fn store_entry(&self, entry: &LogEntry) -> Result<()> {
        let context_json = serde_json::to_string(&entry.context)?;
        let metadata_json = serde_json::to_string(&entry.details.metadata)?;

        sqlx::query(r#"
            INSERT INTO log_entries (
                id, timestamp, sequence_number, event_type, severity,
                actor_id, actor_type, actor_session_id, actor_ip,
                resource_type, resource_id, resource_name, resource_path,
                action, outcome, message, error_code, error_message,
                duration_ms, bytes_transferred, policy_rule_id, justification,
                context, metadata, hash, previous_hash, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(entry.id.to_string())
        .bind(entry.timestamp.to_rfc3339())
        .bind(entry.sequence_number as i64)
        .bind(serde_json::to_string(&entry.event_type)?)
        .bind(serde_json::to_string(&entry.severity)?)
        .bind(&entry.actor.id)
        .bind(serde_json::to_string(&entry.actor.actor_type)?)
        .bind(&entry.actor.session_id)
        .bind(&entry.actor.ip_address)
        .bind(serde_json::to_string(&entry.resource.resource_type)?)
        .bind(&entry.resource.id)
        .bind(&entry.resource.name)
        .bind(&entry.resource.path)
        .bind(serde_json::to_string(&entry.action)?)
        .bind(serde_json::to_string(&entry.outcome)?)
        .bind(&entry.details.message)
        .bind(&entry.details.error_code)
        .bind(&entry.details.error_message)
        .bind(entry.details.duration_ms.map(|d| d as i64))
        .bind(entry.details.bytes_transferred.map(|b| b as i64))
        .bind(&entry.details.policy_rule_id)
        .bind(&entry.details.justification)
        .bind(context_json)
        .bind(metadata_json)
        .bind(&entry.hash)
        .bind(&entry.previous_hash)
        .bind(&entry.signature)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a log entry by ID
    pub async fn get_entry(&self, id: &Uuid) -> Result<Option<LogEntry>> {
        let row = sqlx::query(r#"
            SELECT * FROM log_entries WHERE id = ?
        "#)
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(self.row_to_entry(row)?))
        } else {
            Ok(None)
        }
    }

    /// Get entries by sequence range
    pub async fn get_entries_by_sequence(&self, start: u64, end: u64) -> Result<Vec<LogEntry>> {
        let rows = sqlx::query(r#"
            SELECT * FROM log_entries 
            WHERE sequence_number >= ? AND sequence_number <= ?
            ORDER BY sequence_number ASC
        "#)
        .bind(start as i64)
        .bind(end as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(self.row_to_entry(row)?);
        }

        Ok(entries)
    }

    /// Get entries by time range
    pub async fn get_entries_by_time(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<CompactLogEntry>> {
        let rows = sqlx::query(r#"
            SELECT id, timestamp, sequence_number, event_type, severity,
                   actor_id, resource_type, action, outcome, message, hash, previous_hash
            FROM log_entries 
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
        "#)
        .bind(start.to_rfc3339())
        .bind(end.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(self.row_to_compact_entry(row)?);
        }

        Ok(entries)
    }

    /// Search entries with filters
    pub async fn search_entries(&self, filter: &LogSearchFilter) -> Result<Vec<CompactLogEntry>> {
        let mut query = "SELECT id, timestamp, sequence_number, event_type, severity, actor_id, resource_type, action, outcome, message, hash, previous_hash FROM log_entries WHERE 1=1".to_string();
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(ref event_type) = filter.event_type {
            query.push_str(" AND event_type = ?");
            bind_values.push(serde_json::to_string(event_type)?);
        }

        if let Some(ref severity) = filter.severity {
            query.push_str(" AND severity = ?");
            bind_values.push(serde_json::to_string(severity)?);
        }

        if let Some(ref actor_id) = filter.actor_id {
            query.push_str(" AND actor_id = ?");
            bind_values.push(actor_id.clone());
        }

        if let Some(ref resource_type) = filter.resource_type {
            query.push_str(" AND resource_type = ?");
            bind_values.push(serde_json::to_string(resource_type)?);
        }

        if let Some(ref action) = filter.action {
            query.push_str(" AND action = ?");
            bind_values.push(serde_json::to_string(action)?);
        }

        if let Some(ref outcome) = filter.outcome {
            query.push_str(" AND outcome = ?");
            bind_values.push(serde_json::to_string(outcome)?);
        }

        if let Some(start_time) = filter.start_time {
            query.push_str(" AND timestamp >= ?");
            bind_values.push(start_time.to_rfc3339());
        }

        if let Some(end_time) = filter.end_time {
            query.push_str(" AND timestamp <= ?");
            bind_values.push(end_time.to_rfc3339());
        }

        if let Some(ref message_pattern) = filter.message_pattern {
            query.push_str(" AND message LIKE ?");
            bind_values.push(format!("%{}%", message_pattern));
        }

        query.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = filter.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        if let Some(offset) = filter.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        let mut sqlx_query = sqlx::query(&query);
        for value in bind_values {
            sqlx_query = sqlx_query.bind(value);
        }

        let rows = sqlx_query.fetch_all(&self.pool).await?;
        let mut entries = Vec::new();

        for row in rows {
            entries.push(self.row_to_compact_entry(row)?);
        }

        Ok(entries)
    }

    /// Store a batch
    pub async fn store_batch(&self, batch: &LogBatch) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO log_batches (
                batch_id, sequence_start, sequence_end, batch_hash, signature, timestamp, entry_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(&batch.batch_id)
        .bind(batch.sequence_start as i64)
        .bind(batch.sequence_end as i64)
        .bind(&batch.batch_hash)
        .bind(&batch.signature)
        .bind(batch.timestamp.to_rfc3339())
        .bind(batch.entries.len() as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all batches
    pub async fn get_batches(&self) -> Result<Vec<LogBatch>> {
        let rows = sqlx::query(r#"
            SELECT * FROM log_batches ORDER BY sequence_start ASC
        "#)
        .fetch_all(&self.pool)
        .await?;

        let mut batches = Vec::new();
        for row in rows {
            let batch_id: String = row.try_get("batch_id")?;
            let sequence_start: i64 = row.try_get("sequence_start")?;
            let sequence_end: i64 = row.try_get("sequence_end")?;
            let batch_hash: String = row.try_get("batch_hash")?;
            let signature: String = row.try_get("signature")?;
            let timestamp: String = row.try_get("timestamp")?;
            let timestamp = DateTime::parse_from_rfc3339(&timestamp)?.with_timezone(&Utc);

            // Get entries for this batch
            let entries = self.get_entries_by_sequence(sequence_start as u64, sequence_end as u64).await?;

            batches.push(LogBatch {
                batch_id,
                sequence_start: sequence_start as u64,
                sequence_end: sequence_end as u64,
                entries,
                batch_hash,
                signature,
                timestamp,
            });
        }

        Ok(batches)
    }

    /// Store chain metadata
    pub async fn store_chain_metadata(&self, metadata: &ChainMetadata) -> Result<()> {
        sqlx::query(r#"
            INSERT OR REPLACE INTO chain_metadata (
                chain_id, created_at, last_sequence, last_hash, total_entries, verification_key, algorithm, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(&metadata.chain_id)
        .bind(metadata.created_at.to_rfc3339())
        .bind(metadata.last_sequence as i64)
        .bind(&metadata.last_hash)
        .bind(metadata.total_entries as i64)
        .bind(&metadata.verification_key)
        .bind(&metadata.algorithm)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get chain metadata
    pub async fn get_chain_metadata(&self, chain_id: &str) -> Result<Option<ChainMetadata>> {
        let row = sqlx::query(r#"
            SELECT * FROM chain_metadata WHERE chain_id = ?
        "#)
        .bind(chain_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let created_at: String = row.try_get("created_at")?;
            let created_at = DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc);

            Ok(Some(ChainMetadata {
                chain_id: row.try_get("chain_id")?,
                created_at,
                last_sequence: row.try_get::<i64, _>("last_sequence")? as u64,
                last_hash: row.try_get("last_hash")?,
                total_entries: row.try_get::<i64, _>("total_entries")? as u64,
                verification_key: row.try_get("verification_key")?,
                algorithm: row.try_get("algorithm")?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Store checkpoint
    pub async fn store_checkpoint(&self, checkpoint: &ChainCheckpoint) -> Result<()> {
        let metadata_json = serde_json::to_string(&checkpoint.metadata)?;

        sqlx::query(r#"
            INSERT OR REPLACE INTO chain_checkpoints (
                id, chain_id, sequence_number, hash, signature, timestamp, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&checkpoint.chain_id)
        .bind(checkpoint.sequence as i64)
        .bind(&checkpoint.hash)
        .bind(&checkpoint.signature)
        .bind(checkpoint.timestamp.to_rfc3339())
        .bind(metadata_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get checkpoints for a chain
    pub async fn get_checkpoints(&self, chain_id: &str) -> Result<Vec<ChainCheckpoint>> {
        let rows = sqlx::query(r#"
            SELECT * FROM chain_checkpoints WHERE chain_id = ? ORDER BY sequence_number ASC
        "#)
        .bind(chain_id)
        .fetch_all(&self.pool)
        .await?;

        let mut checkpoints = Vec::new();
        for row in rows {
            let timestamp: String = row.try_get("timestamp")?;
            let timestamp = DateTime::parse_from_rfc3339(&timestamp)?.with_timezone(&Utc);
            let metadata: String = row.try_get("metadata")?;
            let metadata = serde_json::from_str(&metadata)?;

            checkpoints.push(ChainCheckpoint {
                chain_id: row.try_get("chain_id")?,
                sequence: row.try_get::<i64, _>("sequence_number")? as u64,
                hash: row.try_get("hash")?,
                signature: row.try_get("signature")?,
                timestamp,
                metadata,
            });
        }

        Ok(checkpoints)
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> Result<LogStorageStats> {
        let total_entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM log_entries")
            .fetch_one(&self.pool)
            .await?;

        let total_batches: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM log_batches")
            .fetch_one(&self.pool)
            .await?;

        let total_checkpoints: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chain_checkpoints")
            .fetch_one(&self.pool)
            .await?;

        // Get earliest and latest entries
        let earliest: Option<String> = sqlx::query_scalar("SELECT MIN(timestamp) FROM log_entries")
            .fetch_one(&self.pool)
            .await?;

        let latest: Option<String> = sqlx::query_scalar("SELECT MAX(timestamp) FROM log_entries")
            .fetch_one(&self.pool)
            .await?;

        let earliest_entry = earliest.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        let latest_entry = latest.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        // Get severity distribution
        let critical_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM log_entries WHERE severity = ?"
        )
        .bind(serde_json::to_string(&Severity::Critical)?)
        .fetch_one(&self.pool)
        .await?;

        let error_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM log_entries WHERE severity = ?"
        )
        .bind(serde_json::to_string(&Severity::Error)?)
        .fetch_one(&self.pool)
        .await?;

        let warning_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM log_entries WHERE severity = ?"
        )
        .bind(serde_json::to_string(&Severity::Warning)?)
        .fetch_one(&self.pool)
        .await?;

        Ok(LogStorageStats {
            total_entries: total_entries as u64,
            total_batches: total_batches as u64,
            total_checkpoints: total_checkpoints as u64,
            earliest_entry,
            latest_entry,
            critical_entries: critical_count as u64,
            error_entries: error_count as u64,
            warning_entries: warning_count as u64,
        })
    }

    /// Convert database row to LogEntry
    fn row_to_entry(&self, row: sqlx::sqlite::SqliteRow) -> Result<LogEntry> {
        use std::collections::HashMap;
        use crate::{Actor, ActorType, Resource, EventDetails};

        let id: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id).map_err(|e| LogError::InvalidInput(format!("Invalid UUID: {}", e)))?;

        let timestamp: String = row.try_get("timestamp")?;
        let timestamp = DateTime::parse_from_rfc3339(&timestamp)?.with_timezone(&Utc);

        let event_type: String = row.try_get("event_type")?;
        let event_type = serde_json::from_str(&event_type)?;

        let severity: String = row.try_get("severity")?;
        let severity = serde_json::from_str(&severity)?;

        let actor_type: String = row.try_get("actor_type")?;
        let actor_type = serde_json::from_str(&actor_type)?;

        let resource_type: String = row.try_get("resource_type")?;
        let resource_type = serde_json::from_str(&resource_type)?;

        let action: String = row.try_get("action")?;
        let action = serde_json::from_str(&action)?;

        let outcome: String = row.try_get("outcome")?;
        let outcome = serde_json::from_str(&outcome)?;

        let context: String = row.try_get("context")?;
        let context = serde_json::from_str(&context)?;

        let metadata: String = row.try_get("metadata")?;
        let metadata = serde_json::from_str(&metadata)?;

        let actor = Actor {
            actor_type,
            id: row.try_get("actor_id")?,
            name: None, // Not stored in compact format
            session_id: row.try_get("actor_session_id")?,
            ip_address: row.try_get("actor_ip")?,
            user_agent: None, // Not stored in compact format
        };

        let resource = Resource {
            resource_type,
            id: row.try_get("resource_id")?,
            name: row.try_get("resource_name")?,
            path: row.try_get("resource_path")?,
            attributes: HashMap::new(), // Not stored in compact format
        };

        let details = EventDetails {
            message: row.try_get("message")?,
            error_code: row.try_get("error_code")?,
            error_message: row.try_get("error_message")?,
            duration_ms: row.try_get::<Option<i64>, _>("duration_ms")?.map(|d| d as u64),
            bytes_transferred: row.try_get::<Option<i64>, _>("bytes_transferred")?.map(|b| b as u64),
            policy_rule_id: row.try_get("policy_rule_id")?,
            justification: row.try_get("justification")?,
            metadata,
        };

        Ok(LogEntry {
            id,
            timestamp,
            sequence_number: row.try_get::<i64, _>("sequence_number")? as u64,
            event_type,
            severity,
            actor,
            resource,
            action,
            outcome,
            details,
            context,
            hash: row.try_get("hash")?,
            previous_hash: row.try_get("previous_hash")?,
            signature: row.try_get("signature")?,
        })
    }

    /// Convert database row to CompactLogEntry
    fn row_to_compact_entry(&self, row: sqlx::sqlite::SqliteRow) -> Result<CompactLogEntry> {
        let id: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id).map_err(|e| LogError::InvalidInput(format!("Invalid UUID: {}", e)))?;

        let timestamp: String = row.try_get("timestamp")?;
        let timestamp = DateTime::parse_from_rfc3339(&timestamp)?.with_timezone(&Utc);

        let event_type: String = row.try_get("event_type")?;
        let event_type = serde_json::from_str(&event_type)?;

        let severity: String = row.try_get("severity")?;
        let severity = serde_json::from_str(&severity)?;

        let resource_type: String = row.try_get("resource_type")?;
        let resource_type = serde_json::from_str(&resource_type)?;

        let action: String = row.try_get("action")?;
        let action = serde_json::from_str(&action)?;

        let outcome: String = row.try_get("outcome")?;
        let outcome = serde_json::from_str(&outcome)?;

        Ok(CompactLogEntry {
            id,
            timestamp,
            sequence_number: row.try_get::<i64, _>("sequence_number")? as u64,
            event_type,
            severity,
            actor_id: row.try_get("actor_id")?,
            resource_type,
            action,
            outcome,
            message: row.try_get("message")?,
            hash: row.try_get("hash")?,
            previous_hash: row.try_get("previous_hash")?,
        })
    }
}

/// Log search filter
#[derive(Debug, Clone, Default)]
pub struct LogSearchFilter {
    pub event_type: Option<EventType>,
    pub severity: Option<Severity>,
    pub actor_id: Option<String>,
    pub resource_type: Option<ResourceType>,
    pub action: Option<Action>,
    pub outcome: Option<Outcome>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub message_pattern: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Log storage statistics
#[derive(Debug, Clone)]
pub struct LogStorageStats {
    pub total_entries: u64,
    pub total_batches: u64,
    pub total_checkpoints: u64,
    pub earliest_entry: Option<DateTime<Utc>>,
    pub latest_entry: Option<DateTime<Utc>>,
    pub critical_entries: u64,
    pub error_entries: u64,
    pub warning_entries: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Actor, ActorType, Resource, Action, Outcome, EventType, Severity};
    use std::collections::HashMap;

    async fn create_test_storage() -> LogStorage {
        LogStorage::in_memory().await.unwrap()
    }

    fn create_test_entry(sequence: u64) -> LogEntry {
        let actor = Actor {
            actor_type: ActorType::User,
            id: "test_user".to_string(),
            name: Some("Test User".to_string()),
            session_id: Some("session123".to_string()),
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: None,
        };

        let resource = Resource {
            resource_type: ResourceType::Vault,
            id: Some("vault123".to_string()),
            name: Some("Test Vault".to_string()),
            path: None,
            attributes: HashMap::new(),
        };

        LogEntry::new(
            sequence,
            EventType::DataAccess,
            Severity::Info,
            actor,
            resource,
            Action::Read,
            Outcome::Success,
            "Test log entry".to_string(),
        )
    }

    #[tokio::test]
    async fn test_storage_initialization() {
        let storage = create_test_storage().await;
        let stats = storage.get_stats().await.unwrap();
        assert_eq!(stats.total_entries, 0);
    }

    #[tokio::test]
    async fn test_entry_storage_and_retrieval() {
        let storage = create_test_storage().await;
        let mut entry = create_test_entry(1);
        
        // Set hash for storage
        let hash = entry.calculate_hash().unwrap();
        entry.set_hash(hash);

        storage.store_entry(&entry).await.unwrap();

        let retrieved = storage.get_entry(&entry.id).await.unwrap().unwrap();
        assert_eq!(retrieved.id, entry.id);
        assert_eq!(retrieved.sequence_number, entry.sequence_number);
        assert_eq!(retrieved.details.message, entry.details.message);
    }

    #[tokio::test]
    async fn test_search_functionality() {
        let storage = create_test_storage().await;
        
        // Store multiple entries
        for i in 1..=5 {
            let mut entry = create_test_entry(i);
            let hash = entry.calculate_hash().unwrap();
            entry.set_hash(hash);
            storage.store_entry(&entry).await.unwrap();
        }

        let filter = LogSearchFilter {
            event_type: Some(EventType::DataAccess),
            limit: Some(3),
            ..Default::default()
        };

        let results = storage.search_entries(&filter).await.unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|e| e.event_type == EventType::DataAccess));
    }

    #[tokio::test]
    async fn test_chain_metadata_storage() {
        let storage = create_test_storage().await;
        
        let metadata = ChainMetadata {
            chain_id: "test_chain".to_string(),
            created_at: Utc::now(),
            last_sequence: 100,
            last_hash: Some("test_hash".to_string()),
            total_entries: 100,
            verification_key: "test_key".to_string(),
            algorithm: "Dilithium".to_string(),
        };

        storage.store_chain_metadata(&metadata).await.unwrap();

        let retrieved = storage.get_chain_metadata("test_chain").await.unwrap().unwrap();
        assert_eq!(retrieved.chain_id, metadata.chain_id);
        assert_eq!(retrieved.last_sequence, metadata.last_sequence);
        assert_eq!(retrieved.total_entries, metadata.total_entries);
    }
}
