use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

/// Audit log entry with comprehensive event information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub sequence_number: u64,
    pub event_type: EventType,
    pub severity: Severity,
    pub actor: Actor,
    pub resource: Resource,
    pub action: Action,
    pub outcome: Outcome,
    pub details: EventDetails,
    pub context: HashMap<String, String>,
    pub hash: String,
    pub previous_hash: Option<String>,
    pub signature: Option<String>,
}

/// Types of events that can be logged
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    SystemAccess,
    PolicyViolation,
    SecurityAlert,
    ConfigChange,
    UserAction,
    SystemEvent,
    NetworkAccess,
    FileOperation,
    CryptoOperation,
    AuditEvent,
}

/// Event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

/// Actor performing the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub actor_type: ActorType,
    pub id: String,
    pub name: Option<String>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Types of actors
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActorType {
    User,
    System,
    Service,
    Admin,
    Anonymous,
}

/// Resource being accessed or modified
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub resource_type: ResourceType,
    pub id: Option<String>,
    pub name: Option<String>,
    pub path: Option<String>,
    pub attributes: HashMap<String, String>,
}

/// Types of resources
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Vault,
    Secret,
    Policy,
    Terminal,
    SshConnection,
    File,
    Directory,
    Network,
    Configuration,
    Theme,
    User,
    Session,
    Log,
}

/// Action performed on the resource
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
    Execute,
    Connect,
    Disconnect,
    Login,
    Logout,
    Unlock,
    Lock,
    Export,
    Import,
    Copy,
    Move,
    Search,
    Query,
    Verify,
    Sign,
    Encrypt,
    Decrypt,
    Backup,
    Restore,
}

/// Outcome of the action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Outcome {
    Success,
    Failure,
    Partial,
    Denied,
    Error,
}

/// Detailed event information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDetails {
    pub message: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub duration_ms: Option<u64>,
    pub bytes_transferred: Option<u64>,
    pub policy_rule_id: Option<String>,
    pub justification: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(
        sequence_number: u64,
        event_type: EventType,
        severity: Severity,
        actor: Actor,
        resource: Resource,
        action: Action,
        outcome: Outcome,
        message: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            sequence_number,
            event_type,
            severity,
            actor,
            resource,
            action,
            outcome,
            details: EventDetails {
                message,
                error_code: None,
                error_message: None,
                duration_ms: None,
                bytes_transferred: None,
                policy_rule_id: None,
                justification: None,
                metadata: HashMap::new(),
            },
            context: HashMap::new(),
            hash: String::new(), // Will be calculated
            previous_hash: None,
            signature: None,
        }
    }

    /// Add context information
    pub fn with_context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }

    /// Add multiple context entries
    pub fn with_context_map(mut self, context: HashMap<String, String>) -> Self {
        self.context.extend(context);
        self
    }

    /// Set error information
    pub fn with_error(mut self, error_code: String, error_message: String) -> Self {
        self.details.error_code = Some(error_code);
        self.details.error_message = Some(error_message);
        self
    }

    /// Set duration
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.details.duration_ms = Some(duration_ms);
        self
    }

    /// Set bytes transferred
    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.details.bytes_transferred = Some(bytes);
        self
    }

    /// Set policy rule ID
    pub fn with_policy_rule(mut self, rule_id: String) -> Self {
        self.details.policy_rule_id = Some(rule_id);
        self
    }

    /// Set justification
    pub fn with_justification(mut self, justification: String) -> Self {
        self.details.justification = Some(justification);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.details.metadata.insert(key, value);
        self
    }

    /// Calculate hash for this entry (excluding hash and signature fields)
    pub fn calculate_hash(&self) -> crate::Result<String> {
        use sha3::{Digest, Sha3_256};
        
        // Create a copy without hash and signature for hashing
        let mut entry_for_hash = self.clone();
        entry_for_hash.hash = String::new();
        entry_for_hash.signature = None;
        
        let json = serde_json::to_string(&entry_for_hash)?;
        let mut hasher = Sha3_256::new();
        hasher.update(json.as_bytes());
        let result = hasher.finalize();
        
        Ok(hex::encode(result))
    }

    /// Set the hash for this entry
    pub fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    /// Set the previous hash for chain linking
    pub fn set_previous_hash(&mut self, previous_hash: Option<String>) {
        self.previous_hash = previous_hash;
    }

    /// Set digital signature
    pub fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }

    /// Verify the hash of this entry
    pub fn verify_hash(&self) -> crate::Result<bool> {
        let calculated_hash = self.calculate_hash()?;
        Ok(calculated_hash == self.hash)
    }

    /// Check if this entry is critical (requires immediate attention)
    pub fn is_critical(&self) -> bool {
        matches!(self.severity, Severity::Critical) ||
        matches!(self.event_type, EventType::SecurityAlert | EventType::PolicyViolation) ||
        matches!(self.outcome, Outcome::Denied | Outcome::Error)
    }

    /// Get a human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "{} {} {} on {} by {} - {}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            self.severity.to_string().to_uppercase(),
            self.action.to_string().to_uppercase(),
            self.resource.resource_type.to_string().to_lowercase(),
            self.actor.id,
            self.details.message
        )
    }

    /// Convert to compact format for storage
    pub fn to_compact(&self) -> CompactLogEntry {
        CompactLogEntry {
            id: self.id,
            timestamp: self.timestamp,
            sequence_number: self.sequence_number,
            event_type: self.event_type.clone(),
            severity: self.severity.clone(),
            actor_id: self.actor.id.clone(),
            resource_type: self.resource.resource_type.clone(),
            action: self.action.clone(),
            outcome: self.outcome.clone(),
            message: self.details.message.clone(),
            hash: self.hash.clone(),
            previous_hash: self.previous_hash.clone(),
        }
    }
}

/// Compact log entry for efficient storage and transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub sequence_number: u64,
    pub event_type: EventType,
    pub severity: Severity,
    pub actor_id: String,
    pub resource_type: ResourceType,
    pub action: Action,
    pub outcome: Outcome,
    pub message: String,
    pub hash: String,
    pub previous_hash: Option<String>,
}

/// Builder for creating log entries
pub struct LogEntryBuilder {
    sequence_number: u64,
    event_type: EventType,
    severity: Severity,
    actor: Option<Actor>,
    resource: Option<Resource>,
    action: Action,
    outcome: Outcome,
    message: String,
    context: HashMap<String, String>,
    details: EventDetails,
}

impl LogEntryBuilder {
    pub fn new(sequence_number: u64) -> Self {
        Self {
            sequence_number,
            event_type: EventType::UserAction,
            severity: Severity::Info,
            actor: None,
            resource: None,
            action: Action::Read,
            outcome: Outcome::Success,
            message: String::new(),
            context: HashMap::new(),
            details: EventDetails {
                message: String::new(),
                error_code: None,
                error_message: None,
                duration_ms: None,
                bytes_transferred: None,
                policy_rule_id: None,
                justification: None,
                metadata: HashMap::new(),
            },
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
        self.message = message.clone();
        self.details.message = message;
        self
    }

    pub fn context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }

    pub fn error(mut self, code: String, message: String) -> Self {
        self.details.error_code = Some(code);
        self.details.error_message = Some(message);
        self
    }

    pub fn duration(mut self, duration_ms: u64) -> Self {
        self.details.duration_ms = Some(duration_ms);
        self
    }

    pub fn build(self) -> crate::Result<LogEntry> {
        let actor = self.actor.ok_or_else(|| crate::LogError::InvalidEntry("Actor is required".to_string()))?;
        let resource = self.resource.ok_or_else(|| crate::LogError::InvalidEntry("Resource is required".to_string()))?;

        let mut entry = LogEntry::new(
            self.sequence_number,
            self.event_type,
            self.severity,
            actor,
            resource,
            self.action,
            self.outcome,
            self.message,
        );

        entry.context = self.context;
        entry.details = self.details;

        Ok(entry)
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Debug => write!(f, "DEBUG"),
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Error => write!(f, "ERROR"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::Authentication => write!(f, "AUTH"),
            EventType::Authorization => write!(f, "AUTHZ"),
            EventType::DataAccess => write!(f, "DATA_ACCESS"),
            EventType::DataModification => write!(f, "DATA_MOD"),
            EventType::SystemAccess => write!(f, "SYS_ACCESS"),
            EventType::PolicyViolation => write!(f, "POLICY_VIOLATION"),
            EventType::SecurityAlert => write!(f, "SECURITY_ALERT"),
            EventType::ConfigChange => write!(f, "CONFIG_CHANGE"),
            EventType::UserAction => write!(f, "USER_ACTION"),
            EventType::SystemEvent => write!(f, "SYSTEM_EVENT"),
            EventType::NetworkAccess => write!(f, "NETWORK_ACCESS"),
            EventType::FileOperation => write!(f, "FILE_OP"),
            EventType::CryptoOperation => write!(f, "CRYPTO_OP"),
            EventType::AuditEvent => write!(f, "AUDIT"),
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Create => write!(f, "CREATE"),
            Action::Read => write!(f, "READ"),
            Action::Update => write!(f, "UPDATE"),
            Action::Delete => write!(f, "DELETE"),
            Action::Execute => write!(f, "EXECUTE"),
            Action::Connect => write!(f, "CONNECT"),
            Action::Disconnect => write!(f, "DISCONNECT"),
            Action::Login => write!(f, "LOGIN"),
            Action::Logout => write!(f, "LOGOUT"),
            Action::Unlock => write!(f, "UNLOCK"),
            Action::Lock => write!(f, "LOCK"),
            Action::Export => write!(f, "EXPORT"),
            Action::Import => write!(f, "IMPORT"),
            Action::Copy => write!(f, "COPY"),
            Action::Move => write!(f, "MOVE"),
            Action::Search => write!(f, "SEARCH"),
            Action::Query => write!(f, "QUERY"),
            Action::Verify => write!(f, "VERIFY"),
            Action::Sign => write!(f, "SIGN"),
            Action::Encrypt => write!(f, "ENCRYPT"),
            Action::Decrypt => write!(f, "DECRYPT"),
            Action::Backup => write!(f, "BACKUP"),
            Action::Restore => write!(f, "RESTORE"),
        }
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Vault => write!(f, "vault"),
            ResourceType::Secret => write!(f, "secret"),
            ResourceType::Policy => write!(f, "policy"),
            ResourceType::Terminal => write!(f, "terminal"),
            ResourceType::SshConnection => write!(f, "ssh"),
            ResourceType::File => write!(f, "file"),
            ResourceType::Directory => write!(f, "directory"),
            ResourceType::Network => write!(f, "network"),
            ResourceType::Configuration => write!(f, "config"),
            ResourceType::Theme => write!(f, "theme"),
            ResourceType::User => write!(f, "user"),
            ResourceType::Session => write!(f, "session"),
            ResourceType::Log => write!(f, "log"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let actor = Actor {
            actor_type: ActorType::User,
            id: "user123".to_string(),
            name: Some("Alice".to_string()),
            session_id: Some("sess456".to_string()),
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: None,
        };

        let resource = Resource {
            resource_type: ResourceType::Secret,
            id: Some("secret789".to_string()),
            name: Some("API Key".to_string()),
            path: None,
            attributes: HashMap::new(),
        };

        let entry = LogEntry::new(
            1,
            EventType::DataAccess,
            Severity::Info,
            actor,
            resource,
            Action::Read,
            Outcome::Success,
            "User accessed API key".to_string(),
        );

        assert_eq!(entry.sequence_number, 1);
        assert_eq!(entry.event_type, EventType::DataAccess);
        assert_eq!(entry.severity, Severity::Info);
        assert_eq!(entry.action, Action::Read);
        assert_eq!(entry.outcome, Outcome::Success);
        assert!(!entry.is_critical());
    }

    #[test]
    fn test_log_entry_builder() {
        let actor = Actor {
            actor_type: ActorType::User,
            id: "user123".to_string(),
            name: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
        };

        let resource = Resource {
            resource_type: ResourceType::Vault,
            id: None,
            name: None,
            path: None,
            attributes: HashMap::new(),
        };

        let entry = LogEntryBuilder::new(1)
            .event_type(EventType::Authentication)
            .severity(Severity::Warning)
            .actor(actor)
            .resource(resource)
            .action(Action::Login)
            .outcome(Outcome::Failure)
            .message("Failed login attempt".to_string())
            .context("ip".to_string(), "192.168.1.100".to_string())
            .error("AUTH001".to_string(), "Invalid credentials".to_string())
            .build()
            .unwrap();

        assert_eq!(entry.event_type, EventType::Authentication);
        assert_eq!(entry.severity, Severity::Warning);
        assert_eq!(entry.context.get("ip"), Some(&"192.168.1.100".to_string()));
        assert_eq!(entry.details.error_code, Some("AUTH001".to_string()));
    }

    #[test]
    fn test_hash_calculation() {
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
            attributes: HashMap::new(),
        };

        let mut entry = LogEntry::new(
            1,
            EventType::AuditEvent,
            Severity::Info,
            actor,
            resource,
            Action::Create,
            Outcome::Success,
            "Log entry created".to_string(),
        );

        let hash = entry.calculate_hash().unwrap();
        entry.set_hash(hash.clone());

        assert!(!hash.is_empty());
        assert_eq!(entry.hash, hash);
        assert!(entry.verify_hash().unwrap());
    }

    #[test]
    fn test_critical_detection() {
        let actor = Actor {
            actor_type: ActorType::User,
            id: "user123".to_string(),
            name: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
        };

        let resource = Resource {
            resource_type: ResourceType::Vault,
            id: None,
            name: None,
            path: None,
            attributes: HashMap::new(),
        };

        // Critical severity
        let critical_entry = LogEntry::new(
            1,
            EventType::UserAction,
            Severity::Critical,
            actor.clone(),
            resource.clone(),
            Action::Read,
            Outcome::Success,
            "Critical event".to_string(),
        );
        assert!(critical_entry.is_critical());

        // Security alert
        let alert_entry = LogEntry::new(
            2,
            EventType::SecurityAlert,
            Severity::Warning,
            actor.clone(),
            resource.clone(),
            Action::Read,
            Outcome::Success,
            "Security alert".to_string(),
        );
        assert!(alert_entry.is_critical());

        // Denied outcome
        let denied_entry = LogEntry::new(
            3,
            EventType::UserAction,
            Severity::Info,
            actor,
            resource,
            Action::Read,
            Outcome::Denied,
            "Access denied".to_string(),
        );
        assert!(denied_entry.is_critical());
    }
}
