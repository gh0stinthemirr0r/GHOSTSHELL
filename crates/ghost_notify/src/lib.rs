use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub mod engine;
pub mod rules;
pub mod dispatcher;

pub use engine::NotificationEngine;
pub use rules::{AlertRule, AlertRuleBuilder};
pub use dispatcher::NotificationDispatcher;

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "info"),
            AlertSeverity::Warning => write!(f, "warning"),
            AlertSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl AlertSeverity {
    pub fn color(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "#00FFD1",      // Cyan
            AlertSeverity::Warning => "#FFAA00",   // Amber
            AlertSeverity::Critical => "#FF008C",  // Neon red
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            AlertSeverity::Info => 1,
            AlertSeverity::Warning => 2,
            AlertSeverity::Critical => 3,
        }
    }
}

/// Alert source types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSource {
    Policy,
    Vault,
    VPN,
    SSH,
    PCAP,
    Topology,
    System,
    Custom(String),
}

/// Alert metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertMeta {
    pub id: String,
    pub source: AlertSource,
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub context: HashMap<String, String>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub signature: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl AlertMeta {
    pub fn new(
        source: AlertSource,
        severity: AlertSeverity,
        title: String,
        message: String,
    ) -> Self {
        Self {
            id: format!("alert-{}", Uuid::new_v4()),
            source,
            severity,
            title,
            message,
            timestamp: Utc::now(),
            context: HashMap::new(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
            signature: None,
            expires_at: None,
        }
    }

    pub fn with_context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }

    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn acknowledge(&mut self, user: String) {
        self.acknowledged = true;
        self.acknowledged_by = Some(user);
        self.acknowledged_at = Some(Utc::now());
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
}

/// Notification actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationAction {
    Toast,
    Log,
    Email(String),
    Webhook(String),
    Policy(String),
}

/// Filter for querying alerts
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertFilter {
    pub source: Option<AlertSource>,
    pub severity: Option<AlertSeverity>,
    pub acknowledged: Option<bool>,
    pub from_timestamp: Option<DateTime<Utc>>,
    pub to_timestamp: Option<DateTime<Utc>>,
    pub search: Option<String>,
    pub limit: Option<usize>,
}

/// Notification statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationStats {
    pub total_alerts: usize,
    pub unacknowledged_alerts: usize,
    pub critical_alerts: usize,
    pub alerts_by_source: HashMap<String, usize>,
    pub alerts_by_severity: HashMap<String, usize>,
    pub average_acknowledgment_time: Option<f64>, // seconds
}

/// Result type for notification operations
pub type NotificationResult<T> = Result<T, NotificationError>;

/// Notification system errors
#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("Alert not found: {0}")]
    AlertNotFound(String),
    #[error("Invalid rule configuration: {0}")]
    InvalidRule(String),
    #[error("Signature verification failed")]
    SignatureError,
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}
