use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use ghost_notify::{AlertSeverity, AlertSource};

/// Toast notification for real-time display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToastNotification {
    pub id: String,
    pub title: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub source: AlertSource,
    pub timestamp: DateTime<Utc>,
    pub icon: String,
    pub color: String,
    pub glow_color: String,
    pub auto_dismiss: bool,
    pub dismiss_after_ms: Option<u64>,
    pub progress_bar: bool,
    pub actions: Vec<ToastAction>,
    pub animation: ToastAnimation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToastAction {
    pub id: String,
    pub label: String,
    pub icon: Option<String>,
    pub command: String,
    pub style: ToastActionStyle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToastActionStyle {
    Primary,
    Secondary,
    Success,
    Warning,
    Danger,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToastAnimation {
    pub enter: String,
    pub exit: String,
    pub duration_ms: u64,
}

impl Default for ToastAnimation {
    fn default() -> Self {
        Self {
            enter: "slideInRight".to_string(),
            exit: "slideOutRight".to_string(),
            duration_ms: 300,
        }
    }
}

/// Alert card for notification center
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCard {
    pub id: String,
    pub title: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub source: AlertSource,
    pub timestamp: DateTime<Utc>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub icon: String,
    pub color: String,
    pub tags: Vec<AlertTag>,
    pub actions: Vec<AlertCardAction>,
    pub expandable: bool,
    pub expanded_content: Option<AlertExpandedContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertTag {
    pub label: String,
    pub color: String,
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCardAction {
    pub id: String,
    pub label: String,
    pub icon: String,
    pub command: String,
    pub style: AlertActionStyle,
    pub requires_confirmation: bool,
    pub confirmation_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertActionStyle {
    Primary,
    Secondary,
    Success,
    Warning,
    Danger,
    Ghost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertExpandedContent {
    pub context: Vec<ContextItem>,
    pub timeline: Vec<TimelineItem>,
    pub related_alerts: Vec<String>,
    pub evidence: Vec<EvidenceItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextItem {
    pub key: String,
    pub value: String,
    pub icon: Option<String>,
    pub copyable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineItem {
    pub timestamp: DateTime<Utc>,
    pub event: String,
    pub description: String,
    pub icon: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    pub name: String,
    pub type_: String,
    pub size: Option<u64>,
    pub hash: Option<String>,
    pub signature: Option<String>,
    pub download_url: Option<String>,
}

/// Notification center sidebar
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationCenter {
    pub alerts: Vec<AlertCard>,
    pub filters: NotificationFilters,
    pub stats: NotificationCenterStats,
    pub config: NotificationCenterConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationFilters {
    pub severity: Option<AlertSeverity>,
    pub source: Option<AlertSource>,
    pub acknowledged: Option<bool>,
    pub search: Option<String>,
    pub date_range: Option<DateRange>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationCenterStats {
    pub total_alerts: usize,
    pub unacknowledged: usize,
    pub critical: usize,
    pub warnings: usize,
    pub info: usize,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationCenterConfig {
    pub auto_refresh: bool,
    pub refresh_interval_ms: u64,
    pub max_alerts: usize,
    pub show_acknowledged: bool,
    pub group_by_source: bool,
    pub compact_view: bool,
}

impl Default for NotificationCenterConfig {
    fn default() -> Self {
        Self {
            auto_refresh: true,
            refresh_interval_ms: 5000,
            max_alerts: 100,
            show_acknowledged: false,
            group_by_source: false,
            compact_view: false,
        }
    }
}

/// Alert rule configuration UI model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleUI {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub source: AlertSource,
    pub event_pattern: String,
    pub severity: AlertSeverity,
    pub conditions: Vec<RuleCondition>,
    pub actions: Vec<RuleAction>,
    pub rate_limit: Option<RateLimit>,
    pub deduplication: Option<DeduplicationConfig>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub last_triggered: Option<DateTime<Utc>>,
    pub trigger_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: String,
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Matches, // Regex
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAction {
    pub type_: RuleActionType,
    pub config: serde_json::Value,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleActionType {
    Toast,
    Log,
    Email,
    Webhook,
    Policy,
    Script,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_alerts: usize,
    pub window_seconds: u64,
    pub current_count: usize,
    pub window_start: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationConfig {
    pub window_seconds: u64,
    pub fields: Vec<String>,
    pub merge_strategy: MergeStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MergeStrategy {
    KeepFirst,
    KeepLast,
    Increment,
    Merge,
}
