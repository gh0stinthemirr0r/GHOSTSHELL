use serde::{Deserialize, Serialize};
use ghost_notify::{AlertMeta, AlertSeverity, AlertSource};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub mod ui_models;
pub mod formatters;

pub use ui_models::*;
pub use formatters::*;

/// UI-specific alert representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UIAlert {
    pub id: String,
    pub title: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub source: AlertSource,
    pub timestamp: DateTime<Utc>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub context: HashMap<String, String>,
    pub icon: String,
    pub color: String,
    pub actions: Vec<UIAlertAction>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UIAlertAction {
    pub id: String,
    pub label: String,
    pub icon: Option<String>,
    pub style: UIActionStyle,
    pub command: String,
    pub requires_confirmation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UIActionStyle {
    Primary,
    Secondary,
    Success,
    Warning,
    Danger,
    Ghost,
}

impl From<AlertMeta> for UIAlert {
    fn from(alert: AlertMeta) -> Self {
        let icon = match alert.source {
            AlertSource::Policy => "shield-exclamation",
            AlertSource::Vault => "key",
            AlertSource::VPN => "network-wired",
            AlertSource::SSH => "terminal",
            AlertSource::PCAP => "network",
            AlertSource::Topology => "diagram-project",
            AlertSource::System => "computer",
            AlertSource::Custom(_) => "bell",
        };

        let color = alert.severity.color();

        let mut actions = vec![
            UIAlertAction {
                id: "acknowledge".to_string(),
                label: "Acknowledge".to_string(),
                icon: Some("check".to_string()),
                style: UIActionStyle::Primary,
                command: format!("alert:acknowledge:{}", alert.id),
                requires_confirmation: false,
            }
        ];

        // Add source-specific actions
        match alert.source {
            AlertSource::Policy => {
                if let Some(policy_id) = alert.context.get("policy_id") {
                    actions.push(UIAlertAction {
                        id: "view_policy".to_string(),
                        label: "View Policy".to_string(),
                        icon: Some("eye".to_string()),
                        style: UIActionStyle::Secondary,
                        command: format!("navigate:policy:{}", policy_id),
                        requires_confirmation: false,
                    });
                }
            }
            AlertSource::Vault => {
                actions.push(UIAlertAction {
                    id: "open_vault".to_string(),
                    label: "Open Vault".to_string(),
                    icon: Some("folder-open".to_string()),
                    style: UIActionStyle::Secondary,
                    command: "navigate:vault".to_string(),
                    requires_confirmation: false,
                });
                
                if alert.context.contains_key("secret_id") {
                    actions.push(UIAlertAction {
                        id: "rotate_secret".to_string(),
                        label: "Rotate Secret".to_string(),
                        icon: Some("refresh".to_string()),
                        style: UIActionStyle::Warning,
                        command: format!("vault:rotate:{}", alert.context.get("secret_id").unwrap()),
                        requires_confirmation: true,
                    });
                }
            }
            AlertSource::VPN => {
                actions.push(UIAlertAction {
                    id: "check_vpn".to_string(),
                    label: "Check VPN Status".to_string(),
                    icon: Some("network-wired".to_string()),
                    style: UIActionStyle::Secondary,
                    command: "navigate:vpn".to_string(),
                    requires_confirmation: false,
                });
            }
            AlertSource::SSH => {
                actions.push(UIAlertAction {
                    id: "ssh_manager".to_string(),
                    label: "SSH Manager".to_string(),
                    icon: Some("terminal".to_string()),
                    style: UIActionStyle::Secondary,
                    command: "navigate:ssh".to_string(),
                    requires_confirmation: false,
                });
            }
            _ => {}
        }

        // Generate tags
        let mut tags = vec![
            format!("{:?}", alert.source).to_lowercase(),
            format!("{:?}", alert.severity).to_lowercase(),
        ];

        if let Some(host) = alert.context.get("host") {
            tags.push(format!("host:{}", host));
        }
        if let Some(user) = alert.context.get("user") {
            tags.push(format!("user:{}", user));
        }

        Self {
            id: alert.id,
            title: alert.title,
            message: alert.message,
            severity: alert.severity,
            source: alert.source,
            timestamp: alert.timestamp,
            acknowledged: alert.acknowledged,
            acknowledged_by: alert.acknowledged_by,
            acknowledged_at: alert.acknowledged_at,
            context: alert.context,
            icon: icon.to_string(),
            color: color.to_string(),
            actions,
            tags,
        }
    }
}

/// Alert list view configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertListConfig {
    pub show_acknowledged: bool,
    pub severity_filter: Option<AlertSeverity>,
    pub source_filter: Option<AlertSource>,
    pub search_query: Option<String>,
    pub sort_by: AlertSortBy,
    pub sort_order: SortOrder,
    pub page_size: usize,
    pub auto_refresh: bool,
    pub refresh_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSortBy {
    Timestamp,
    Severity,
    Source,
    Title,
    Acknowledged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortOrder {
    Ascending,
    Descending,
}

impl Default for AlertListConfig {
    fn default() -> Self {
        Self {
            show_acknowledged: false,
            severity_filter: None,
            source_filter: None,
            search_query: None,
            sort_by: AlertSortBy::Timestamp,
            sort_order: SortOrder::Descending,
            page_size: 50,
            auto_refresh: true,
            refresh_interval_ms: 5000, // 5 seconds
        }
    }
}

/// Alert statistics for dashboard display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDashboardStats {
    pub total_alerts: usize,
    pub unacknowledged_alerts: usize,
    pub critical_alerts: usize,
    pub warning_alerts: usize,
    pub info_alerts: usize,
    pub alerts_last_hour: usize,
    pub alerts_last_24h: usize,
    pub top_sources: Vec<(String, usize)>,
    pub average_response_time: Option<f64>,
    pub trend_data: Vec<AlertTrendPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertTrendPoint {
    pub timestamp: DateTime<Utc>,
    pub count: usize,
    pub severity_breakdown: HashMap<String, usize>,
}

/// Notification center configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationCenterConfig {
    pub position: NotificationPosition,
    pub max_visible_toasts: usize,
    pub default_toast_duration_ms: u64,
    pub enable_sound: bool,
    pub sound_volume: f32,
    pub enable_desktop_notifications: bool,
    pub theme: NotificationTheme,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationPosition {
    TopRight,
    TopLeft,
    BottomRight,
    BottomLeft,
    TopCenter,
    BottomCenter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTheme {
    pub background_color: String,
    pub text_color: String,
    pub border_color: String,
    pub glow_intensity: f32,
    pub blur_radius: f32,
    pub border_radius: f32,
}

impl Default for NotificationCenterConfig {
    fn default() -> Self {
        Self {
            position: NotificationPosition::TopRight,
            max_visible_toasts: 5,
            default_toast_duration_ms: 5000,
            enable_sound: true,
            sound_volume: 0.7,
            enable_desktop_notifications: false,
            theme: NotificationTheme {
                background_color: "rgba(12, 15, 28, 0.9)".to_string(),
                text_color: "#EAEAEA".to_string(),
                border_color: "#00FFD1".to_string(),
                glow_intensity: 0.6,
                blur_radius: 18.0,
                border_radius: 14.0,
            },
        }
    }
}
