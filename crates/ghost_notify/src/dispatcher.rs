use crate::{AlertMeta, NotificationAction, NotificationResult, NotificationError};
use tokio::sync::mpsc;
use tracing::{info, error, warn};

/// Handles dispatching notifications to various destinations
pub struct NotificationDispatcher {
    toast_sender: Option<mpsc::UnboundedSender<AlertMeta>>,
    webhook_client: reqwest::Client,
}

impl NotificationDispatcher {
    pub fn new() -> Self {
        Self {
            toast_sender: None,
            webhook_client: reqwest::Client::new(),
        }
    }

    /// Set the toast notification sender (for UI integration)
    pub fn set_toast_sender(&mut self, sender: mpsc::UnboundedSender<AlertMeta>) {
        self.toast_sender = Some(sender);
    }

    /// Dispatch an alert according to its configured actions
    pub async fn dispatch(&self, alert: &AlertMeta, actions: &[NotificationAction]) -> NotificationResult<()> {
        for action in actions {
            if let Err(e) = self.dispatch_single(alert, action).await {
                error!("Failed to dispatch alert {} via {:?}: {}", alert.id, action, e);
            }
        }
        Ok(())
    }

    async fn dispatch_single(&self, alert: &AlertMeta, action: &NotificationAction) -> NotificationResult<()> {
        match action {
            NotificationAction::Toast => {
                self.dispatch_toast(alert).await
            }
            NotificationAction::Log => {
                self.dispatch_log(alert).await
            }
            NotificationAction::Email(address) => {
                self.dispatch_email(alert, address).await
            }
            NotificationAction::Webhook(url) => {
                self.dispatch_webhook(alert, url).await
            }
            NotificationAction::Policy(policy_id) => {
                self.dispatch_policy(alert, policy_id).await
            }
        }
    }

    async fn dispatch_toast(&self, alert: &AlertMeta) -> NotificationResult<()> {
        if let Some(sender) = &self.toast_sender {
            sender.send(alert.clone())
                .map_err(|_| NotificationError::StorageError("Failed to send toast notification".to_string()))?;
            info!("Toast notification sent for alert: {}", alert.id);
        } else {
            warn!("Toast sender not configured, skipping toast notification for alert: {}", alert.id);
        }
        Ok(())
    }

    async fn dispatch_log(&self, alert: &AlertMeta) -> NotificationResult<()> {
        // This is handled by the NotificationEngine itself
        info!("Log notification for alert: {} - {}", alert.id, alert.title);
        Ok(())
    }

    async fn dispatch_email(&self, alert: &AlertMeta, _address: &str) -> NotificationResult<()> {
        // Email implementation would go here
        // For now, just log that we would send an email
        info!("Would send email notification for alert: {} to {}", alert.id, _address);
        Ok(())
    }

    async fn dispatch_webhook(&self, alert: &AlertMeta, url: &str) -> NotificationResult<()> {
        let payload = serde_json::json!({
            "alert": alert,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "ghostshell"
        });

        match self.webhook_client
            .post(url)
            .json(&payload)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Webhook notification sent successfully for alert: {}", alert.id);
                } else {
                    error!("Webhook returned error status {} for alert: {}", response.status(), alert.id);
                }
            }
            Err(e) => {
                error!("Failed to send webhook notification for alert {}: {}", alert.id, e);
                return Err(NotificationError::StorageError(format!("Webhook failed: {}", e)));
            }
        }

        Ok(())
    }

    async fn dispatch_policy(&self, alert: &AlertMeta, policy_id: &str) -> NotificationResult<()> {
        // Policy action implementation would go here
        // This could trigger policy enforcement, create incidents, etc.
        info!("Would trigger policy {} for alert: {}", policy_id, alert.id);
        Ok(())
    }
}

impl Default for NotificationDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Toast notification data for UI
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToastNotification {
    pub id: String,
    pub title: String,
    pub message: String,
    pub severity: crate::AlertSeverity,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub auto_dismiss: bool,
    pub dismiss_after_ms: Option<u64>,
    pub actions: Vec<ToastAction>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToastAction {
    pub label: String,
    pub action: String,
    pub style: ToastActionStyle,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ToastActionStyle {
    Primary,
    Secondary,
    Danger,
}

impl From<&AlertMeta> for ToastNotification {
    fn from(alert: &AlertMeta) -> Self {
        let dismiss_after_ms = match alert.severity {
            crate::AlertSeverity::Info => Some(5000),      // 5 seconds
            crate::AlertSeverity::Warning => Some(15000),  // 15 seconds
            crate::AlertSeverity::Critical => None,        // Persistent until acknowledged
        };

        let mut actions = vec![
            ToastAction {
                label: "Acknowledge".to_string(),
                action: format!("acknowledge:{}", alert.id),
                style: ToastActionStyle::Primary,
            }
        ];

        // Add context-specific actions
        match alert.source {
            crate::AlertSource::Policy => {
                actions.push(ToastAction {
                    label: "View Policy".to_string(),
                    action: format!("navigate:policy:{}", alert.context.get("policy_id").unwrap_or(&"".to_string())),
                    style: ToastActionStyle::Secondary,
                });
            }
            crate::AlertSource::Vault => {
                actions.push(ToastAction {
                    label: "Open Vault".to_string(),
                    action: "navigate:vault".to_string(),
                    style: ToastActionStyle::Secondary,
                });
            }
            crate::AlertSource::VPN => {
                actions.push(ToastAction {
                    label: "Check VPN".to_string(),
                    action: "navigate:vpn".to_string(),
                    style: ToastActionStyle::Secondary,
                });
            }
            crate::AlertSource::SSH => {
                actions.push(ToastAction {
                    label: "SSH Manager".to_string(),
                    action: "navigate:ssh".to_string(),
                    style: ToastActionStyle::Secondary,
                });
            }
            _ => {}
        }

        Self {
            id: alert.id.clone(),
            title: alert.title.clone(),
            message: alert.message.clone(),
            severity: alert.severity.clone(),
            timestamp: alert.timestamp,
            auto_dismiss: dismiss_after_ms.is_some(),
            dismiss_after_ms,
            actions,
        }
    }
}
