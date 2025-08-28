use crate::{AlertMeta, AlertFilter, NotificationStats, NotificationResult, NotificationError, AlertRule};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use ghost_log::{AuditLogger, LogEntry, Severity, EventType, Actor, ActorType, Resource, Action, Outcome};
use ghost_pq::signatures::{DilithiumSigner, DilithiumPrivateKey, DilithiumVariant};

/// Core notification engine
pub struct NotificationEngine {
    alerts: Arc<RwLock<HashMap<String, AlertMeta>>>,
    rules: Arc<RwLock<HashMap<String, AlertRule>>>,
    logger: Arc<AuditLogger>,
    signer: Arc<DilithiumSigner>,
    private_key: Arc<DilithiumPrivateKey>,
    alert_sender: mpsc::UnboundedSender<AlertMeta>,
    alert_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<AlertMeta>>>>,
}

impl NotificationEngine {
    pub fn new(logger: Arc<AuditLogger>, signer: Arc<DilithiumSigner>) -> NotificationResult<Self> {
        let (alert_sender, alert_receiver) = mpsc::unbounded_channel();
        
        // Generate a private key for signing alerts
        let private_key = Arc::new(DilithiumPrivateKey::from_bytes(vec![0u8; 32], DilithiumVariant::Dilithium3)
            .map_err(|_| NotificationError::SignatureError)?);
        
        Ok(Self {
            alerts: Arc::new(RwLock::new(HashMap::new())),
            rules: Arc::new(RwLock::new(HashMap::new())),
            logger,
            signer,
            private_key,
            alert_sender,
            alert_receiver: Arc::new(RwLock::new(Some(alert_receiver))),
        })
    }

    /// Initialize the notification engine
    pub async fn initialize(&self) -> NotificationResult<()> {
        tracing::debug!("NotificationEngine::initialize() - Entry");
        
        // Load default rules
        tracing::debug!("NotificationEngine::initialize() - About to load default rules");
        self.load_default_rules().await?;
        tracing::debug!("NotificationEngine::initialize() - Default rules loaded");
        
        // Start the alert processing loop
        tracing::debug!("NotificationEngine::initialize() - About to start alert processor");
        self.start_alert_processor().await;
        tracing::debug!("NotificationEngine::initialize() - Alert processor started");
        
        tracing::debug!("NotificationEngine::initialize() - Completed successfully");
        Ok(())
    }

    /// Add a new alert to the system
    pub async fn add_alert(&self, mut alert: AlertMeta) -> NotificationResult<String> {
        // Sign the alert
        let alert_json = serde_json::to_string(&alert)?;
        let signature = self.signer.sign(&self.private_key, alert_json.as_bytes())
            .map_err(|_| NotificationError::SignatureError)?;
        alert.signature = Some(hex::encode(&signature.signature));

        // Store the alert
        let alert_id = alert.id.clone();
        {
            let mut alerts = self.alerts.write().await;
            alerts.insert(alert_id.clone(), alert.clone());
        }

        // Log the alert (simplified for now)
        // TODO: Implement proper logging with sequence numbers
        tracing::info!("Alert created: {:?} - {} (ID: {})", alert.severity, alert.title, alert_id);

        // Send to alert processor
        self.alert_sender.send(alert).map_err(|_| NotificationError::StorageError("Failed to queue alert".to_string()))?;

        Ok(alert_id)
    }

    /// Get alerts with optional filtering
    pub async fn get_alerts(&self, filter: Option<AlertFilter>) -> NotificationResult<Vec<AlertMeta>> {
        let alerts = self.alerts.read().await;
        let mut result: Vec<AlertMeta> = alerts.values().cloned().collect();

        // Apply filters
        if let Some(filter) = filter {
            if let Some(source) = filter.source {
                result.retain(|alert| alert.source == source);
            }
            if let Some(severity) = filter.severity {
                result.retain(|alert| alert.severity == severity);
            }
            if let Some(acknowledged) = filter.acknowledged {
                result.retain(|alert| alert.acknowledged == acknowledged);
            }
            if let Some(from_ts) = filter.from_timestamp {
                result.retain(|alert| alert.timestamp >= from_ts);
            }
            if let Some(to_ts) = filter.to_timestamp {
                result.retain(|alert| alert.timestamp <= to_ts);
            }
            if let Some(search) = filter.search {
                let search_lower = search.to_lowercase();
                result.retain(|alert| {
                    alert.title.to_lowercase().contains(&search_lower) ||
                    alert.message.to_lowercase().contains(&search_lower)
                });
            }
            if let Some(limit) = filter.limit {
                result.truncate(limit);
            }
        }

        // Sort by timestamp (newest first)
        result.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Remove expired alerts
        result.retain(|alert| !alert.is_expired());

        Ok(result)
    }

    /// Acknowledge an alert
    pub async fn acknowledge_alert(&self, alert_id: &str, user: String) -> NotificationResult<()> {
        let mut alerts = self.alerts.write().await;
        
        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.acknowledge(user.clone());
            
            // Log the acknowledgment (simplified for now)
            // TODO: Implement proper logging with sequence numbers
            tracing::info!("Alert acknowledged by {}: {}", user, alert_id);
            
            Ok(())
        } else {
            Err(NotificationError::AlertNotFound(alert_id.to_string()))
        }
    }

    /// Get notification statistics
    pub async fn get_stats(&self) -> NotificationResult<NotificationStats> {
        let alerts = self.alerts.read().await;
        let alert_list: Vec<&AlertMeta> = alerts.values().collect();

        let total_alerts = alert_list.len();
        let unacknowledged_alerts = alert_list.iter().filter(|a| !a.acknowledged).count();
        let critical_alerts = alert_list.iter().filter(|a| matches!(a.severity, crate::AlertSeverity::Critical)).count();

        let mut alerts_by_source = HashMap::new();
        let mut alerts_by_severity = HashMap::new();

        for alert in &alert_list {
            let source_key = format!("{:?}", alert.source);
            *alerts_by_source.entry(source_key).or_insert(0) += 1;
            
            let severity_key = format!("{:?}", alert.severity);
            *alerts_by_severity.entry(severity_key).or_insert(0) += 1;
        }

        // Calculate average acknowledgment time
        let acknowledged_alerts: Vec<&AlertMeta> = alert_list.iter()
            .filter(|a| a.acknowledged && a.acknowledged_at.is_some())
            .cloned()
            .collect();

        let average_acknowledgment_time = if !acknowledged_alerts.is_empty() {
            let total_time: f64 = acknowledged_alerts.iter()
                .map(|a| {
                    let ack_time = a.acknowledged_at.unwrap();
                    (ack_time - a.timestamp).num_seconds() as f64
                })
                .sum();
            Some(total_time / acknowledged_alerts.len() as f64)
        } else {
            None
        };

        Ok(NotificationStats {
            total_alerts,
            unacknowledged_alerts,
            critical_alerts,
            alerts_by_source,
            alerts_by_severity,
            average_acknowledgment_time,
        })
    }

    /// Add or update an alert rule
    pub async fn add_rule(&self, rule: AlertRule) -> NotificationResult<()> {
        let mut rules = self.rules.write().await;
        rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    /// Get all alert rules
    pub async fn get_rules(&self) -> NotificationResult<Vec<AlertRule>> {
        let rules = self.rules.read().await;
        Ok(rules.values().cloned().collect())
    }

    /// Remove an alert rule
    pub async fn remove_rule(&self, rule_id: &str) -> NotificationResult<()> {
        let mut rules = self.rules.write().await;
        rules.remove(rule_id);
        Ok(())
    }

    /// Clean up expired alerts
    pub async fn cleanup_expired_alerts(&self) -> NotificationResult<usize> {
        let mut alerts = self.alerts.write().await;
        let initial_count = alerts.len();
        
        alerts.retain(|_, alert| !alert.is_expired());
        
        let removed_count = initial_count - alerts.len();
        Ok(removed_count)
    }

    /// Load default alert rules
    async fn load_default_rules(&self) -> NotificationResult<()> {
        use crate::rules::AlertRuleBuilder;
        use crate::{AlertSource, AlertSeverity, NotificationAction};

        let default_rules = vec![
            AlertRuleBuilder::new("policy-violation")
                .source(AlertSource::Policy)
                .event("violation")
                .severity(AlertSeverity::Critical)
                .actions(vec![NotificationAction::Toast, NotificationAction::Log])
                .build(),
            
            AlertRuleBuilder::new("vault-expiry")
                .source(AlertSource::Vault)
                .event("expiry")
                .severity(AlertSeverity::Warning)
                .actions(vec![NotificationAction::Toast, NotificationAction::Log])
                .build(),
            
            AlertRuleBuilder::new("vpn-disconnect")
                .source(AlertSource::VPN)
                .event("disconnect")
                .severity(AlertSeverity::Warning)
                .actions(vec![NotificationAction::Toast, NotificationAction::Log])
                .build(),
            
            AlertRuleBuilder::new("ssh-auth-fail")
                .source(AlertSource::SSH)
                .event("auth_fail")
                .severity(AlertSeverity::Warning)
                .actions(vec![NotificationAction::Toast, NotificationAction::Log])
                .build(),
        ];

        for rule in default_rules {
            self.add_rule(rule).await?;
        }

        Ok(())
    }

    /// Start the alert processing background task
    async fn start_alert_processor(&self) {
        let mut receiver_guard = self.alert_receiver.write().await;
        if let Some(mut receiver) = receiver_guard.take() {
            tokio::spawn(async move {
                while let Some(alert) = receiver.recv().await {
                    // Process alert (could trigger additional actions here)
                    tracing::info!("Processing alert: {:?} - {}", alert.severity, alert.title);
                }
            });
        }
    }
}
