use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;
use ghost_notify::{
    NotificationEngine, AlertMeta, AlertFilter, NotificationStats, AlertRule, 
    AlertSource, AlertSeverity, NotificationResult, NotificationError
};
use ghost_alert::{UIAlert, AlertListConfig, NotificationCenterConfig};
use serde_json::Value;

/// Get all alerts with optional filtering
#[tauri::command]
pub async fn notify_get_alerts(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
    filter: Option<AlertFilter>,
) -> Result<Vec<UIAlert>, String> {
    let engine = engine.lock().await;
    let alerts = engine.get_alerts(filter).await
        .map_err(|e| e.to_string())?;
    
    Ok(alerts.into_iter().map(UIAlert::from).collect())
}

/// Get a specific alert by ID
#[tauri::command]
pub async fn notify_get_alert(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
    alert_id: String,
) -> Result<Option<UIAlert>, String> {
    let engine = engine.lock().await;
    let filter = AlertFilter {
        search: Some(alert_id.clone()),
        limit: Some(1),
        ..Default::default()
    };
    
    let alerts = engine.get_alerts(Some(filter)).await
        .map_err(|e| e.to_string())?;
    
    Ok(alerts.into_iter()
        .find(|alert| alert.id == alert_id)
        .map(UIAlert::from))
}

/// Create a new alert
#[tauri::command]
pub async fn notify_create_alert(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
    source: String,
    severity: String,
    title: String,
    message: String,
    context: Option<std::collections::HashMap<String, String>>,
) -> Result<String, String> {
    let engine = engine.lock().await;
    
    let alert_source = parse_alert_source(&source)?;
    let alert_severity = parse_alert_severity(&severity)?;
    
    let mut alert = AlertMeta::new(alert_source, alert_severity, title, message);
    
    if let Some(ctx) = context {
        for (key, value) in ctx {
            alert = alert.with_context(key, value);
        }
    }
    
    engine.add_alert(alert).await
        .map_err(|e| e.to_string())
}

/// Acknowledge an alert
#[tauri::command]
pub async fn notify_acknowledge_alert(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
    alert_id: String,
    user: String,
) -> Result<(), String> {
    let engine = engine.lock().await;
    engine.acknowledge_alert(&alert_id, user).await
        .map_err(|e| e.to_string())
}

/// Get notification statistics
#[tauri::command]
pub async fn notify_get_stats(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
) -> Result<NotificationStats, String> {
    let engine = engine.lock().await;
    engine.get_stats().await
        .map_err(|e| e.to_string())
}

/// Get all alert rules
#[tauri::command]
pub async fn notify_get_rules(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
) -> Result<Vec<AlertRule>, String> {
    let engine = engine.lock().await;
    engine.get_rules().await
        .map_err(|e| e.to_string())
}

/// Add or update an alert rule
#[tauri::command]
pub async fn notify_save_rule(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
    rule: AlertRule,
) -> Result<(), String> {
    let engine = engine.lock().await;
    engine.add_rule(rule).await
        .map_err(|e| e.to_string())
}

/// Remove an alert rule
#[tauri::command]
pub async fn notify_delete_rule(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
    rule_id: String,
) -> Result<(), String> {
    let engine = engine.lock().await;
    engine.remove_rule(&rule_id).await
        .map_err(|e| e.to_string())
}

/// Clean up expired alerts
#[tauri::command]
pub async fn notify_cleanup_expired(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
) -> Result<usize, String> {
    let engine = engine.lock().await;
    engine.cleanup_expired_alerts().await
        .map_err(|e| e.to_string())
}

/// Test an alert rule
#[tauri::command]
pub async fn notify_test_rule(
    rule: AlertRule,
    test_source: String,
    test_event: String,
    test_context: std::collections::HashMap<String, String>,
) -> Result<bool, String> {
    let alert_source = parse_alert_source(&test_source)?;
    Ok(rule.matches(&alert_source, &test_event, &test_context))
}

/// Get notification center configuration
#[tauri::command]
pub async fn notify_get_config() -> Result<NotificationCenterConfig, String> {
    // In a real implementation, this would load from storage
    Ok(NotificationCenterConfig::default())
}

/// Save notification center configuration
#[tauri::command]
pub async fn notify_save_config(
    config: NotificationCenterConfig,
) -> Result<(), String> {
    // In a real implementation, this would save to storage
    tracing::info!("Saving notification config: {:?}", config);
    Ok(())
}

/// Export alerts as JSON
#[tauri::command]
pub async fn notify_export_alerts(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
    filter: Option<AlertFilter>,
    format: Option<String>,
) -> Result<String, String> {
    let engine = engine.lock().await;
    let alerts = engine.get_alerts(filter).await
        .map_err(|e| e.to_string())?;
    
    let export_format = format.unwrap_or_else(|| "json".to_string());
    
    match export_format.as_str() {
        "json" => {
            serde_json::to_string_pretty(&alerts)
                .map_err(|e| format!("JSON serialization error: {}", e))
        }
        "csv" => {
            export_alerts_as_csv(&alerts)
        }
        _ => Err(format!("Unsupported export format: {}", export_format))
    }
}

/// Bulk acknowledge alerts
#[tauri::command]
pub async fn notify_bulk_acknowledge(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
    alert_ids: Vec<String>,
    user: String,
) -> Result<Vec<String>, String> {
    let engine = engine.lock().await;
    let mut failed_ids = Vec::new();
    
    for alert_id in alert_ids {
        if let Err(_) = engine.acknowledge_alert(&alert_id, user.clone()).await {
            failed_ids.push(alert_id);
        }
    }
    
    Ok(failed_ids)
}

/// Search alerts by text
#[tauri::command]
pub async fn notify_search_alerts(
    engine: State<'_, Arc<Mutex<NotificationEngine>>>,
    query: String,
    limit: Option<usize>,
) -> Result<Vec<UIAlert>, String> {
    let engine = engine.lock().await;
    let filter = AlertFilter {
        search: Some(query),
        limit,
        ..Default::default()
    };
    
    let alerts = engine.get_alerts(Some(filter)).await
        .map_err(|e| e.to_string())?;
    
    Ok(alerts.into_iter().map(UIAlert::from).collect())
}

// Helper functions

fn parse_alert_source(source: &str) -> Result<AlertSource, String> {
    match source.to_lowercase().as_str() {
        "policy" => Ok(AlertSource::Policy),
        "vault" => Ok(AlertSource::Vault),
        "vpn" => Ok(AlertSource::VPN),
        "ssh" => Ok(AlertSource::SSH),
        "pcap" => Ok(AlertSource::PCAP),
        "topology" => Ok(AlertSource::Topology),
        "system" => Ok(AlertSource::System),
        custom => Ok(AlertSource::Custom(custom.to_string())),
    }
}

fn parse_alert_severity(severity: &str) -> Result<AlertSeverity, String> {
    match severity.to_lowercase().as_str() {
        "info" => Ok(AlertSeverity::Info),
        "warning" | "warn" => Ok(AlertSeverity::Warning),
        "critical" | "crit" => Ok(AlertSeverity::Critical),
        _ => Err(format!("Invalid severity: {}", severity)),
    }
}

fn export_alerts_as_csv(alerts: &[AlertMeta]) -> Result<String, String> {
    let mut csv = String::new();
    csv.push_str("ID,Source,Severity,Title,Message,Timestamp,Acknowledged,Context\n");
    
    for alert in alerts {
        let context_json = serde_json::to_string(&alert.context)
            .unwrap_or_else(|_| "{}".to_string());
        
        csv.push_str(&format!(
            "{},{:?},{:?},{},{},{},{},{}\n",
            alert.id,
            alert.source,
            alert.severity,
            escape_csv_field(&alert.title),
            escape_csv_field(&alert.message),
            alert.timestamp.to_rfc3339(),
            alert.acknowledged,
            escape_csv_field(&context_json)
        ));
    }
    
    Ok(csv)
}

fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}
