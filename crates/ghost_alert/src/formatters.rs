use chrono::{DateTime, Utc, Duration};
use ghost_notify::{AlertSeverity, AlertSource};

/// Format alert timestamp for display
pub fn format_timestamp(timestamp: DateTime<Utc>) -> String {
    let now = Utc::now();
    let diff = now - timestamp;

    if diff < Duration::minutes(1) {
        "Just now".to_string()
    } else if diff < Duration::hours(1) {
        let minutes = diff.num_minutes();
        format!("{} minute{} ago", minutes, if minutes == 1 { "" } else { "s" })
    } else if diff < Duration::days(1) {
        let hours = diff.num_hours();
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else if diff < Duration::days(7) {
        let days = diff.num_days();
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    } else {
        timestamp.format("%Y-%m-%d %H:%M UTC").to_string()
    }
}

/// Format alert severity for display
pub fn format_severity(severity: &AlertSeverity) -> String {
    match severity {
        AlertSeverity::Info => "Info".to_string(),
        AlertSeverity::Warning => "Warning".to_string(),
        AlertSeverity::Critical => "Critical".to_string(),
    }
}

/// Get severity icon
pub fn severity_icon(severity: &AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Info => "info-circle",
        AlertSeverity::Warning => "exclamation-triangle",
        AlertSeverity::Critical => "exclamation-circle",
    }
}

/// Get severity color
pub fn severity_color(severity: &AlertSeverity) -> &'static str {
    severity.color()
}

/// Get severity CSS class
pub fn severity_css_class(severity: &AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Info => "alert-info",
        AlertSeverity::Warning => "alert-warning",
        AlertSeverity::Critical => "alert-critical",
    }
}

/// Format alert source for display
pub fn format_source(source: &AlertSource) -> String {
    match source {
        AlertSource::Policy => "Policy Engine".to_string(),
        AlertSource::Vault => "GhostVault".to_string(),
        AlertSource::VPN => "VPN Manager".to_string(),
        AlertSource::SSH => "SSH Manager".to_string(),
        AlertSource::PCAP => "PCAP Studio".to_string(),
        AlertSource::Topology => "Network Topology".to_string(),
        AlertSource::System => "System".to_string(),
        AlertSource::Custom(name) => name.clone(),
    }
}

/// Get source icon
pub fn source_icon(source: &AlertSource) -> &'static str {
    match source {
        AlertSource::Policy => "shield-alt",
        AlertSource::Vault => "key",
        AlertSource::VPN => "network-wired",
        AlertSource::SSH => "terminal",
        AlertSource::PCAP => "network",
        AlertSource::Topology => "project-diagram",
        AlertSource::System => "server",
        AlertSource::Custom(_) => "bell",
    }
}

/// Get source color
pub fn source_color(source: &AlertSource) -> &'static str {
    match source {
        AlertSource::Policy => "#FF008C",    // Neon pink
        AlertSource::Vault => "#AFFF00",     // Neon green
        AlertSource::VPN => "#00FFD1",       // Cyan
        AlertSource::SSH => "#FF6B00",       // Orange
        AlertSource::PCAP => "#8A2BE2",      // Blue violet
        AlertSource::Topology => "#FFD700",  // Gold
        AlertSource::System => "#C0C0C0",    // Silver
        AlertSource::Custom(_) => "#FFFFFF", // White
    }
}

/// Format alert message with context
pub fn format_alert_message(title: &str, message: &str, context: &std::collections::HashMap<String, String>) -> String {
    let mut formatted = message.to_string();
    
    // Replace context variables in the message
    for (key, value) in context {
        let placeholder = format!("{{{}}}", key);
        formatted = formatted.replace(&placeholder, value);
    }
    
    formatted
}

/// Generate alert summary
pub fn generate_alert_summary(alerts: &[crate::UIAlert]) -> String {
    if alerts.is_empty() {
        return "No alerts".to_string();
    }

    let critical_count = alerts.iter().filter(|a| matches!(a.severity, AlertSeverity::Critical)).count();
    let warning_count = alerts.iter().filter(|a| matches!(a.severity, AlertSeverity::Warning)).count();
    let info_count = alerts.iter().filter(|a| matches!(a.severity, AlertSeverity::Info)).count();

    let mut parts = Vec::new();
    
    if critical_count > 0 {
        parts.push(format!("{} critical", critical_count));
    }
    if warning_count > 0 {
        parts.push(format!("{} warning{}", warning_count, if warning_count == 1 { "" } else { "s" }));
    }
    if info_count > 0 {
        parts.push(format!("{} info", info_count));
    }

    if parts.len() == 1 {
        format!("{} alert{}", alerts.len(), if alerts.len() == 1 { "" } else { "s" })
    } else {
        parts.join(", ")
    }
}

/// Format duration in human-readable format
pub fn format_duration(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{:.1}s", seconds)
    } else if seconds < 3600.0 {
        let minutes = seconds / 60.0;
        format!("{:.1}m", minutes)
    } else if seconds < 86400.0 {
        let hours = seconds / 3600.0;
        format!("{:.1}h", hours)
    } else {
        let days = seconds / 86400.0;
        format!("{:.1}d", days)
    }
}

/// Truncate text with ellipsis
pub fn truncate_text(text: &str, max_length: usize) -> String {
    if text.len() <= max_length {
        text.to_string()
    } else {
        format!("{}...", &text[..max_length.saturating_sub(3)])
    }
}

/// Generate CSS for alert glow effect
pub fn generate_glow_css(color: &str, intensity: f32) -> String {
    format!(
        "box-shadow: 0 0 {}px {}px {}, 0 0 {}px {}px {}",
        (10.0 * intensity) as i32,
        (2.0 * intensity) as i32,
        color,
        (20.0 * intensity) as i32,
        (4.0 * intensity) as i32,
        color
    )
}

/// Generate CSS for alert border
pub fn generate_border_css(color: &str, width: f32) -> String {
    format!("border: {}px solid {}", width, color)
}

/// Format alert context for display
pub fn format_context_items(context: &std::collections::HashMap<String, String>) -> Vec<(String, String)> {
    let mut items: Vec<(String, String)> = context.iter()
        .map(|(k, v)| (format_context_key(k), v.clone()))
        .collect();
    
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items
}

fn format_context_key(key: &str) -> String {
    key.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_format_timestamp() {
        let now = Utc::now();
        
        assert_eq!(format_timestamp(now), "Just now");
        assert_eq!(format_timestamp(now - Duration::minutes(5)), "5 minutes ago");
        assert_eq!(format_timestamp(now - Duration::minutes(1)), "1 minute ago");
        assert_eq!(format_timestamp(now - Duration::hours(2)), "2 hours ago");
        assert_eq!(format_timestamp(now - Duration::hours(1)), "1 hour ago");
    }

    #[test]
    fn test_format_context_key() {
        assert_eq!(format_context_key("user_id"), "User Id");
        assert_eq!(format_context_key("host_name"), "Host Name");
        assert_eq!(format_context_key("policy"), "Policy");
    }

    #[test]
    fn test_truncate_text() {
        assert_eq!(truncate_text("Hello, World!", 10), "Hello,...");
        assert_eq!(truncate_text("Short", 10), "Short");
        assert_eq!(truncate_text("", 10), "");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30.5), "30.5s");
        assert_eq!(format_duration(90.0), "1.5m");
        assert_eq!(format_duration(3660.0), "1.0h");
        assert_eq!(format_duration(90000.0), "1.0d");
    }
}
