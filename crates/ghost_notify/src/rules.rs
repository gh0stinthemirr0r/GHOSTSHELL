use crate::{AlertSource, AlertSeverity, NotificationAction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Alert rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub source: AlertSource,
    pub event: String,
    pub severity: AlertSeverity,
    pub enabled: bool,
    pub actions: Vec<NotificationAction>,
    pub conditions: HashMap<String, String>,
    pub rate_limit: Option<RateLimit>,
    pub deduplication: Option<DeduplicationConfig>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_alerts: usize,
    pub window_seconds: u64,
}

/// Deduplication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationConfig {
    pub window_seconds: u64,
    pub fields: Vec<String>, // Fields to use for deduplication
}

/// Builder for creating alert rules
pub struct AlertRuleBuilder {
    rule: AlertRule,
}

impl AlertRuleBuilder {
    pub fn new(id: &str) -> Self {
        Self {
            rule: AlertRule {
                id: id.to_string(),
                name: id.to_string(),
                description: None,
                source: AlertSource::System,
                event: "default".to_string(),
                severity: AlertSeverity::Info,
                enabled: true,
                actions: vec![NotificationAction::Log],
                conditions: HashMap::new(),
                rate_limit: None,
                deduplication: None,
            },
        }
    }

    pub fn name(mut self, name: &str) -> Self {
        self.rule.name = name.to_string();
        self
    }

    pub fn description(mut self, description: &str) -> Self {
        self.rule.description = Some(description.to_string());
        self
    }

    pub fn source(mut self, source: AlertSource) -> Self {
        self.rule.source = source;
        self
    }

    pub fn event(mut self, event: &str) -> Self {
        self.rule.event = event.to_string();
        self
    }

    pub fn severity(mut self, severity: AlertSeverity) -> Self {
        self.rule.severity = severity;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.rule.enabled = enabled;
        self
    }

    pub fn actions(mut self, actions: Vec<NotificationAction>) -> Self {
        self.rule.actions = actions;
        self
    }

    pub fn condition(mut self, key: &str, value: &str) -> Self {
        self.rule.conditions.insert(key.to_string(), value.to_string());
        self
    }

    pub fn conditions(mut self, conditions: HashMap<String, String>) -> Self {
        self.rule.conditions = conditions;
        self
    }

    pub fn rate_limit(mut self, max_alerts: usize, window_seconds: u64) -> Self {
        self.rule.rate_limit = Some(RateLimit {
            max_alerts,
            window_seconds,
        });
        self
    }

    pub fn deduplication(mut self, window_seconds: u64, fields: Vec<String>) -> Self {
        self.rule.deduplication = Some(DeduplicationConfig {
            window_seconds,
            fields,
        });
        self
    }

    pub fn build(self) -> AlertRule {
        self.rule
    }
}

impl AlertRule {
    /// Check if this rule matches the given event
    pub fn matches(&self, source: &AlertSource, event: &str, context: &HashMap<String, String>) -> bool {
        if !self.enabled {
            return false;
        }

        // Check source match
        if self.source != *source {
            return false;
        }

        // Check event match (supports wildcards)
        if !self.event_matches(event) {
            return false;
        }

        // Check conditions
        for (key, expected_value) in &self.conditions {
            if let Some(actual_value) = context.get(key) {
                if !self.condition_matches(expected_value, actual_value) {
                    return false;
                }
            } else {
                // Required condition not present
                return false;
            }
        }

        true
    }

    fn event_matches(&self, event: &str) -> bool {
        if self.event == "*" {
            return true;
        }

        if self.event.contains('*') {
            // Simple wildcard matching
            let pattern = self.event.replace('*', ".*");
            if let Ok(regex) = regex::Regex::new(&pattern) {
                return regex.is_match(event);
            }
        }

        self.event == event
    }

    fn condition_matches(&self, expected: &str, actual: &str) -> bool {
        // Support for comparison operators
        if expected.starts_with(">=") {
            if let (Ok(exp), Ok(act)) = (expected[2..].parse::<f64>(), actual.parse::<f64>()) {
                return act >= exp;
            }
        } else if expected.starts_with("<=") {
            if let (Ok(exp), Ok(act)) = (expected[2..].parse::<f64>(), actual.parse::<f64>()) {
                return act <= exp;
            }
        } else if expected.starts_with(">") {
            if let (Ok(exp), Ok(act)) = (expected[1..].parse::<f64>(), actual.parse::<f64>()) {
                return act > exp;
            }
        } else if expected.starts_with("<") {
            if let (Ok(exp), Ok(act)) = (expected[1..].parse::<f64>(), actual.parse::<f64>()) {
                return act < exp;
            }
        } else if expected.starts_with("!=") {
            return actual != &expected[2..];
        } else if expected.contains('*') {
            // Wildcard matching
            let pattern = expected.replace('*', ".*");
            if let Ok(regex) = regex::Regex::new(&pattern) {
                return regex.is_match(actual);
            }
        }

        // Exact match
        expected == actual
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_builder() {
        let rule = AlertRuleBuilder::new("test-rule")
            .name("Test Rule")
            .description("A test rule")
            .source(AlertSource::Policy)
            .event("violation")
            .severity(AlertSeverity::Critical)
            .condition("host", "prod-*")
            .rate_limit(5, 60)
            .build();

        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.name, "Test Rule");
        assert_eq!(rule.source, AlertSource::Policy);
        assert_eq!(rule.event, "violation");
        assert!(matches!(rule.severity, AlertSeverity::Critical));
        assert!(rule.rate_limit.is_some());
    }

    #[test]
    fn test_rule_matching() {
        let rule = AlertRuleBuilder::new("test")
            .source(AlertSource::Policy)
            .event("violation")
            .condition("severity", "high")
            .build();

        let mut context = HashMap::new();
        context.insert("severity".to_string(), "high".to_string());

        assert!(rule.matches(&AlertSource::Policy, "violation", &context));
        assert!(!rule.matches(&AlertSource::VPN, "violation", &context));
        assert!(!rule.matches(&AlertSource::Policy, "info", &context));
    }

    #[test]
    fn test_wildcard_matching() {
        let rule = AlertRuleBuilder::new("test")
            .source(AlertSource::SSH)
            .event("auth_*")
            .condition("host", "prod-*")
            .build();

        let mut context = HashMap::new();
        context.insert("host".to_string(), "prod-db01".to_string());

        assert!(rule.matches(&AlertSource::SSH, "auth_fail", &context));
        assert!(rule.matches(&AlertSource::SSH, "auth_success", &context));
        assert!(!rule.matches(&AlertSource::SSH, "connect", &context));

        context.insert("host".to_string(), "dev-db01".to_string());
        assert!(!rule.matches(&AlertSource::SSH, "auth_fail", &context));
    }

    #[test]
    fn test_numeric_conditions() {
        let rule = AlertRuleBuilder::new("test")
            .source(AlertSource::System)
            .event("metric")
            .condition("cpu_usage", ">80")
            .condition("memory_usage", ">=90")
            .build();

        let mut context = HashMap::new();
        context.insert("cpu_usage".to_string(), "85".to_string());
        context.insert("memory_usage".to_string(), "90".to_string());

        assert!(rule.matches(&AlertSource::System, "metric", &context));

        context.insert("cpu_usage".to_string(), "75".to_string());
        assert!(!rule.matches(&AlertSource::System, "metric", &context));
    }
}
