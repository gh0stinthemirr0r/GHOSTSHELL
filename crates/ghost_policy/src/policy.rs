use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use crate::{PolicyError, Result};

/// Top-level policy document
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub version: u32,
    pub metadata: Option<PolicyMetadata>,
    pub defaults: Option<PolicyDefaults>,
    pub rules: Vec<PolicyRule>,
}

/// Policy metadata
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyMetadata {
    pub name: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
}

/// Default policy settings
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PolicyDefaults {
    pub pq_required: Option<bool>,
    pub allow_classical: Option<bool>,
    pub default_effect: Option<Effect>,
    pub audit_all: Option<bool>,
    pub mfa_timeout_minutes: Option<u32>,
}

/// Individual policy rule
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyRule {
    pub id: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<u32>,
    pub resource: Resource,
    pub action: Action,
    pub when: Option<Conditions>,
    pub effect: Effect,
    pub constraints: Option<Constraints>,
}

/// Resources that can be protected by policy
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum Resource {
    Terminal,
    Ssh,
    Vault,
    Vpn,
    Browser,
    Files,
    Clipboard,
    Network,
    Theme,
    Settings,
    Logs,
    Policy,
}

/// Actions that can be performed on resources
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    Read,
    Write,
    Exec,
    Connect,
    Download,
    Upload,
    Autofill,
    Copy,
    Paste,
    Delete,
    Create,
    Update,
    Export,
    Import,
    Switch,
    Apply,
    Reload,
    Query,
    Browse,
    Search,
}

/// Policy decision effects
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
    AllowWithJustification,
}

/// Conditions for rule matching
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Conditions {
    // Time-based conditions
    pub time_before: Option<DateTime<Utc>>,
    pub time_after: Option<DateTime<Utc>>,
    pub time_of_day: Option<TimeRange>,
    pub days_of_week: Option<Vec<Weekday>>,
    
    // Security conditions
    pub host_tags: Option<Vec<String>>,
    pub sensitivity_tags: Option<Vec<String>>,
    pub pq_required: Option<bool>,
    pub via_vpn: Option<bool>,
    pub mfa_required: Option<bool>,
    pub signed_by: Option<String>,
    
    // Context conditions
    pub pane: Option<String>,
    pub mime: Option<Vec<String>>,
    pub size_mb: Option<HashMap<String, u64>>,
    pub path_pattern: Option<String>,
    pub network_zone: Option<NetworkZone>,
    
    // User conditions
    pub user_roles: Option<Vec<String>>,
    pub user_groups: Option<Vec<String>>,
    pub session_duration_max: Option<u32>,
}

/// Time range for time-of-day conditions
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeRange {
    pub start: String, // HH:MM format
    pub end: String,   // HH:MM format
}

/// Days of the week
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Network security zones
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum NetworkZone {
    Trusted,
    Corporate,
    Public,
    Restricted,
}

/// Constraints applied when rule matches
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Constraints {
    // Time-based constraints
    pub auto_clear_ms: Option<u64>,
    pub max_duration_ms: Option<u64>,
    pub session_timeout_ms: Option<u64>,
    
    // Security constraints
    pub mask_preview: Option<bool>,
    pub quarantine: Option<bool>,
    pub require_approval: Option<bool>,
    pub audit_level: Option<String>,
    
    // Size and scope constraints
    pub max_size_mb: Option<u64>,
    pub max_files: Option<u32>,
    pub allowed_extensions: Option<Vec<String>>,
    pub blocked_extensions: Option<Vec<String>>,
    
    // Notification constraints
    pub notify_admin: Option<bool>,
    pub user_warning: Option<String>,
    pub justification_required: Option<bool>,
}

impl Policy {
    /// Create a new empty policy
    pub fn new(version: u32) -> Self {
        Self {
            version,
            metadata: None,
            defaults: None,
            rules: Vec::new(),
        }
    }

    /// Load policy from TOML string
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(PolicyError::TomlError)
    }

    /// Load policy from JSON string
    pub fn from_json(content: &str) -> Result<Self> {
        serde_json::from_str(content).map_err(PolicyError::SerializationError)
    }

    /// Auto-detect format and parse
    pub fn from_string(content: &str) -> Result<Self> {
        // Try TOML first, then JSON
        if let Ok(policy) = Self::from_toml(content) {
            Ok(policy)
        } else if let Ok(policy) = Self::from_json(content) {
            Ok(policy)
        } else {
            Err(PolicyError::ParseError("Content is neither valid TOML nor JSON".to_string()))
        }
    }

    /// Convert to TOML string
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| PolicyError::ParseError(format!("TOML serialization error: {}", e)))
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(PolicyError::SerializationError)
    }

    /// Validate policy structure
    pub fn validate(&self) -> Result<()> {
        // Check for duplicate rule IDs
        let mut rule_ids = std::collections::HashSet::new();
        for rule in &self.rules {
            if !rule_ids.insert(&rule.id) {
                return Err(PolicyError::ValidationError(
                    format!("Duplicate rule ID: {}", rule.id)
                ));
            }
        }

        // Validate individual rules
        for rule in &self.rules {
            rule.validate()?;
        }

        Ok(())
    }

    /// Add a rule to the policy
    pub fn add_rule(&mut self, rule: PolicyRule) -> Result<()> {
        // Check for duplicate ID
        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(PolicyError::ValidationError(
                format!("Rule ID already exists: {}", rule.id)
            ));
        }

        rule.validate()?;
        self.rules.push(rule);
        Ok(())
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, rule_id: &str) -> Result<()> {
        let initial_len = self.rules.len();
        self.rules.retain(|rule| rule.id != rule_id);
        
        if self.rules.len() == initial_len {
            return Err(PolicyError::ResourceNotFound(
                format!("Rule not found: {}", rule_id)
            ));
        }
        
        Ok(())
    }

    /// Get rule by ID
    pub fn get_rule(&self, rule_id: &str) -> Option<&PolicyRule> {
        self.rules.iter().find(|rule| rule.id == rule_id)
    }

    /// Get mutable rule by ID
    pub fn get_rule_mut(&mut self, rule_id: &str) -> Option<&mut PolicyRule> {
        self.rules.iter_mut().find(|rule| rule.id == rule_id)
    }

    /// List rules for a specific resource/action combination
    pub fn rules_for(&self, resource: &Resource, action: &Action) -> Vec<&PolicyRule> {
        self.rules
            .iter()
            .filter(|rule| {
                rule.enabled.unwrap_or(true) && 
                &rule.resource == resource && 
                &rule.action == action
            })
            .collect()
    }

    /// Get enabled rules sorted by priority
    pub fn enabled_rules(&self) -> Vec<&PolicyRule> {
        let mut rules: Vec<&PolicyRule> = self.rules
            .iter()
            .filter(|rule| rule.enabled.unwrap_or(true))
            .collect();
        
        rules.sort_by_key(|rule| rule.priority.unwrap_or(100));
        rules
    }

    /// Update metadata
    pub fn set_metadata(&mut self, metadata: PolicyMetadata) {
        self.metadata = Some(metadata);
    }

    /// Update defaults
    pub fn set_defaults(&mut self, defaults: PolicyDefaults) {
        self.defaults = Some(defaults);
    }
}

impl PolicyRule {
    /// Create a new policy rule
    pub fn new(id: String, resource: Resource, action: Action, effect: Effect) -> Self {
        Self {
            id,
            description: None,
            enabled: Some(true),
            priority: None,
            resource,
            action,
            when: None,
            effect,
            constraints: None,
        }
    }

    /// Validate rule structure
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(PolicyError::ValidationError("Rule ID cannot be empty".to_string()));
        }

        // Validate conditions if present
        if let Some(conditions) = &self.when {
            conditions.validate()?;
        }

        // Validate constraints if present
        if let Some(constraints) = &self.constraints {
            constraints.validate()?;
        }

        Ok(())
    }

    /// Check if rule is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    /// Get rule priority (lower number = higher priority)
    pub fn priority(&self) -> u32 {
        self.priority.unwrap_or(100)
    }
}

impl Conditions {
    /// Validate condition structure
    pub fn validate(&self) -> Result<()> {
        // Validate time range
        if let Some(time_range) = &self.time_of_day {
            time_range.validate()?;
        }

        // Validate path pattern if present
        if let Some(pattern) = &self.path_pattern {
            regex::Regex::new(pattern)
                .map_err(|e| PolicyError::InvalidCondition(
                    format!("Invalid path pattern '{}': {}", pattern, e)
                ))?;
        }

        // Validate size constraints
        if let Some(size_constraints) = &self.size_mb {
            for (operator, _) in size_constraints {
                if !matches!(operator.as_str(), "<=" | ">=" | "==" | "<" | ">") {
                    return Err(PolicyError::InvalidCondition(
                        format!("Invalid size operator: {}", operator)
                    ));
                }
            }
        }

        Ok(())
    }
}

impl TimeRange {
    /// Validate time range format
    pub fn validate(&self) -> Result<()> {
        fn parse_time(time_str: &str) -> Result<(u32, u32)> {
            let parts: Vec<&str> = time_str.split(':').collect();
            if parts.len() != 2 {
                return Err(PolicyError::InvalidCondition(
                    format!("Invalid time format: {}", time_str)
                ));
            }

            let hour: u32 = parts[0].parse()
                .map_err(|_| PolicyError::InvalidCondition(
                    format!("Invalid hour: {}", parts[0])
                ))?;
            let minute: u32 = parts[1].parse()
                .map_err(|_| PolicyError::InvalidCondition(
                    format!("Invalid minute: {}", parts[1])
                ))?;

            if hour > 23 || minute > 59 {
                return Err(PolicyError::InvalidCondition(
                    format!("Invalid time: {}:{}", hour, minute)
                ));
            }

            Ok((hour, minute))
        }

        parse_time(&self.start)?;
        parse_time(&self.end)?;
        Ok(())
    }
}

impl Constraints {
    /// Validate constraint values
    pub fn validate(&self) -> Result<()> {
        // Validate file extensions
        if let Some(extensions) = &self.allowed_extensions {
            for ext in extensions {
                if ext.is_empty() {
                    return Err(PolicyError::ValidationError(
                        "File extension cannot be empty".to_string()
                    ));
                }
            }
        }

        if let Some(extensions) = &self.blocked_extensions {
            for ext in extensions {
                if ext.is_empty() {
                    return Err(PolicyError::ValidationError(
                        "File extension cannot be empty".to_string()
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Default policies for common scenarios
impl Policy {
    /// Create a restrictive default policy
    pub fn restrictive_default() -> Self {
        let mut policy = Policy::new(1);
        
        policy.set_defaults(PolicyDefaults {
            pq_required: Some(true),
            allow_classical: Some(false),
            default_effect: Some(Effect::Deny),
            audit_all: Some(true),
            mfa_timeout_minutes: Some(15),
        });

        // Allow basic terminal operations
        policy.add_rule(PolicyRule::new(
            "allow-terminal-read".to_string(),
            Resource::Terminal,
            Action::Read,
            Effect::Allow,
        )).unwrap();

        // Require justification for sensitive operations
        let mut vault_write = PolicyRule::new(
            "vault-write-justify".to_string(),
            Resource::Vault,
            Action::Write,
            Effect::AllowWithJustification,
        );
        vault_write.constraints = Some(Constraints {
            audit_level: Some("high".to_string()),
            justification_required: Some(true),
            ..Default::default()
        });
        policy.add_rule(vault_write).unwrap();

        policy
    }

    /// Create a permissive development policy
    pub fn development_default() -> Self {
        let mut policy = Policy::new(1);
        
        policy.set_defaults(PolicyDefaults {
            pq_required: Some(false),
            allow_classical: Some(true),
            default_effect: Some(Effect::Allow),
            audit_all: Some(false),
            mfa_timeout_minutes: Some(60),
        });

        // Block only dangerous operations
        policy.add_rule(PolicyRule::new(
            "block-system-delete".to_string(),
            Resource::Files,
            Action::Delete,
            Effect::Deny,
        )).unwrap();

        policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy = Policy::new(1);
        assert_eq!(policy.version, 1);
        assert!(policy.rules.is_empty());
    }

    #[test]
    fn test_rule_validation() {
        let rule = PolicyRule::new(
            "test-rule".to_string(),
            Resource::Terminal,
            Action::Read,
            Effect::Allow,
        );
        
        assert!(rule.validate().is_ok());
        assert!(rule.is_enabled());
        assert_eq!(rule.priority(), 100);
    }

    #[test]
    fn test_policy_serialization() {
        let policy = Policy::restrictive_default();
        
        let toml_str = policy.to_toml().unwrap();
        let parsed_policy = Policy::from_toml(&toml_str).unwrap();
        assert_eq!(parsed_policy.version, policy.version);
        
        let json_str = policy.to_json().unwrap();
        let parsed_policy = Policy::from_json(&json_str).unwrap();
        assert_eq!(parsed_policy.version, policy.version);
    }

    #[test]
    fn test_time_range_validation() {
        let valid_range = TimeRange {
            start: "09:00".to_string(),
            end: "17:30".to_string(),
        };
        assert!(valid_range.validate().is_ok());

        let invalid_range = TimeRange {
            start: "25:00".to_string(),
            end: "17:30".to_string(),
        };
        assert!(invalid_range.validate().is_err());
    }

    #[test]
    fn test_rule_management() {
        let mut policy = Policy::new(1);
        
        let rule = PolicyRule::new(
            "test-rule".to_string(),
            Resource::Terminal,
            Action::Read,
            Effect::Allow,
        );
        
        assert!(policy.add_rule(rule).is_ok());
        assert_eq!(policy.rules.len(), 1);
        
        assert!(policy.get_rule("test-rule").is_some());
        assert!(policy.remove_rule("test-rule").is_ok());
        assert_eq!(policy.rules.len(), 0);
    }
}
