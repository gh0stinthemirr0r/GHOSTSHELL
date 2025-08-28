use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Policy overlay that gets applied to base layouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOverlay {
    pub force_hide: Vec<String>,
    pub force_show: Vec<String>,
    pub locks: HashMap<String, String>,
}

impl Default for PolicyOverlay {
    fn default() -> Self {
        Self {
            force_hide: Vec::new(),
            force_show: Vec::new(),
            locks: HashMap::new(),
        }
    }
}

impl PolicyOverlay {
    /// Create a policy overlay for a specific role
    pub fn for_role(role: &str) -> Self {
        match role {
            "auditor" => Self {
                force_hide: vec![
                    "ghostbrowse".to_string(),
                    "surveyor".to_string(),
                    "pcap".to_string(),
                ],
                force_show: vec![
                    "compliance".to_string(),
                    "reporting".to_string(),
                    "ghostvault".to_string(),
                ],
                locks: [
                    ("compliance".to_string(), "policy:auditor_required".to_string()),
                    ("reporting".to_string(), "policy:auditor_required".to_string()),
                ]
                .into_iter()
                .collect(),
            },
            "analyst" => Self {
                force_hide: vec![],
                force_show: vec![
                    "layers".to_string(),
                    "surveyor".to_string(),
                    "pcap".to_string(),
                    "topology".to_string(),
                ],
                locks: HashMap::new(),
            },
            "ops" => Self {
                force_hide: vec!["compliance".to_string()],
                force_show: vec![
                    "terminal".to_string(),
                    "ghostssh".to_string(),
                    "ghostvpn".to_string(),
                ],
                locks: HashMap::new(),
            },
            "minimal" => Self {
                force_hide: vec![
                    "layers".to_string(),
                    "surveyor".to_string(),
                    "pcap".to_string(),
                    "topology".to_string(),
                    "compliance".to_string(),
                    "reporting".to_string(),
                ],
                force_show: vec![
                    "terminal".to_string(),
                    "ghostvault".to_string(),
                ],
                locks: HashMap::new(),
            },
            "exec" => Self {
                force_hide: vec![
                    "layers".to_string(),
                    "surveyor".to_string(),
                    "pcap".to_string(),
                    "topology".to_string(),
                    "ghostssh".to_string(),
                    "ghostbrowse".to_string(),
                ],
                force_show: vec![
                    "compliance".to_string(),
                    "reporting".to_string(),
                ],
                locks: [
                    ("compliance".to_string(), "policy:exec_required".to_string()),
                    ("reporting".to_string(), "policy:exec_required".to_string()),
                ]
                .into_iter()
                .collect(),
            },
            _ => Self::default(),
        }
    }

    /// Create a policy overlay for a specific environment
    pub fn for_environment(env: &str) -> Self {
        match env {
            "prod" => Self {
                force_hide: vec!["ghostbrowse".to_string()],
                force_show: vec!["compliance".to_string()],
                locks: [
                    ("ghostbrowse".to_string(), "policy:prod_restricted".to_string()),
                    ("compliance".to_string(), "policy:prod_required".to_string()),
                ]
                .into_iter()
                .collect(),
            },
            "dev" => Self::default(),
            "staging" => Self {
                force_hide: Vec::new(),
                force_show: vec!["compliance".to_string()],
                locks: [
                    ("compliance".to_string(), "policy:staging_monitoring".to_string()),
                ]
                .into_iter()
                .collect(),
            },
            _ => Self::default(),
        }
    }

    /// Merge multiple policy overlays (later overlays take precedence)
    pub fn merge(mut self, other: PolicyOverlay) -> Self {
        // Merge force_hide (union)
        for item in other.force_hide {
            if !self.force_hide.contains(&item) {
                self.force_hide.push(item);
            }
        }

        // Merge force_show (union, but remove from force_hide if present)
        for item in other.force_show {
            if !self.force_show.contains(&item) {
                self.force_show.push(item.clone());
            }
            // Remove from force_hide if present (force_show takes precedence)
            self.force_hide.retain(|x| x != &item);
        }

        // Merge locks (other takes precedence)
        self.locks.extend(other.locks);

        self
    }
}

/// Policy rule for navigation visibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavPolicyRule {
    pub id: String,
    pub resource: String,
    pub action: String,
    pub when_conditions: HashMap<String, String>,
    pub effect: PolicyEffect,
    pub constraints: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

impl NavPolicyRule {
    /// Check if this rule applies to the current context
    pub fn applies_to_context(&self, context: &PolicyContext) -> bool {
        for (key, expected_value) in &self.when_conditions {
            match key.as_str() {
                "role" => {
                    if context.role != *expected_value {
                        return false;
                    }
                }
                "env" => {
                    if context.environment != *expected_value {
                        return false;
                    }
                }
                "org" => {
                    if context.organization != *expected_value {
                        return false;
                    }
                }
                _ => {
                    // Unknown condition, skip
                    continue;
                }
            }
        }
        true
    }

    /// Get the module ID this rule applies to
    pub fn get_module_id(&self) -> Option<&String> {
        self.constraints.get("module")
    }

    /// Check if this rule should lock the module
    pub fn should_lock(&self) -> bool {
        self.constraints
            .get("lock")
            .map(|v| v == "true")
            .unwrap_or(false)
    }
}

/// Context for policy evaluation
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub role: String,
    pub environment: String,
    pub organization: String,
    pub user_id: String,
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self {
            role: "user".to_string(),
            environment: "dev".to_string(),
            organization: "default".to_string(),
            user_id: "anonymous".to_string(),
        }
    }
}

/// Policy engine for navigation rules
pub struct NavPolicyEngine {
    rules: Vec<NavPolicyRule>,
}

impl NavPolicyEngine {
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    pub fn with_rules(rules: Vec<NavPolicyRule>) -> Self {
        Self { rules }
    }

    /// Compute policy overlay for given context
    pub fn compute_overlay(&self, context: &PolicyContext) -> PolicyOverlay {
        let mut overlay = PolicyOverlay::default();

        for rule in &self.rules {
            if !rule.applies_to_context(context) {
                continue;
            }

            if let Some(module_id) = rule.get_module_id() {
                match rule.effect {
                    PolicyEffect::Allow => {
                        overlay.force_show.push(module_id.clone());
                        if rule.should_lock() {
                            overlay.locks.insert(
                                module_id.clone(),
                                format!("policy:{}", rule.id),
                            );
                        }
                    }
                    PolicyEffect::Deny => {
                        overlay.force_hide.push(module_id.clone());
                        if rule.should_lock() {
                            overlay.locks.insert(
                                module_id.clone(),
                                format!("policy:{}", rule.id),
                            );
                        }
                    }
                }
            }
        }

        overlay
    }

    fn default_rules() -> Vec<NavPolicyRule> {
        vec![
            NavPolicyRule {
                id: "hide-browser-in-prod".to_string(),
                resource: "ui.sidebar".to_string(),
                action: "visibility".to_string(),
                when_conditions: [("env".to_string(), "prod".to_string())]
                    .into_iter()
                    .collect(),
                effect: PolicyEffect::Deny,
                constraints: [
                    ("module".to_string(), "ghostbrowse".to_string()),
                    ("lock".to_string(), "true".to_string()),
                ]
                .into_iter()
                .collect(),
            },
            NavPolicyRule {
                id: "force-show-vault".to_string(),
                resource: "ui.sidebar".to_string(),
                action: "visibility".to_string(),
                when_conditions: HashMap::new(),
                effect: PolicyEffect::Allow,
                constraints: [
                    ("module".to_string(), "ghostvault".to_string()),
                    ("lock".to_string(), "true".to_string()),
                ]
                .into_iter()
                .collect(),
            },
            NavPolicyRule {
                id: "only-auditor-compliance".to_string(),
                resource: "ui.sidebar".to_string(),
                action: "visibility".to_string(),
                when_conditions: [("role".to_string(), "auditor".to_string())]
                    .into_iter()
                    .collect(),
                effect: PolicyEffect::Allow,
                constraints: [
                    ("module".to_string(), "compliance".to_string()),
                    ("lock".to_string(), "true".to_string()),
                ]
                .into_iter()
                .collect(),
            },
        ]
    }
}
