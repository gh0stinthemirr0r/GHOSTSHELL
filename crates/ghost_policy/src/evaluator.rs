use crate::{Policy, PolicyRule, PolicyDecision, Effect, Resource, Action, Conditions};
use std::collections::HashMap;
use chrono::Utc;

/// Policy Decision Point (PDP) - evaluates policies and makes decisions
pub struct PolicyEvaluator {
    policy: Policy,
}

impl PolicyEvaluator {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// Evaluate a request against the loaded policy
    pub fn evaluate(
        &self,
        subject: &HashMap<String, String>,
        resource: &Resource,
        action: &Action,
        context: &HashMap<String, String>,
    ) -> PolicyDecision {
        // Find all matching rules
        let mut matching_rules = Vec::new();
        
        for rule in &self.policy.rules {
            if self.rule_matches(rule, resource, action, subject, context) {
                matching_rules.push(rule);
            }
        }

        // If no rules match, apply default policy
        if matching_rules.is_empty() {
            return self.apply_default_policy(resource, action);
        }

        // Apply rule precedence (most specific first)
        matching_rules.sort_by(|a, b| self.rule_specificity(b).cmp(&self.rule_specificity(a)));

        // Return decision from highest precedence rule
        let rule = matching_rules[0];
        PolicyDecision {
            effect: rule.effect.clone(),
            matched_rule_id: Some(rule.id.clone()),
            constraints: rule.constraints.clone(),
            reason: Some(format!("Matched rule: {}", rule.id)),
        }
    }

    /// Check if a rule matches the request
    fn rule_matches(
        &self,
        rule: &PolicyRule,
        resource: &Resource,
        action: &Action,
        subject: &HashMap<String, String>,
        context: &HashMap<String, String>,
    ) -> bool {
        // Resource and action must match
        if &rule.resource != resource || &rule.action != action {
            return false;
        }

        // Check conditions if present
        if let Some(conditions) = &rule.when {
            if !self.evaluate_conditions(conditions, subject, context) {
                return false;
            }
        }

        true
    }

    /// Evaluate rule conditions
    fn evaluate_conditions(
        &self,
        conditions: &Conditions,
        _subject: &HashMap<String, String>,
        context: &HashMap<String, String>,
    ) -> bool {
        let now = Utc::now();

        // Time-based conditions
        if let Some(time_before) = &conditions.time_before {
            if now >= *time_before {
                return false;
            }
        }

        if let Some(time_after) = &conditions.time_after {
            if now <= *time_after {
                return false;
            }
        }

        // Host tags
        if let Some(required_tags) = &conditions.host_tags {
            let default_tags = String::new();
            let host_tags = context.get("host_tags").unwrap_or(&default_tags);
            let host_tag_list: Vec<&str> = host_tags.split(',').collect();
            
            for required_tag in required_tags {
                if !host_tag_list.contains(&required_tag.as_str()) {
                    return false;
                }
            }
        }

        // Sensitivity tags
        if let Some(required_sensitivity) = &conditions.sensitivity_tags {
            let default_sensitivity = String::new();
            let sensitivity = context.get("sensitivity").unwrap_or(&default_sensitivity);
            if !required_sensitivity.contains(sensitivity) {
                return false;
            }
        }

        // Post-quantum requirement
        if let Some(pq_required) = conditions.pq_required {
            let pq_available = context.get("pq_available")
                .and_then(|s| s.parse::<bool>().ok())
                .unwrap_or(false);
            
            if pq_required && !pq_available {
                return false;
            }
        }

        // VPN requirement
        if let Some(via_vpn) = conditions.via_vpn {
            let vpn_active = context.get("vpn_active")
                .and_then(|s| s.parse::<bool>().ok())
                .unwrap_or(false);
            
            if via_vpn && !vpn_active {
                return false;
            }
        }

        // Signature verification
        if let Some(required_signer) = &conditions.signed_by {
            let default_signer = String::new();
            let signer = context.get("signed_by").unwrap_or(&default_signer);
            if signer != required_signer {
                return false;
            }
        }

        // UI pane context
        if let Some(required_pane) = &conditions.pane {
            let default_pane = String::new();
            let current_pane = context.get("pane").unwrap_or(&default_pane);
            if current_pane != required_pane {
                return false;
            }
        }

        // MIME type restrictions
        if let Some(allowed_mimes) = &conditions.mime {
            let default_mime = String::new();
            let file_mime = context.get("mime_type").unwrap_or(&default_mime);
            if !allowed_mimes.contains(file_mime) {
                return false;
            }
        }

        // Size restrictions
        if let Some(size_constraints) = &conditions.size_mb {
            let file_size = context.get("size_mb")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            for (operator, limit) in size_constraints {
                match operator.as_str() {
                    "<=" => if file_size > *limit { return false; },
                    ">=" => if file_size < *limit { return false; },
                    "==" => if file_size != *limit { return false; },
                    "<" => if file_size >= *limit { return false; },
                    ">" => if file_size <= *limit { return false; },
                    _ => continue,
                }
            }
        }

        true
    }

    /// Calculate rule specificity for precedence
    fn rule_specificity(&self, rule: &PolicyRule) -> u32 {
        let mut specificity = 0;

        // Base specificity for having conditions
        if rule.when.is_some() {
            specificity += 100;
        }

        // Add specificity for each condition type
        if let Some(conditions) = &rule.when {
            if conditions.time_before.is_some() { specificity += 10; }
            if conditions.time_after.is_some() { specificity += 10; }
            if conditions.host_tags.is_some() { specificity += 20; }
            if conditions.sensitivity_tags.is_some() { specificity += 15; }
            if conditions.pq_required.is_some() { specificity += 25; }
            if conditions.via_vpn.is_some() { specificity += 15; }
            if conditions.signed_by.is_some() { specificity += 30; }
            if conditions.pane.is_some() { specificity += 5; }
            if conditions.mime.is_some() { specificity += 10; }
            if conditions.size_mb.is_some() { specificity += 10; }
        }

        specificity
    }

    /// Apply default policy when no rules match
    fn apply_default_policy(&self, resource: &Resource, action: &Action) -> PolicyDecision {
        // Check policy defaults
        if let Some(defaults) = &self.policy.defaults {
            // For PQ-sensitive operations, require PQ if default is set
            if defaults.pq_required.unwrap_or(false) {
                match (resource, action) {
                    (Resource::Vault, _) | 
                    (Resource::Ssh, Action::Connect) |
                    (Resource::Files, Action::Write) => {
                        return PolicyDecision {
                            effect: Effect::AllowWithJustification,
                            matched_rule_id: None,
                            constraints: None,
                            reason: Some("Default policy: PQ required for sensitive operations".to_string()),
                        };
                    }
                    _ => {}
                }
            }

            // Allow classical crypto if explicitly enabled
            if defaults.allow_classical.unwrap_or(false) {
                return PolicyDecision {
                    effect: Effect::Allow,
                    matched_rule_id: None,
                    constraints: None,
                    reason: Some("Default policy: Classical crypto allowed".to_string()),
                };
            }
        }

        // Default deny for security
        PolicyDecision {
            effect: Effect::Deny,
            matched_rule_id: None,
            constraints: None,
            reason: Some("Default policy: Deny (no matching rules)".to_string()),
        }
    }

    /// Update the policy at runtime
    pub fn update_policy(&mut self, new_policy: Policy) {
        self.policy = new_policy;
    }

    /// Get current policy version
    pub fn policy_version(&self) -> u32 {
        self.policy.version
    }

    /// List all rules for a specific resource/action combination
    pub fn list_rules_for(&self, resource: &Resource, action: &Action) -> Vec<&PolicyRule> {
        self.policy.rules
            .iter()
            .filter(|rule| &rule.resource == resource && &rule.action == action)
            .collect()
    }

    /// Dry-run evaluation (returns detailed analysis)
    pub fn dry_run(
        &self,
        subject: &HashMap<String, String>,
        resource: &Resource,
        action: &Action,
        context: &HashMap<String, String>,
    ) -> DryRunResult {
        let mut result = DryRunResult {
            decision: self.evaluate(subject, resource, action, context),
            evaluated_rules: Vec::new(),
            context_used: context.clone(),
            warnings: Vec::new(),
        };

        // Analyze all rules for debugging
        for rule in &self.policy.rules {
            let matches = self.rule_matches(rule, resource, action, subject, context);
            let specificity = self.rule_specificity(rule);
            
            result.evaluated_rules.push(RuleEvaluation {
                rule_id: rule.id.clone(),
                matches,
                specificity,
                conditions_met: if let Some(conditions) = &rule.when {
                    self.evaluate_conditions(conditions, subject, context)
                } else {
                    true
                },
            });
        }

        // Add warnings for common issues
        if result.decision.effect == Effect::Deny {
            result.warnings.push("Request denied - consider adding explicit allow rule".to_string());
        }

        if context.get("pq_available").is_none() {
            result.warnings.push("Post-quantum availability not specified in context".to_string());
        }

        result
    }
}

/// Detailed result for dry-run evaluation
#[derive(Debug, Clone)]
pub struct DryRunResult {
    pub decision: PolicyDecision,
    pub evaluated_rules: Vec<RuleEvaluation>,
    pub context_used: HashMap<String, String>,
    pub warnings: Vec<String>,
}

/// Individual rule evaluation result
#[derive(Debug, Clone)]
pub struct RuleEvaluation {
    pub rule_id: String,
    pub matches: bool,
    pub specificity: u32,
    pub conditions_met: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PolicyRule, PolicyDefaults};

    fn create_test_policy() -> Policy {
        Policy {
            version: 1,
            defaults: Some(PolicyDefaults {
                pq_required: Some(true),
                allow_classical: Some(false),
            }),
            rules: vec![
                PolicyRule {
                    id: "allow-vault-read".to_string(),
                    resource: Resource::Vault,
                    action: Action::Read,
                    when: None,
                    effect: Effect::Allow,
                    constraints: None,
                },
                PolicyRule {
                    id: "require-pq-vault-write".to_string(),
                    resource: Resource::Vault,
                    action: Action::Write,
                    when: Some(Conditions {
                        pq_required: Some(true),
                        ..Default::default()
                    }),
                    effect: Effect::Allow,
                    constraints: None,
                },
            ],
        }
    }

    #[test]
    fn test_basic_evaluation() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);
        
        let subject = HashMap::new();
        let context = HashMap::from([
            ("pq_available".to_string(), "true".to_string()),
        ]);

        // Test vault read (should be allowed)
        let decision = evaluator.evaluate(&subject, &Resource::Vault, &Action::Read, &context);
        assert!(matches!(decision.effect, Effect::Allow));
        assert_eq!(decision.matched_rule_id, Some("allow-vault-read".to_string()));

        // Test vault write with PQ (should be allowed)
        let decision = evaluator.evaluate(&subject, &Resource::Vault, &Action::Write, &context);
        assert!(matches!(decision.effect, Effect::Allow));
        assert_eq!(decision.matched_rule_id, Some("require-pq-vault-write".to_string()));
    }

    #[test]
    fn test_pq_requirement() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);
        
        let subject = HashMap::new();
        let context_no_pq = HashMap::from([
            ("pq_available".to_string(), "false".to_string()),
        ]);

        // Test vault write without PQ (should be denied)
        let decision = evaluator.evaluate(&subject, &Resource::Vault, &Action::Write, &context_no_pq);
        assert!(matches!(decision.effect, Effect::Deny));
    }

    #[test]
    fn test_dry_run() {
        let policy = create_test_policy();
        let evaluator = PolicyEvaluator::new(policy);
        
        let subject = HashMap::new();
        let context = HashMap::from([
            ("pq_available".to_string(), "true".to_string()),
        ]);

        let result = evaluator.dry_run(&subject, &Resource::Vault, &Action::Read, &context);
        assert!(matches!(result.decision.effect, Effect::Allow));
        assert_eq!(result.evaluated_rules.len(), 2);
        assert!(result.evaluated_rules.iter().any(|r| r.rule_id == "allow-vault-read" && r.matches));
    }
}
