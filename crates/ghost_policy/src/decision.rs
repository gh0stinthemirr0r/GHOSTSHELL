use crate::{Effect, Constraints};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Policy decision with enforcement details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub effect: Effect,
    pub matched_rule_id: Option<String>,
    pub constraints: Option<Constraints>,
    pub reason: Option<String>,
}

/// Policy Enforcement Point (PEP) decision
#[derive(Debug, Clone)]
pub struct EnforcementDecision {
    pub policy_decision: PolicyDecision,
    pub enforcement_actions: Vec<EnforcementAction>,
    pub audit_required: bool,
    pub user_notification: Option<String>,
}

/// Actions that the PEP should take
#[derive(Debug, Clone)]
pub enum EnforcementAction {
    /// Allow the operation to proceed
    Allow,
    
    /// Deny the operation
    Deny,
    
    /// Require user justification
    RequireJustification { prompt: String },
    
    /// Apply time-based constraints
    ApplyTimeLimit { duration_ms: u64 },
    
    /// Auto-clear clipboard after specified time
    AutoClearClipboard { after_ms: u64 },
    
    /// Mask sensitive data in previews
    MaskPreview,
    
    /// Quarantine downloaded files
    QuarantineFile { path: String },
    
    /// Require additional MFA verification
    RequireMFA { method: String },
    
    /// Log the operation with specific details
    AuditLog { level: AuditLevel, details: String },
    
    /// Show warning to user
    ShowWarning { message: String },
    
    /// Limit operation scope
    LimitScope { max_size_mb: u64 },
}

/// Audit logging levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditLevel {
    Info,
    Warning,
    Critical,
}

impl PolicyDecision {
    /// Create an allow decision
    pub fn allow() -> Self {
        Self {
            effect: Effect::Allow,
            matched_rule_id: None,
            constraints: None,
            reason: None,
        }
    }

    /// Create a deny decision
    pub fn deny(reason: &str) -> Self {
        Self {
            effect: Effect::Deny,
            matched_rule_id: None,
            constraints: None,
            reason: Some(reason.to_string()),
        }
    }

    /// Create an allow with justification decision
    pub fn allow_with_justification(reason: &str) -> Self {
        Self {
            effect: Effect::AllowWithJustification,
            matched_rule_id: None,
            constraints: None,
            reason: Some(reason.to_string()),
        }
    }

    /// Check if the decision allows the operation
    pub fn is_allowed(&self) -> bool {
        matches!(self.effect, Effect::Allow | Effect::AllowWithJustification)
    }

    /// Check if the decision requires user justification
    pub fn requires_justification(&self) -> bool {
        matches!(self.effect, Effect::AllowWithJustification)
    }

    /// Check if the decision denies the operation
    pub fn is_denied(&self) -> bool {
        matches!(self.effect, Effect::Deny)
    }

    /// Get the reason for the decision
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Convert to enforcement decision
    pub fn to_enforcement(&self) -> EnforcementDecision {
        let mut actions = Vec::new();
        let mut audit_required = false;
        let mut user_notification = None;

        match &self.effect {
            Effect::Allow => {
                actions.push(EnforcementAction::Allow);
            }
            Effect::Deny => {
                actions.push(EnforcementAction::Deny);
                audit_required = true;
                user_notification = Some(
                    self.reason.clone().unwrap_or_else(|| "Access denied by policy".to_string())
                );
            }
            Effect::AllowWithJustification => {
                actions.push(EnforcementAction::RequireJustification {
                    prompt: "Please provide justification for this action".to_string(),
                });
                audit_required = true;
            }
        }

        // Apply constraints if present
        if let Some(constraints) = &self.constraints {
            if let Some(auto_clear_ms) = constraints.auto_clear_ms {
                actions.push(EnforcementAction::AutoClearClipboard { after_ms: auto_clear_ms });
            }

            if constraints.mask_preview.unwrap_or(false) {
                actions.push(EnforcementAction::MaskPreview);
            }

            if constraints.quarantine.unwrap_or(false) {
                // Path will be filled in by the PEP
                actions.push(EnforcementAction::QuarantineFile { path: String::new() });
            }

            if let Some(max_duration_ms) = constraints.max_duration_ms {
                actions.push(EnforcementAction::ApplyTimeLimit { duration_ms: max_duration_ms });
            }

            if let Some(max_size_mb) = constraints.max_size_mb {
                actions.push(EnforcementAction::LimitScope { max_size_mb });
            }
        }

        // Always audit critical decisions
        if self.is_denied() || self.requires_justification() {
            actions.push(EnforcementAction::AuditLog {
                level: if self.is_denied() { AuditLevel::Warning } else { AuditLevel::Info },
                details: format!("Policy decision: {:?}, Rule: {:?}", 
                    self.effect, self.matched_rule_id),
            });
        }

        EnforcementDecision {
            policy_decision: self.clone(),
            enforcement_actions: actions,
            audit_required,
            user_notification,
        }
    }
}

impl EnforcementDecision {
    /// Check if the operation should be allowed to proceed
    pub fn should_allow(&self) -> bool {
        self.enforcement_actions.iter().any(|action| {
            matches!(action, EnforcementAction::Allow)
        }) && !self.enforcement_actions.iter().any(|action| {
            matches!(action, EnforcementAction::Deny)
        })
    }

    /// Check if user justification is required
    pub fn requires_justification(&self) -> bool {
        self.enforcement_actions.iter().any(|action| {
            matches!(action, EnforcementAction::RequireJustification { .. })
        })
    }

    /// Get justification prompt if required
    pub fn justification_prompt(&self) -> Option<&str> {
        for action in &self.enforcement_actions {
            if let EnforcementAction::RequireJustification { prompt } = action {
                return Some(prompt);
            }
        }
        None
    }

    /// Check if MFA is required
    pub fn requires_mfa(&self) -> bool {
        self.enforcement_actions.iter().any(|action| {
            matches!(action, EnforcementAction::RequireMFA { .. })
        })
    }

    /// Get clipboard auto-clear timeout
    pub fn clipboard_auto_clear_ms(&self) -> Option<u64> {
        for action in &self.enforcement_actions {
            if let EnforcementAction::AutoClearClipboard { after_ms } = action {
                return Some(*after_ms);
            }
        }
        None
    }

    /// Check if preview should be masked
    pub fn should_mask_preview(&self) -> bool {
        self.enforcement_actions.iter().any(|action| {
            matches!(action, EnforcementAction::MaskPreview)
        })
    }

    /// Check if file should be quarantined
    pub fn should_quarantine(&self) -> bool {
        self.enforcement_actions.iter().any(|action| {
            matches!(action, EnforcementAction::QuarantineFile { .. })
        })
    }

    /// Get operation time limit
    pub fn time_limit_ms(&self) -> Option<u64> {
        for action in &self.enforcement_actions {
            if let EnforcementAction::ApplyTimeLimit { duration_ms } = action {
                return Some(*duration_ms);
            }
        }
        None
    }

    /// Get size limit
    pub fn size_limit_mb(&self) -> Option<u64> {
        for action in &self.enforcement_actions {
            if let EnforcementAction::LimitScope { max_size_mb } = action {
                return Some(*max_size_mb);
            }
        }
        None
    }

    /// Get warning message for user
    pub fn warning_message(&self) -> Option<&str> {
        for action in &self.enforcement_actions {
            if let EnforcementAction::ShowWarning { message } = action {
                return Some(message);
            }
        }
        None
    }

    /// Get audit actions
    pub fn audit_actions(&self) -> Vec<&EnforcementAction> {
        self.enforcement_actions.iter()
            .filter(|action| matches!(action, EnforcementAction::AuditLog { .. }))
            .collect()
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.effect {
            Effect::Allow => write!(f, "ALLOW"),
            Effect::Deny => write!(f, "DENY"),
            Effect::AllowWithJustification => write!(f, "ALLOW_WITH_JUSTIFICATION"),
        }?;

        if let Some(rule_id) = &self.matched_rule_id {
            write!(f, " (rule: {})", rule_id)?;
        }

        if let Some(reason) = &self.reason {
            write!(f, " - {}", reason)?;
        }

        Ok(())
    }
}

impl fmt::Display for EnforcementAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnforcementAction::Allow => write!(f, "Allow"),
            EnforcementAction::Deny => write!(f, "Deny"),
            EnforcementAction::RequireJustification { prompt } => {
                write!(f, "Require justification: {}", prompt)
            }
            EnforcementAction::ApplyTimeLimit { duration_ms } => {
                write!(f, "Time limit: {}ms", duration_ms)
            }
            EnforcementAction::AutoClearClipboard { after_ms } => {
                write!(f, "Auto-clear clipboard after {}ms", after_ms)
            }
            EnforcementAction::MaskPreview => write!(f, "Mask preview"),
            EnforcementAction::QuarantineFile { path } => {
                write!(f, "Quarantine file: {}", path)
            }
            EnforcementAction::RequireMFA { method } => {
                write!(f, "Require MFA: {}", method)
            }
            EnforcementAction::AuditLog { level, details } => {
                write!(f, "Audit log ({:?}): {}", level, details)
            }
            EnforcementAction::ShowWarning { message } => {
                write!(f, "Warning: {}", message)
            }
            EnforcementAction::LimitScope { max_size_mb } => {
                write!(f, "Size limit: {}MB", max_size_mb)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Constraints;

    #[test]
    fn test_policy_decision_creation() {
        let allow = PolicyDecision::allow();
        assert!(allow.is_allowed());
        assert!(!allow.requires_justification());
        assert!(!allow.is_denied());

        let deny = PolicyDecision::deny("Test reason");
        assert!(!deny.is_allowed());
        assert!(!deny.requires_justification());
        assert!(deny.is_denied());
        assert_eq!(deny.reason(), Some("Test reason"));

        let justify = PolicyDecision::allow_with_justification("Sensitive operation");
        assert!(justify.is_allowed());
        assert!(justify.requires_justification());
        assert!(!justify.is_denied());
    }

    #[test]
    fn test_enforcement_conversion() {
        let decision = PolicyDecision {
            effect: Effect::AllowWithJustification,
            matched_rule_id: Some("test-rule".to_string()),
            constraints: Some(Constraints {
                auto_clear_ms: Some(30000),
                mask_preview: Some(true),
                quarantine: Some(false),
                max_duration_ms: None,
                max_size_mb: Some(100),
            }),
            reason: Some("Test".to_string()),
        };

        let enforcement = decision.to_enforcement();
        
        assert!(enforcement.requires_justification());
        assert_eq!(enforcement.clipboard_auto_clear_ms(), Some(30000));
        assert!(enforcement.should_mask_preview());
        assert!(!enforcement.should_quarantine());
        assert_eq!(enforcement.size_limit_mb(), Some(100));
        assert!(enforcement.audit_required);
    }

    #[test]
    fn test_display_formatting() {
        let decision = PolicyDecision {
            effect: Effect::Deny,
            matched_rule_id: Some("deny-rule".to_string()),
            constraints: None,
            reason: Some("Access forbidden".to_string()),
        };

        let display = format!("{}", decision);
        assert!(display.contains("DENY"));
        assert!(display.contains("deny-rule"));
        assert!(display.contains("Access forbidden"));
    }
}
