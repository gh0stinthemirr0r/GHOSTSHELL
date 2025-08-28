use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tauri::{State, Window};
use chrono::Utc;

use ghost_policy::{
    PolicyEvaluator, ExecutionContext, ContextBuilder, PolicyDecision, EnforcementDecision,
    Resource, Action, NetworkTrust, SensitivityLevel, Policy
};
use ghost_log::{
    AuditLogger, EventType, Severity, Actor, ActorType, 
    ResourceType, Action as LogAction, Outcome
};
use ghost_log::entry::LogEntryBuilder;

/// Policy Enforcement Point - mediates all access decisions
pub struct PolicyEnforcementPoint {
    evaluator: Arc<RwLock<Option<PolicyEvaluator>>>,
    audit_logger: Arc<RwLock<Option<AuditLogger>>>,
    current_user: Arc<RwLock<Option<String>>>,
    session_context: Arc<RwLock<HashMap<String, String>>>,
}

/// Policy statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyStats {
    pub version: String,
    pub total_rules: u32,
    pub has_policy: bool,
}

/// PEP decision with enforcement actions
#[derive(Debug, Clone)]
pub struct PepDecision {
    pub allowed: bool,
    pub requires_justification: bool,
    pub justification_prompt: Option<String>,
    pub auto_clear_clipboard_ms: Option<u64>,
    pub mask_preview: bool,
    pub quarantine_file: bool,
    pub time_limit_ms: Option<u64>,
    pub size_limit_mb: Option<u64>,
    pub warning_message: Option<String>,
    pub audit_required: bool,
    pub policy_rule_id: Option<String>,
}

impl Default for PolicyEnforcementPoint {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEnforcementPoint {
    /// Create new PEP instance
    pub fn new() -> Self {
        Self {
            evaluator: Arc::new(RwLock::new(None)),
            audit_logger: Arc::new(RwLock::new(None)),
            current_user: Arc::new(RwLock::new(None)),
            session_context: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize PEP with policy and audit logger
    pub async fn initialize(&self, policy: Policy, database_path: &str) -> anyhow::Result<()> {
        // Initialize policy evaluator
        let evaluator = PolicyEvaluator::new(policy);
        let mut eval_guard = self.evaluator.write().await;
        *eval_guard = Some(evaluator);
        drop(eval_guard);

        // Initialize audit logger
        let logger = AuditLogger::new(database_path, "ghostshell_audit".to_string(), Default::default()).await?;
        let mut logger_guard = self.audit_logger.write().await;
        *logger_guard = Some(logger);
        drop(logger_guard);

        tracing::info!("Policy Enforcement Point initialized");
        Ok(())
    }

    /// Set current user context
    pub async fn set_user(&self, user_id: String) {
        let mut user_guard = self.current_user.write().await;
        *user_guard = Some(user_id);
    }

    /// Update session context
    pub async fn update_session_context(&self, key: String, value: String) {
        let mut context_guard = self.session_context.write().await;
        context_guard.insert(key, value);
    }

    /// Evaluate access request
    pub async fn evaluate_access(
        &self,
        resource: Resource,
        action: Action,
        context: Option<HashMap<String, String>>,
        window: Option<&Window>,
    ) -> anyhow::Result<PepDecision> {
        // Get current user
        let user_id = {
            let user_guard = self.current_user.read().await;
            user_guard.clone().unwrap_or_else(|| "anonymous".to_string())
        };

        // Build execution context
        let mut exec_context = ContextBuilder::new()
            .user(&user_id, "user") // TODO: Get actual role from user management
            .pq_available(true) // TODO: Detect actual PQ availability
            .network_trust(NetworkTrust::Trusted) // TODO: Detect network context
            .sensitivity(SensitivityLevel::Internal) // TODO: Classify based on resource
            .build();

        // Add session context
        {
            let session_guard = self.session_context.read().await;
            for (key, value) in session_guard.iter() {
                exec_context = exec_context.with_env(key, value);
            }
        }

        // Add request-specific context
        if let Some(ctx) = context {
            for (key, value) in ctx {
                exec_context = exec_context.with_env(&key, &value);
            }
        }

        // Add window context if available
        if let Some(window) = window {
            exec_context = exec_context.with_env("window_label", &window.label().to_string());
        }

        // Evaluate policy
        let policy_decision = {
            let evaluator_guard = self.evaluator.read().await;
            if let Some(evaluator) = evaluator_guard.as_ref() {
                let policy_context = exec_context.to_policy_context();
                evaluator.evaluate(&exec_context.subject, &resource, &action, &policy_context)
            } else {
                // Default deny if no policy loaded
                PolicyDecision::deny("No policy loaded")
            }
        };

        // Convert to enforcement decision
        let enforcement = policy_decision.to_enforcement();

        // Create PEP decision
        let pep_decision = PepDecision {
            allowed: enforcement.should_allow(),
            requires_justification: enforcement.requires_justification(),
            justification_prompt: enforcement.justification_prompt().map(|s| s.to_string()),
            auto_clear_clipboard_ms: enforcement.clipboard_auto_clear_ms(),
            mask_preview: enforcement.should_mask_preview(),
            quarantine_file: enforcement.should_quarantine(),
            time_limit_ms: enforcement.time_limit_ms(),
            size_limit_mb: enforcement.size_limit_mb(),
            warning_message: enforcement.warning_message().map(|s| s.to_string()),
            audit_required: enforcement.audit_required,
            policy_rule_id: policy_decision.matched_rule_id.clone(),
        };

        // Audit the decision
        self.audit_decision(&user_id, &resource, &action, &policy_decision, &exec_context).await?;

        Ok(pep_decision)
    }

    /// Audit policy decision
    async fn audit_decision(
        &self,
        user_id: &str,
        resource: &Resource,
        action: &Action,
        decision: &PolicyDecision,
        context: &ExecutionContext,
    ) -> anyhow::Result<()> {
        let logger_guard = self.audit_logger.read().await;
        if let Some(logger) = logger_guard.as_ref() {
            let actor = Actor {
                actor_type: ActorType::User,
                id: user_id.to_string(),
                name: None,
                session_id: context.session.as_ref().map(|s| s.session_id.clone()),
                ip_address: context.environment.get("client_ip").cloned(),
                user_agent: context.environment.get("user_agent").cloned(),
            };

            let log_resource = ghost_log::Resource {
                resource_type: map_policy_resource_to_log(resource),
                id: context.environment.get("resource_id").cloned(),
                name: context.environment.get("resource_name").cloned(),
                path: context.environment.get("resource_path").cloned(),
                attributes: HashMap::new(),
            };

            let log_action = map_policy_action_to_log(action);
            let outcome = if decision.is_allowed() { Outcome::Success } else { Outcome::Denied };
            let severity = if decision.is_denied() { Severity::Warning } else { Severity::Info };
            let event_type = if decision.is_denied() { EventType::PolicyViolation } else { EventType::Authorization };

            let mut log_builder = logger.log_event().await
                .event_type(event_type)
                .severity(severity)
                .actor(actor)
                .resource(log_resource)
                .action(log_action)
                .outcome(outcome)
                .message(format!("Policy decision: {} for {} on {}", 
                    if decision.is_allowed() { "ALLOW" } else { "DENY" },
                    format!("{:?}", action),
                    format!("{:?}", resource)
                ));

            // Add policy rule ID if available
            if let Some(rule_id) = &decision.matched_rule_id {
                log_builder = log_builder.policy_rule(rule_id.clone());
            }

            // Add context information
            for (key, value) in &context.environment {
                log_builder = log_builder.context(key.clone(), value.clone());
            }

            log_builder.submit().await?;
        }

        Ok(())
    }

    /// Load policy from file
    pub async fn load_policy(&self, policy_content: &str) -> anyhow::Result<()> {
        let policy = Policy::from_string(policy_content)?;
        policy.validate()?;

        let evaluator = PolicyEvaluator::new(policy);
        let mut eval_guard = self.evaluator.write().await;
        *eval_guard = Some(evaluator);

        tracing::info!("Policy loaded and validated");
        Ok(())
    }

    /// Get policy statistics
    pub async fn get_policy_stats(&self) -> Option<PolicyStats> {
        let evaluator_guard = self.evaluator.read().await;
        if let Some(evaluator) = evaluator_guard.as_ref() {
            Some(PolicyStats {
                version: "1.0".to_string(), // Default version
                total_rules: 0, // TODO: Add method to get rule count
                has_policy: true,
            })
        } else {
            Some(PolicyStats {
                version: "none".to_string(),
                total_rules: 0,
                has_policy: false,
            })
        }
    }

    /// Dry-run policy evaluation for testing
    pub async fn dry_run_policy(
        &self,
        resource: Resource,
        action: Action,
        context: HashMap<String, String>,
    ) -> anyhow::Result<DryRunResult> {
        let user_id = {
            let user_guard = self.current_user.read().await;
            user_guard.clone().unwrap_or_else(|| "test_user".to_string())
        };

        let mut exec_context = ContextBuilder::new()
            .user(&user_id, "user")
            .pq_available(true)
            .build();

        for (key, value) in context {
            exec_context = exec_context.with_env(&key, &value);
        }

        let evaluator_guard = self.evaluator.read().await;
        if let Some(evaluator) = evaluator_guard.as_ref() {
            let policy_context = exec_context.to_policy_context();
            let dry_run = evaluator.dry_run(&exec_context.subject, &resource, &action, &policy_context);
            
            Ok(DryRunResult {
                decision: dry_run.decision,
                evaluated_rules: dry_run.evaluated_rules.len(),
                warnings: dry_run.warnings,
                context_used: dry_run.context_used,
            })
        } else {
            Err(anyhow::anyhow!("No policy loaded"))
        }
    }
}



/// Dry run result for UI
#[derive(Debug, Clone, serde::Serialize)]
pub struct DryRunResult {
    pub decision: PolicyDecision,
    pub evaluated_rules: usize,
    pub warnings: Vec<String>,
    pub context_used: HashMap<String, String>,
}

/// Map policy resource to log resource type
fn map_policy_resource_to_log(resource: &Resource) -> ResourceType {
    match resource {
        Resource::Terminal => ResourceType::Terminal,
        Resource::Ssh => ResourceType::SshConnection,
        Resource::Vault => ResourceType::Vault,
        Resource::Vpn => ResourceType::Network,
        Resource::Browser => ResourceType::Network,
        Resource::Files => ResourceType::File,
        Resource::Clipboard => ResourceType::File, // Closest match
        Resource::Network => ResourceType::Network,
        Resource::Theme => ResourceType::Theme,
        Resource::Settings => ResourceType::Configuration,
        Resource::Logs => ResourceType::Log,
        Resource::Policy => ResourceType::Configuration,
    }
}

/// Map policy action to log action
fn map_policy_action_to_log(action: &Action) -> LogAction {
    match action {
        Action::Read => LogAction::Read,
        Action::Write => LogAction::Update,
        Action::Exec => LogAction::Execute,
        Action::Connect => LogAction::Connect,
        Action::Download => LogAction::Read,
        Action::Upload => LogAction::Create,
        Action::Autofill => LogAction::Read,
        Action::Copy => LogAction::Copy,
        Action::Paste => LogAction::Create,
        Action::Delete => LogAction::Delete,
        Action::Create => LogAction::Create,
        Action::Update => LogAction::Update,
        Action::Export => LogAction::Export,
        Action::Import => LogAction::Import,
        Action::Switch => LogAction::Update,
        Action::Apply => LogAction::Update,
        Action::Reload => LogAction::Read,
        Action::Query => LogAction::Query,
        Action::Browse => LogAction::Read,
        Action::Search => LogAction::Search,
    }
}

/// Tauri state wrapper for PEP
pub type PepState = Arc<PolicyEnforcementPoint>;

/// Initialize PEP for Tauri
pub async fn initialize_pep() -> anyhow::Result<PepState> {
    let pep = Arc::new(PolicyEnforcementPoint::new());
    
    // Load default restrictive policy
    let default_policy = Policy::restrictive_default();
    
    // Use the pre-created database file
    let database_path = "data/ghostshell_audit.db";
    
    // Ensure the database file exists
    if !std::path::Path::new(database_path).exists() {
        tracing::warn!("Database file not found at {}, falling back to in-memory database", database_path);
        let database_path = ":memory:";
        pep.initialize(default_policy, database_path).await?;
    } else {
        tracing::info!("Initializing PEP with database: {}", database_path);
        pep.initialize(default_policy, database_path).await?;
    }
    
    Ok(pep)
}



/// Macro for easy PEP enforcement in Tauri commands
#[macro_export]
macro_rules! enforce_policy {
    ($pep:expr, $resource:expr, $action:expr, $window:expr) => {
        {
            let decision = $pep.evaluate_access($resource, $action, None, Some($window)).await.map_err(|e| e.to_string())?;
            if !decision.allowed {
                return Err(format!("Access denied by policy: {}", 
                    decision.warning_message.unwrap_or_else(|| "No reason provided".to_string())));
            }
            decision
        }
    };
    
    ($pep:expr, $resource:expr, $action:expr, $context:expr, $window:expr) => {
        {
            let decision = $pep.evaluate_access($resource, $action, Some($context), Some($window)).await.map_err(|e| e.to_string())?;
            if !decision.allowed {
                return Err(format!("Access denied by policy: {}", 
                    decision.warning_message.unwrap_or_else(|| "No reason provided".to_string())));
            }
            decision
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_policy::{Policy, PolicyRule, Effect};

    #[tokio::test]
    async fn test_pep_initialization() {
        let pep = PolicyEnforcementPoint::new();
        let policy = Policy::restrictive_default();
        
        let result = pep.initialize(policy, ":memory:").await;
        assert!(result.is_ok());
        
        let stats = pep.get_policy_stats().await.unwrap();
        assert!(stats.has_policy);
        assert!(stats.total_rules > 0);
    }

    #[tokio::test]
    async fn test_access_evaluation() {
        let pep = PolicyEnforcementPoint::new();
        let policy = Policy::development_default(); // More permissive for testing
        
        pep.initialize(policy, ":memory:").await.unwrap();
        pep.set_user("test_user".to_string()).await;
        
        let decision = pep.evaluate_access(
            Resource::Terminal,
            Action::Read,
            None,
            None,
        ).await.unwrap();
        
        // Development policy should allow terminal read
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn test_policy_loading() {
        let pep = PolicyEnforcementPoint::new();
        
        let policy_toml = r#"
            version = 1
            
            [[rules]]
            id = "allow-terminal-read"
            resource = "Terminal"
            action = "Read"
            effect = "Allow"
        "#;
        
        let result = pep.load_policy(policy_toml).await;
        assert!(result.is_ok());
        
        let stats = pep.get_policy_stats().await.unwrap();
        assert!(stats.has_policy);
        assert_eq!(stats.total_rules, 1);
    }
}
