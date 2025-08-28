use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Execution context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Subject attributes (user, role, etc.)
    pub subject: HashMap<String, String>,
    
    /// Environmental context
    pub environment: HashMap<String, String>,
    
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Session information
    pub session: Option<SessionContext>,
    
    /// Security context
    pub security: SecurityContext,
}

/// Session-specific context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub mfa_verified: bool,
    pub mfa_expires_at: Option<DateTime<Utc>>,
}

/// Security-related context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Post-quantum cryptography availability
    pub pq_available: bool,
    
    /// VPN connection status
    pub vpn_active: bool,
    
    /// Current network trust level
    pub network_trust: NetworkTrust,
    
    /// Host security tags
    pub host_tags: Vec<String>,
    
    /// Data sensitivity classification
    pub sensitivity_level: SensitivityLevel,
    
    /// Digital signature verification
    pub signature_info: Option<SignatureInfo>,
}

/// Network trust levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkTrust {
    Trusted,    // Corporate network, localhost
    Untrusted,  // Public WiFi, unknown networks
    Hostile,    // Known malicious networks
}

/// Data sensitivity classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SensitivityLevel {
    Public,
    Internal,
    Confidential,
    Secret,
    TopSecret,
}

/// Digital signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub signer_id: String,
    pub algorithm: String,
    pub verified: bool,
    pub signed_at: DateTime<Utc>,
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new(subject: HashMap<String, String>) -> Self {
        Self {
            subject,
            environment: HashMap::new(),
            timestamp: Utc::now(),
            session: None,
            security: SecurityContext::default(),
        }
    }

    /// Create context for a specific user
    pub fn for_user(user_id: &str, role: &str) -> Self {
        let mut subject = HashMap::new();
        subject.insert("user_id".to_string(), user_id.to_string());
        subject.insert("role".to_string(), role.to_string());
        
        Self::new(subject)
    }

    /// Add environment variable
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.environment.insert(key.to_string(), value.to_string());
        self
    }

    /// Set session information
    pub fn with_session(mut self, session: SessionContext) -> Self {
        self.session = Some(session);
        self
    }

    /// Set security context
    pub fn with_security(mut self, security: SecurityContext) -> Self {
        self.security = security;
        self
    }

    /// Convert to policy evaluation format
    pub fn to_policy_context(&self) -> HashMap<String, String> {
        let mut context = self.environment.clone();
        
        // Add security context
        context.insert("pq_available".to_string(), self.security.pq_available.to_string());
        context.insert("vpn_active".to_string(), self.security.vpn_active.to_string());
        context.insert("network_trust".to_string(), format!("{:?}", self.security.network_trust));
        context.insert("sensitivity".to_string(), format!("{:?}", self.security.sensitivity_level));
        context.insert("host_tags".to_string(), self.security.host_tags.join(","));
        
        // Add session context if available
        if let Some(session) = &self.session {
            context.insert("session_id".to_string(), session.session_id.clone());
            context.insert("mfa_verified".to_string(), session.mfa_verified.to_string());
            
            if let Some(mfa_expires) = session.mfa_expires_at {
                let now = Utc::now();
                context.insert("mfa_valid".to_string(), (now < mfa_expires).to_string());
            }
        }
        
        // Add signature info if available
        if let Some(sig) = &self.security.signature_info {
            context.insert("signed_by".to_string(), sig.signer_id.clone());
            context.insert("signature_verified".to_string(), sig.verified.to_string());
            context.insert("signature_algorithm".to_string(), sig.algorithm.clone());
        }
        
        context
    }

    /// Check if MFA is currently valid
    pub fn is_mfa_valid(&self) -> bool {
        if let Some(session) = &self.session {
            if !session.mfa_verified {
                return false;
            }
            
            if let Some(expires_at) = session.mfa_expires_at {
                return Utc::now() < expires_at;
            }
            
            true
        } else {
            false
        }
    }

    /// Check if post-quantum crypto is required for this context
    pub fn requires_pq(&self) -> bool {
        match self.security.sensitivity_level {
            SensitivityLevel::Secret | SensitivityLevel::TopSecret => true,
            SensitivityLevel::Confidential => !matches!(self.security.network_trust, NetworkTrust::Trusted),
            _ => false,
        }
    }

    /// Get user role
    pub fn user_role(&self) -> Option<&String> {
        self.subject.get("role")
    }

    /// Get user ID
    pub fn user_id(&self) -> Option<&String> {
        self.subject.get("user_id")
    }

    /// Check if user has specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.user_role().map_or(false, |r| r == role)
    }

    /// Add host security tag
    pub fn add_host_tag(&mut self, tag: String) {
        if !self.security.host_tags.contains(&tag) {
            self.security.host_tags.push(tag);
        }
    }

    /// Set data sensitivity level
    pub fn set_sensitivity(&mut self, level: SensitivityLevel) {
        self.security.sensitivity_level = level;
    }

    /// Update network trust level
    pub fn set_network_trust(&mut self, trust: NetworkTrust) {
        self.security.network_trust = trust;
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self {
            pq_available: false,
            vpn_active: false,
            network_trust: NetworkTrust::Untrusted,
            host_tags: Vec::new(),
            sensitivity_level: SensitivityLevel::Internal,
            signature_info: None,
        }
    }
}

impl SessionContext {
    /// Create a new session context
    pub fn new(session_id: String) -> Self {
        let now = Utc::now();
        Self {
            session_id,
            started_at: now,
            last_activity: now,
            mfa_verified: false,
            mfa_expires_at: None,
        }
    }

    /// Mark MFA as verified with expiration
    pub fn verify_mfa(&mut self, expires_in_minutes: u32) {
        self.mfa_verified = true;
        self.mfa_expires_at = Some(Utc::now() + chrono::Duration::minutes(expires_in_minutes as i64));
    }

    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Check if session is expired (inactive for too long)
    pub fn is_expired(&self, max_idle_minutes: u32) -> bool {
        let max_idle = chrono::Duration::minutes(max_idle_minutes as i64);
        Utc::now() - self.last_activity > max_idle
    }
}

/// Context builder for fluent API
pub struct ContextBuilder {
    context: ExecutionContext,
}

impl ContextBuilder {
    pub fn new() -> Self {
        Self {
            context: ExecutionContext::new(HashMap::new()),
        }
    }

    pub fn user(mut self, user_id: &str, role: &str) -> Self {
        self.context.subject.insert("user_id".to_string(), user_id.to_string());
        self.context.subject.insert("role".to_string(), role.to_string());
        self
    }

    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.context.environment.insert(key.to_string(), value.to_string());
        self
    }

    pub fn pq_available(mut self, available: bool) -> Self {
        self.context.security.pq_available = available;
        self
    }

    pub fn vpn_active(mut self, active: bool) -> Self {
        self.context.security.vpn_active = active;
        self
    }

    pub fn network_trust(mut self, trust: NetworkTrust) -> Self {
        self.context.security.network_trust = trust;
        self
    }

    pub fn sensitivity(mut self, level: SensitivityLevel) -> Self {
        self.context.security.sensitivity_level = level;
        self
    }

    pub fn host_tag(mut self, tag: &str) -> Self {
        self.context.security.host_tags.push(tag.to_string());
        self
    }

    pub fn session(mut self, session_id: &str, mfa_verified: bool) -> Self {
        let mut session = SessionContext::new(session_id.to_string());
        if mfa_verified {
            session.verify_mfa(30); // 30 minute default
        }
        self.context.session = Some(session);
        self
    }

    pub fn build(self) -> ExecutionContext {
        self.context
    }
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let context = ContextBuilder::new()
            .user("alice", "admin")
            .env("pane", "terminal")
            .pq_available(true)
            .vpn_active(false)
            .sensitivity(SensitivityLevel::Confidential)
            .host_tag("corporate")
            .session("sess123", true)
            .build();

        assert_eq!(context.user_id(), Some(&"alice".to_string()));
        assert_eq!(context.user_role(), Some(&"admin".to_string()));
        assert!(context.security.pq_available);
        assert!(!context.security.vpn_active);
        assert!(context.is_mfa_valid());
        assert!(context.has_role("admin"));
    }

    #[test]
    fn test_policy_context_conversion() {
        let context = ContextBuilder::new()
            .user("bob", "user")
            .pq_available(true)
            .vpn_active(true)
            .sensitivity(SensitivityLevel::Secret)
            .build();

        let policy_context = context.to_policy_context();
        
        assert_eq!(policy_context.get("pq_available"), Some(&"true".to_string()));
        assert_eq!(policy_context.get("vpn_active"), Some(&"true".to_string()));
        assert_eq!(policy_context.get("sensitivity"), Some(&"Secret".to_string()));
    }

    #[test]
    fn test_pq_requirements() {
        let mut context = ContextBuilder::new()
            .sensitivity(SensitivityLevel::Secret)
            .build();
        
        assert!(context.requires_pq());

        context.set_sensitivity(SensitivityLevel::Public);
        assert!(!context.requires_pq());

        context.set_sensitivity(SensitivityLevel::Confidential);
        context.set_network_trust(NetworkTrust::Untrusted);
        assert!(context.requires_pq());

        context.set_network_trust(NetworkTrust::Trusted);
        assert!(!context.requires_pq());
    }

    #[test]
    fn test_session_expiration() {
        let mut session = SessionContext::new("test".to_string());
        
        // Fresh session should not be expired
        assert!(!session.is_expired(30));
        
        // Manually set old timestamp
        session.last_activity = Utc::now() - chrono::Duration::minutes(45);
        assert!(session.is_expired(30));
    }
}
