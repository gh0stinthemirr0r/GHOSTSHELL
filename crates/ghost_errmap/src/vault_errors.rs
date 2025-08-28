use super::{ErrorMapper, ErrorMapping, ErrorCategory, ErrorSeverity, ErrorClassification, ErrorMapResult, ErrorMapError, compile_pattern};
use regex::Regex;

pub struct VaultErrorMapper {
    patterns: Vec<(Regex, ErrorMapping)>,
}

impl VaultErrorMapper {
    pub fn new() -> Self {
        let mut mapper = Self {
            patterns: Vec::new(),
        };
        mapper.load_patterns();
        mapper
    }

    fn load_patterns(&mut self) {
        let mappings = vec![
            ErrorMapping {
                pattern: r"(?i)secret\s+expired|key\s+expired".to_string(),
                category: ErrorCategory::Cryptography,
                severity: ErrorSeverity::Critical,
                description: "Vault secret or key has expired".to_string(),
                common_causes: vec![
                    "Secret reached TTL limit".to_string(),
                    "Automatic rotation failed".to_string(),
                    "Manual rotation overdue".to_string(),
                    "Policy enforcement triggered".to_string(),
                ],
                suggested_actions: vec![
                    "Rotate expired secret immediately".to_string(),
                    "Update applications using the secret".to_string(),
                    "Check rotation policy settings".to_string(),
                    "Run secret rotation playbook".to_string(),
                ],
                playbook_refs: vec![
                    "pb-vault-secret-rotation".to_string(),
                    "pb-emergency-key-renewal".to_string(),
                ],
                confidence: 0.95,
            },
            ErrorMapping {
                pattern: r"(?i)vault\s+sealed|vault\s+is\s+sealed".to_string(),
                category: ErrorCategory::Configuration,
                severity: ErrorSeverity::Critical,
                description: "Vault is in sealed state".to_string(),
                common_causes: vec![
                    "Vault restart without auto-unseal".to_string(),
                    "Seal threshold reached".to_string(),
                    "Manual seal operation".to_string(),
                    "Security incident response".to_string(),
                ],
                suggested_actions: vec![
                    "Unseal vault with authorized keys".to_string(),
                    "Check vault status and logs".to_string(),
                    "Verify unseal key availability".to_string(),
                    "Contact vault administrator".to_string(),
                ],
                playbook_refs: vec![
                    "pb-vault-unseal".to_string(),
                    "pb-vault-emergency-recovery".to_string(),
                ],
                confidence: 0.98,
            },
            ErrorMapping {
                pattern: r"(?i)permission\s+denied|access\s+denied".to_string(),
                category: ErrorCategory::Authorization,
                severity: ErrorSeverity::Error,
                description: "Insufficient vault permissions".to_string(),
                common_causes: vec![
                    "Token lacks required policy".to_string(),
                    "Path not accessible to user".to_string(),
                    "Token expired".to_string(),
                    "Role permissions insufficient".to_string(),
                ],
                suggested_actions: vec![
                    "Check token policies".to_string(),
                    "Renew or refresh token".to_string(),
                    "Request additional permissions".to_string(),
                    "Verify path accessibility".to_string(),
                ],
                playbook_refs: vec![
                    "pb-vault-token-management".to_string(),
                    "pb-vault-policy-update".to_string(),
                ],
                confidence: 0.90,
            },
            ErrorMapping {
                pattern: r"(?i)connection\s+refused|vault\s+unreachable".to_string(),
                category: ErrorCategory::Network,
                severity: ErrorSeverity::Critical,
                description: "Cannot connect to Vault service".to_string(),
                common_causes: vec![
                    "Vault service down".to_string(),
                    "Network connectivity issue".to_string(),
                    "Firewall blocking connection".to_string(),
                    "Wrong vault address".to_string(),
                ],
                suggested_actions: vec![
                    "Check vault service status".to_string(),
                    "Verify network connectivity".to_string(),
                    "Test vault address and port".to_string(),
                    "Check firewall rules".to_string(),
                ],
                playbook_refs: vec![
                    "pb-vault-service-check".to_string(),
                    "pb-network-diagnostics".to_string(),
                ],
                confidence: 0.92,
            },
            ErrorMapping {
                pattern: r"(?i)invalid\s+token|token\s+expired".to_string(),
                category: ErrorCategory::Authentication,
                severity: ErrorSeverity::Error,
                description: "Vault token is invalid or expired".to_string(),
                common_causes: vec![
                    "Token TTL exceeded".to_string(),
                    "Token revoked".to_string(),
                    "Invalid token format".to_string(),
                    "Token not found".to_string(),
                ],
                suggested_actions: vec![
                    "Authenticate to get new token".to_string(),
                    "Check token TTL settings".to_string(),
                    "Verify token format".to_string(),
                    "Use token renewal if available".to_string(),
                ],
                playbook_refs: vec![
                    "pb-vault-authentication".to_string(),
                    "pb-token-renewal".to_string(),
                ],
                confidence: 0.94,
            },
        ];

        for mapping in mappings {
            if let Ok(regex) = compile_pattern(&mapping.pattern) {
                self.patterns.push((regex, mapping));
            }
        }
    }
}

impl ErrorMapper for VaultErrorMapper {
    fn classify_error(&self, error_text: &str) -> ErrorMapResult<ErrorClassification> {
        for (regex, mapping) in &self.patterns {
            if regex.is_match(error_text) {
                return Ok(ErrorClassification {
                    category: mapping.category.clone(),
                    severity: mapping.severity.clone(),
                    description: mapping.description.clone(),
                    common_causes: mapping.common_causes.clone(),
                    suggested_actions: mapping.suggested_actions.clone(),
                    playbook_refs: mapping.playbook_refs.clone(),
                    confidence: mapping.confidence,
                    matched_pattern: mapping.pattern.clone(),
                });
            }
        }
        
        Err(ErrorMapError::NoMappingFound(error_text.to_string()))
    }

    fn get_category(&self) -> &str {
        "vault"
    }

    fn get_patterns(&self) -> &[ErrorMapping] {
        &[]
    }
}

impl Default for VaultErrorMapper {
    fn default() -> Self {
        Self::new()
    }
}
