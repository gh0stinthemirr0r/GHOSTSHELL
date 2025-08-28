use super::{ErrorMapper, ErrorMapping, ErrorCategory, ErrorSeverity, ErrorClassification, ErrorMapResult, ErrorMapError, compile_pattern};
use regex::Regex;

pub struct SSHErrorMapper {
    patterns: Vec<(Regex, ErrorMapping)>,
}

impl SSHErrorMapper {
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
                pattern: r"(?i)permission\s+denied\s*\(publickey\)".to_string(),
                category: ErrorCategory::Authentication,
                severity: ErrorSeverity::Error,
                description: "SSH public key authentication failed".to_string(),
                common_causes: vec![
                    "SSH key not added to authorized_keys".to_string(),
                    "SSH key expired or rotated".to_string(),
                    "Wrong SSH key being used".to_string(),
                    "Vault key expired".to_string(),
                ],
                suggested_actions: vec![
                    "Check Vault for expired keys".to_string(),
                    "Rotate SSH key in Vault".to_string(),
                    "Verify SSH key is in authorized_keys".to_string(),
                    "Run SSH key rotation playbook".to_string(),
                ],
                playbook_refs: vec![
                    "pb-rotate-ssh-keys".to_string(),
                    "pb-vault-key-renewal".to_string(),
                ],
                confidence: 0.95,
            },
            ErrorMapping {
                pattern: r"(?i)connection\s+refused".to_string(),
                category: ErrorCategory::Network,
                severity: ErrorSeverity::Error,
                description: "SSH connection refused by remote host".to_string(),
                common_causes: vec![
                    "SSH daemon not running".to_string(),
                    "Port blocked by firewall".to_string(),
                    "Host unreachable".to_string(),
                    "Service overloaded".to_string(),
                ],
                suggested_actions: vec![
                    "Check if SSH service is running".to_string(),
                    "Verify firewall rules".to_string(),
                    "Test network connectivity".to_string(),
                    "Check service status".to_string(),
                ],
                playbook_refs: vec![
                    "pb-network-diagnostics".to_string(),
                    "pb-ssh-service-check".to_string(),
                ],
                confidence: 0.90,
            },
            ErrorMapping {
                pattern: r"(?i)host\s+key\s+verification\s+failed".to_string(),
                category: ErrorCategory::Cryptography,
                severity: ErrorSeverity::Critical,
                description: "SSH host key verification failed".to_string(),
                common_causes: vec![
                    "Host key changed (possible MITM attack)".to_string(),
                    "Host was reinstalled".to_string(),
                    "DNS spoofing".to_string(),
                    "Load balancer configuration change".to_string(),
                ],
                suggested_actions: vec![
                    "Verify host identity through secure channel".to_string(),
                    "Update known_hosts file if legitimate".to_string(),
                    "Investigate potential security breach".to_string(),
                    "Contact system administrator".to_string(),
                ],
                playbook_refs: vec![
                    "pb-host-key-verification".to_string(),
                    "pb-security-incident".to_string(),
                ],
                confidence: 0.98,
            },
            ErrorMapping {
                pattern: r"(?i)no\s+matching\s+key\s+exchange\s+method".to_string(),
                category: ErrorCategory::Cryptography,
                severity: ErrorSeverity::Error,
                description: "SSH key exchange algorithm mismatch".to_string(),
                common_causes: vec![
                    "Post-quantum only policy enforced".to_string(),
                    "Legacy SSH client/server".to_string(),
                    "Cryptographic policy mismatch".to_string(),
                    "Algorithm deprecation".to_string(),
                ],
                suggested_actions: vec![
                    "Enable post-quantum SSH algorithms".to_string(),
                    "Update SSH client configuration".to_string(),
                    "Check cryptographic policy settings".to_string(),
                    "Use PQ-compatible SSH client".to_string(),
                ],
                playbook_refs: vec![
                    "pb-pq-ssh-config".to_string(),
                    "pb-crypto-policy-update".to_string(),
                ],
                confidence: 0.92,
            },
            ErrorMapping {
                pattern: r"(?i)connection\s+timed\s+out".to_string(),
                category: ErrorCategory::Network,
                severity: ErrorSeverity::Warning,
                description: "SSH connection timed out".to_string(),
                common_causes: vec![
                    "Network latency too high".to_string(),
                    "Packet loss".to_string(),
                    "Firewall dropping packets".to_string(),
                    "Server overloaded".to_string(),
                ],
                suggested_actions: vec![
                    "Check network connectivity".to_string(),
                    "Increase SSH timeout values".to_string(),
                    "Test with different network path".to_string(),
                    "Monitor server load".to_string(),
                ],
                playbook_refs: vec![
                    "pb-network-diagnostics".to_string(),
                    "pb-ssh-timeout-config".to_string(),
                ],
                confidence: 0.85,
            },
        ];

        for mapping in mappings {
            if let Ok(regex) = compile_pattern(&mapping.pattern) {
                self.patterns.push((regex, mapping));
            }
        }
    }
}

impl ErrorMapper for SSHErrorMapper {
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
        "ssh"
    }

    fn get_patterns(&self) -> &[ErrorMapping] {
        // This would need to be implemented to return the mappings
        // For now, return empty slice
        &[]
    }
}

impl Default for SSHErrorMapper {
    fn default() -> Self {
        Self::new()
    }
}
