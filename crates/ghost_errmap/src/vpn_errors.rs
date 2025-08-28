use super::{ErrorMapper, ErrorMapping, ErrorCategory, ErrorSeverity, ErrorClassification, ErrorMapResult, ErrorMapError, compile_pattern};
use regex::Regex;

pub struct VPNErrorMapper {
    patterns: Vec<(Regex, ErrorMapping)>,
}

impl VPNErrorMapper {
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
                pattern: r"(?i)no\s+matching\s+cipher|cipher\s+mismatch".to_string(),
                category: ErrorCategory::Cryptography,
                severity: ErrorSeverity::Error,
                description: "VPN cipher negotiation failed".to_string(),
                common_causes: vec![
                    "Post-quantum only policy enforced".to_string(),
                    "Legacy VPN server configuration".to_string(),
                    "Cipher suite mismatch".to_string(),
                    "Outdated VPN client".to_string(),
                ],
                suggested_actions: vec![
                    "Enable post-quantum VPN ciphers".to_string(),
                    "Update VPN client configuration".to_string(),
                    "Check server cipher support".to_string(),
                    "Use PQ-compatible VPN client".to_string(),
                ],
                playbook_refs: vec![
                    "pb-pq-vpn-config".to_string(),
                    "pb-vpn-cipher-update".to_string(),
                ],
                confidence: 0.93,
            },
            ErrorMapping {
                pattern: r"(?i)authentication\s+failed|auth\s+failed".to_string(),
                category: ErrorCategory::Authentication,
                severity: ErrorSeverity::Error,
                description: "VPN authentication failed".to_string(),
                common_causes: vec![
                    "Incorrect credentials".to_string(),
                    "Certificate expired".to_string(),
                    "User account disabled".to_string(),
                    "Two-factor authentication required".to_string(),
                ],
                suggested_actions: vec![
                    "Verify username and password".to_string(),
                    "Check certificate validity".to_string(),
                    "Renew expired certificates".to_string(),
                    "Contact VPN administrator".to_string(),
                ],
                playbook_refs: vec![
                    "pb-vpn-auth-troubleshoot".to_string(),
                    "pb-certificate-renewal".to_string(),
                ],
                confidence: 0.90,
            },
            ErrorMapping {
                pattern: r"(?i)connection\s+timeout|vpn\s+timeout".to_string(),
                category: ErrorCategory::Network,
                severity: ErrorSeverity::Warning,
                description: "VPN connection timed out".to_string(),
                common_causes: vec![
                    "Network latency too high".to_string(),
                    "VPN server overloaded".to_string(),
                    "Firewall blocking VPN traffic".to_string(),
                    "ISP throttling VPN connections".to_string(),
                ],
                suggested_actions: vec![
                    "Try different VPN server".to_string(),
                    "Check network connectivity".to_string(),
                    "Adjust timeout settings".to_string(),
                    "Test with different protocol".to_string(),
                ],
                playbook_refs: vec![
                    "pb-vpn-server-selection".to_string(),
                    "pb-network-optimization".to_string(),
                ],
                confidence: 0.85,
            },
            ErrorMapping {
                pattern: r"(?i)certificate\s+verification\s+failed".to_string(),
                category: ErrorCategory::Cryptography,
                severity: ErrorSeverity::Critical,
                description: "VPN certificate verification failed".to_string(),
                common_causes: vec![
                    "Certificate expired".to_string(),
                    "Certificate revoked".to_string(),
                    "CA certificate missing".to_string(),
                    "Clock synchronization issue".to_string(),
                ],
                suggested_actions: vec![
                    "Check certificate expiration".to_string(),
                    "Verify CA certificate chain".to_string(),
                    "Synchronize system clock".to_string(),
                    "Renew VPN certificates".to_string(),
                ],
                playbook_refs: vec![
                    "pb-certificate-verification".to_string(),
                    "pb-time-synchronization".to_string(),
                ],
                confidence: 0.95,
            },
            ErrorMapping {
                pattern: r"(?i)server\s+unreachable|vpn\s+server\s+down".to_string(),
                category: ErrorCategory::Network,
                severity: ErrorSeverity::Error,
                description: "VPN server is unreachable".to_string(),
                common_causes: vec![
                    "VPN server maintenance".to_string(),
                    "Network routing issue".to_string(),
                    "Server overload".to_string(),
                    "DNS resolution failure".to_string(),
                ],
                suggested_actions: vec![
                    "Try alternative VPN server".to_string(),
                    "Check server status page".to_string(),
                    "Verify DNS resolution".to_string(),
                    "Test network connectivity".to_string(),
                ],
                playbook_refs: vec![
                    "pb-vpn-failover".to_string(),
                    "pb-dns-troubleshoot".to_string(),
                ],
                confidence: 0.88,
            },
        ];

        for mapping in mappings {
            if let Ok(regex) = compile_pattern(&mapping.pattern) {
                self.patterns.push((regex, mapping));
            }
        }
    }
}

impl ErrorMapper for VPNErrorMapper {
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
        "vpn"
    }

    fn get_patterns(&self) -> &[ErrorMapping] {
        &[]
    }
}

impl Default for VPNErrorMapper {
    fn default() -> Self {
        Self::new()
    }
}
