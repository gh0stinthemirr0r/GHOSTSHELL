use super::{ErrorMapper, ErrorMapping, ErrorCategory, ErrorSeverity, ErrorClassification, ErrorMapResult, ErrorMapError, compile_pattern};
use regex::Regex;

pub struct ComplianceErrorMapper {
    patterns: Vec<(Regex, ErrorMapping)>,
}

impl ComplianceErrorMapper {
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
                pattern: r"(?i)control\s+failed|compliance\s+violation".to_string(),
                category: ErrorCategory::Policy,
                severity: ErrorSeverity::Critical,
                description: "Compliance control check failed".to_string(),
                common_causes: vec![
                    "Policy configuration drift".to_string(),
                    "Missing security controls".to_string(),
                    "Expired certificates or keys".to_string(),
                    "Unauthorized configuration changes".to_string(),
                ],
                suggested_actions: vec![
                    "Review failed control details".to_string(),
                    "Run remediation playbook".to_string(),
                    "Update security configuration".to_string(),
                    "Generate compliance report".to_string(),
                ],
                playbook_refs: vec![
                    "pb-compliance-remediation".to_string(),
                    "pb-security-baseline".to_string(),
                ],
                confidence: 0.92,
            },
            ErrorMapping {
                pattern: r"(?i)sla\s+breach|sla.*unmet".to_string(),
                category: ErrorCategory::Policy,
                severity: ErrorSeverity::Error,
                description: "Service Level Agreement breach detected".to_string(),
                common_causes: vec![
                    "Performance degradation".to_string(),
                    "Service unavailability".to_string(),
                    "Resource constraints".to_string(),
                    "Process automation failure".to_string(),
                ],
                suggested_actions: vec![
                    "Investigate performance metrics".to_string(),
                    "Scale resources if needed".to_string(),
                    "Review automation processes".to_string(),
                    "Implement corrective measures".to_string(),
                ],
                playbook_refs: vec![
                    "pb-performance-optimization".to_string(),
                    "pb-sla-recovery".to_string(),
                ],
                confidence: 0.88,
            },
            ErrorMapping {
                pattern: r"(?i)evidence\s+missing|insufficient\s+evidence".to_string(),
                category: ErrorCategory::Configuration,
                severity: ErrorSeverity::Warning,
                description: "Compliance evidence is missing or insufficient".to_string(),
                common_causes: vec![
                    "Logging not properly configured".to_string(),
                    "Evidence collection disabled".to_string(),
                    "Log rotation deleted evidence".to_string(),
                    "Monitoring gaps".to_string(),
                ],
                suggested_actions: vec![
                    "Enable comprehensive logging".to_string(),
                    "Configure evidence collection".to_string(),
                    "Review log retention policies".to_string(),
                    "Implement monitoring coverage".to_string(),
                ],
                playbook_refs: vec![
                    "pb-evidence-collection".to_string(),
                    "pb-logging-configuration".to_string(),
                ],
                confidence: 0.85,
            },
            ErrorMapping {
                pattern: r"(?i)framework\s+mismatch|unsupported\s+framework".to_string(),
                category: ErrorCategory::Configuration,
                severity: ErrorSeverity::Error,
                description: "Compliance framework configuration issue".to_string(),
                common_causes: vec![
                    "Framework not properly configured".to_string(),
                    "Version mismatch".to_string(),
                    "Missing framework components".to_string(),
                    "Incompatible framework settings".to_string(),
                ],
                suggested_actions: vec![
                    "Verify framework configuration".to_string(),
                    "Update framework version".to_string(),
                    "Install missing components".to_string(),
                    "Review framework compatibility".to_string(),
                ],
                playbook_refs: vec![
                    "pb-framework-setup".to_string(),
                    "pb-compliance-configuration".to_string(),
                ],
                confidence: 0.90,
            },
            ErrorMapping {
                pattern: r"(?i)signature\s+verification\s+failed|invalid\s+signature".to_string(),
                category: ErrorCategory::Cryptography,
                severity: ErrorSeverity::Critical,
                description: "Evidence signature verification failed".to_string(),
                common_causes: vec![
                    "Evidence tampering detected".to_string(),
                    "Signature key compromised".to_string(),
                    "Clock synchronization issue".to_string(),
                    "Signature algorithm mismatch".to_string(),
                ],
                suggested_actions: vec![
                    "Investigate potential tampering".to_string(),
                    "Verify signature keys".to_string(),
                    "Check system time synchronization".to_string(),
                    "Re-generate evidence signatures".to_string(),
                ],
                playbook_refs: vec![
                    "pb-security-incident".to_string(),
                    "pb-signature-verification".to_string(),
                ],
                confidence: 0.95,
            },
        ];

        for mapping in mappings {
            if let Ok(regex) = compile_pattern(&mapping.pattern) {
                self.patterns.push((regex, mapping));
            }
        }
    }
}

impl ErrorMapper for ComplianceErrorMapper {
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
        "compliance"
    }

    fn get_patterns(&self) -> &[ErrorMapping] {
        &[]
    }
}

impl Default for ComplianceErrorMapper {
    fn default() -> Self {
        Self::new()
    }
}
