use super::{ErrorMapper, ErrorMapping, ErrorCategory, ErrorSeverity, ErrorClassification, ErrorMapResult, ErrorMapError, compile_pattern};
use regex::Regex;

pub struct TerminalErrorMapper {
    patterns: Vec<(Regex, ErrorMapping)>,
}

impl TerminalErrorMapper {
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
                pattern: r"(?i)command\s+not\s+found".to_string(),
                category: ErrorCategory::Configuration,
                severity: ErrorSeverity::Warning,
                description: "Command not found in PATH".to_string(),
                common_causes: vec![
                    "Command not installed".to_string(),
                    "PATH environment variable incorrect".to_string(),
                    "Typo in command name".to_string(),
                    "Command in different location".to_string(),
                ],
                suggested_actions: vec![
                    "Check command spelling".to_string(),
                    "Install required package".to_string(),
                    "Update PATH environment variable".to_string(),
                    "Use full path to command".to_string(),
                ],
                playbook_refs: vec![
                    "pb-package-management".to_string(),
                    "pb-environment-setup".to_string(),
                ],
                confidence: 0.95,
            },
            ErrorMapping {
                pattern: r"(?i)permission\s+denied".to_string(),
                category: ErrorCategory::Authorization,
                severity: ErrorSeverity::Error,
                description: "Insufficient permissions to execute command".to_string(),
                common_causes: vec![
                    "File not executable".to_string(),
                    "User lacks required permissions".to_string(),
                    "Directory permissions incorrect".to_string(),
                    "SELinux/AppArmor policy blocking".to_string(),
                ],
                suggested_actions: vec![
                    "Check file permissions with ls -la".to_string(),
                    "Use sudo if elevated privileges needed".to_string(),
                    "Verify directory permissions".to_string(),
                    "Check security policy settings".to_string(),
                ],
                playbook_refs: vec![
                    "pb-permission-management".to_string(),
                    "pb-security-policy-check".to_string(),
                ],
                confidence: 0.90,
            },
            ErrorMapping {
                pattern: r"(?i)no\s+such\s+file\s+or\s+directory".to_string(),
                category: ErrorCategory::Resource,
                severity: ErrorSeverity::Warning,
                description: "File or directory does not exist".to_string(),
                common_causes: vec![
                    "Incorrect file path".to_string(),
                    "File was deleted or moved".to_string(),
                    "Typo in filename".to_string(),
                    "Working directory changed".to_string(),
                ],
                suggested_actions: vec![
                    "Verify file path is correct".to_string(),
                    "Check current working directory".to_string(),
                    "Use find command to locate file".to_string(),
                    "Check if file was moved or deleted".to_string(),
                ],
                playbook_refs: vec![
                    "pb-file-management".to_string(),
                    "pb-directory-navigation".to_string(),
                ],
                confidence: 0.95,
            },
            ErrorMapping {
                pattern: r"(?i)disk\s+full|no\s+space\s+left".to_string(),
                category: ErrorCategory::Resource,
                severity: ErrorSeverity::Critical,
                description: "Insufficient disk space".to_string(),
                common_causes: vec![
                    "Disk partition full".to_string(),
                    "Large log files".to_string(),
                    "Temporary files not cleaned".to_string(),
                    "Database growth".to_string(),
                ],
                suggested_actions: vec![
                    "Check disk usage with df -h".to_string(),
                    "Clean temporary files".to_string(),
                    "Rotate or compress log files".to_string(),
                    "Free up disk space".to_string(),
                ],
                playbook_refs: vec![
                    "pb-disk-cleanup".to_string(),
                    "pb-log-rotation".to_string(),
                ],
                confidence: 0.98,
            },
            ErrorMapping {
                pattern: r"(?i)operation\s+not\s+permitted".to_string(),
                category: ErrorCategory::Policy,
                severity: ErrorSeverity::Error,
                description: "Operation blocked by security policy".to_string(),
                common_causes: vec![
                    "GhostShell policy restriction".to_string(),
                    "System security policy".to_string(),
                    "Insufficient privileges".to_string(),
                    "Resource protection active".to_string(),
                ],
                suggested_actions: vec![
                    "Check GhostShell policy settings".to_string(),
                    "Request policy exception".to_string(),
                    "Use alternative approach".to_string(),
                    "Contact security administrator".to_string(),
                ],
                playbook_refs: vec![
                    "pb-policy-management".to_string(),
                    "pb-security-exception".to_string(),
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

impl ErrorMapper for TerminalErrorMapper {
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
        "terminal"
    }

    fn get_patterns(&self) -> &[ErrorMapping] {
        &[]
    }
}

impl Default for TerminalErrorMapper {
    fn default() -> Self {
        Self::new()
    }
}
