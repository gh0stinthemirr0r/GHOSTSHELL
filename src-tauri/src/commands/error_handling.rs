// error_handling.rs - Comprehensive error handling and validation

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CsvImportError {
    #[error("File not found: {path}")]
    FileNotFound { path: String },
    
    #[error("Permission denied: {path}")]
    PermissionDenied { path: String },
    
    #[error("Invalid file format: {message}")]
    InvalidFormat { message: String },
    
    #[error("Encoding error: {encoding} - {message}")]
    EncodingError { encoding: String, message: String },
    
    #[error("CSV parsing error at line {line}: {message}")]
    CsvParseError { line: usize, message: String },
    
    #[error("Validation error: {field} - {message}")]
    ValidationError { field: String, message: String },
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("CSV error: {0}")]
    CsvError(#[from] csv::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub line_number: Option<usize>,
    pub severity: ErrorSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    pub field: String,
    pub message: String,
    pub line_number: Option<usize>,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Critical,  // Prevents processing
    High,      // May cause issues
    Medium,    // Should be addressed
    Low,       // Informational
}

pub struct PolicyRuleValidator {
    required_fields: Vec<String>,
    valid_actions: Vec<String>,
    max_field_length: usize,
}

impl Default for PolicyRuleValidator {
    fn default() -> Self {
        Self {
            required_fields: vec![
                "name".to_string(),
                "action".to_string(),
            ],
            valid_actions: vec![
                "allow".to_string(),
                "deny".to_string(), 
                "drop".to_string(),
                "reject".to_string(),
            ],
            max_field_length: 1000,
        }
    }
}

impl PolicyRuleValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate_rule(&self, rule: &serde_json::Value, line_number: Option<usize>) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut suggestions = Vec::new();

        let rule_obj = match rule.as_object() {
            Some(obj) => obj,
            None => {
                errors.push(ValidationError {
                    field: "rule".to_string(),
                    message: "Rule is not a valid JSON object".to_string(),
                    line_number,
                    severity: ErrorSeverity::Critical,
                });
                return ValidationResult { valid: false, errors, warnings, suggestions };
            }
        };

        // Check required fields
        for field in &self.required_fields {
            if !rule_obj.contains_key(field) || rule_obj[field].is_null() {
                errors.push(ValidationError {
                    field: field.clone(),
                    message: format!("Required field '{}' is missing", field),
                    line_number,
                    severity: ErrorSeverity::Critical,
                });
            } else if let Some(value) = rule_obj[field].as_str() {
                if value.trim().is_empty() {
                    warnings.push(ValidationWarning {
                        field: field.clone(),
                        message: format!("Required field '{}' is empty", field),
                        line_number,
                        suggestion: Some("Provide a meaningful value for this field".to_string()),
                    });
                }
            }
        }

        // Validate action field
        if let Some(action) = rule_obj.get("action").and_then(|v| v.as_str()) {
            let action_lower = action.to_lowercase();
            if !self.valid_actions.contains(&action_lower) {
                warnings.push(ValidationWarning {
                    field: "action".to_string(),
                    message: format!("Unknown action '{}', expected one of: {}", action, self.valid_actions.join(", ")),
                    line_number,
                    suggestion: Some("Use standard actions: allow, deny, drop, or reject".to_string()),
                });
            }
        }

        // Validate name field
        if let Some(name) = rule_obj.get("name").and_then(|v| v.as_str()) {
            if name.len() > self.max_field_length {
                warnings.push(ValidationWarning {
                    field: "name".to_string(),
                    message: format!("Rule name is very long ({} characters)", name.len()),
                    line_number,
                    suggestion: Some("Consider shortening the rule name".to_string()),
                });
            }
            
            if name.chars().any(|c| !c.is_ascii()) {
                warnings.push(ValidationWarning {
                    field: "name".to_string(),
                    message: "Rule name contains non-ASCII characters".to_string(),
                    line_number,
                    suggestion: Some("Consider using ASCII characters only for compatibility".to_string()),
                });
            }
        }

        // Validate zone fields
        for zone_field in ["from", "to"] {
            if let Some(zones) = rule_obj.get(zone_field) {
                if let Some(zone_array) = zones.as_array() {
                    if zone_array.is_empty() {
                        warnings.push(ValidationWarning {
                            field: zone_field.to_string(),
                            message: format!("Zone field '{}' is empty", zone_field),
                            line_number,
                            suggestion: Some("Specify source and destination zones for better security".to_string()),
                        });
                    }
                    
                    // Check for 'any' zones
                    for zone in zone_array {
                        if let Some(zone_str) = zone.as_str() {
                            if zone_str.to_lowercase() == "any" {
                                warnings.push(ValidationWarning {
                                    field: zone_field.to_string(),
                                    message: format!("Using 'any' zone in '{}' reduces security", zone_field),
                                    line_number,
                                    suggestion: Some("Specify specific zones when possible".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Validate address fields
        for addr_field in ["source", "destination"] {
            if let Some(addresses) = rule_obj.get(addr_field) {
                if let Some(addr_array) = addresses.as_array() {
                    for addr in addr_array {
                        if let Some(addr_str) = addr.as_str() {
                            if addr_str.to_lowercase() == "any" && addr_field == "destination" {
                                warnings.push(ValidationWarning {
                                    field: addr_field.to_string(),
                                    message: "Rule allows access to any destination".to_string(),
                                    line_number,
                                    suggestion: Some("Consider restricting destination addresses".to_string()),
                                });
                            }
                            
                            // Basic IP address validation
                            if !addr_str.to_lowercase().contains("any") && 
                               !self.is_valid_address_format(addr_str) {
                                warnings.push(ValidationWarning {
                                    field: addr_field.to_string(),
                                    message: format!("Address '{}' format may be invalid", addr_str),
                                    line_number,
                                    suggestion: Some("Verify address format (IP, CIDR, or FQDN)".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check for overly permissive rules
        let has_any_source = rule_obj.get("source")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str().map(|s| s.to_lowercase() == "any").unwrap_or(false)))
            .unwrap_or(false);
            
        let has_any_destination = rule_obj.get("destination")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str().map(|s| s.to_lowercase() == "any").unwrap_or(false)))
            .unwrap_or(false);
            
        let has_any_application = rule_obj.get("application")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str().map(|s| s.to_lowercase() == "any").unwrap_or(false)))
            .unwrap_or(false);

        if has_any_source && has_any_destination && has_any_application {
            warnings.push(ValidationWarning {
                field: "rule".to_string(),
                message: "Rule is very permissive (any source, destination, and application)".to_string(),
                line_number,
                suggestion: Some("Review if this broad access is necessary".to_string()),
            });
        }

        // Add general suggestions
        if warnings.is_empty() && errors.is_empty() {
            suggestions.push("Rule appears to be well-formed".to_string());
        }

        ValidationResult {
            valid: errors.iter().all(|e| !matches!(e.severity, ErrorSeverity::Critical)),
            errors,
            warnings,
            suggestions,
        }
    }

    fn is_valid_address_format(&self, address: &str) -> bool {
        // Basic validation for IP addresses, CIDRs, and FQDNs
        if address.parse::<std::net::IpAddr>().is_ok() {
            return true;
        }
        
        // CIDR notation
        if address.contains('/') {
            let parts: Vec<&str> = address.split('/').collect();
            if parts.len() == 2 {
                if let (Ok(_), Ok(prefix)) = (parts[0].parse::<std::net::IpAddr>(), parts[1].parse::<u8>()) {
                    return prefix <= 128; // IPv6 max prefix
                }
            }
        }
        
        // Basic FQDN check (contains dots and valid characters)
        if address.contains('.') && 
           address.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') &&
           !address.starts_with('.') && !address.ends_with('.') {
            return true;
        }
        
        // Address group or object name
        if address.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return true;
        }
        
        false
    }
}

// Data quality analyzer
pub struct DataQualityAnalyzer;

impl DataQualityAnalyzer {
    pub fn analyze_csv_quality(headers: &[String], rules: &[serde_json::Value]) -> DataQualityReport {
        let mut report = DataQualityReport::new();
        
        // Analyze headers
        report.header_analysis = Self::analyze_headers(headers);
        
        // Analyze data completeness
        report.completeness_analysis = Self::analyze_completeness(rules);
        report.consistency_analysis = Self::analyze_consistency(rules);
        
        // Overall quality score
        report.quality_score = Self::calculate_quality_score(&report);
        
        report
    }
    
    fn analyze_headers(headers: &[String]) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            total_headers: headers.len(),
            recognized_headers: 0,
            unknown_headers: Vec::new(),
            duplicate_headers: Vec::new(),
            suggestions: Vec::new(),
        };
        
        let expected_headers = [
            "name", "type", "from", "to", "source", "destination",
            "application", "service", "action", "description"
        ];
        
        let mut seen_headers = std::collections::HashSet::new();
        
        for header in headers {
            let normalized = header.to_lowercase().trim().to_string();
            
            if seen_headers.contains(&normalized) {
                analysis.duplicate_headers.push(header.clone());
            } else {
                seen_headers.insert(normalized.clone());
            }
            
            let recognized = expected_headers.iter()
                .any(|&expected| normalized.contains(expected) || expected.contains(&normalized));
                
            if recognized {
                analysis.recognized_headers += 1;
            } else {
                analysis.unknown_headers.push(header.clone());
            }
        }
        
        // Generate suggestions
        if analysis.recognized_headers < 3 {
            analysis.suggestions.push("Very few recognized headers found. Verify this is a PAN-OS policy export.".to_string());
        }
        
        if !analysis.duplicate_headers.is_empty() {
            analysis.suggestions.push("Duplicate headers detected. This may cause parsing issues.".to_string());
        }
        
        analysis
    }
    
    fn analyze_completeness(rules: &[serde_json::Value]) -> CompletenessAnalysis {
        let mut analysis = CompletenessAnalysis {
            total_rules: rules.len(),
            field_completeness: std::collections::HashMap::new(),
            empty_rules: 0,
            suggestions: Vec::new(),
        };
        
        let important_fields = ["name", "action", "source", "destination"];
        
        for field in &important_fields {
            let mut complete_count = 0;
            
            for rule in rules {
                if let Some(value) = rule.get(field) {
                    if !value.is_null() {
                        if let Some(str_val) = value.as_str() {
                            if !str_val.trim().is_empty() {
                                complete_count += 1;
                            }
                        } else if value.is_array() && !value.as_array().unwrap().is_empty() {
                            complete_count += 1;
                        }
                    }
                }
            }
            
            let completeness_ratio = if rules.is_empty() { 
                0.0 
            } else { 
                complete_count as f64 / rules.len() as f64 
            };
            
            analysis.field_completeness.insert(field.to_string(), completeness_ratio);
        }
        
        // Count empty rules
        analysis.empty_rules = rules.iter()
            .filter(|rule| {
                rule.as_object()
                    .map(|obj| obj.values().all(|v| v.is_null() || 
                        v.as_str().map(|s| s.trim().is_empty()).unwrap_or(false)))
                    .unwrap_or(true)
            })
            .count();
            
        // Generate suggestions
        for (field, &ratio) in &analysis.field_completeness {
            if ratio < 0.5 {
                analysis.suggestions.push(format!("Field '{}' is missing in over 50% of rules", field));
            }
        }
        
        if analysis.empty_rules > 0 {
            analysis.suggestions.push(format!("{} empty rules found", analysis.empty_rules));
        }
        
        analysis
    }
    
    fn analyze_consistency(rules: &[serde_json::Value]) -> ConsistencyAnalysis {
        let mut analysis = ConsistencyAnalysis {
            inconsistent_actions: 0,
            naming_inconsistencies: Vec::new(),
            suggestions: Vec::new(),
        };
        
        let mut action_formats = std::collections::HashSet::new();
        let mut naming_patterns = std::collections::HashMap::new();
        
        for rule in rules {
            // Check action consistency
            if let Some(action) = rule.get("action").and_then(|v| v.as_str()) {
                action_formats.insert(action.to_string());
            }
            
            // Check naming patterns
            if let Some(name) = rule.get("name").and_then(|v| v.as_str()) {
                let pattern = Self::extract_naming_pattern(name);
                *naming_patterns.entry(pattern).or_insert(0) += 1;
            }
        }
        
        // Analyze findings
        if action_formats.len() > 4 {
            analysis.inconsistent_actions = action_formats.len() - 4; // Standard actions
            analysis.suggestions.push("Multiple action formats detected. Consider standardizing.".to_string());
        }
        
        let dominant_pattern = naming_patterns.iter()
            .max_by_key(|(_, &count)| count)
            .map(|(pattern, _)| pattern);
            
        if let Some(pattern) = dominant_pattern {
            let inconsistent = rules.iter()
                .filter_map(|rule| rule.get("name").and_then(|v| v.as_str()))
                .filter(|name| Self::extract_naming_pattern(name) != *pattern)
                .collect::<Vec<_>>();
                
            for name in inconsistent.into_iter().take(5) { // Limit examples
                analysis.naming_inconsistencies.push(name.to_string());
            }
        }
        
        analysis
    }
    
    fn extract_naming_pattern(name: &str) -> String {
        // Simple pattern extraction based on common conventions
        if name.contains('-') {
            "hyphen-separated".to_string()
        } else if name.contains('_') {
            "underscore_separated".to_string()
        } else if name.chars().any(|c| c.is_uppercase()) && name.chars().any(|c| c.is_lowercase()) {
            "CamelCase".to_string()
        } else {
            "other".to_string()
        }
    }
    
    fn calculate_quality_score(report: &DataQualityReport) -> f64 {
        let mut score = 100.0;
        
        // Header quality (0-30 points)
        let header_ratio = if report.header_analysis.total_headers == 0 {
            0.0
        } else {
            report.header_analysis.recognized_headers as f64 / report.header_analysis.total_headers as f64
        };
        score += (header_ratio * 30.0) - 30.0;
        
        // Completeness quality (0-40 points)
        let avg_completeness = report.completeness_analysis.field_completeness
            .values()
            .sum::<f64>() / report.completeness_analysis.field_completeness.len().max(1) as f64;
        score += (avg_completeness * 40.0) - 40.0;
        
        // Consistency quality (0-30 points)
        if report.consistency_analysis.inconsistent_actions > 5 {
            score -= 15.0;
        }
        if report.consistency_analysis.naming_inconsistencies.len() > 10 {
            score -= 15.0;
        }
        
        score.max(0.0).min(100.0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DataQualityReport {
    pub quality_score: f64,
    pub header_analysis: HeaderAnalysis,
    pub completeness_analysis: CompletenessAnalysis,
    pub consistency_analysis: ConsistencyAnalysis,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeaderAnalysis {
    pub total_headers: usize,
    pub recognized_headers: usize,
    pub unknown_headers: Vec<String>,
    pub duplicate_headers: Vec<String>,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompletenessAnalysis {
    pub total_rules: usize,
    pub field_completeness: std::collections::HashMap<String, f64>,
    pub empty_rules: usize,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsistencyAnalysis {
    pub inconsistent_actions: usize,
    pub naming_inconsistencies: Vec<String>,
    pub suggestions: Vec<String>,
}

impl DataQualityReport {
    fn new() -> Self {
        Self {
            quality_score: 0.0,
            header_analysis: HeaderAnalysis {
                total_headers: 0,
                recognized_headers: 0,
                unknown_headers: Vec::new(),
                duplicate_headers: Vec::new(),
                suggestions: Vec::new(),
            },
            completeness_analysis: CompletenessAnalysis {
                total_rules: 0,
                field_completeness: std::collections::HashMap::new(),
                empty_rules: 0,
                suggestions: Vec::new(),
            },
            consistency_analysis: ConsistencyAnalysis {
                inconsistent_actions: 0,
                naming_inconsistencies: Vec::new(),
                suggestions: Vec::new(),
            },
        }
    }
}
