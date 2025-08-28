use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Control mapping between frameworks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMapping {
    pub source_control_id: String,
    pub target_control_id: String,
    pub mapping_type: MappingType,
    pub confidence: f64,
    pub notes: Option<String>,
}

/// Types of control mappings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MappingType {
    Exact,      // Controls are functionally identical
    Partial,    // Controls overlap but are not identical
    Related,    // Controls are related but address different aspects
    Derived,    // Target control is derived from source control
}

/// Cross-framework mapping manager
pub struct MappingManager {
    mappings: Vec<ControlMapping>,
    framework_mappings: HashMap<(String, String), Vec<ControlMapping>>,
}

impl MappingManager {
    pub fn new() -> Self {
        let mut manager = Self {
            mappings: Vec::new(),
            framework_mappings: HashMap::new(),
        };
        manager.load_builtin_mappings();
        manager
    }

    pub fn add_mapping(&mut self, mapping: ControlMapping) {
        // Extract framework IDs from control IDs (simplified approach)
        let source_framework = self.extract_framework_id(&mapping.source_control_id);
        let target_framework = self.extract_framework_id(&mapping.target_control_id);
        
        let key = (source_framework, target_framework);
        self.framework_mappings
            .entry(key)
            .or_insert_with(Vec::new)
            .push(mapping.clone());
        
        self.mappings.push(mapping);
    }

    pub fn get_mappings(&self, source_framework: &str, target_framework: &str) -> Vec<&ControlMapping> {
        let key = (source_framework.to_string(), target_framework.to_string());
        self.framework_mappings
            .get(&key)
            .map(|mappings| mappings.iter().collect())
            .unwrap_or_default()
    }

    pub fn find_mapped_controls(&self, control_id: &str) -> Vec<&ControlMapping> {
        self.mappings
            .iter()
            .filter(|mapping| {
                mapping.source_control_id == control_id || mapping.target_control_id == control_id
            })
            .collect()
    }

    fn extract_framework_id(&self, control_id: &str) -> String {
        // Simple extraction based on control ID format
        if control_id.starts_with("NIST-CSF-") {
            "NIST-CSF".to_string()
        } else if control_id.starts_with("CIS-") {
            "CIS-v8".to_string()
        } else if control_id.starts_with("ISO-27001-") {
            "ISO-27001".to_string()
        } else if control_id.starts_with("SOC2-") {
            "SOC2".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn load_builtin_mappings(&mut self) {
        // NIST CSF to CIS Controls mappings
        self.add_mapping(ControlMapping {
            source_control_id: "NIST-CSF-PR.AC-1".to_string(),
            target_control_id: "CIS-4.1".to_string(),
            mapping_type: MappingType::Related,
            confidence: 0.8,
            notes: Some("Both address secure configuration and access control".to_string()),
        });

        // NIST CSF to ISO 27001 mappings
        self.add_mapping(ControlMapping {
            source_control_id: "NIST-CSF-PR.AC-1".to_string(),
            target_control_id: "ISO-27001-A.9.4.2".to_string(),
            mapping_type: MappingType::Partial,
            confidence: 0.9,
            notes: Some("Both address identity and access management".to_string()),
        });

        // ISO 27001 to SOC 2 mappings
        self.add_mapping(ControlMapping {
            source_control_id: "ISO-27001-A.9.4.2".to_string(),
            target_control_id: "SOC2-CC6.1".to_string(),
            mapping_type: MappingType::Related,
            confidence: 0.85,
            notes: Some("Both address access controls".to_string()),
        });

        // CIS to SOC 2 mappings
        self.add_mapping(ControlMapping {
            source_control_id: "CIS-4.1".to_string(),
            target_control_id: "SOC2-CC6.1".to_string(),
            mapping_type: MappingType::Partial,
            confidence: 0.7,
            notes: Some("Secure configuration supports access control objectives".to_string()),
        });
    }
}

impl Default for MappingManager {
    fn default() -> Self {
        Self::new()
    }
}
