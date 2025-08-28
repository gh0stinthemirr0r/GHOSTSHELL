use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod catalog;
pub mod mappings;

pub use catalog::*;
pub use mappings::*;

/// Control definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub description: String,
    pub framework_id: String,
    pub domain: String,
    pub implementation_guidance: String,
    pub assessment_procedures: Vec<String>,
    pub references: Vec<String>,
    pub priority: ControlPriority,
    pub maturity_level: MaturityLevel,
}

/// Control priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Maturity levels for controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaturityLevel {
    Basic,
    Foundational,
    Organizational,
    Advanced,
}

/// Framework metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkMeta {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub publisher: String,
    pub publication_date: String,
    pub url: Option<String>,
    pub domains: Vec<String>,
    pub total_controls: usize,
}

/// Control catalog
pub struct ControlCatalog {
    frameworks: HashMap<String, FrameworkMeta>,
    controls: HashMap<String, Control>,
    framework_controls: HashMap<String, Vec<String>>,
}

impl ControlCatalog {
    pub fn new() -> Self {
        let mut catalog = Self {
            frameworks: HashMap::new(),
            controls: HashMap::new(),
            framework_controls: HashMap::new(),
        };
        catalog.load_builtin_catalogs();
        catalog
    }

    pub fn add_framework(&mut self, framework: FrameworkMeta) {
        self.frameworks.insert(framework.id.clone(), framework);
    }

    pub fn add_control(&mut self, control: Control) {
        let framework_id = control.framework_id.clone();
        let control_id = control.id.clone();
        
        self.controls.insert(control_id.clone(), control);
        
        self.framework_controls
            .entry(framework_id)
            .or_insert_with(Vec::new)
            .push(control_id);
    }

    pub fn get_framework(&self, id: &str) -> Option<&FrameworkMeta> {
        self.frameworks.get(id)
    }

    pub fn get_control(&self, id: &str) -> Option<&Control> {
        self.controls.get(id)
    }

    pub fn list_frameworks(&self) -> Vec<&FrameworkMeta> {
        self.frameworks.values().collect()
    }

    pub fn list_controls_for_framework(&self, framework_id: &str) -> Vec<&Control> {
        if let Some(control_ids) = self.framework_controls.get(framework_id) {
            control_ids
                .iter()
                .filter_map(|id| self.controls.get(id))
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn search_controls(&self, query: &str) -> Vec<&Control> {
        let query_lower = query.to_lowercase();
        self.controls
            .values()
            .filter(|control| {
                control.title.to_lowercase().contains(&query_lower)
                    || control.description.to_lowercase().contains(&query_lower)
                    || control.id.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    fn load_builtin_catalogs(&mut self) {
        self.load_nist_csf();
        self.load_cis_controls();
        self.load_iso_27001();
        self.load_soc2();
    }

    fn load_nist_csf(&mut self) {
        self.add_framework(FrameworkMeta {
            id: "NIST-CSF".to_string(),
            name: "NIST Cybersecurity Framework".to_string(),
            version: "1.1".to_string(),
            description: "Framework for improving critical infrastructure cybersecurity".to_string(),
            publisher: "National Institute of Standards and Technology".to_string(),
            publication_date: "2018-04-16".to_string(),
            url: Some("https://www.nist.gov/cyberframework".to_string()),
            domains: vec![
                "Identify".to_string(),
                "Protect".to_string(),
                "Detect".to_string(),
                "Respond".to_string(),
                "Recover".to_string(),
            ],
            total_controls: 108,
        });

        // Sample NIST CSF controls
        self.add_control(Control {
            id: "NIST-CSF-PR.AC-1".to_string(),
            title: "Identity and credentials are issued, managed, verified, revoked, and audited".to_string(),
            description: "Identities and credentials for authorized devices, users and processes are issued, managed, verified, revoked, and audited for authorized devices, users and processes.".to_string(),
            framework_id: "NIST-CSF".to_string(),
            domain: "Protect".to_string(),
            implementation_guidance: "Implement identity and access management systems with proper lifecycle management".to_string(),
            assessment_procedures: vec![
                "Review identity management policies and procedures".to_string(),
                "Test credential issuance and revocation processes".to_string(),
                "Verify audit logging of identity events".to_string(),
            ],
            references: vec![
                "NIST SP 800-53 AC-2, IA-2, IA-4, IA-5, IA-8".to_string(),
            ],
            priority: ControlPriority::Critical,
            maturity_level: MaturityLevel::Foundational,
        });

        self.add_control(Control {
            id: "NIST-CSF-PR.DS-1".to_string(),
            title: "Data-at-rest is protected".to_string(),
            description: "Data-at-rest is protected using appropriate encryption and access controls.".to_string(),
            framework_id: "NIST-CSF".to_string(),
            domain: "Protect".to_string(),
            implementation_guidance: "Implement encryption for sensitive data at rest and proper access controls".to_string(),
            assessment_procedures: vec![
                "Review data classification and encryption policies".to_string(),
                "Test encryption implementation for data at rest".to_string(),
                "Verify access controls for encrypted data".to_string(),
            ],
            references: vec![
                "NIST SP 800-53 SC-28".to_string(),
            ],
            priority: ControlPriority::High,
            maturity_level: MaturityLevel::Foundational,
        });
    }

    fn load_cis_controls(&mut self) {
        self.add_framework(FrameworkMeta {
            id: "CIS-v8".to_string(),
            name: "CIS Controls v8".to_string(),
            version: "8.0".to_string(),
            description: "Center for Internet Security Controls version 8".to_string(),
            publisher: "Center for Internet Security".to_string(),
            publication_date: "2021-05-18".to_string(),
            url: Some("https://www.cisecurity.org/controls".to_string()),
            domains: vec![
                "Basic CIS Controls".to_string(),
                "Foundational CIS Controls".to_string(),
                "Organizational CIS Controls".to_string(),
            ],
            total_controls: 153,
        });

        self.add_control(Control {
            id: "CIS-4.1".to_string(),
            title: "Establish and Maintain a Secure Configuration Process".to_string(),
            description: "Establish and maintain a secure configuration process for enterprise assets and software.".to_string(),
            framework_id: "CIS-v8".to_string(),
            domain: "Foundational CIS Controls".to_string(),
            implementation_guidance: "Develop and implement secure configuration standards for all systems".to_string(),
            assessment_procedures: vec![
                "Review secure configuration standards".to_string(),
                "Test configuration management processes".to_string(),
                "Verify compliance with configuration baselines".to_string(),
            ],
            references: vec![
                "NIST SP 800-53 CM-2, CM-6".to_string(),
            ],
            priority: ControlPriority::High,
            maturity_level: MaturityLevel::Foundational,
        });
    }

    fn load_iso_27001(&mut self) {
        self.add_framework(FrameworkMeta {
            id: "ISO-27001".to_string(),
            name: "ISO/IEC 27001:2013".to_string(),
            version: "2013".to_string(),
            description: "Information security management systems requirements".to_string(),
            publisher: "International Organization for Standardization".to_string(),
            publication_date: "2013-10-01".to_string(),
            url: Some("https://www.iso.org/standard/54534.html".to_string()),
            domains: vec![
                "Information Security Policies".to_string(),
                "Organization of Information Security".to_string(),
                "Human Resource Security".to_string(),
                "Asset Management".to_string(),
                "Access Control".to_string(),
                "Cryptography".to_string(),
                "Physical and Environmental Security".to_string(),
                "Operations Security".to_string(),
                "Communications Security".to_string(),
                "System Acquisition, Development and Maintenance".to_string(),
                "Supplier Relationships".to_string(),
                "Information Security Incident Management".to_string(),
                "Information Security Aspects of Business Continuity Management".to_string(),
                "Compliance".to_string(),
            ],
            total_controls: 114,
        });

        self.add_control(Control {
            id: "ISO-27001-A.9.4.2".to_string(),
            title: "Secure log-on procedures".to_string(),
            description: "Where required by the access control policy, access to systems and applications shall be controlled by a secure log-on procedure.".to_string(),
            framework_id: "ISO-27001".to_string(),
            domain: "Access Control".to_string(),
            implementation_guidance: "Implement secure authentication mechanisms including multi-factor authentication".to_string(),
            assessment_procedures: vec![
                "Review authentication policies and procedures".to_string(),
                "Test log-on procedures for security controls".to_string(),
                "Verify multi-factor authentication implementation".to_string(),
            ],
            references: vec![
                "ISO/IEC 27002:2013 A.9.4.2".to_string(),
            ],
            priority: ControlPriority::Critical,
            maturity_level: MaturityLevel::Basic,
        });
    }

    fn load_soc2(&mut self) {
        self.add_framework(FrameworkMeta {
            id: "SOC2".to_string(),
            name: "SOC 2 Type II".to_string(),
            version: "2017".to_string(),
            description: "Service Organization Control 2 Trust Services Criteria".to_string(),
            publisher: "American Institute of CPAs".to_string(),
            publication_date: "2017-01-01".to_string(),
            url: Some("https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html".to_string()),
            domains: vec![
                "Security".to_string(),
                "Availability".to_string(),
                "Processing Integrity".to_string(),
                "Confidentiality".to_string(),
                "Privacy".to_string(),
            ],
            total_controls: 64,
        });

        self.add_control(Control {
            id: "SOC2-CC6.1".to_string(),
            title: "Logical and physical access controls".to_string(),
            description: "The entity implements logical and physical access controls to protect against threats from sources outside its system boundaries.".to_string(),
            framework_id: "SOC2".to_string(),
            domain: "Security".to_string(),
            implementation_guidance: "Implement comprehensive access controls for both logical and physical access".to_string(),
            assessment_procedures: vec![
                "Review access control policies and procedures".to_string(),
                "Test logical access controls".to_string(),
                "Test physical access controls".to_string(),
                "Verify access monitoring and logging".to_string(),
            ],
            references: vec![
                "TSC CC6.1".to_string(),
            ],
            priority: ControlPriority::Critical,
            maturity_level: MaturityLevel::Basic,
        });
    }
}

impl Default for ControlCatalog {
    fn default() -> Self {
        Self::new()
    }
}
