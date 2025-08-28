use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub mod playbook_linker;
pub mod policy_linker;

pub use playbook_linker::PlaybookLinker;
pub use policy_linker::PolicyLinker;

/// Link result type
pub type LinkResult<T> = Result<T, LinkError>;

/// Link errors
#[derive(Error, Debug)]
pub enum LinkError {
    #[error("Playbook not found: {0}")]
    PlaybookNotFound(String),
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),
    #[error("Invalid link reference: {0}")]
    InvalidReference(String),
    #[error("Link generation failed: {0}")]
    GenerationFailed(String),
}

/// Link types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LinkType {
    Playbook,
    Policy,
    Documentation,
    Evidence,
    Report,
}

/// Action link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLink {
    pub link_type: LinkType,
    pub id: String,
    pub title: String,
    pub description: String,
    pub url: Option<String>,
    pub parameters: HashMap<String, String>,
    pub priority: u8, // 1-10, higher is more important
    pub estimated_time: Option<String>,
}

/// Playbook reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookReference {
    pub playbook_id: String,
    pub playbook_name: String,
    pub description: String,
    pub category: String,
    pub estimated_duration: String,
    pub required_permissions: Vec<String>,
    pub parameters: HashMap<String, String>,
}

/// Policy reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReference {
    pub policy_id: String,
    pub policy_name: String,
    pub description: String,
    pub category: String,
    pub compliance_frameworks: Vec<String>,
    pub enforcement_level: String,
}

/// Link context for generating appropriate links
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkContext {
    pub error_category: Option<String>,
    pub severity: Option<String>,
    pub component: Option<String>,
    pub user_role: Option<String>,
    pub permissions: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Main link engine
pub struct LinkEngine {
    playbook_linker: PlaybookLinker,
    policy_linker: PolicyLinker,
    playbook_registry: HashMap<String, PlaybookReference>,
    policy_registry: HashMap<String, PolicyReference>,
}

impl LinkEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            playbook_linker: PlaybookLinker::new(),
            policy_linker: PolicyLinker::new(),
            playbook_registry: HashMap::new(),
            policy_registry: HashMap::new(),
        };
        engine.load_registries();
        engine
    }

    pub fn generate_action_links(
        &self,
        error_category: &str,
        context: &LinkContext,
    ) -> LinkResult<Vec<ActionLink>> {
        let mut links = Vec::new();

        // Get playbook links
        if let Ok(playbook_links) = self.playbook_linker.get_relevant_playbooks(error_category, context) {
            links.extend(playbook_links);
        }

        // Get policy links
        if let Ok(policy_links) = self.policy_linker.get_relevant_policies(error_category, context) {
            links.extend(policy_links);
        }

        // Sort by priority (highest first)
        links.sort_by(|a, b| b.priority.cmp(&a.priority));

        Ok(links)
    }

    pub fn get_playbook_reference(&self, playbook_id: &str) -> Option<&PlaybookReference> {
        self.playbook_registry.get(playbook_id)
    }

    pub fn get_policy_reference(&self, policy_id: &str) -> Option<&PolicyReference> {
        self.policy_registry.get(policy_id)
    }

    fn load_registries(&mut self) {
        // Load playbook registry
        let playbooks = vec![
            PlaybookReference {
                playbook_id: "pb-rotate-ssh-keys".to_string(),
                playbook_name: "SSH Key Rotation".to_string(),
                description: "Rotate expired or compromised SSH keys".to_string(),
                category: "Authentication".to_string(),
                estimated_duration: "5-10 minutes".to_string(),
                required_permissions: vec!["vault:write".to_string(), "ssh:manage".to_string()],
                parameters: HashMap::new(),
            },
            PlaybookReference {
                playbook_id: "pb-vault-secret-rotation".to_string(),
                playbook_name: "Vault Secret Rotation".to_string(),
                description: "Rotate expired secrets in Vault".to_string(),
                category: "Cryptography".to_string(),
                estimated_duration: "10-15 minutes".to_string(),
                required_permissions: vec!["vault:admin".to_string()],
                parameters: HashMap::new(),
            },
            PlaybookReference {
                playbook_id: "pb-compliance-remediation".to_string(),
                playbook_name: "Compliance Remediation".to_string(),
                description: "Fix compliance control failures".to_string(),
                category: "Compliance".to_string(),
                estimated_duration: "15-30 minutes".to_string(),
                required_permissions: vec!["compliance:admin".to_string()],
                parameters: HashMap::new(),
            },
            PlaybookReference {
                playbook_id: "pb-network-diagnostics".to_string(),
                playbook_name: "Network Diagnostics".to_string(),
                description: "Diagnose and fix network connectivity issues".to_string(),
                category: "Network".to_string(),
                estimated_duration: "10-20 minutes".to_string(),
                required_permissions: vec!["network:diagnose".to_string()],
                parameters: HashMap::new(),
            },
        ];

        for playbook in playbooks {
            self.playbook_registry.insert(playbook.playbook_id.clone(), playbook);
        }

        // Load policy registry
        let policies = vec![
            PolicyReference {
                policy_id: "pol-pq-only".to_string(),
                policy_name: "Post-Quantum Only Policy".to_string(),
                description: "Enforce post-quantum cryptography for all connections".to_string(),
                category: "Cryptography".to_string(),
                compliance_frameworks: vec!["NIST".to_string(), "ISO27001".to_string()],
                enforcement_level: "strict".to_string(),
            },
            PolicyReference {
                policy_id: "pol-ssh-key-rotation".to_string(),
                policy_name: "SSH Key Rotation Policy".to_string(),
                description: "Mandatory SSH key rotation every 30 days".to_string(),
                category: "Authentication".to_string(),
                compliance_frameworks: vec!["SOC2".to_string(), "PCI-DSS".to_string()],
                enforcement_level: "enforced".to_string(),
            },
            PolicyReference {
                policy_id: "pol-vault-access".to_string(),
                policy_name: "Vault Access Control Policy".to_string(),
                description: "Role-based access control for Vault operations".to_string(),
                category: "Authorization".to_string(),
                compliance_frameworks: vec!["SOC2".to_string(), "ISO27001".to_string()],
                enforcement_level: "strict".to_string(),
            },
        ];

        for policy in policies {
            self.policy_registry.insert(policy.policy_id.clone(), policy);
        }
    }
}

impl Default for LinkEngine {
    fn default() -> Self {
        Self::new()
    }
}
