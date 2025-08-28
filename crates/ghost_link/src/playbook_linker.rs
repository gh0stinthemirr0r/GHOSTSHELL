use crate::{ActionLink, LinkType, LinkContext, LinkResult, LinkError};

pub struct PlaybookLinker;

impl PlaybookLinker {
    pub fn new() -> Self {
        Self
    }

    pub fn get_relevant_playbooks(
        &self,
        error_category: &str,
        context: &LinkContext,
    ) -> LinkResult<Vec<ActionLink>> {
        let mut links = Vec::new();

        match error_category.to_lowercase().as_str() {
            "authentication" => {
                links.push(ActionLink {
                    link_type: LinkType::Playbook,
                    id: "pb-rotate-ssh-keys".to_string(),
                    title: "Rotate SSH Keys".to_string(),
                    description: "Fix authentication issues by rotating SSH keys".to_string(),
                    url: Some("/playbooks/rotate-ssh-keys".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 9,
                    estimated_time: Some("5-10 minutes".to_string()),
                });

                links.push(ActionLink {
                    link_type: LinkType::Playbook,
                    id: "pb-vault-key-renewal".to_string(),
                    title: "Renew Vault Keys".to_string(),
                    description: "Renew expired Vault authentication keys".to_string(),
                    url: Some("/playbooks/vault-key-renewal".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 8,
                    estimated_time: Some("10-15 minutes".to_string()),
                });
            }
            "network" => {
                links.push(ActionLink {
                    link_type: LinkType::Playbook,
                    id: "pb-network-diagnostics".to_string(),
                    title: "Network Diagnostics".to_string(),
                    description: "Diagnose and resolve network connectivity issues".to_string(),
                    url: Some("/playbooks/network-diagnostics".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 8,
                    estimated_time: Some("10-20 minutes".to_string()),
                });

                links.push(ActionLink {
                    link_type: LinkType::Playbook,
                    id: "pb-firewall-check".to_string(),
                    title: "Firewall Configuration Check".to_string(),
                    description: "Verify and update firewall rules".to_string(),
                    url: Some("/playbooks/firewall-check".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 7,
                    estimated_time: Some("15-25 minutes".to_string()),
                });
            }
            "cryptography" => {
                links.push(ActionLink {
                    link_type: LinkType::Playbook,
                    id: "pb-pq-crypto-config".to_string(),
                    title: "Post-Quantum Crypto Configuration".to_string(),
                    description: "Configure post-quantum cryptography settings".to_string(),
                    url: Some("/playbooks/pq-crypto-config".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 9,
                    estimated_time: Some("20-30 minutes".to_string()),
                });

                links.push(ActionLink {
                    link_type: LinkType::Playbook,
                    id: "pb-certificate-renewal".to_string(),
                    title: "Certificate Renewal".to_string(),
                    description: "Renew expired or expiring certificates".to_string(),
                    url: Some("/playbooks/certificate-renewal".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 8,
                    estimated_time: Some("15-25 minutes".to_string()),
                });
            }
            "policy" => {
                links.push(ActionLink {
                    link_type: LinkType::Playbook,
                    id: "pb-compliance-remediation".to_string(),
                    title: "Compliance Remediation".to_string(),
                    description: "Fix compliance policy violations".to_string(),
                    url: Some("/playbooks/compliance-remediation".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 9,
                    estimated_time: Some("15-30 minutes".to_string()),
                });

                links.push(ActionLink {
                    link_type: LinkType::Playbook,
                    id: "pb-policy-update".to_string(),
                    title: "Policy Configuration Update".to_string(),
                    description: "Update and apply security policy configurations".to_string(),
                    url: Some("/playbooks/policy-update".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 7,
                    estimated_time: Some("20-40 minutes".to_string()),
                });
            }
            _ => {
                links.push(ActionLink {
                    link_type: LinkType::Playbook,
                    id: "pb-general-troubleshooting".to_string(),
                    title: "General Troubleshooting".to_string(),
                    description: "General system troubleshooting procedures".to_string(),
                    url: Some("/playbooks/general-troubleshooting".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 5,
                    estimated_time: Some("10-30 minutes".to_string()),
                });
            }
        }

        Ok(links)
    }
}

impl Default for PlaybookLinker {
    fn default() -> Self {
        Self::new()
    }
}
