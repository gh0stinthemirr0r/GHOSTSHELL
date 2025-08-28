use crate::{ActionLink, LinkType, LinkContext, LinkResult};

pub struct PolicyLinker;

impl PolicyLinker {
    pub fn new() -> Self {
        Self
    }

    pub fn get_relevant_policies(
        &self,
        error_category: &str,
        context: &LinkContext,
    ) -> LinkResult<Vec<ActionLink>> {
        let mut links = Vec::new();

        match error_category.to_lowercase().as_str() {
            "authentication" => {
                links.push(ActionLink {
                    link_type: LinkType::Policy,
                    id: "pol-ssh-key-rotation".to_string(),
                    title: "SSH Key Rotation Policy".to_string(),
                    description: "Review SSH key rotation requirements and timelines".to_string(),
                    url: Some("/policies/ssh-key-rotation".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 7,
                    estimated_time: Some("5 minutes".to_string()),
                });
            }
            "cryptography" => {
                links.push(ActionLink {
                    link_type: LinkType::Policy,
                    id: "pol-pq-only".to_string(),
                    title: "Post-Quantum Only Policy".to_string(),
                    description: "Review post-quantum cryptography enforcement policy".to_string(),
                    url: Some("/policies/pq-only".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 8,
                    estimated_time: Some("3 minutes".to_string()),
                });
            }
            "policy" => {
                links.push(ActionLink {
                    link_type: LinkType::Policy,
                    id: "pol-compliance-framework".to_string(),
                    title: "Compliance Framework Policy".to_string(),
                    description: "Review compliance framework requirements".to_string(),
                    url: Some("/policies/compliance-framework".to_string()),
                    parameters: std::collections::HashMap::new(),
                    priority: 6,
                    estimated_time: Some("10 minutes".to_string()),
                });
            }
            _ => {}
        }

        Ok(links)
    }
}

impl Default for PolicyLinker {
    fn default() -> Self {
        Self::new()
    }
}
