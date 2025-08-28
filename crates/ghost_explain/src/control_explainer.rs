use crate::{Explanation, ExplanationType, ExplanationContext, ExplainResult, ExplainError};
use std::collections::HashMap;

pub struct ControlExplainer {
    control_definitions: HashMap<String, ControlDefinition>,
}

#[derive(Debug, Clone)]
struct ControlDefinition {
    name: String,
    description: String,
    category: String,
    common_failures: Vec<String>,
    remediation_steps: Vec<String>,
}

impl ControlExplainer {
    pub fn new() -> Self {
        let mut explainer = Self {
            control_definitions: HashMap::new(),
        };
        explainer.load_control_definitions();
        explainer
    }

    pub fn explain_failure(
        &self,
        control_id: &str,
        context: &ExplanationContext,
    ) -> ExplainResult<Explanation> {
        let control_def = self.control_definitions
            .get(control_id)
            .ok_or_else(|| ExplainError::ControlNotFound(control_id.to_string()))?;

        let title = format!("Control Failure: {} - {}", control_id, control_def.name);
        let summary = format!("Control {} has failed: {}", control_id, control_def.description);
        
        let detailed_analysis = format!(
            "The {} control ({}) has failed its compliance check. \
            This control is part of the {} category and is critical for maintaining \
            security posture. The failure indicates that the expected security \
            measures are not properly implemented or functioning as designed.",
            control_def.name,
            control_id,
            control_def.category
        );

        let severity = context.severity.as_deref().unwrap_or("medium");
        let impact = match severity {
            "critical" => "Immediate security risk with potential for significant business impact",
            "high" => "Elevated security risk requiring prompt attention",
            "medium" => "Moderate security risk that should be addressed in planned maintenance",
            _ => "Low security risk for future consideration",
        };

        Ok(Explanation {
            explanation_type: ExplanationType::ControlFailure,
            title,
            summary,
            detailed_analysis,
            root_causes: control_def.common_failures.clone(),
            impact_assessment: impact.to_string(),
            recommended_actions: control_def.remediation_steps.clone(),
            playbook_references: vec![
                format!("pb-{}-remediation", control_id.to_lowercase()),
                "pb-compliance-remediation".to_string(),
            ],
            evidence_references: vec![
                format!("control:{}", control_id),
                format!("category:{}", control_def.category),
            ],
            confidence_score: 0.88,
            generated_at: chrono::Utc::now(),
        })
    }

    fn load_control_definitions(&mut self) {
        let controls = vec![
            ("CIS-4.1", ControlDefinition {
                name: "Secure Configuration Management".to_string(),
                description: "Maintain secure configurations for all systems".to_string(),
                category: "Configuration Management".to_string(),
                common_failures: vec![
                    "Configuration drift from baseline".to_string(),
                    "Unauthorized configuration changes".to_string(),
                    "Missing security hardening".to_string(),
                ],
                remediation_steps: vec![
                    "Review and update configuration baselines".to_string(),
                    "Implement configuration monitoring".to_string(),
                    "Apply security hardening guidelines".to_string(),
                ],
            }),
            ("SOC2-CC6.1", ControlDefinition {
                name: "Logical Access Controls".to_string(),
                description: "Implement logical access security measures".to_string(),
                category: "Access Control".to_string(),
                common_failures: vec![
                    "Excessive user privileges".to_string(),
                    "Inactive accounts not disabled".to_string(),
                    "Weak authentication mechanisms".to_string(),
                ],
                remediation_steps: vec![
                    "Review and right-size user permissions".to_string(),
                    "Disable inactive user accounts".to_string(),
                    "Implement multi-factor authentication".to_string(),
                ],
            }),
            ("NIST-AC-2", ControlDefinition {
                name: "Account Management".to_string(),
                description: "Manage information system accounts".to_string(),
                category: "Access Control".to_string(),
                common_failures: vec![
                    "Accounts not properly provisioned".to_string(),
                    "Lack of account lifecycle management".to_string(),
                    "Insufficient account monitoring".to_string(),
                ],
                remediation_steps: vec![
                    "Implement account provisioning procedures".to_string(),
                    "Establish account lifecycle management".to_string(),
                    "Enable account activity monitoring".to_string(),
                ],
            }),
        ];

        for (id, definition) in controls {
            self.control_definitions.insert(id.to_string(), definition);
        }
    }
}

impl Default for ControlExplainer {
    fn default() -> Self {
        Self::new()
    }
}
