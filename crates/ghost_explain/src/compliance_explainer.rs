use crate::{Explanation, ExplanationType, ExplanationContext, ExplainResult, ExplainError};
use std::collections::HashMap;

pub struct ComplianceExplainer {
    templates: HashMap<String, String>,
}

impl ComplianceExplainer {
    pub fn new() -> Self {
        let mut explainer = Self {
            templates: HashMap::new(),
        };
        explainer.load_templates();
        explainer
    }

    pub fn explain_gap(
        &self,
        framework: &str,
        context: &ExplanationContext,
    ) -> ExplainResult<Explanation> {
        let title = format!("Compliance Gap Analysis: {}", framework);
        let summary = format!("Compliance gap detected in {} framework", framework);
        
        let detailed_analysis = match framework.to_lowercase().as_str() {
            "soc2" => "SOC 2 compliance gap indicates insufficient security controls or monitoring. This may affect customer trust and regulatory compliance.".to_string(),
            "pci-dss" => "PCI DSS compliance gap suggests payment card data security issues. Immediate remediation required to maintain payment processing capabilities.".to_string(),
            "iso27001" => "ISO 27001 compliance gap indicates information security management system deficiencies. Review and update security policies and procedures.".to_string(),
            "nist" => "NIST framework compliance gap suggests cybersecurity framework implementation issues. Assess current security posture and implement missing controls.".to_string(),
            _ => format!("Compliance gap in {} framework requires immediate attention. Review framework requirements and current implementation.", framework),
        };

        Ok(Explanation {
            explanation_type: ExplanationType::ComplianceGap,
            title,
            summary,
            detailed_analysis,
            root_causes: vec![
                "Configuration drift from baseline".to_string(),
                "Missing security controls".to_string(),
                "Inadequate monitoring".to_string(),
            ],
            impact_assessment: "May result in regulatory penalties, loss of certifications, and reduced customer trust".to_string(),
            recommended_actions: vec![
                "Review compliance requirements".to_string(),
                "Implement missing controls".to_string(),
                "Update security policies".to_string(),
                "Enhance monitoring and logging".to_string(),
            ],
            playbook_references: vec![
                "pb-compliance-remediation".to_string(),
                "pb-security-baseline".to_string(),
            ],
            evidence_references: vec![],
            confidence_score: 0.85,
            generated_at: chrono::Utc::now(),
        })
    }

    pub fn generate_executive_summary(
        &self,
        controls: &[String],
        context: &ExplanationContext,
    ) -> ExplainResult<Explanation> {
        let failed_count = controls.len();
        let title = "Executive Compliance Summary".to_string();
        let summary = format!("{} compliance controls require attention", failed_count);
        
        let detailed_analysis = format!(
            "Compliance assessment reveals {} controls that need remediation. \
            This represents a significant compliance risk that requires immediate attention. \
            The affected controls span multiple security domains and may impact \
            regulatory compliance, customer trust, and business operations.",
            failed_count
        );

        Ok(Explanation {
            explanation_type: ExplanationType::ExecutiveSummary,
            title,
            summary,
            detailed_analysis,
            root_causes: vec![
                "Insufficient security governance".to_string(),
                "Lack of continuous monitoring".to_string(),
                "Inadequate change management".to_string(),
            ],
            impact_assessment: "High risk of regulatory penalties and business disruption".to_string(),
            recommended_actions: vec![
                "Prioritize critical control remediation".to_string(),
                "Implement continuous compliance monitoring".to_string(),
                "Establish governance framework".to_string(),
                "Conduct regular compliance assessments".to_string(),
            ],
            playbook_references: vec![
                "pb-compliance-program".to_string(),
                "pb-governance-framework".to_string(),
            ],
            evidence_references: vec![],
            confidence_score: 0.90,
            generated_at: chrono::Utc::now(),
        })
    }

    fn load_templates(&mut self) {
        self.templates.insert(
            "gap_analysis".to_string(),
            "Compliance gap in {framework} indicates {issue_type}. Root cause: {root_cause}. Impact: {impact}. Recommended action: {action}.".to_string(),
        );
        
        self.templates.insert(
            "executive_summary".to_string(),
            "Executive Summary: {failed_count} controls failed. Priority: {priority}. Timeline: {timeline}. Business impact: {impact}.".to_string(),
        );
    }
}

impl Default for ComplianceExplainer {
    fn default() -> Self {
        Self::new()
    }
}
