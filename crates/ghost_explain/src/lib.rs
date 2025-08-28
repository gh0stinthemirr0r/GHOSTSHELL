use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub mod compliance_explainer;
pub mod control_explainer;
pub mod signal_explainer;

pub use compliance_explainer::ComplianceExplainer;
pub use control_explainer::ControlExplainer;
pub use signal_explainer::SignalExplainer;

/// Explanation result type
pub type ExplainResult<T> = Result<T, ExplainError>;

/// Explanation errors
#[derive(Error, Debug)]
pub enum ExplainError {
    #[error("Control not found: {0}")]
    ControlNotFound(String),
    #[error("Signal not found: {0}")]
    SignalNotFound(String),
    #[error("Framework not supported: {0}")]
    UnsupportedFramework(String),
    #[error("Explanation generation failed: {0}")]
    GenerationFailed(String),
}

/// Explanation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExplanationType {
    ControlFailure,
    SignalAnalysis,
    ComplianceGap,
    Remediation,
    ExecutiveSummary,
}

/// Explanation context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationContext {
    pub control_id: Option<String>,
    pub signal_id: Option<String>,
    pub framework: Option<String>,
    pub severity: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Generated explanation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Explanation {
    pub explanation_type: ExplanationType,
    pub title: String,
    pub summary: String,
    pub detailed_analysis: String,
    pub root_causes: Vec<String>,
    pub impact_assessment: String,
    pub recommended_actions: Vec<String>,
    pub playbook_references: Vec<String>,
    pub evidence_references: Vec<String>,
    pub confidence_score: f64,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Explanation template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationTemplate {
    pub template_id: String,
    pub explanation_type: ExplanationType,
    pub title_template: String,
    pub summary_template: String,
    pub analysis_template: String,
    pub variables: Vec<String>,
}

/// Main explanation engine
pub struct ExplanationEngine {
    compliance_explainer: ComplianceExplainer,
    control_explainer: ControlExplainer,
    signal_explainer: SignalExplainer,
    templates: HashMap<String, ExplanationTemplate>,
}

impl ExplanationEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            compliance_explainer: ComplianceExplainer::new(),
            control_explainer: ControlExplainer::new(),
            signal_explainer: SignalExplainer::new(),
            templates: HashMap::new(),
        };
        engine.load_templates();
        engine
    }

    pub fn explain_control_failure(
        &self,
        control_id: &str,
        context: &ExplanationContext,
    ) -> ExplainResult<Explanation> {
        self.control_explainer.explain_failure(control_id, context)
    }

    pub fn explain_signal_analysis(
        &self,
        signal_id: &str,
        context: &ExplanationContext,
    ) -> ExplainResult<Explanation> {
        self.signal_explainer.explain_signal(signal_id, context)
    }

    pub fn explain_compliance_gap(
        &self,
        framework: &str,
        context: &ExplanationContext,
    ) -> ExplainResult<Explanation> {
        self.compliance_explainer.explain_gap(framework, context)
    }

    pub fn generate_executive_summary(
        &self,
        controls: &[String],
        context: &ExplanationContext,
    ) -> ExplainResult<Explanation> {
        self.compliance_explainer.generate_executive_summary(controls, context)
    }

    fn load_templates(&mut self) {
        // Load predefined explanation templates
        let templates = vec![
            ExplanationTemplate {
                template_id: "control_failure".to_string(),
                explanation_type: ExplanationType::ControlFailure,
                title_template: "Control {control_id} Failed: {control_name}".to_string(),
                summary_template: "The {framework} control {control_id} has failed with {severity} severity. This indicates {issue_type}.".to_string(),
                analysis_template: "Analysis shows that {root_cause}. The failure occurred because {detailed_reason}. This impacts {affected_systems} and may result in {potential_consequences}.".to_string(),
                variables: vec!["control_id".to_string(), "control_name".to_string(), "framework".to_string(), "severity".to_string(), "issue_type".to_string(), "root_cause".to_string(), "detailed_reason".to_string(), "affected_systems".to_string(), "potential_consequences".to_string()],
            },
            ExplanationTemplate {
                template_id: "signal_analysis".to_string(),
                explanation_type: ExplanationType::SignalAnalysis,
                title_template: "Signal Analysis: {signal_name}".to_string(),
                summary_template: "Signal {signal_id} indicates {signal_status} with confidence {confidence}%.".to_string(),
                analysis_template: "The signal data shows {signal_details}. This suggests {interpretation} based on {evidence_sources}.".to_string(),
                variables: vec!["signal_id".to_string(), "signal_name".to_string(), "signal_status".to_string(), "confidence".to_string(), "signal_details".to_string(), "interpretation".to_string(), "evidence_sources".to_string()],
            },
        ];

        for template in templates {
            self.templates.insert(template.template_id.clone(), template);
        }
    }

    pub fn get_template(&self, template_id: &str) -> Option<&ExplanationTemplate> {
        self.templates.get(template_id)
    }
}

impl Default for ExplanationEngine {
    fn default() -> Self {
        Self::new()
    }
}
