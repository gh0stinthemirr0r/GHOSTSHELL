use crate::{Explanation, ExplanationType, ExplanationContext, ExplainResult, ExplainError};

pub struct SignalExplainer;

impl SignalExplainer {
    pub fn new() -> Self {
        Self
    }

    pub fn explain_signal(
        &self,
        signal_id: &str,
        context: &ExplanationContext,
    ) -> ExplainResult<Explanation> {
        let title = format!("Signal Analysis: {}", signal_id);
        let summary = format!("Analysis of signal {} indicates potential compliance issue", signal_id);
        
        let detailed_analysis = format!(
            "Signal {} has been triggered, indicating a deviation from expected \
            compliance behavior. This signal is part of the continuous monitoring \
            system and helps identify potential compliance violations before they \
            become critical issues.",
            signal_id
        );

        Ok(Explanation {
            explanation_type: ExplanationType::SignalAnalysis,
            title,
            summary,
            detailed_analysis,
            root_causes: vec![
                "System configuration change".to_string(),
                "Policy violation detected".to_string(),
                "Threshold exceeded".to_string(),
            ],
            impact_assessment: "Potential compliance risk requiring investigation".to_string(),
            recommended_actions: vec![
                "Investigate signal trigger".to_string(),
                "Review related system changes".to_string(),
                "Validate compliance status".to_string(),
            ],
            playbook_references: vec![
                "pb-signal-investigation".to_string(),
                "pb-compliance-validation".to_string(),
            ],
            evidence_references: vec![
                format!("signal:{}", signal_id),
            ],
            confidence_score: 0.75,
            generated_at: chrono::Utc::now(),
        })
    }
}

impl Default for SignalExplainer {
    fn default() -> Self {
        Self::new()
    }
}
