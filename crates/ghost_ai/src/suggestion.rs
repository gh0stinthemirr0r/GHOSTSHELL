use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use crate::{SuggestionSource, SuggestionMetadata};

/// AI suggestion errors
#[derive(Error, Debug)]
pub enum AIError {
    #[error("AI engine is disabled")]
    EngineDisabled,
    #[error("Classification failed: {0}")]
    ClassificationFailed(String),
    #[error("Explanation failed: {0}")]
    ExplanationFailed(String),
    #[error("Confidence too low: {0}")]
    LowConfidence(f64),
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Signature generation failed: {0}")]
    SignatureFailed(String),
    #[error("Context invalid: {0}")]
    InvalidContext(String),
}

/// AI suggestion context for generating suggestions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestionContext {
    pub source: SuggestionSource,
    pub error_text: String,
    pub component: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub additional_context: HashMap<String, String>,
}

impl SuggestionContext {
    pub fn new(source: SuggestionSource, error_text: String) -> Self {
        Self {
            source,
            error_text,
            component: None,
            user_id: None,
            session_id: None,
            additional_context: HashMap::new(),
        }
    }

    pub fn with_component(mut self, component: String) -> Self {
        self.component = Some(component);
        self
    }

    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn add_context(mut self, key: String, value: String) -> Self {
        self.additional_context.insert(key, value);
        self
    }
}

/// AI suggestion result type
pub type SuggestionResult<T> = Result<T, AIError>;

/// Complete AI suggestion with all metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AISuggestion {
    pub metadata: SuggestionMetadata,
    pub error_text: String,
    pub analysis: String,
    pub explanation: String,
    pub recommended_actions: Vec<String>,
    pub playbook_links: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub context: HashMap<String, String>,
}

impl AISuggestion {
    pub fn new(
        source: SuggestionSource,
        error_text: String,
        confidence: f64,
        priority: crate::SuggestionPriority,
    ) -> Self {
        Self {
            metadata: SuggestionMetadata::new(source, confidence, priority),
            error_text,
            analysis: String::new(),
            explanation: String::new(),
            recommended_actions: Vec::new(),
            playbook_links: Vec::new(),
            evidence_refs: Vec::new(),
            context: HashMap::new(),
        }
    }

    pub fn with_analysis(mut self, analysis: String) -> Self {
        self.analysis = analysis;
        self
    }

    pub fn with_explanation(mut self, explanation: String) -> Self {
        self.explanation = explanation;
        self
    }

    pub fn add_action(mut self, action: String) -> Self {
        self.recommended_actions.push(action);
        self
    }

    pub fn add_playbook(mut self, playbook_id: String) -> Self {
        self.playbook_links.push(playbook_id);
        self
    }

    pub fn add_evidence(mut self, evidence_ref: String) -> Self {
        self.evidence_refs.push(evidence_ref);
        self
    }

    pub fn add_context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }

    /// Get suggestion ID
    pub fn id(&self) -> &str {
        &self.metadata.id
    }

    /// Get confidence level
    pub fn confidence(&self) -> f64 {
        self.metadata.confidence
    }

    /// Get priority
    pub fn priority(&self) -> &crate::SuggestionPriority {
        &self.metadata.priority
    }

    /// Check if suggestion is signed
    pub fn is_signed(&self) -> bool {
        self.metadata.signature.is_some()
    }

    /// Get signature if available
    pub fn signature(&self) -> Option<&str> {
        self.metadata.signature.as_deref()
    }
}
