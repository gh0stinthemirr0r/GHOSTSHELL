use crate::{AIConfig, AIStats, SuggestionSource, SuggestionPriority, SuggestionMetadata, AIError};
use ghost_errmap::{UniversalErrorMapper, ErrorClassification};
use ghost_explain::{ExplanationEngine, ExplanationContext, ExplanationType};
use ghost_link::{LinkEngine, LinkContext};
use ghost_log::AuditLogger;
use ghost_pq::signatures::DilithiumSigner;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn, error};

/// AI suggestion with full context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AISuggestion {
    pub metadata: SuggestionMetadata,
    pub error_text: String,
    pub classification: ErrorClassification,
    pub explanation: String,
    pub recommended_actions: Vec<String>,
    pub playbook_links: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub context: HashMap<String, String>,
}

/// AI suggestion context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestionContext {
    pub source: SuggestionSource,
    pub error_text: String,
    pub component: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub additional_context: HashMap<String, String>,
}

/// AI suggestion result
pub type SuggestionResult<T> = Result<T, AIError>;

/// Main AI engine
pub struct AIEngine {
    config: AIConfig,
    error_mapper: UniversalErrorMapper,
    explanation_engine: ExplanationEngine,
    link_engine: LinkEngine,
    logger: Arc<AuditLogger>,
    signer: Arc<DilithiumSigner>,
    stats: AIStats,
}

impl AIEngine {
    pub fn new(
        config: AIConfig,
        logger: Arc<AuditLogger>,
        signer: Arc<DilithiumSigner>,
    ) -> SuggestionResult<Self> {
        Ok(Self {
            config,
            error_mapper: UniversalErrorMapper::new(),
            explanation_engine: ExplanationEngine::new(),
            link_engine: LinkEngine::new(),
            logger,
            signer,
            stats: AIStats::default(),
        })
    }

    pub async fn initialize(&self) -> SuggestionResult<()> {
        debug!("AIEngine::initialize() - Entry");
        info!("AI Engine initialized with config: enabled={}, min_confidence={}", 
              self.config.enabled, self.config.min_confidence);
        debug!("AIEngine::initialize() - Completed successfully");
        Ok(())
    }

    /// Generate AI suggestion for an error
    pub async fn generate_suggestion(
        &mut self,
        context: SuggestionContext,
    ) -> SuggestionResult<AISuggestion> {
        let start_time = Instant::now();
        
        if !self.config.enabled {
            return Err(AIError::EngineDisabled);
        }

        debug!("Generating AI suggestion for error: {}", context.error_text);

        // Classify the error
        let classification = self.error_mapper
            .classify_error(&context.error_text, context.component.as_deref())
            .map_err(|e| AIError::ClassificationFailed(e.to_string()))?;

        // Check confidence threshold
        if classification.confidence < self.config.min_confidence {
            debug!("Classification confidence {} below threshold {}", 
                   classification.confidence, self.config.min_confidence);
            return Err(AIError::LowConfidence(classification.confidence));
        }

        // Generate explanation
        let explanation_context = ExplanationContext {
            control_id: None,
            signal_id: None,
            framework: None,
            severity: Some(format!("{:?}", classification.severity)),
            metadata: context.additional_context.clone(),
        };

        let explanation = match classification.category {
            ghost_errmap::ErrorCategory::Authentication => {
                format!("Authentication error detected: {}. {}", 
                        classification.description, 
                        classification.common_causes.join("; "))
            }
            ghost_errmap::ErrorCategory::Network => {
                format!("Network connectivity issue: {}. Common causes include: {}", 
                        classification.description,
                        classification.common_causes.join(", "))
            }
            ghost_errmap::ErrorCategory::Cryptography => {
                format!("Cryptographic error: {}. This may indicate: {}", 
                        classification.description,
                        classification.common_causes.join(" or "))
            }
            ghost_errmap::ErrorCategory::Policy => {
                format!("Policy violation detected: {}. Possible reasons: {}", 
                        classification.description,
                        classification.common_causes.join("; "))
            }
            _ => {
                format!("System error: {}. Investigate: {}", 
                        classification.description,
                        classification.common_causes.join(", "))
            }
        };

        // Generate action links
        let link_context = LinkContext {
            error_category: Some(format!("{:?}", classification.category)),
            severity: Some(format!("{:?}", classification.severity)),
            component: context.component.clone(),
            user_role: None,
            permissions: vec![],
            metadata: context.additional_context.clone(),
        };

        let action_links = self.link_engine
            .generate_action_links(&format!("{:?}", classification.category), &link_context)
            .unwrap_or_default();

        // Determine priority based on severity
        let priority = match classification.severity {
            ghost_errmap::ErrorSeverity::Critical => SuggestionPriority::Critical,
            ghost_errmap::ErrorSeverity::Error => SuggestionPriority::Warning,
            _ => SuggestionPriority::Info,
        };

        // Create suggestion metadata
        let mut metadata = SuggestionMetadata::new(
            context.source.clone(),
            classification.confidence,
            priority,
        );

        // Add evidence references
        metadata.add_evidence(
            "error_classification".to_string(),
            classification.matched_pattern.clone(),
            format!("Matched pattern: {}", classification.matched_pattern),
        );

        if let Some(session_id) = &context.session_id {
            metadata.add_evidence(
                "session".to_string(),
                session_id.clone(),
                "Session context".to_string(),
            );
        }

        // Create the suggestion
        let confidence = classification.confidence;
        let suggested_actions = classification.suggested_actions.clone();
        let mut suggestion = AISuggestion {
            metadata,
            error_text: context.error_text.clone(),
            classification,
            explanation,
            recommended_actions: suggested_actions,
            playbook_links: action_links.iter()
                .filter(|link| link.link_type == ghost_link::LinkType::Playbook)
                .map(|link| link.id.clone())
                .collect(),
            evidence_refs: vec![],
            context: context.additional_context,
        };

        // Sign the suggestion if enabled
        if self.config.enable_signing {
            if let Ok(signature) = self.sign_suggestion(&suggestion).await {
                suggestion.metadata.signature = Some(signature);
            }
        }

        // Update statistics
        let elapsed = start_time.elapsed();
        self.update_stats(&context.source, confidence, elapsed);

        // Log the suggestion
        info!("Generated AI suggestion {} for {} error with confidence {:.2}", 
              suggestion.metadata.id, 
              format!("{:?}", context.source),
              confidence);

        Ok(suggestion)
    }

    /// Generate compliance insight
    pub async fn generate_compliance_insight(
        &mut self,
        control_id: &str,
        framework: &str,
        context: HashMap<String, String>,
    ) -> SuggestionResult<AISuggestion> {
        debug!("Generating compliance insight for control: {}", control_id);

        let explanation_context = ExplanationContext {
            control_id: Some(control_id.to_string()),
            signal_id: None,
            framework: Some(framework.to_string()),
            severity: None,
            metadata: context.clone(),
        };

        let explanation = self.explanation_engine
            .explain_control_failure(control_id, &explanation_context)
            .map_err(|e| AIError::ExplanationFailed(e.to_string()))?;

        let mut metadata = SuggestionMetadata::new(
            SuggestionSource::Compliance,
            explanation.confidence_score,
            SuggestionPriority::Warning,
        );

        metadata.add_evidence(
            "control".to_string(),
            control_id.to_string(),
            format!("Compliance control: {}", control_id),
        );

        let suggestion = AISuggestion {
            metadata,
            error_text: format!("Control {} failed", control_id),
            classification: ghost_errmap::ErrorClassification {
                category: ghost_errmap::ErrorCategory::Policy,
                severity: ghost_errmap::ErrorSeverity::Warning,
                description: explanation.summary.clone(),
                common_causes: explanation.root_causes.clone(),
                suggested_actions: explanation.recommended_actions.clone(),
                playbook_refs: explanation.playbook_references.clone(),
                confidence: explanation.confidence_score,
                matched_pattern: "compliance_control".to_string(),
            },
            explanation: explanation.detailed_analysis,
            recommended_actions: explanation.recommended_actions,
            playbook_links: explanation.playbook_references,
            evidence_refs: explanation.evidence_references,
            context,
        };

        info!("Generated compliance insight for control {}", control_id);
        Ok(suggestion)
    }

    /// Sign an AI suggestion
    async fn sign_suggestion(&self, suggestion: &AISuggestion) -> SuggestionResult<String> {
        let suggestion_json = serde_json::to_string(suggestion)
            .map_err(|e| AIError::SerializationFailed(e.to_string()))?;

        // For now, return a placeholder signature
        // In a real implementation, this would use the DilithiumSigner
        Ok(format!("ai_sig_{}", suggestion.metadata.id))
    }

    /// Update engine statistics
    fn update_stats(&mut self, source: &SuggestionSource, confidence: f64, elapsed: Duration) {
        self.stats.total_suggestions += 1;
        
        let source_key = format!("{:?}", source);
        *self.stats.suggestions_by_source.entry(source_key).or_insert(0) += 1;
        
        // Update running averages
        let total = self.stats.total_suggestions as f64;
        self.stats.average_confidence = 
            (self.stats.average_confidence * (total - 1.0) + confidence) / total;
        
        let elapsed_ms = elapsed.as_millis() as f64;
        self.stats.average_response_time_ms = 
            (self.stats.average_response_time_ms * (total - 1.0) + elapsed_ms) / total;
    }

    /// Get engine statistics
    pub fn get_stats(&self) -> &AIStats {
        &self.stats
    }

    /// Get engine configuration
    pub fn get_config(&self) -> &AIConfig {
        &self.config
    }

    /// Update engine configuration
    pub fn update_config(&mut self, config: AIConfig) {
        self.config = config;
        info!("AI Engine configuration updated");
    }
}
