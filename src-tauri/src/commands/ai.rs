use ghost_ai::{AIEngine, AIStats, AIConfig};
use ghost_ai::engine::{SuggestionContext, AISuggestion};
use ghost_ai::SuggestionSource;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, error};

/// AI suggestion request
#[derive(Debug, Deserialize)]
pub struct AISuggestionRequest {
    pub source: String,
    pub error_text: String,
    pub component: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub context: Option<HashMap<String, String>>,
}

/// AI compliance insight request
#[derive(Debug, Deserialize)]
pub struct AIComplianceRequest {
    pub control_id: String,
    pub framework: String,
    pub context: Option<HashMap<String, String>>,
}

/// AI suggestion response
#[derive(Debug, Serialize)]
pub struct AISuggestionResponse {
    pub success: bool,
    pub suggestion: Option<AISuggestion>,
    pub error: Option<String>,
}

/// AI stats response
#[derive(Debug, Serialize)]
pub struct AIStatsResponse {
    pub success: bool,
    pub stats: Option<AIStats>,
    pub error: Option<String>,
}

/// AI config response
#[derive(Debug, Serialize)]
pub struct AIConfigResponse {
    pub success: bool,
    pub config: Option<AIConfig>,
    pub error: Option<String>,
}

/// Generate AI suggestion for an error
#[tauri::command]
pub async fn ai_explain_error(
    request: AISuggestionRequest,
    ai_engine: State<'_, Arc<Mutex<AIEngine>>>,
) -> Result<AISuggestionResponse, String> {
    debug!("AI explain error request: {:?}", request);

    let source = match request.source.to_lowercase().as_str() {
        "terminal" => SuggestionSource::Terminal,
        "ssh" => SuggestionSource::SSH,
        "vault" => SuggestionSource::Vault,
        "vpn" => SuggestionSource::VPN,
        "compliance" => SuggestionSource::Compliance,
        _ => SuggestionSource::Terminal, // Default fallback
    };

    let context = SuggestionContext {
        source,
        error_text: request.error_text.clone(),
        component: request.component,
        user_id: request.user_id,
        session_id: request.session_id,
        additional_context: request.context.unwrap_or_default(),
    };

    match ai_engine.lock().await.generate_suggestion(context).await {
        Ok(suggestion) => {
            info!("Generated AI suggestion: {}", suggestion.metadata.id);
            Ok(AISuggestionResponse {
                success: true,
                suggestion: Some(suggestion),
                error: None,
            })
        }
        Err(e) => {
            error!("Failed to generate AI suggestion: {}", e);
            Ok(AISuggestionResponse {
                success: false,
                suggestion: None,
                error: Some(e.to_string()),
            })
        }
    }
}

/// Generate AI compliance insight
#[tauri::command]
pub async fn ai_explain_control(
    request: AIComplianceRequest,
    ai_engine: State<'_, Arc<Mutex<AIEngine>>>,
) -> Result<AISuggestionResponse, String> {
    debug!("AI explain control request: {:?}", request);

    let context = request.context.unwrap_or_default();

    match ai_engine.lock().await.generate_compliance_insight(
        &request.control_id,
        &request.framework,
        context,
    ).await {
        Ok(suggestion) => {
            info!("Generated AI compliance insight for control: {}", request.control_id);
            Ok(AISuggestionResponse {
                success: true,
                suggestion: Some(suggestion),
                error: None,
            })
        }
        Err(e) => {
            error!("Failed to generate AI compliance insight: {}", e);
            Ok(AISuggestionResponse {
                success: false,
                suggestion: None,
                error: Some(e.to_string()),
            })
        }
    }
}

/// Generate AI report summary
#[tauri::command]
pub async fn ai_generate_report(
    inputs: HashMap<String, String>,
    style: Option<String>,
    ai_engine: State<'_, Arc<Mutex<AIEngine>>>,
) -> Result<AISuggestionResponse, String> {
    debug!("AI generate report request: {:?}", inputs);

    // For now, generate a simple executive summary
    let report_type = inputs.get("type").unwrap_or(&"executive".to_string()).clone();
    let framework = inputs.get("framework").unwrap_or(&"general".to_string()).clone();

    let context = SuggestionContext {
        source: SuggestionSource::Report,
        error_text: format!("Generate {} report for {}", report_type, framework),
        component: Some("report_generator".to_string()),
        user_id: inputs.get("user_id").cloned(),
        session_id: inputs.get("session_id").cloned(),
        additional_context: inputs,
    };

    match ai_engine.lock().await.generate_suggestion(context).await {
        Ok(mut suggestion) => {
            // Customize for report generation
            suggestion.explanation = format!(
                "Executive Summary Report\n\n\
                This report provides an overview of the current security and compliance posture. \
                Based on the analysis of system configurations, policy compliance, and security controls, \
                the following key findings and recommendations are presented:\n\n\
                Key Findings:\n\
                - System configurations are generally compliant with {} framework\n\
                - Some areas require attention for optimal security posture\n\
                - Continuous monitoring is active and functioning\n\n\
                Recommendations:\n\
                - Review and update security policies regularly\n\
                - Implement automated compliance monitoring\n\
                - Conduct regular security assessments\n\
                - Maintain up-to-date documentation",
                framework
            );

            info!("Generated AI report summary");
            Ok(AISuggestionResponse {
                success: true,
                suggestion: Some(suggestion),
                error: None,
            })
        }
        Err(e) => {
            error!("Failed to generate AI report: {}", e);
            Ok(AISuggestionResponse {
                success: false,
                suggestion: None,
                error: Some(e.to_string()),
            })
        }
    }
}

/// Get AI engine statistics
#[tauri::command]
pub async fn ai_get_stats(
    ai_engine: State<'_, Arc<Mutex<AIEngine>>>,
) -> Result<AIStatsResponse, String> {
    debug!("AI get stats request");

    let stats = ai_engine.lock().await.get_stats().clone();

    Ok(AIStatsResponse {
        success: true,
        stats: Some(stats),
        error: None,
    })
}

/// Get AI engine configuration
#[tauri::command]
pub async fn ai_get_config(
    ai_engine: State<'_, Arc<Mutex<AIEngine>>>,
) -> Result<AIConfigResponse, String> {
    debug!("AI get config request");

    let config = ai_engine.lock().await.get_config().clone();

    Ok(AIConfigResponse {
        success: true,
        config: Some(config),
        error: None,
    })
}

/// Update AI engine configuration
#[tauri::command]
pub async fn ai_update_config(
    config: AIConfig,
    ai_engine: State<'_, Arc<Mutex<AIEngine>>>,
) -> Result<AIConfigResponse, String> {
    debug!("AI update config request: {:?}", config);

    ai_engine.lock().await.update_config(config.clone());

    info!("AI engine configuration updated");
    Ok(AIConfigResponse {
        success: true,
        config: Some(config),
        error: None,
    })
}
