use crate::analysis::{Analyzer, RuleLike as AnalysisRuleLike, AnalysisResults, Exporter};
use serde_json::{Value, Map};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use ghost_log::{get_ghost_log, LogSeverity};

/// Tauri command for comprehensive PAN-OS policy analysis
#[tauri::command]
pub async fn analyze_policy_rules(rules_data: Vec<Value>) -> Result<Value, String> {
    // Log the start of policy analysis
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "policy-analysis-start",
            &format!("Starting comprehensive policy analysis for {} rules", rules_data.len())
        );
    }
    
    // Convert JSON values to RuleLike structs
    let mut rules = Vec::new();
    
    for (idx, rule_value) in rules_data.iter().enumerate() {
        match parse_rule_from_value(rule_value.clone()) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                // Log rule parsing error
                if let Some(ghost_log) = get_ghost_log() {
                    let _ = ghost_log.log(
                        "pan-evaluator",
                        LogSeverity::Error,
                        "rule-parse-error",
                        &format!("Failed to parse rule at index {}: {}", idx, e)
                    );
                }
                return Err(format!("Failed to parse rule at index {}: {}", idx, e));
            }
        }
    }
    
    // Perform comprehensive analysis using the sophisticated analyzer
    let analyzer = Analyzer::new(rules.clone(), HashMap::new()); // Empty hits map for CSV-based analysis
    let results = analyzer.analyze("CSV Import");
    
    // Log analysis results
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "policy-analysis-complete",
            &format!(
                "Analysis complete: {} total rules, {} unused, {} shadowed, {} merge opportunities", 
                results.rules.len(),
                results.unused_rules.len(),
                results.shadow_findings.len(),
                results.merge_proposals.len()
            )
        );
        
        // Log detailed findings
        if !results.unused_rules.is_empty() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Warn,
                "unused-rules-found",
                &format!("Found {} unused rules (0 hits): {:?}", 
                    results.unused_rules.len(),
                    results.unused_rules.iter().map(|r| &r.name).collect::<Vec<_>>()
                )
            );
        }
        
        if !results.shadow_findings.is_empty() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Warn,
                "shadowed-rules-found",
                &format!("Found {} shadowed rules: {:?}", 
                    results.shadow_findings.len(),
                    results.shadow_findings.iter().map(|s| &s.shadowed_rule).collect::<Vec<_>>()
                )
            );
        }
        
        if !results.merge_proposals.is_empty() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Info,
                "merge-opportunities-found",
                &format!("Found {} merge opportunities: {:?}", 
                    results.merge_proposals.len(),
                    results.merge_proposals.iter().map(|m| &m.proposed_name).collect::<Vec<_>>()
                )
            );
        }
    }
    
    // Convert to format expected by frontend
    let analysis_data = Exporter::dataframe_with_recommendations(
        &results.rules,
        &results.unused_rules,
        &results.shadow_findings,
        &results.merge_proposals,
    );
    
    // Log export generation
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "analysis-export-generated",
            &format!("Generated analysis export with {} rules and {} overview metrics", 
                analysis_data.len(),
                results.overview_metrics.len()
            )
        );
    }
    
    // Return comprehensive results
    Ok(Exporter::export_json(
        &analysis_data,
        &results.overview_metrics,
        &results.unused_rules,
        &results.shadow_findings,
        &results.merge_proposals,
    ))
}

/// Convert JSON value to RuleLike struct with comprehensive field mapping
fn parse_rule_from_value(value: Value) -> Result<AnalysisRuleLike, String> {
    let obj = value.as_object().ok_or("Rule must be an object")?;
    
    let get_string = |key: &str| -> String {
        obj.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
    };
    
    let get_string_array = |key: &str| -> Vec<String> {
        let str_val = get_string(key);
        if str_val.is_empty() || str_val == "any" {
            vec!["any".to_string()]
        } else {
            str_val.split(", ").map(|s| s.trim().to_string()).collect()
        }
    };
    
    let get_i32 = |key: &str| -> i32 {
        obj.get(key)
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(0) as i32
    };
    
    let get_i64 = |key: &str| -> Option<i64> {
        obj.get(key)
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
    };
    
    let get_bool = |key: &str| -> bool {
        obj.get(key)
            .and_then(|v| v.as_bool().or_else(|| {
                v.as_str().map(|s| s.to_lowercase() == "true" || s == "1")
            }))
            .unwrap_or(false)
    };
    
    let get_optional_string = |key: &str| -> Option<String> {
        let val = get_string(key);
        if val.is_empty() { None } else { Some(val) }
    };
    
    Ok(AnalysisRuleLike {
        name: get_string("name"),
        position: get_i32("position"),
        action: get_string("action"),
        fromzone: get_string_array("sourceZone"),
        tozone: get_string_array("destinationZone"),
        source: get_string_array("sourceAddress"),
        destination: get_string_array("destinationAddress"),
        application: get_string_array("application"),
        service: get_string_array("service"),
        source_user: get_string_array("sourceUser"),
        url_category: get_string_array("urlCategory"),
        schedule: get_optional_string("schedule"),
        log_setting: get_optional_string("logSetting"),
        log_start: Some(get_bool("logStart")),
        log_end: Some(get_bool("logEnd")),
        profile_setting: get_optional_string("profile"),
        disabled: get_bool("disabled"),
        negate_source: get_bool("negateSrc"),
        negate_destination: get_bool("negateDst"),
        location: get_optional_string("prePost"),
        hits_total: get_i64("ruleUsageHitCount"),
        last_hit: get_optional_string("ruleUsageLastHit"),
        counter_since: get_optional_string("ruleUsageFirstHit"),
        tags: get_optional_string("tags"),
        rule_type: get_optional_string("type"),
        source_device: get_optional_string("sourceDevice"),
        destination_device: get_optional_string("destinationDevice"),
        apps_seen: get_optional_string("ruleUsageAppsSeen"),
        days_no_new_apps: get_optional_string("daysWithNoNewApps"),
        modified: get_optional_string("modified"),
        created: get_optional_string("created"),
    })
}