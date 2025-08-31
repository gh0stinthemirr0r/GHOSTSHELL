use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::collections::HashMap;
use ghost_log::{get_ghost_log, LogSeverity};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanApiConfig {
    pub url: String,
    pub key: String,
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse {
    pub success: bool,
    pub data: Option<Value>,
    pub error: Option<String>,
    pub status_code: Option<u16>,
}

/// Test PAN-OS API connection
#[tauri::command]
pub async fn test_pan_api_connection(config: PanApiConfig) -> Result<ApiResponse, String> {
    // Log API test start
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "api-test-start",
            &format!("Testing PAN-OS API connection to: {}", config.url)
        );
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout.unwrap_or(30)))
        .danger_accept_invalid_certs(true) // Many firewalls use self-signed certs
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Test with system info endpoint
    let test_url = format!("{}/restapi/v10.1/System/SystemInfo", config.url.trim_end_matches('/'));
    
    let response = client
        .get(&test_url)
        .header("X-PAN-KEY", &config.key)
        .header("Content-Type", "application/json")
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            let status_code = status.as_u16();
            
            if status.is_success() {
                // Try to parse response
                match resp.text().await {
                    Ok(body) => {
                        // Log successful connection
                        if let Some(ghost_log) = get_ghost_log() {
                            let _ = ghost_log.log(
                                "pan-evaluator",
                                LogSeverity::Info,
                                "api-test-success",
                                &format!("Successfully connected to PAN-OS API: {}", config.url)
                            );
                        }

                        // Try to parse as JSON
                        let data = serde_json::from_str::<Value>(&body).ok();
                        
                        Ok(ApiResponse {
                            success: true,
                            data,
                            error: None,
                            status_code: Some(status_code),
                        })
                    },
                    Err(e) => {
                        let error_msg = format!("Failed to read response body: {}", e);
                        
                        if let Some(ghost_log) = get_ghost_log() {
                            let _ = ghost_log.log(
                                "pan-evaluator",
                                LogSeverity::Error,
                                "api-test-body-error",
                                &error_msg
                            );
                        }

                        Ok(ApiResponse {
                            success: false,
                            data: None,
                            error: Some(error_msg),
                            status_code: Some(status_code),
                        })
                    }
                }
            } else {
                let error_msg = match resp.text().await {
                    Ok(body) => format!("API returned status {}: {}", status_code, body),
                    Err(_) => format!("API returned status {}", status_code),
                };

                if let Some(ghost_log) = get_ghost_log() {
                    let _ = ghost_log.log(
                        "pan-evaluator",
                        LogSeverity::Error,
                        "api-test-http-error",
                        &error_msg
                    );
                }

                Ok(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(error_msg),
                    status_code: Some(status_code),
                })
            }
        },
        Err(e) => {
            let error_msg = format!("Connection failed: {}", e);
            
            if let Some(ghost_log) = get_ghost_log() {
                let _ = ghost_log.log(
                    "pan-evaluator",
                    LogSeverity::Error,
                    "api-test-connection-error",
                    &error_msg
                );
            }

            Ok(ApiResponse {
                success: false,
                data: None,
                error: Some(error_msg),
                status_code: None,
            })
        }
    }
}

/// Fetch security rules from PAN-OS API
#[tauri::command]
pub async fn fetch_pan_security_rules(config: PanApiConfig) -> Result<Value, String> {
    // Log rule fetch start
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "api-rules-fetch-start",
            &format!("Fetching security rules from PAN-OS API: {}", config.url)
        );
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout.unwrap_or(60)))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Fetch security rules
    let rules_url = format!("{}/restapi/v10.1/Policies/SecurityRules", config.url.trim_end_matches('/'));
    
    let response = client
        .get(&rules_url)
        .header("X-PAN-KEY", &config.key)
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch security rules: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        let error_msg = format!("API returned status {}: {}", status.as_u16(), error_body);
        
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Error,
                "api-rules-fetch-error",
                &error_msg
            );
        }
        
        return Err(error_msg);
    }

    let body = response.text().await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    // Parse the response
    let api_response: Value = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse API response: {}", e))?;

    // Convert API response to our internal format
    let rules = convert_api_rules_to_internal_format(&api_response)?;

    // Log successful fetch
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "api-rules-fetch-success",
            &format!("Successfully fetched {} security rules from API", 
                rules.as_array().map(|a| a.len()).unwrap_or(0))
        );
    }

    Ok(serde_json::json!({
        "overview": [],
        "rules": rules
    }))
}

/// Fetch rule usage statistics from PAN-OS API
#[tauri::command]
pub async fn fetch_pan_rule_usage(config: PanApiConfig) -> Result<Value, String> {
    // Log usage fetch start
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "api-usage-fetch-start",
            &format!("Fetching rule usage statistics from PAN-OS API: {}", config.url)
        );
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout.unwrap_or(60)))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Fetch rule usage statistics
    let usage_url = format!("{}/restapi/v10.1/Policies/SecurityRules/RuleUsage", config.url.trim_end_matches('/'));
    
    let response = client
        .get(&usage_url)
        .header("X-PAN-KEY", &config.key)
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch rule usage: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        let error_msg = format!("API returned status {}: {}", status.as_u16(), error_body);
        
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Error,
                "api-usage-fetch-error",
                &error_msg
            );
        }
        
        return Err(error_msg);
    }

    let body = response.text().await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    // Parse the response
    let usage_data: Value = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse usage response: {}", e))?;

    // Log successful fetch
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "api-usage-fetch-success",
            "Successfully fetched rule usage statistics from API"
        );
    }

    Ok(usage_data)
}

/// Convert PAN-OS API rule format to our internal format
fn convert_api_rules_to_internal_format(api_response: &Value) -> Result<Value, String> {
    // This is a simplified conversion - in reality, you'd need to handle
    // the specific PAN-OS API response format
    let rules = api_response
        .get("result")
        .and_then(|r| r.get("entry"))
        .and_then(|e| e.as_array())
        .ok_or("Invalid API response format")?;

    let mut converted_rules = Vec::new();

    for (index, rule) in rules.iter().enumerate() {
        let rule_obj = rule.as_object()
            .ok_or("Rule is not an object")?;

        let mut converted_rule = serde_json::Map::new();

        // Basic rule information
        converted_rule.insert("position".to_string(), Value::Number((index + 1).into()));
        converted_rule.insert("name".to_string(), 
            rule_obj.get("@name")
                .and_then(|v| v.as_str())
                .map(|s| Value::String(s.to_string()))
                .unwrap_or(Value::String(format!("rule_{}", index + 1)))
        );

        // Action
        converted_rule.insert("action".to_string(),
            rule_obj.get("action")
                .and_then(|v| v.as_str())
                .map(|s| Value::String(s.to_lowercase()))
                .unwrap_or(Value::String("allow".to_string()))
        );

        // Zones
        let from_zones = extract_array_field(rule_obj, "from");
        let to_zones = extract_array_field(rule_obj, "to");
        converted_rule.insert("fromZone".to_string(), Value::Array(from_zones));
        converted_rule.insert("toZone".to_string(), Value::Array(to_zones));

        // Addresses
        let source_addresses = extract_array_field(rule_obj, "source");
        let dest_addresses = extract_array_field(rule_obj, "destination");
        converted_rule.insert("sourceAddress".to_string(), Value::Array(source_addresses));
        converted_rule.insert("destinationAddress".to_string(), Value::Array(dest_addresses));

        // Applications and services
        let applications = extract_array_field(rule_obj, "application");
        let services = extract_array_field(rule_obj, "service");
        converted_rule.insert("application".to_string(), Value::Array(applications));
        converted_rule.insert("service".to_string(), Value::Array(services));

        // Users
        let source_users = extract_array_field(rule_obj, "source-user");
        converted_rule.insert("sourceUser".to_string(), Value::Array(source_users));

        // Default values for fields that might not be in API response
        converted_rule.insert("ruleUsageHitCount".to_string(), Value::Number(0.into()));
        converted_rule.insert("ruleUsageLastHit".to_string(), Value::String("".to_string()));
        converted_rule.insert("ruleUsageFirstHit".to_string(), Value::String("".to_string()));
        converted_rule.insert("disabled".to_string(), Value::Bool(false));
        converted_rule.insert("tags".to_string(), Value::Array(vec![]));
        converted_rule.insert("ruleType".to_string(), Value::String("universal".to_string()));

        converted_rules.push(Value::Object(converted_rule));
    }

    Ok(Value::Array(converted_rules))
}

/// Helper function to extract array fields from PAN-OS API response
fn extract_array_field(rule_obj: &serde_json::Map<String, Value>, field_name: &str) -> Vec<Value> {
    rule_obj.get(field_name)
        .and_then(|v| {
            if let Some(array) = v.as_array() {
                Some(array.clone())
            } else if let Some(string) = v.as_str() {
                Some(vec![Value::String(string.to_string())])
            } else {
                None
            }
        })
        .unwrap_or_else(|| vec![Value::String("any".to_string())])
}

/// Generic PAN-OS API call function
#[tauri::command]
pub async fn pan_api_call(
    config: PanApiConfig,
    endpoint: String,
    method: Option<String>,
    body: Option<Value>,
) -> Result<Value, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout.unwrap_or(30)))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let url = format!("{}{}", config.url.trim_end_matches('/'), endpoint);
    let method = method.unwrap_or_else(|| "GET".to_string());

    let mut request = match method.to_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        _ => return Err(format!("Unsupported HTTP method: {}", method)),
    };

    request = request
        .header("X-PAN-KEY", &config.key)
        .header("Content-Type", "application/json");

    if let Some(body_data) = body {
        request = request.json(&body_data);
    }

    let response = request.send().await
        .map_err(|e| format!("API request failed: {}", e))?;

    let status = response.status();
    let body_text = response.text().await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if status.is_success() {
        serde_json::from_str(&body_text)
            .map_err(|e| format!("Failed to parse response JSON: {}", e))
    } else {
        Err(format!("API returned status {}: {}", status.as_u16(), body_text))
    }
}
