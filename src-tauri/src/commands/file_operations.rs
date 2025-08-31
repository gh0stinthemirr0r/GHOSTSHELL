use tauri::api::dialog::FileDialogBuilder;
use std::path::PathBuf;
use std::fs;
use csv::{ReaderBuilder, StringRecord};
use serde_json::{Value, Map};
use std::collections::HashMap;
use ghost_log::{get_ghost_log, LogSeverity};
use serde::{Deserialize, Serialize};
use encoding_rs::Encoding;
use encoding_rs_io::DecodeReaderBytesBuilder;
use std::io::{Read, BufReader};
use chardet::{detect, charset2encoding};
// Removed csv_sniffer due to API compatibility issues
use strsim::jaro_winkler;
use std::fs::File;
use std::time::SystemTime;
use tokio::sync::oneshot;
use crate::analysis::{Exporter, OverviewMetric};

// Data structures for robust CSV handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvValidationResult {
    pub valid: bool,
    pub headers: Vec<String>,
    pub row_count: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub encoding: String,
    pub delimiter: String,
    pub sample_data: Vec<HashMap<String, String>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvParseResult {
    pub success: bool,
    pub row_count: usize,
    pub encoding_detected: String,
    pub delimiter_detected: String,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub modified: String,
    pub created: String,
    pub extension: String,
    pub name: String,
}

#[tauri::command]
pub async fn open_file_dialog() -> Result<Option<String>, String> {
    let (tx, rx) = oneshot::channel();
    
    FileDialogBuilder::new()
        .add_filter("CSV Files", &["csv"])
        .add_filter("All Files", &["*"])
        .pick_file(move |file_path| {
            let result = file_path.map(|path| path.to_string_lossy().to_string());
            let _ = tx.send(result);
        });
    
    match rx.await {
        Ok(result) => Ok(result),
        Err(_) => Err("Dialog was cancelled or failed".to_string()),
    }
}

#[tauri::command]
pub async fn open_directory_dialog() -> Result<Option<String>, String> {
    let (tx, rx) = oneshot::channel();
    
    FileDialogBuilder::new()
        .pick_folder(move |dir_path| {
            let result = dir_path.map(|path| path.to_string_lossy().to_string());
            let _ = tx.send(result);
        });
    
    match rx.await {
        Ok(result) => Ok(result),
        Err(_) => Err("Dialog was cancelled or failed".to_string()),
    }
}

#[tauri::command]
pub async fn parse_csv_headers(file_path: String) -> Result<Vec<String>, String> {
    // Log the start of CSV header parsing
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "csv-header-parse-start",
            &format!("Starting CSV header parsing for file: {}", file_path)
        );
    }
    
    let path = PathBuf::from(&file_path);
    
    if !path.exists() {
        let error_msg = "File does not exist".to_string();
        // Log file not found error
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Error,
                "csv-file-not-found",
                &format!("File not found: {}", file_path)
            );
        }
        return Err(error_msg);
    }
    
    let contents = fs::read_to_string(&path)
        .map_err(|e| {
            let error_msg = format!("Failed to read file: {}", e);
            // Log file read error
            if let Some(ghost_log) = get_ghost_log() {
                let _ = ghost_log.log(
                    "pan-evaluator",
                    LogSeverity::Error,
                    "csv-file-read-error",
                    &error_msg
                );
            }
            error_msg
        })?;
    
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(contents.as_bytes());
    
    let headers = reader.headers()
        .map_err(|e| format!("Failed to parse CSV headers: {}", e))?;
    
    let header_list: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    
    // Validate that we have the expected PAN-OS policy columns (matching actual CSV export format)
    // Note: The first column is empty ("") in PAN-OS exports, representing the Position
    let required_columns = vec![
        "", "Name", "Tags", "Type", "Source Zone", "Source Address", "Source User", "Source Device",
        "Destination Zone", "Destination Address", "Destination Device", "Application", "Service",
        "Action", "Profile", "Options", "Rule Usage Hit Count", "Rule Usage Last Hit", 
        "Rule Usage First Hit", "Rule Usage Apps Seen", "Days With No New Apps", "Modified", "Created"
    ];
    
    let missing_columns: Vec<String> = required_columns.iter()
        .filter(|&col| !header_list.contains(&col.to_string()))
        .map(|&col| col.to_string())
        .collect();
    
    if !missing_columns.is_empty() {
        let error_msg = format!("CSV missing required columns: {}", missing_columns.join(", "));
        // Log missing columns error
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Error,
                "csv-missing-columns",
                &error_msg
            );
        }
        return Err(error_msg);
    }
    
    // Log successful header parsing
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "csv-header-parse-success",
            &format!("Successfully parsed {} headers from CSV file: {}", header_list.len(), file_path)
        );
    }
    
    Ok(header_list)
}

fn parse_evaluator_output(contents: &str) -> Result<Value, String> {
    let mut overview_metrics = Vec::new();
    let mut rules_data = Vec::new();
    
    // Find the sections by looking for the markers
    let overview_start = contents.find("=== OVERVIEW ===");
    let analysis_start = contents.find("=== ANALYSIS ===");
    
    if let Some(overview_pos) = overview_start {
        let overview_end = analysis_start.unwrap_or(contents.len());
        let overview_section = &contents[overview_pos + 16..overview_end]; // Skip "=== OVERVIEW ==="
        
        // Parse overview section using CSV reader
        let mut reader = ReaderBuilder::new()
            .has_headers(true)
            .from_reader(overview_section.trim().as_bytes());
        
        for result in reader.records() {
            if let Ok(record) = result {
                if record.len() >= 4 {
                    let mut metric = Map::new();
                    metric.insert("category".to_string(), Value::String(record[0].to_string()));
                    metric.insert("metric".to_string(), Value::String(record[1].to_string()));
                    metric.insert("value".to_string(), Value::String(record[2].to_string()));
                    metric.insert("description".to_string(), Value::String(record[3].to_string()));
                    overview_metrics.push(Value::Object(metric));
                }
            }
        }
    }
    
    if let Some(analysis_pos) = analysis_start {
        let analysis_section = &contents[analysis_pos + 16..]; // Skip "=== ANALYSIS ==="
        
        // Parse analysis section using CSV reader
        let mut reader = ReaderBuilder::new()
            .has_headers(true)
            .from_reader(analysis_section.trim().as_bytes());
        
        let headers = reader.headers().map_err(|e| format!("Failed to parse analysis headers: {}", e))?.clone();
        
        for result in reader.records() {
            if let Ok(record) = result {
                let mut rule = Map::new();
                
                for (i, header) in headers.iter().enumerate() {
                    if i < record.len() {
                        let value = record[i].trim().to_string();
                        
                        // Convert header to camelCase for consistency
                        let key = match header {
                            "" => "position".to_string(), // Empty column is position in PAN-OS exports
                            "Position" => "position".to_string(),
                            "Name" => "name".to_string(),
                            "Tags" => "tags".to_string(),
                            "Type" => "ruleType".to_string(),
                            "Source Zone" => "fromZone".to_string(),
                            "Source Address" => "sourceAddress".to_string(),
                            "Source User" => "sourceUser".to_string(),
                            "Source Device" => "sourceDevice".to_string(),
                            "Destination Zone" => "toZone".to_string(),
                            "Destination Address" => "destinationAddress".to_string(),
                            "Destination Device" => "destinationDevice".to_string(),
                            "Application" => "application".to_string(),
                            "Service" => "service".to_string(),
                            "Action" => "action".to_string(),
                            "Profile" => "profile".to_string(),
                            "Options" => "options".to_string(),
                            "Rule Usage Hit Count" => "ruleUsageHitCount".to_string(),
                            "Rule Usage Last Hit" => "ruleUsageLastHit".to_string(),
                            "Rule Usage First Hit" => "ruleUsageFirstHit".to_string(),
                            "Rule Usage Apps Seen" => "ruleUsageAppsSeen".to_string(),
                            "Days With No New Apps" => "daysWithNoNewApps".to_string(),
                            "Modified" => "modified".to_string(),
                            "Created" => "created".to_string(),
                            "Recommendation" => "recommendation".to_string(),
                            _ => header.to_lowercase().replace(" ", "_")
                        };
                        
                        // Parse numeric values
                        if key == "position" || key == "ruleUsageHitCount" || key == "ruleUsageAppsSeen" || key == "daysWithNoNewApps" {
                            if let Ok(num) = value.parse::<u64>() {
                                rule.insert(key, Value::Number(num.into()));
                            } else {
                                rule.insert(key, Value::String(value));
                            }
                        } else {
                            rule.insert(key, Value::String(value));
                        }
                    }
                }
                
                rules_data.push(Value::Object(rule));
            }
        }
    }
    
    let mut result = Map::new();
    result.insert("overview".to_string(), Value::Array(overview_metrics));
    result.insert("rules".to_string(), Value::Array(rules_data));
    
    Ok(Value::Object(result))
}

fn parse_list_field(field_value: &str) -> Vec<String> {
    if field_value.is_empty() || field_value.to_lowercase() == "any" {
        return vec!["any".to_string()];
    }
    
    // Split by semicolon and clean up each item (following original evaluator logic)
    let items: Vec<String> = field_value.split(';')
        .map(|item| {
            let mut cleaned = item.trim().to_string();
            // Remove [Disabled] prefixes
            if cleaned.starts_with("[Disabled]") {
                cleaned = cleaned.replace("[Disabled]", "").trim().to_string();
            }
            cleaned
        })
        .filter(|item| !item.is_empty())
        .collect();
    
    if items.is_empty() {
        vec!["any".to_string()]
    } else {
        items
    }
}

#[tauri::command]
pub async fn parse_csv_file(file_path: String, _expected_columns: Vec<String>) -> Result<Value, String> {
    // Log the start of CSV file parsing
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "csv-file-parse-start",
            &format!("Starting CSV file parsing for: {}", file_path)
        );
    }
    
    let path = PathBuf::from(&file_path);
    
    if !path.exists() {
        let error_msg = "File does not exist".to_string();
        // Log file not found error
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Error,
                "csv-file-not-found",
                &format!("File not found during parsing: {}", file_path)
            );
        }
        return Err(error_msg);
    }
    
    let contents = fs::read_to_string(&path)
        .map_err(|e| {
            let error_msg = format!("Failed to read file: {}", e);
            // Log file read error
            if let Some(ghost_log) = get_ghost_log() {
                let _ = ghost_log.log(
                    "pan-evaluator",
                    LogSeverity::Error,
                    "csv-file-read-error",
                    &format!("Failed to read CSV file {}: {}", file_path, e)
                );
            }
            error_msg
        })?;
    
    // Check if this is an evaluator output file (has OVERVIEW and ANALYSIS sections)
    if contents.contains("=== OVERVIEW ===") && contents.contains("=== ANALYSIS ===") {
        // Log evaluator output detection
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Info,
                "csv-evaluator-format-detected",
                &format!("Detected evaluator output format in file: {}", file_path)
            );
        }
        return parse_evaluator_output(&contents);
    }
    
    // Log raw PAN-OS export detection
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "csv-raw-format-detected",
            &format!("Detected raw PAN-OS export format in file: {}", file_path)
        );
    }
    
    // Otherwise, parse as regular PAN-OS export CSV
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(contents.as_bytes());
    
    let headers = reader.headers()
        .map_err(|e| format!("Failed to parse CSV headers: {}", e))?
        .clone();
    
    let mut records = Vec::new();
    
    for (idx, result) in reader.records().enumerate() {
        let record = result.map_err(|e| format!("Failed to parse CSV record: {}", e))?;
        
        let mut row = Map::new();
        let mut rule_data = HashMap::new();
        
        // Parse each field according to the original evaluator logic
        for (i, field) in record.iter().enumerate() {
            if let Some(header) = headers.get(i) {
                rule_data.insert(header.to_string(), field.to_string());
            }
        }
        
        // Parse position - first try the empty column, then fall back to index
        let position = if let Some(pos_str) = rule_data.get("") {
            pos_str.parse::<usize>().unwrap_or(idx + 1)
        } else {
            idx + 1
        };
        row.insert("position".to_string(), Value::Number(position.into()));
        
        // Parse rule name
        let name = rule_data.get("Name").unwrap_or(&format!("rule_{}", position)).trim().to_string();
        row.insert("name".to_string(), Value::String(name.clone()));
        
        // Parse action
        let action = rule_data.get("Action").unwrap_or(&"allow".to_string()).trim().to_lowercase();
        row.insert("action".to_string(), Value::String(action));
        
        // Parse zones
        let fromzone = parse_list_field(rule_data.get("Source Zone").unwrap_or(&"any".to_string()));
        let tozone = parse_list_field(rule_data.get("Destination Zone").unwrap_or(&"any".to_string()));
        row.insert("fromZone".to_string(), Value::Array(fromzone.into_iter().map(Value::String).collect()));
        row.insert("toZone".to_string(), Value::Array(tozone.into_iter().map(Value::String).collect()));
        
        // Parse addresses
        let source = parse_list_field(rule_data.get("Source Address").unwrap_or(&"any".to_string()));
        let destination = parse_list_field(rule_data.get("Destination Address").unwrap_or(&"any".to_string()));
        row.insert("sourceAddress".to_string(), Value::Array(source.into_iter().map(Value::String).collect()));
        row.insert("destinationAddress".to_string(), Value::Array(destination.into_iter().map(Value::String).collect()));
        
        // Parse applications and services
        let application = parse_list_field(rule_data.get("Application").unwrap_or(&"any".to_string()));
        let service = parse_list_field(rule_data.get("Service").unwrap_or(&"any".to_string()));
        row.insert("application".to_string(), Value::Array(application.into_iter().map(Value::String).collect()));
        row.insert("service".to_string(), Value::Array(service.into_iter().map(Value::String).collect()));
        
        // Parse users
        let source_user = parse_list_field(rule_data.get("Source User").unwrap_or(&"any".to_string()));
        row.insert("sourceUser".to_string(), Value::Array(source_user.into_iter().map(Value::String).collect()));
        
        // Parse hit counts
        let hit_count_default = "0".to_string();
        let hit_count_str = rule_data.get("Rule Usage Hit Count").unwrap_or(&hit_count_default);
        let hits_total: u64 = hit_count_str.parse().unwrap_or(0);
        row.insert("ruleUsageHitCount".to_string(), Value::Number(hits_total.into()));
        
        // Parse timestamps
        let last_hit = rule_data.get("Rule Usage Last Hit").unwrap_or(&"".to_string()).clone();
        let first_hit = rule_data.get("Rule Usage First Hit").unwrap_or(&"".to_string()).clone();
        row.insert("ruleUsageLastHit".to_string(), Value::String(last_hit));
        row.insert("ruleUsageFirstHit".to_string(), Value::String(first_hit));
        
        // Parse other fields
        let tags = parse_list_field(rule_data.get("Tags").unwrap_or(&"".to_string()));
        let tags_clone = tags.clone(); // Clone for later use
        row.insert("tags".to_string(), Value::Array(tags.into_iter().map(Value::String).collect()));
        
        let rule_type = rule_data.get("Type").unwrap_or(&"universal".to_string()).clone();
        row.insert("ruleType".to_string(), Value::String(rule_type));
        
        let profile = rule_data.get("Profile").unwrap_or(&"".to_string()).clone();
        row.insert("profile".to_string(), Value::String(profile));
        
        // Determine if rule is disabled
        let disabled = name.starts_with("[Disabled]") || 
                      tags_clone.iter().any(|tag| tag.starts_with("[Disabled]"));
        row.insert("disabled".to_string(), Value::Bool(disabled));
        
        // Add all original CSV columns for reference
        for (key, value) in rule_data {
            row.insert(format!("csv_{}", key.replace(" ", "_").to_lowercase()), Value::String(value));
        }
        
        records.push(Value::Object(row));
    }
    
    // Return in the same format as evaluator output for consistency
    let mut result = Map::new();
    result.insert("overview".to_string(), Value::Array(Vec::new())); // No overview for raw CSV
    result.insert("rules".to_string(), Value::Array(records.clone()));
    
    // Log successful CSV parsing
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "csv-file-parse-success",
            &format!("Successfully parsed {} rules from CSV file: {}", records.len(), file_path)
        );
    }
    
    Ok(Value::Object(result))
}

/// Robust CSV structure validation with encoding detection
#[tauri::command]
pub async fn validate_csv_structure(file_path: String) -> Result<CsvValidationResult, String> {
    // Log validation start
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "csv-validation-start",
            &format!("Starting CSV validation for: {}", file_path)
        );
    }
    
    let path = PathBuf::from(&file_path);
    
    if !path.exists() {
        return Ok(CsvValidationResult {
            valid: false,
            headers: Vec::new(),
            row_count: 0,
            warnings: Vec::new(),
            errors: vec!["File does not exist".to_string()],
            encoding: "Unknown".to_string(),
            delimiter: ",".to_string(),
            sample_data: Vec::new(),
            error: Some("File not found".to_string()),
        });
    }
    
    let mut result = CsvValidationResult {
        valid: false,
        headers: Vec::new(),
        row_count: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
        encoding: "UTF-8".to_string(),
        delimiter: ",".to_string(),
        sample_data: Vec::new(),
        error: None,
    };
    
    // Step 1: Detect file encoding
    let file_bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            result.error = Some(format!("Failed to read file: {}", e));
            result.errors.push(format!("IO Error: {}", e));
            return Ok(result);
        }
    };
    
    // Detect encoding using chardet
    let detected = detect(&file_bytes);
    let encoding_name = detected.0;
    let confidence = detected.1;
    
    result.encoding = encoding_name.to_string();
    
    if confidence < 0.7 {
        result.warnings.push(format!(
            "Low confidence ({:.1}%) in encoding detection. Detected: {}", 
            confidence * 100.0, 
            encoding_name
        ));
    }
    
    // Step 2: Convert to UTF-8 string
    let encoding_name = charset2encoding(&encoding_name);
    let encoding = encoding_rs::Encoding::for_label(encoding_name.as_bytes()).unwrap_or(encoding_rs::UTF_8);
    let (content, _encoding_used, had_errors) = encoding.decode(&file_bytes);
    
    if had_errors {
        result.warnings.push("Some characters could not be decoded properly".to_string());
    }
    
    // Step 3: Simple CSV format detection (fallback)
    // Try to detect delimiter by sampling first few lines
    let lines: Vec<&str> = content.lines().take(5).collect();
    let mut delimiter = b','; // default
    
    if !lines.is_empty() {
        let first_line = lines[0];
        let comma_count = first_line.matches(',').count();
        let semicolon_count = first_line.matches(';').count();
        let tab_count = first_line.matches('\t').count();
        
        if semicolon_count > comma_count && semicolon_count > tab_count {
            delimiter = b';';
        } else if tab_count > comma_count && tab_count > semicolon_count {
            delimiter = b'\t';
        }
    }
    
    result.delimiter = (delimiter as char).to_string();
    
    // Step 4: Parse CSV headers and sample data
    let mut reader = ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(true)
        .flexible(true) // Allow variable number of fields
        .from_reader(content.as_bytes());
    
    // Get headers
    match reader.headers() {
        Ok(headers) => {
            result.headers = headers.iter().map(|h| h.to_string()).collect();
            
            // Check for empty headers (common in PAN-OS exports)
            let empty_headers = result.headers.iter()
                .enumerate()
                .filter(|(_, h)| h.trim().is_empty())
                .count();
                
            if empty_headers > 0 {
                result.warnings.push(format!("{} empty header(s) found", empty_headers));
            }
            
            // Check for duplicate headers
            let mut seen = std::collections::HashSet::new();
            let mut duplicates = Vec::new();
            
            for header in &result.headers {
                if !seen.insert(header.to_lowercase()) {
                    duplicates.push(header.clone());
                }
            }
            
            if !duplicates.is_empty() {
                result.warnings.push(format!("Duplicate headers found: {}", duplicates.join(", ")));
            }
        }
        Err(e) => {
            result.errors.push(format!("Failed to parse headers: {}", e));
            return Ok(result);
        }
    }
    
    // Step 5: Count rows and collect sample data
    let mut row_count = 0;
    let mut sample_count = 0;
    const MAX_SAMPLES: usize = 5;
    
    for (idx, record_result) in reader.records().enumerate() {
        match record_result {
            Ok(record) => {
                row_count += 1;
                
                // Collect sample data
                if sample_count < MAX_SAMPLES {
                    let mut sample_row = HashMap::new();
                    
                    for (i, field) in record.iter().enumerate() {
                        if let Some(header) = result.headers.get(i) {
                            sample_row.insert(
                                if header.as_str().trim().is_empty() { 
                                    format!("Column_{}", i + 1) 
                                } else { 
                                    header.clone() 
                                }, 
                                field.to_string()
                            );
                        }
                    }
                    
                    result.sample_data.push(sample_row);
                    sample_count += 1;
                }
            }
            Err(e) => {
                result.warnings.push(format!("Row {} parsing warning: {}", idx + 1, e));
                // Continue processing other rows
            }
        }
    }
    
    result.row_count = row_count;
    
    // Step 6: Validate for PAN-OS policy format
    let expected_headers = [
        "name", "type", "from", "to", "source", "destination", 
        "application", "service", "action", "description"
    ];
    
    let mut recognized_headers = 0;
    for expected in &expected_headers {
        let found = result.headers.iter().any(|h| {
            let similarity = jaro_winkler(&h.to_lowercase(), expected);
            similarity > 0.8 || h.to_lowercase().contains(expected)
        });
        
        if found {
            recognized_headers += 1;
        }
    }
    
    if recognized_headers < 3 {
        result.warnings.push(
            "Few recognized PAN-OS policy headers found. This may not be a policy export file.".to_string()
        );
    }
    
    // Step 7: Final validation
    result.valid = result.errors.is_empty() && 
                   !result.headers.is_empty() && 
                   result.row_count > 0;
    
    if result.valid {
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Info,
                "csv-validation-success",
                &format!("CSV validation successful: {} rows, {} headers, encoding: {}", 
                    result.row_count, result.headers.len(), result.encoding)
            );
        }
    } else {
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Error,
                "csv-validation-failed",
                &format!("CSV validation failed: {}", result.errors.join(", "))
            );
        }
    }
    
    Ok(result)
}

/// Robust CSV file parsing with comprehensive error handling
#[tauri::command]
pub async fn parse_csv_file_robust(
    file_path: String, 
    expected_columns: Vec<String>
) -> Result<CsvParseResult, String> {
    // Log parsing start
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "csv-robust-parse-start",
            &format!("Starting robust CSV parsing for: {}", file_path)
        );
    }
    
    let path = PathBuf::from(&file_path);
    
    if !path.exists() {
        return Ok(CsvParseResult {
            success: false,
            row_count: 0,
            encoding_detected: "Unknown".to_string(),
            delimiter_detected: ",".to_string(),
            warnings: Vec::new(),
            errors: vec!["File does not exist".to_string()],
            data: Value::Null,
        });
    }
    
    let mut result = CsvParseResult {
        success: false,
        row_count: 0,
        encoding_detected: "UTF-8".to_string(),
        delimiter_detected: ",".to_string(),
        warnings: Vec::new(),
        errors: Vec::new(),
        data: Value::Null,
    };
    
    // Step 1: Detect encoding and format
    let file_bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            result.errors.push(format!("Failed to read file: {}", e));
            return Ok(result);
        }
    };
    
    // Detect encoding
    let detected = detect(&file_bytes);
    result.encoding_detected = detected.0.to_string();
    
    // Convert to UTF-8
    let encoding_name = charset2encoding(&detected.0);
    let encoding = encoding_rs::Encoding::for_label(encoding_name.as_bytes()).unwrap_or(encoding_rs::UTF_8);
    let (content, _encoding_used, had_errors) = encoding.decode(&file_bytes);
    
    if had_errors {
        result.warnings.push("Some characters could not be decoded properly".to_string());
    }
    
    // Simple CSV format detection (fallback)
    let lines: Vec<&str> = content.lines().take(5).collect();
    let mut delimiter = b','; // default
    
    if !lines.is_empty() {
        let first_line = lines[0];
        let comma_count = first_line.matches(',').count();
        let semicolon_count = first_line.matches(';').count();
        let tab_count = first_line.matches('\t').count();
        
        if semicolon_count > comma_count && semicolon_count > tab_count {
            delimiter = b';';
        } else if tab_count > comma_count && tab_count > semicolon_count {
            delimiter = b'\t';
        }
    }
    
    result.delimiter_detected = (delimiter as char).to_string();
    
    // Step 2: Check if this is evaluator output format
    if content.contains("=== OVERVIEW ===") && content.contains("=== ANALYSIS ===") {
        result.warnings.push("Detected evaluator output format".to_string());
        
        match parse_evaluator_output(&content) {
            Ok(parsed_data) => {
                result.success = true;
                result.data = parsed_data;
                
                if let Some(rules) = result.data.get("rules").and_then(|r| r.as_array()) {
                    result.row_count = rules.len();
                }
                
                return Ok(result);
            }
            Err(e) => {
                result.errors.push(format!("Failed to parse evaluator output: {}", e));
                return Ok(result);
            }
        }
    }
    
    // Step 3: Parse as regular CSV
    let mut reader = ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());
    
    // Get headers
    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(e) => {
            result.errors.push(format!("Failed to parse CSV headers: {}", e));
            return Ok(result);
        }
    };
    
    let header_list: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    
    // Step 4: Parse records with validation
    let mut records = Vec::new();
    let mut parse_errors = 0;
    
    for (idx, record_result) in reader.records().enumerate() {
        match record_result {
            Ok(record) => {
                let mut rule_data = HashMap::new();
                
                // Map CSV fields to rule structure
                for (i, field) in record.iter().enumerate() {
                    if let Some(header) = header_list.get(i) {
                        rule_data.insert(header.to_string(), field.to_string());
                    }
                }
                
                // Convert to standardized rule format (same as existing logic)
                let rule_json = convert_csv_row_to_rule(&rule_data, idx + 1);
                records.push(rule_json);
            }
            Err(e) => {
                parse_errors += 1;
                result.warnings.push(format!("Row {} parsing error: {}", idx + 1, e));
                
                // Skip malformed rows but continue processing
                if parse_errors > 10 {
                    result.errors.push("Too many parsing errors, stopping".to_string());
                    break;
                }
            }
        }
    }
    
    result.row_count = records.len();
    
    // Step 5: Create result data structure
    let mut data = Map::new();
    data.insert("overview".to_string(), Value::Array(Vec::new())); // No overview for raw CSV
    data.insert("rules".to_string(), Value::Array(records));
    
    result.data = Value::Object(data);
    result.success = result.errors.is_empty() && result.row_count > 0;
    
    // Log completion
    if result.success {
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Info,
                "csv-robust-parse-success",
                &format!("Successfully parsed {} rules from CSV", result.row_count)
            );
        }
    } else {
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "pan-evaluator",
                LogSeverity::Error,
                "csv-robust-parse-failed",
                &format!("CSV parsing failed: {}", result.errors.join(", "))
            );
        }
    }
    
    Ok(result)
}

/// Get file information for display
#[tauri::command]
pub async fn get_file_info(file_path: String) -> Result<FileInfo, String> {
    let path = PathBuf::from(&file_path);
    
    if !path.exists() {
        return Err("File does not exist".to_string());
    }
    
    let metadata = fs::metadata(&path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    
    let modified = metadata.modified()
        .map_err(|e| format!("Failed to get modification time: {}", e))?;
    
    let created = metadata.created()
        .map_err(|e| format!("Failed to get creation time: {}", e))?;
    
    Ok(FileInfo {
        path: file_path.clone(),
        size: metadata.len(),
        modified: format!("{:?}", modified),
        created: format!("{:?}", created),
        extension: path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_string(),
        name: path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// Convert CSV row data to standardized rule JSON format
fn convert_csv_row_to_rule(rule_data: &HashMap<String, String>, position: usize) -> Value {
    let mut row = Map::new();
    
    // Parse position - handle empty first column
    let pos = if let Some(pos_str) = rule_data.get("") {
        pos_str.parse::<usize>().unwrap_or(position)
    } else {
        position
    };
    row.insert("position".to_string(), Value::Number(pos.into()));
    
    // Parse rule name
    let name = rule_data.get("Name").unwrap_or(&format!("rule_{}", pos)).trim().to_string();
    row.insert("name".to_string(), Value::String(name.clone()));
    
    // Parse action
    let action = rule_data.get("Action").unwrap_or(&"allow".to_string()).trim().to_lowercase();
    row.insert("action".to_string(), Value::String(action));
    
    // Parse zones
    let fromzone = parse_list_field(rule_data.get("Source Zone").unwrap_or(&"any".to_string()));
    let tozone = parse_list_field(rule_data.get("Destination Zone").unwrap_or(&"any".to_string()));
    row.insert("fromZone".to_string(), Value::Array(fromzone.into_iter().map(Value::String).collect()));
    row.insert("toZone".to_string(), Value::Array(tozone.into_iter().map(Value::String).collect()));
    
    // Parse addresses
    let source = parse_list_field(rule_data.get("Source Address").unwrap_or(&"any".to_string()));
    let destination = parse_list_field(rule_data.get("Destination Address").unwrap_or(&"any".to_string()));
    row.insert("sourceAddress".to_string(), Value::Array(source.into_iter().map(Value::String).collect()));
    row.insert("destinationAddress".to_string(), Value::Array(destination.into_iter().map(Value::String).collect()));
    
    // Parse applications and services
    let application = parse_list_field(rule_data.get("Application").unwrap_or(&"any".to_string()));
    let service = parse_list_field(rule_data.get("Service").unwrap_or(&"any".to_string()));
    row.insert("application".to_string(), Value::Array(application.into_iter().map(Value::String).collect()));
    row.insert("service".to_string(), Value::Array(service.into_iter().map(Value::String).collect()));
    
    // Parse users
    let source_user = parse_list_field(rule_data.get("Source User").unwrap_or(&"any".to_string()));
    row.insert("sourceUser".to_string(), Value::Array(source_user.into_iter().map(Value::String).collect()));
    
    // Parse hit counts
    let default_hit_count = "0".to_string();
    let hit_count_str = rule_data.get("Rule Usage Hit Count").unwrap_or(&default_hit_count);
    let hits_total: u64 = hit_count_str.parse().unwrap_or(0);
    row.insert("ruleUsageHitCount".to_string(), Value::Number(hits_total.into()));
    
    // Parse timestamps
    let last_hit = rule_data.get("Rule Usage Last Hit").unwrap_or(&"".to_string()).clone();
    let first_hit = rule_data.get("Rule Usage First Hit").unwrap_or(&"".to_string()).clone();
    row.insert("ruleUsageLastHit".to_string(), Value::String(last_hit));
    row.insert("ruleUsageFirstHit".to_string(), Value::String(first_hit));
    
    // Parse other fields
    let tags = parse_list_field(rule_data.get("Tags").unwrap_or(&"".to_string()));
    let tags_clone = tags.clone();
    row.insert("tags".to_string(), Value::Array(tags.into_iter().map(Value::String).collect()));
    
    let rule_type = rule_data.get("Type").unwrap_or(&"universal".to_string()).clone();
    row.insert("ruleType".to_string(), Value::String(rule_type));
    
    let profile = rule_data.get("Profile").unwrap_or(&"".to_string()).clone();
    row.insert("profile".to_string(), Value::String(profile));
    
    // Determine if rule is disabled
    let disabled = name.starts_with("[Disabled]") || 
                  tags_clone.iter().any(|tag| tag.starts_with("[Disabled]"));
    row.insert("disabled".to_string(), Value::Bool(disabled));
    
    // Add all original CSV columns for reference
    for (key, value) in rule_data {
        row.insert(format!("csv_{}", key.replace(" ", "_").to_lowercase()), Value::String(value.clone()));
    }
    
    Value::Object(row)
}

/// Export analysis results to various formats
#[tauri::command]
pub async fn export_analysis_results(
    data: Value,
    format: String,
    output_path: Option<String>,
) -> Result<String, String> {
    // Log export start
    if let Some(ghost_log) = get_ghost_log() {
        let _ = ghost_log.log(
            "pan-evaluator",
            LogSeverity::Info,
            "export-start",
            &format!("Starting export to {} format", format)
        );
    }

    // Extract data from the input
    let overview_data: Vec<OverviewMetric> = serde_json::from_value(
        data.get("overview").cloned().unwrap_or(Value::Array(vec![]))
    ).map_err(|e| format!("Failed to parse overview data: {}", e))?;

    let rules_data: Vec<HashMap<String, String>> = serde_json::from_value(
        data.get("rules").cloned().unwrap_or(Value::Array(vec![]))
    ).map_err(|e| format!("Failed to parse rules data: {}", e))?;

    // Generate output path if not provided
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let default_filename = format!("pan_analysis_{}.{}", timestamp, format.to_lowercase());
    let output_dir = dirs::desktop_dir().unwrap_or_else(|| PathBuf::from("."));
    let file_path = output_path.unwrap_or_else(|| {
        output_dir.join(&default_filename).to_string_lossy().to_string()
    });

    // Export based on format
    let result = match format.to_lowercase().as_str() {
        "xlsx" => {
            Exporter::export_xlsx(&rules_data, &overview_data, &file_path)
        },
        "pdf" => {
            Exporter::export_pdf(&rules_data, &overview_data, &file_path)
        },
        "html" => {
            Exporter::export_html(&rules_data, &overview_data, &file_path)
        },
        "csv" => {
            Exporter::export_csv_with_sections(&rules_data, &overview_data, &file_path)
        },
        _ => {
            return Err(format!("Unsupported export format: {}", format));
        }
    };

    match result {
        Ok(path) => {
            // Log successful export
            if let Some(ghost_log) = get_ghost_log() {
                let _ = ghost_log.log(
                    "pan-evaluator",
                    LogSeverity::Info,
                    "export-success",
                    &format!("Successfully exported to {}: {}", format, path)
                );
            }
            Ok(path)
        },
        Err(e) => {
            // Log export error
            if let Some(ghost_log) = get_ghost_log() {
                let _ = ghost_log.log(
                    "pan-evaluator",
                    LogSeverity::Error,
                    "export-error",
                    &format!("Export failed for {}: {}", format, e)
                );
            }
            Err(e)
        }
    }
}
