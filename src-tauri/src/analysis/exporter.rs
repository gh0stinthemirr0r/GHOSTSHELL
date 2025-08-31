use super::data_structures::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use serde_json::Value;
use rust_xlsxwriter::{Workbook, Worksheet, Format, Color};
use printpdf::*;
use chrono::Utc;

/// Exporter for multiple formats matching Python Exporter class
pub struct Exporter;

impl Exporter {
    /// Header order matching Python script exactly
    pub const HEADER_ORDER: &'static [&'static str] = &[
        "Position", "Name", "Tags", "Type", "Source Zone", "Source Address", "Source User", "Source Device",
        "Destination Zone", "Destination Address", "Destination Device", "Application", "Service", "Action",
        "Profile", "Options", "Rule Usage Hit Count", "Rule Usage Last Hit", "Rule Usage First Hit",
        "Rule Usage Apps Seen", "Days With No New Apps", "Modified", "Created", "Recommendation"
    ];

    /// Create dataframe with recommendations matching Python logic
    pub fn dataframe_with_recommendations(
        rules: &[RuleLike],
        unused: &[RuleLike],
        shadows: &[ShadowFinding],
        merges: &[Proposal],
    ) -> Vec<HashMap<String, String>> {
        let mut result = Vec::new();
        
        // Create recommendation map
        let mut recommendations: HashMap<String, Vec<String>> = HashMap::new();

        // Add unused rule recommendations
        for rule in unused {
            recommendations
                .entry(rule.name.clone())
                .or_insert_with(Vec::new)
                .push("Disable: 0 hits over observation window.".to_string());
        }

        // Add shadow recommendations
        for shadow in shadows {
            recommendations
                .entry(shadow.shadowed_rule.clone())
                .or_insert_with(Vec::new)
                .push(format!(
                    "Shadowed by '{}' (pos {}); consider merge into top-most and remove after review.",
                    shadow.shadowing_rule, shadow.shadowing_position
                ));
        }

        // Add merge recommendations
        for proposal in merges {
            for rule_name in &proposal.source_rules {
                let other_rules: Vec<String> = proposal.source_rules
                    .iter()
                    .zip(&proposal.positions)
                    .filter(|(name, _)| *name != rule_name)
                    .map(|(name, pos)| format!("{} (pos {})", name, pos))
                    .collect();

                let msg = format!(
                    "Merge-candidate with {}; confidence={}. {}",
                    other_rules.join(", "),
                    proposal.confidence,
                    proposal.order_reason
                ).trim().to_string();

                recommendations
                    .entry(rule_name.clone())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
        }

        // Create rows with recommendations
        for rule in rules {
            let mut row = rule.to_row();
            
            // Add recommendation
            let rec = recommendations
                .get(&rule.name)
                .map(|recs| recs.join(" | "))
                .unwrap_or_default();
            row.insert("Recommendation".to_string(), rec);

            result.push(row);
        }

        // Sort by position
        result.sort_by_key(|row| {
            row.get("Position")
                .and_then(|p| p.parse::<i32>().ok())
                .unwrap_or(0)
        });

        result
    }

    /// Export to CSV format
    pub fn export_csv(data: &[HashMap<String, String>], path: &str) -> Result<String, String> {
        let mut file = File::create(path).map_err(|e| format!("Failed to create CSV file: {}", e))?;
        
        // Write header
        let header = Self::HEADER_ORDER.join(",");
        writeln!(file, "{}", header).map_err(|e| format!("Failed to write CSV header: {}", e))?;

        // Write data rows
        for row in data {
            let values: Vec<String> = Self::HEADER_ORDER
                .iter()
                .map(|col| {
                    let empty_string = String::new();
                    let value = row.get(*col).unwrap_or(&empty_string);
                    // Escape commas and quotes in CSV
                    if value.contains(',') || value.contains('"') || value.contains('\n') {
                        format!("\"{}\"", value.replace('"', "\"\""))
                    } else {
                        value.clone()
                    }
                })
                .collect();
            
            writeln!(file, "{}", values.join(","))
                .map_err(|e| format!("Failed to write CSV row: {}", e))?;
        }

        Ok(path.to_string())
    }

    /// Export CSV with sections (Overview + Analysis) matching Python script
    pub fn export_csv_with_sections(
        analysis_data: &[HashMap<String, String>],
        overview_data: &[OverviewMetric],
        path: &str,
    ) -> Result<String, String> {
        let mut file = File::create(path).map_err(|e| format!("Failed to create CSV file: {}", e))?;

        // Write overview section
        writeln!(file, "=== OVERVIEW ===").map_err(|e| format!("Failed to write section header: {}", e))?;
        writeln!(file, "Category,Metric,Value,Description").map_err(|e| format!("Failed to write overview header: {}", e))?;
        
        for metric in overview_data {
            writeln!(
                file,
                "{},{},{},{}",
                Self::escape_csv_value(&metric.category),
                Self::escape_csv_value(&metric.metric),
                Self::escape_csv_value(&metric.value),
                Self::escape_csv_value(&metric.description)
            ).map_err(|e| format!("Failed to write overview row: {}", e))?;
        }

        // Write separator
        writeln!(file, "").map_err(|e| format!("Failed to write separator: {}", e))?;
        writeln!(file, "=== ANALYSIS ===").map_err(|e| format!("Failed to write section header: {}", e))?;

        // Write analysis section
        let header = Self::HEADER_ORDER.join(",");
        writeln!(file, "{}", header).map_err(|e| format!("Failed to write analysis header: {}", e))?;

        for row in analysis_data {
            let values: Vec<String> = Self::HEADER_ORDER
                .iter()
                .map(|col| {
                    let empty_string = String::new();
                    let value = row.get(*col).unwrap_or(&empty_string);
                    Self::escape_csv_value(value)
                })
                .collect();
            
            writeln!(file, "{}", values.join(","))
                .map_err(|e| format!("Failed to write analysis row: {}", e))?;
        }

        Ok(path.to_string())
    }

    /// Export to JSON format for frontend consumption
    pub fn export_json(
        analysis_data: &[HashMap<String, String>],
        overview_data: &[OverviewMetric],
        unused: &[RuleLike],
        shadows: &[ShadowFinding],
        merges: &[Proposal],
    ) -> Value {
        serde_json::json!({
            "overview": overview_data,
            "rules": analysis_data,
            "analysis": {
                "unused_rules": unused,
                "shadow_findings": shadows,
                "merge_proposals": merges
            },
            "summary": {
                "total_rules": analysis_data.len(),
                "unused_count": unused.len(),
                "shadow_count": shadows.len(),
                "merge_count": merges.len()
            }
        })
    }

    /// Helper to escape CSV values
    fn escape_csv_value(value: &str) -> String {
        if value.contains(',') || value.contains('"') || value.contains('\n') {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_string()
        }
    }

    /// Export to Excel (XLSX) format with professional formatting
    pub fn export_xlsx(
        analysis_data: &[HashMap<String, String>],
        overview_data: &[OverviewMetric],
        path: &str,
    ) -> Result<String, String> {
        let mut workbook = Workbook::new();
        
        // Create formats
        let header_format = Format::new()
            .set_bold()
            .set_background_color(Color::RGB(0x4472C4))
            .set_font_color(Color::White)
            .set_border(rust_xlsxwriter::FormatBorder::Thin);
            
        let category_format = Format::new()
            .set_bold()
            .set_background_color(Color::RGB(0xE7E6E6))
            .set_border(rust_xlsxwriter::FormatBorder::Thin);
            
        let data_format = Format::new()
            .set_border(rust_xlsxwriter::FormatBorder::Thin);
            
        let recommendation_format = Format::new()
            .set_border(rust_xlsxwriter::FormatBorder::Thin)
            .set_text_wrap();

        // Overview worksheet
        let mut overview_sheet = workbook.add_worksheet();
        overview_sheet.set_name("Overview").map_err(|e| format!("Failed to set sheet name: {}", e))?;
        
        // Overview headers
        overview_sheet.write_string_with_format(0, 0, "Category", &header_format).map_err(|e| format!("Write error: {}", e))?;
        overview_sheet.write_string_with_format(0, 1, "Metric", &header_format).map_err(|e| format!("Write error: {}", e))?;
        overview_sheet.write_string_with_format(0, 2, "Value", &header_format).map_err(|e| format!("Write error: {}", e))?;
        overview_sheet.write_string_with_format(0, 3, "Description", &header_format).map_err(|e| format!("Write error: {}", e))?;
        
        // Overview data
        for (row_idx, metric) in overview_data.iter().enumerate() {
            let row = row_idx + 1;
            overview_sheet.write_string_with_format(row as u32, 0, &metric.category, &category_format).map_err(|e| format!("Write error: {}", e))?;
            overview_sheet.write_string_with_format(row as u32, 1, &metric.metric, &data_format).map_err(|e| format!("Write error: {}", e))?;
            overview_sheet.write_string_with_format(row as u32, 2, &metric.value, &data_format).map_err(|e| format!("Write error: {}", e))?;
            overview_sheet.write_string_with_format(row as u32, 3, &metric.description, &data_format).map_err(|e| format!("Write error: {}", e))?;
        }
        
        // Set column widths for overview
        overview_sheet.set_column_width(0, 15.0).map_err(|e| format!("Column width error: {}", e))?;
        overview_sheet.set_column_width(1, 25.0).map_err(|e| format!("Column width error: {}", e))?;
        overview_sheet.set_column_width(2, 15.0).map_err(|e| format!("Column width error: {}", e))?;
        overview_sheet.set_column_width(3, 50.0).map_err(|e| format!("Column width error: {}", e))?;

        // Analysis worksheet
        let mut analysis_sheet = workbook.add_worksheet();
        analysis_sheet.set_name("Policy Analysis").map_err(|e| format!("Failed to set sheet name: {}", e))?;
        
        // Analysis headers
        for (col_idx, header) in Self::HEADER_ORDER.iter().enumerate() {
            analysis_sheet.write_string_with_format(0, col_idx as u16, *header, &header_format).map_err(|e| format!("Write error: {}", e))?;
        }
        
        // Analysis data
        for (row_idx, row_data) in analysis_data.iter().enumerate() {
            let row = row_idx + 1;
            for (col_idx, col_name) in Self::HEADER_ORDER.iter().enumerate() {
                let empty_string = String::new();
                let value = row_data.get(*col_name).unwrap_or(&empty_string);
                
                let format = if *col_name == "Recommendation" {
                    &recommendation_format
                } else {
                    &data_format
                };
                
                analysis_sheet.write_string_with_format(row as u32, col_idx as u16, value, format).map_err(|e| format!("Write error: {}", e))?;
            }
        }
        
        // Set column widths for analysis
        for (col_idx, _) in Self::HEADER_ORDER.iter().enumerate() {
            let width = match col_idx {
                0 => 8.0,   // Position
                1 => 20.0,  // Name
                23 => 40.0, // Recommendation
                _ => 15.0,  // Default
            };
            analysis_sheet.set_column_width(col_idx as u16, width).map_err(|e| format!("Column width error: {}", e))?;
        }

        // Save workbook
        workbook.save(path).map_err(|e| format!("Failed to save Excel file: {}", e))?;
        
        Ok(path.to_string())
    }

    /// Export to PDF format with professional formatting
    pub fn export_pdf(
        analysis_data: &[HashMap<String, String>],
        overview_data: &[OverviewMetric],
        path: &str,
    ) -> Result<String, String> {
        let (doc, page1, layer1) = PdfDocument::new("PAN-OS Policy Analysis Report", Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(page1).get_layer(layer1);
        
        // Load fonts
        let font = doc.add_builtin_font(BuiltinFont::HelveticaBold).map_err(|e| format!("Font error: {}", e))?;
        let regular_font = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| format!("Font error: {}", e))?;
        
        let mut y_position = Mm(280.0);
        
        // Title
        current_layer.use_text("PAN-OS Policy Analysis Report", 18.0, Mm(20.0), y_position, &font);
        y_position -= Mm(10.0);
        
        // Date
        let date_str = format!("Generated: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
        current_layer.use_text(&date_str, 12.0, Mm(20.0), y_position, &regular_font);
        y_position -= Mm(20.0);
        
        // Overview section
        current_layer.use_text("Overview Metrics", 14.0, Mm(20.0), y_position, &font);
        y_position -= Mm(10.0);
        
        // Overview table (simplified for PDF)
        for metric in overview_data.iter().take(20) { // Limit for space
            if y_position < Mm(30.0) {
                break; // Avoid going off page
            }
            
            let line = format!("{}: {} - {}", metric.metric, metric.value, metric.description);
            current_layer.use_text(&line, 10.0, Mm(20.0), y_position, &regular_font);
            y_position -= Mm(6.0);
        }
        
        // Analysis summary
        y_position -= Mm(10.0);
        current_layer.use_text("Policy Rules Analysis", 14.0, Mm(20.0), y_position, &font);
        y_position -= Mm(8.0);
        
        let summary = format!("Total Rules Analyzed: {}", analysis_data.len());
        current_layer.use_text(&summary, 12.0, Mm(20.0), y_position, &regular_font);
        y_position -= Mm(6.0);
        
        let unused_count = analysis_data.iter().filter(|r| {
            r.get("Recommendation").map_or(false, |rec| rec.contains("Disable: 0 hits"))
        }).count();
        
        let unused_summary = format!("Unused Rules (0 hits): {}", unused_count);
        current_layer.use_text(&unused_summary, 12.0, Mm(20.0), y_position, &regular_font);
        y_position -= Mm(6.0);
        
        let shadow_count = analysis_data.iter().filter(|r| {
            r.get("Recommendation").map_or(false, |rec| rec.contains("Shadowed by"))
        }).count();
        
        let shadow_summary = format!("Shadowed Rules: {}", shadow_count);
        current_layer.use_text(&shadow_summary, 12.0, Mm(20.0), y_position, &regular_font);
        y_position -= Mm(6.0);
        
        let merge_count = analysis_data.iter().filter(|r| {
            r.get("Recommendation").map_or(false, |rec| rec.contains("Merge-candidate"))
        }).count();
        
        let merge_summary = format!("Merge Opportunities: {}", merge_count);
        current_layer.use_text(&merge_summary, 12.0, Mm(20.0), y_position, &regular_font);
        
        // Note about detailed data
        y_position -= Mm(15.0);
        current_layer.use_text("Note: For detailed rule-by-rule analysis, please refer to the Excel export.", 10.0, Mm(20.0), y_position, &regular_font);
        
        // Save PDF
        doc.save(&mut std::io::BufWriter::new(File::create(path).map_err(|e| format!("Failed to create PDF file: {}", e))?))
            .map_err(|e| format!("Failed to save PDF: {}", e))?;
        
        Ok(path.to_string())
    }

    /// Generate HTML report (enhanced implementation)
    pub fn export_html(
        analysis_data: &[HashMap<String, String>],
        overview_data: &[OverviewMetric],
        path: &str,
    ) -> Result<String, String> {
        let mut html = String::new();
        
        html.push_str("<!DOCTYPE html>\n");
        html.push_str("<html><head><title>PAN-OS Policy Analysis Report</title>\n");
        html.push_str("<meta charset='UTF-8'>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }\n");
        html.push_str(".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n");
        html.push_str("h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }\n");
        html.push_str("h2 { color: #34495e; margin-top: 30px; }\n");
        html.push_str("table { border-collapse: collapse; width: 100%; margin: 20px 0; }\n");
        html.push_str("th, td { border: 1px solid #ddd; padding: 12px 8px; text-align: left; }\n");
        html.push_str("th { background-color: #3498db; color: white; font-weight: bold; }\n");
        html.push_str("tr:nth-child(even) { background-color: #f8f9fa; }\n");
        html.push_str("tr:hover { background-color: #e8f4f8; }\n");
        html.push_str(".overview { margin-bottom: 30px; }\n");
        html.push_str(".category { font-weight: bold; background-color: #ecf0f1; }\n");
        html.push_str(".metric-value { font-weight: bold; color: #2980b9; }\n");
        html.push_str(".recommendation { max-width: 300px; word-wrap: break-word; }\n");
        html.push_str(".unused { background-color: #fff3cd; }\n");
        html.push_str(".shadowed { background-color: #f8d7da; }\n");
        html.push_str(".merge { background-color: #d4edda; }\n");
        html.push_str(".summary { background: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }\n");
        html.push_str("</style></head><body>\n");
        
        html.push_str("<div class='container'>\n");
        html.push_str("<h1>PAN-OS Policy Analysis Report</h1>\n");
        html.push_str(&format!("<p><strong>Generated:</strong> {}</p>\n", Utc::now().format("%Y-%m-%d %H:%M:%S")));
        
        // Summary section
        let total_rules = analysis_data.len();
        let unused_count = analysis_data.iter().filter(|r| {
            r.get("Recommendation").map_or(false, |rec| rec.contains("Disable: 0 hits"))
        }).count();
        let shadow_count = analysis_data.iter().filter(|r| {
            r.get("Recommendation").map_or(false, |rec| rec.contains("Shadowed by"))
        }).count();
        let merge_count = analysis_data.iter().filter(|r| {
            r.get("Recommendation").map_or(false, |rec| rec.contains("Merge-candidate"))
        }).count();
        
        html.push_str("<div class='summary'>\n");
        html.push_str("<h2>Executive Summary</h2>\n");
        html.push_str(&format!("<p><strong>Total Rules:</strong> {}</p>\n", total_rules));
        html.push_str(&format!("<p><strong>Unused Rules (0 hits):</strong> {} ({:.1}%)</p>\n", unused_count, (unused_count as f64 / total_rules as f64) * 100.0));
        html.push_str(&format!("<p><strong>Shadowed Rules:</strong> {} ({:.1}%)</p>\n", shadow_count, (shadow_count as f64 / total_rules as f64) * 100.0));
        html.push_str(&format!("<p><strong>Merge Opportunities:</strong> {} ({:.1}%)</p>\n", merge_count, (merge_count as f64 / total_rules as f64) * 100.0));
        html.push_str("</div>\n");
        
        // Overview section
        html.push_str("<div class='overview'>\n");
        html.push_str("<h2>Overview Metrics</h2>\n");
        html.push_str("<table>\n");
        html.push_str("<tr><th>Category</th><th>Metric</th><th>Value</th><th>Description</th></tr>\n");
        
        for metric in overview_data {
            html.push_str(&format!(
                "<tr><td class='category'>{}</td><td>{}</td><td class='metric-value'>{}</td><td>{}</td></tr>\n",
                html_escape::encode_text(&metric.category),
                html_escape::encode_text(&metric.metric),
                html_escape::encode_text(&metric.value),
                html_escape::encode_text(&metric.description)
            ));
        }
        
        html.push_str("</table>\n");
        html.push_str("</div>\n");
        
        // Analysis section
        html.push_str("<h2>Policy Rules Analysis</h2>\n");
        html.push_str("<table>\n");
        html.push_str("<tr>");
        for header in Self::HEADER_ORDER {
            html.push_str(&format!("<th>{}</th>", html_escape::encode_text(header)));
        }
        html.push_str("</tr>\n");
        
        for row in analysis_data {
            let row_class = if let Some(rec) = row.get("Recommendation") {
                if rec.contains("Disable: 0 hits") {
                    "unused"
                } else if rec.contains("Shadowed by") {
                    "shadowed"
                } else if rec.contains("Merge-candidate") {
                    "merge"
                } else {
                    ""
                }
            } else {
                ""
            };
            
            html.push_str(&format!("<tr class='{}'>", row_class));
            for col in Self::HEADER_ORDER {
                let empty_string = String::new();
                let value = row.get(*col).unwrap_or(&empty_string);
                let class = if *col == "Recommendation" { " class='recommendation'" } else { "" };
                html.push_str(&format!("<td{}>{}</td>", class, html_escape::encode_text(value)));
            }
            html.push_str("</tr>\n");
        }
        
        html.push_str("</table>\n");
        html.push_str("</div>\n");
        html.push_str("</body></html>\n");

        let mut file = File::create(path).map_err(|e| format!("Failed to create HTML file: {}", e))?;
        file.write_all(html.as_bytes()).map_err(|e| format!("Failed to write HTML file: {}", e))?;

        Ok(path.to_string())
    }
}
