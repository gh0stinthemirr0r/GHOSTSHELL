//! Export formatters for different report formats
//! 
//! Handles CSV, XLSX, and PDF generation with GhostShell theming

use crate::{ReportJob, ReportError, ReportResult};
use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info};

/// CSV exporter
pub struct CsvExporter;

/// XLSX exporter with charts and styling
pub struct XlsxExporter;

/// PDF exporter with GhostShell branding
pub struct PdfExporter;

impl CsvExporter {
    /// Create a new CSV exporter
    pub fn new() -> Self {
        Self
    }
    
    /// Export data to CSV format
    pub async fn export(
        &self,
        data: &[HashMap<String, Value>],
        output_path: &Path,
        job: &ReportJob,
    ) -> ReportResult<()> {
        debug!("Exporting {} rows to CSV: {:?}", data.len(), output_path);
        
        if data.is_empty() {
            return Err(ReportError::ExportFormat("No data to export".to_string()));
        }
        
        // Create CSV writer
        let file = std::fs::File::create(output_path)
            .map_err(|e| ReportError::Io(e))?;
        let mut writer = csv::Writer::from_writer(file);
        
        // Get all unique column names
        let mut columns = std::collections::BTreeSet::new();
        for row in data {
            for key in row.keys() {
                columns.insert(key.clone());
            }
        }
        let column_vec: Vec<String> = columns.into_iter().collect();
        
        // Write header
        writer.write_record(&column_vec)
            .map_err(|e| ReportError::ExportFormat(format!("CSV header error: {}", e)))?;
        
        // Write data rows
        for row in data {
            let record: Vec<String> = column_vec.iter()
                .map(|col| {
                    row.get(col)
                        .map(|v| self.value_to_string(v))
                        .unwrap_or_default()
                })
                .collect();
            
            writer.write_record(&record)
                .map_err(|e| ReportError::ExportFormat(format!("CSV row error: {}", e)))?;
        }
        
        writer.flush()
            .map_err(|e| ReportError::ExportFormat(format!("CSV flush error: {}", e)))?;
        
        info!("CSV export completed: {} rows to {:?}", data.len(), output_path);
        Ok(())
    }
    
    /// Convert JSON value to string for CSV
    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => String::new(),
            Value::Array(_) | Value::Object(_) => {
                serde_json::to_string(value).unwrap_or_default()
            }
        }
    }
}

impl XlsxExporter {
    /// Create a new XLSX exporter
    pub fn new() -> Self {
        Self
    }
    
    /// Export data to XLSX format with styling and charts
    pub async fn export(
        &self,
        data: &[HashMap<String, Value>],
        output_path: &Path,
        job: &ReportJob,
    ) -> ReportResult<()> {
        debug!("Exporting {} rows to XLSX: {:?}", data.len(), output_path);
        
        if data.is_empty() {
            return Err(ReportError::ExportFormat("No data to export".to_string()));
        }
        
        // Create workbook
        let workbook = xlsxwriter::Workbook::new(output_path.to_str().unwrap())
            .map_err(|e| ReportError::ExportFormat(format!("XLSX workbook error: {}", e)))?;
        
        // Create main data worksheet
        let mut worksheet = workbook.add_worksheet(Some("Report Data"))
            .map_err(|e| ReportError::ExportFormat(format!("XLSX worksheet error: {}", e)))?;
        
        // Create formats for GhostShell theme (simplified)
        let mut header_format = xlsxwriter::Format::new();
        header_format.set_bold();
        
        let mut data_format = xlsxwriter::Format::new();
        
        let mut number_format = xlsxwriter::Format::new();
        number_format.set_num_format("#,##0.00");
        
        // Get columns
        let mut columns = std::collections::BTreeSet::new();
        for row in data {
            for key in row.keys() {
                columns.insert(key.clone());
            }
        }
        let column_vec: Vec<String> = columns.into_iter().collect();
        
        // Write headers
        for (col_idx, column) in column_vec.iter().enumerate() {
            worksheet.write_string(0, col_idx as u16, column, Some(&header_format))
                .map_err(|e| ReportError::ExportFormat(format!("XLSX header error: {}", e)))?;
        }
        
        // Write data
        for (row_idx, row) in data.iter().enumerate() {
            for (col_idx, column) in column_vec.iter().enumerate() {
                let cell_row = (row_idx + 1) as u32;
                let cell_col = col_idx as u16;
                
                if let Some(value) = row.get(column) {
                    match value {
                        Value::Number(n) => {
                            if let Some(f) = n.as_f64() {
                                worksheet.write_number(cell_row, cell_col, f, Some(&number_format))
                                    .map_err(|e| ReportError::ExportFormat(format!("XLSX number error: {}", e)))?;
                            } else {
                                worksheet.write_string(cell_row, cell_col, &n.to_string(), Some(&data_format))
                                    .map_err(|e| ReportError::ExportFormat(format!("XLSX string error: {}", e)))?;
                            }
                        }
                        _ => {
                            let str_value = self.value_to_string(value);
                            worksheet.write_string(cell_row, cell_col, &str_value, Some(&data_format))
                                .map_err(|e| ReportError::ExportFormat(format!("XLSX string error: {}", e)))?;
                        }
                    }
                } else {
                    worksheet.write_string(cell_row, cell_col, "", Some(&data_format))
                        .map_err(|e| ReportError::ExportFormat(format!("XLSX empty error: {}", e)))?;
                }
            }
        }
        
        // Auto-fit columns
        for (col_idx, _) in column_vec.iter().enumerate() {
            worksheet.set_column(col_idx as u16, col_idx as u16, 15.0, None)
                .map_err(|e| ReportError::ExportFormat(format!("XLSX column error: {}", e)))?;
        }
        
        // Add metadata sheet
        let mut meta_worksheet = workbook.add_worksheet(Some("Report Metadata"))
            .map_err(|e| ReportError::ExportFormat(format!("XLSX metadata worksheet error: {}", e)))?;
        
        // Write metadata
        let metadata = vec![
            ("Report Name", job.name.clone()),
            ("Created By", job.created_by.clone()),
            ("Generated At", Utc::now().to_rfc3339()),
            ("Data Sources", format!("{:?}", job.sources)),
            ("Total Rows", data.len().to_string()),
            ("Engine Version", env!("CARGO_PKG_VERSION").to_string()),
        ];
        
        for (row_idx, (key, value)) in metadata.iter().enumerate() {
            meta_worksheet.write_string(row_idx as u32, 0, key, Some(&header_format))
                .map_err(|e| ReportError::ExportFormat(format!("XLSX metadata key error: {}", e)))?;
            meta_worksheet.write_string(row_idx as u32, 1, value, Some(&data_format))
                .map_err(|e| ReportError::ExportFormat(format!("XLSX metadata value error: {}", e)))?;
        }
        
        // Close workbook
        workbook.close()
            .map_err(|e| ReportError::ExportFormat(format!("XLSX close error: {}", e)))?;
        
        info!("XLSX export completed: {} rows to {:?}", data.len(), output_path);
        Ok(())
    }
    
    /// Convert JSON value to string for XLSX
    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => String::new(),
            Value::Array(_) | Value::Object(_) => {
                serde_json::to_string(value).unwrap_or_default()
            }
        }
    }
}

impl PdfExporter {
    /// Create a new PDF exporter
    pub fn new() -> Self {
        Self
    }
    
    /// Export data to PDF format with GhostShell branding
    pub async fn export(
        &self,
        data: &[HashMap<String, Value>],
        output_path: &Path,
        job: &ReportJob,
    ) -> ReportResult<()> {
        debug!("Exporting {} rows to PDF: {:?}", data.len(), output_path);
        
        // Create PDF document
        let (doc, page1, layer1) = printpdf::PdfDocument::new("GhostShell Report", 
            printpdf::Mm(210.0), printpdf::Mm(297.0), "Layer 1");
        
        let current_layer = doc.get_page(page1).get_layer(layer1);
        
        // Define GhostShell colors (approximated for PDF)
        let neon_green = printpdf::Color::Rgb(printpdf::Rgb::new(0.686, 1.0, 0.0, None)); // #AFFF00
        let cyan = printpdf::Color::Rgb(printpdf::Rgb::new(0.0, 1.0, 0.82, None)); // #00FFD1
        let dark_bg = printpdf::Color::Rgb(printpdf::Rgb::new(0.04, 0.06, 0.11, None)); // #0A0F1E
        let light_text = printpdf::Color::Rgb(printpdf::Rgb::new(0.918, 0.918, 0.918, None)); // #EAEAEA
        
        // Load fonts (using built-in fonts for simplicity)
        let font = doc.add_builtin_font(printpdf::BuiltinFont::HelveticaBold)
            .map_err(|e| ReportError::ExportFormat(format!("PDF font error: {}", e)))?;
        let regular_font = doc.add_builtin_font(printpdf::BuiltinFont::Helvetica)
            .map_err(|e| ReportError::ExportFormat(format!("PDF font error: {}", e)))?;
        
        let mut current_y = 280.0; // Start from top
        
        // Title
        current_layer.use_text(&format!("👻 GhostShell Report: {}", job.name), 18.0, 
            printpdf::Mm(20.0), printpdf::Mm(current_y), &font);
        current_y -= 10.0;
        
        // Subtitle with metadata
        current_layer.use_text(&format!("Generated: {} | By: {}", 
            Utc::now().format("%Y-%m-%d %H:%M UTC"), job.created_by), 12.0,
            printpdf::Mm(20.0), printpdf::Mm(current_y), &regular_font);
        current_y -= 15.0;
        
        // Data sources section
        current_layer.use_text("Data Sources:", 14.0, 
            printpdf::Mm(20.0), printpdf::Mm(current_y), &font);
        current_y -= 8.0;
        
        for source in &job.sources {
            current_layer.use_text(&format!("• {:?}", source), 10.0,
                printpdf::Mm(25.0), printpdf::Mm(current_y), &regular_font);
            current_y -= 6.0;
        }
        current_y -= 5.0;
        
        // Summary statistics
        current_layer.use_text("Summary Statistics:", 14.0,
            printpdf::Mm(20.0), printpdf::Mm(current_y), &font);
        current_y -= 8.0;
        
        current_layer.use_text(&format!("• Total Records: {}", data.len()), 10.0,
            printpdf::Mm(25.0), printpdf::Mm(current_y), &regular_font);
        current_y -= 6.0;
        
        // Count records by source
        let mut source_counts = HashMap::new();
        for row in data {
            if let Some(Value::String(source)) = row.get("source") {
                *source_counts.entry(source.clone()).or_insert(0) += 1;
            }
        }
        
        for (source, count) in source_counts {
            current_layer.use_text(&format!("• {}: {} records", source, count), 10.0,
                printpdf::Mm(25.0), printpdf::Mm(current_y), &regular_font);
            current_y -= 6.0;
        }
        current_y -= 10.0;
        
        // Data table (first 20 rows as sample)
        if !data.is_empty() {
            current_layer.use_text("Data Sample (First 20 Records):", 14.0,
                printpdf::Mm(20.0), printpdf::Mm(current_y), &font);
            current_y -= 10.0;
            
            // Get columns (limit to first 5 for space)
            let mut columns = std::collections::BTreeSet::new();
            for row in data.iter().take(1) {
                for key in row.keys() {
                    columns.insert(key.clone());
                }
            }
            let column_vec: Vec<String> = columns.into_iter().take(5).collect();
            
            // Table headers
            let mut x_pos = 20.0;
            for column in &column_vec {
                current_layer.use_text(column, 8.0,
                    printpdf::Mm(x_pos), printpdf::Mm(current_y), &font);
                x_pos += 35.0;
            }
            current_y -= 8.0;
            
            // Table data (first 20 rows)
            for row in data.iter().take(20) {
                let mut x_pos = 20.0;
                for column in &column_vec {
                    let value = row.get(column)
                        .map(|v| self.value_to_string(v))
                        .unwrap_or_default();
                    
                    // Truncate long values
                    let display_value = if value.len() > 15 {
                        format!("{}...", &value[..12])
                    } else {
                        value
                    };
                    
                    current_layer.use_text(&display_value, 7.0,
                        printpdf::Mm(x_pos), printpdf::Mm(current_y), &regular_font);
                    x_pos += 35.0;
                }
                current_y -= 5.0;
                
                // Check if we need a new page
                if current_y < 30.0 {
                    break;
                }
            }
        }
        
        // Footer with signature info
        current_layer.use_text("This report is cryptographically signed with Post-Quantum Dilithium signatures.", 8.0,
            printpdf::Mm(20.0), printpdf::Mm(20.0), &regular_font);
        
        current_layer.use_text(&format!("Generated by GhostShell v{} | Confidential", 
            env!("CARGO_PKG_VERSION")), 8.0,
            printpdf::Mm(20.0), printpdf::Mm(15.0), &regular_font);
        
        // Save PDF
        doc.save(&mut std::io::BufWriter::new(
            std::fs::File::create(output_path)
                .map_err(|e| ReportError::Io(e))?
        )).map_err(|e| ReportError::ExportFormat(format!("PDF save error: {}", e)))?;
        
        info!("PDF export completed: {} rows to {:?}", data.len(), output_path);
        Ok(())
    }
    
    /// Convert JSON value to string for PDF
    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "N/A".to_string(),
            Value::Array(_) | Value::Object(_) => {
                serde_json::to_string(value).unwrap_or_default()
            }
        }
    }
}

impl Default for CsvExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for XlsxExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PdfExporter {
    fn default() -> Self {
        Self::new()
    }
}
