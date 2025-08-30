//! Report templates and styling
//! 
//! Provides predefined templates and styling options for reports

use crate::{ReportJob, ReportError, ReportResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Report template definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTemplate {
    /// Template identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Template description
    pub description: String,
    /// Template category
    pub category: TemplateCategory,
    /// Styling configuration
    pub styling: TemplateStyling,
    /// Default sections to include
    pub sections: Vec<TemplateSection>,
    /// Template variables
    pub variables: HashMap<String, TemplateVariable>,
}

/// Template categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TemplateCategory {
    /// Security and compliance reports
    Security,
    /// Network analysis reports
    Network,
    /// System monitoring reports
    System,
    /// Incident response reports
    Incident,
    /// Audit and compliance reports
    Audit,
    /// Custom user templates
    Custom,
}

/// Template styling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateStyling {
    /// Color scheme
    pub color_scheme: ColorScheme,
    /// Font configuration
    pub fonts: FontConfig,
    /// Logo and branding
    pub branding: BrandingConfig,
    /// Layout settings
    pub layout: LayoutConfig,
}

/// Color schemes for reports
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ColorScheme {
    /// GhostShell cyberpunk theme (neon colors)
    GhostShellNeon,
    /// Corporate professional theme
    Corporate,
    /// High contrast for accessibility
    HighContrast,
    /// Grayscale for printing
    Grayscale,
    /// Custom color palette
    Custom(CustomColors),
}

/// Custom color palette
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomColors {
    /// Primary color
    pub primary: String,
    /// Secondary color
    pub secondary: String,
    /// Accent color
    pub accent: String,
    /// Background color
    pub background: String,
    /// Text color
    pub text: String,
}

/// Font configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontConfig {
    /// Header font
    pub header_font: String,
    /// Body font
    pub body_font: String,
    /// Monospace font for code/data
    pub mono_font: String,
    /// Base font size
    pub base_size: u32,
}

/// Branding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandingConfig {
    /// Organization name
    pub organization: String,
    /// Logo path or URL
    pub logo_path: Option<String>,
    /// Footer text
    pub footer_text: String,
    /// Watermark text
    pub watermark: Option<String>,
}

/// Layout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutConfig {
    /// Page margins (in points)
    pub margins: Margins,
    /// Header height
    pub header_height: u32,
    /// Footer height
    pub footer_height: u32,
    /// Column layout
    pub columns: u32,
}

/// Page margins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Margins {
    pub top: u32,
    pub bottom: u32,
    pub left: u32,
    pub right: u32,
}

/// Template sections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSection {
    /// Section identifier
    pub id: String,
    /// Section title
    pub title: String,
    /// Section type
    pub section_type: SectionType,
    /// Whether section is required
    pub required: bool,
    /// Section order
    pub order: u32,
}

/// Section types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SectionType {
    /// Title page
    TitlePage,
    /// Executive summary
    ExecutiveSummary,
    /// Table of contents
    TableOfContents,
    /// Data table
    DataTable,
    /// Chart/visualization
    Chart,
    /// Text content
    TextContent,
    /// Appendix
    Appendix,
    /// Signature page
    SignaturePage,
}

/// Template variables for customization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariable {
    /// Variable name
    pub name: String,
    /// Variable type
    pub var_type: VariableType,
    /// Default value
    pub default_value: Option<String>,
    /// Description
    pub description: String,
    /// Whether variable is required
    pub required: bool,
}

/// Variable types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableType {
    Text,
    Number,
    Date,
    Boolean,
    Color,
    Font,
}

/// Template manager
pub struct TemplateManager {
    /// Built-in templates
    templates: HashMap<String, ReportTemplate>,
}

impl TemplateManager {
    /// Create a new template manager
    pub fn new() -> Self {
        let mut manager = Self {
            templates: HashMap::new(),
        };
        
        // Load built-in templates
        manager.load_builtin_templates();
        
        manager
    }
    
    /// Load built-in templates
    fn load_builtin_templates(&mut self) {
        // GhostShell Security Audit Template
        let security_template = ReportTemplate {
            id: "ghostshell-security-audit".to_string(),
            name: "GhostShell Security Audit".to_string(),
            description: "Comprehensive security audit report with cyberpunk styling".to_string(),
            category: TemplateCategory::Security,
            styling: TemplateStyling {
                color_scheme: ColorScheme::GhostShellNeon,
                fonts: FontConfig {
                    header_font: "JetBrains Mono".to_string(),
                    body_font: "Space Grotesk".to_string(),
                    mono_font: "JetBrains Mono".to_string(),
                    base_size: 12,
                },
                branding: BrandingConfig {
                    organization: "GhostShell Security".to_string(),
                    logo_path: Some("assets/ghostshell-logo.png".to_string()),
                    footer_text: "Confidential - Post-Quantum Secured".to_string(),
                    watermark: Some("👻 GHOSTSHELL".to_string()),
                },
                layout: LayoutConfig {
                    margins: Margins { top: 72, bottom: 72, left: 72, right: 72 },
                    header_height: 50,
                    footer_height: 30,
                    columns: 1,
                },
            },
            sections: vec![
                TemplateSection {
                    id: "title".to_string(),
                    title: "Title Page".to_string(),
                    section_type: SectionType::TitlePage,
                    required: true,
                    order: 1,
                },
                TemplateSection {
                    id: "executive-summary".to_string(),
                    title: "Executive Summary".to_string(),
                    section_type: SectionType::ExecutiveSummary,
                    required: true,
                    order: 2,
                },
                TemplateSection {
                    id: "security-events".to_string(),
                    title: "Security Events".to_string(),
                    section_type: SectionType::DataTable,
                    required: true,
                    order: 3,
                },
                TemplateSection {
                    id: "network-analysis".to_string(),
                    title: "Network Analysis".to_string(),
                    section_type: SectionType::Chart,
                    required: false,
                    order: 4,
                },
                TemplateSection {
                    id: "signatures".to_string(),
                    title: "Cryptographic Signatures".to_string(),
                    section_type: SectionType::SignaturePage,
                    required: true,
                    order: 5,
                },
            ],
            variables: HashMap::new(),
        };
        
        self.templates.insert(security_template.id.clone(), security_template);
        
        // Corporate Professional Template
        let corporate_template = ReportTemplate {
            id: "corporate-professional".to_string(),
            name: "Corporate Professional".to_string(),
            description: "Clean, professional report template for executive audiences".to_string(),
            category: TemplateCategory::Audit,
            styling: TemplateStyling {
                color_scheme: ColorScheme::Corporate,
                fonts: FontConfig {
                    header_font: "Arial".to_string(),
                    body_font: "Arial".to_string(),
                    mono_font: "Courier New".to_string(),
                    base_size: 11,
                },
                branding: BrandingConfig {
                    organization: "Organization Name".to_string(),
                    logo_path: None,
                    footer_text: "Confidential Report".to_string(),
                    watermark: None,
                },
                layout: LayoutConfig {
                    margins: Margins { top: 72, bottom: 72, left: 72, right: 72 },
                    header_height: 40,
                    footer_height: 25,
                    columns: 1,
                },
            },
            sections: vec![
                TemplateSection {
                    id: "title".to_string(),
                    title: "Title Page".to_string(),
                    section_type: SectionType::TitlePage,
                    required: true,
                    order: 1,
                },
                TemplateSection {
                    id: "toc".to_string(),
                    title: "Table of Contents".to_string(),
                    section_type: SectionType::TableOfContents,
                    required: true,
                    order: 2,
                },
                TemplateSection {
                    id: "summary".to_string(),
                    title: "Executive Summary".to_string(),
                    section_type: SectionType::ExecutiveSummary,
                    required: true,
                    order: 3,
                },
                TemplateSection {
                    id: "data".to_string(),
                    title: "Data Analysis".to_string(),
                    section_type: SectionType::DataTable,
                    required: true,
                    order: 4,
                },
            ],
            variables: HashMap::new(),
        };
        
        self.templates.insert(corporate_template.id.clone(), corporate_template);
        
        // Network Analysis Template
        let network_template = ReportTemplate {
            id: "network-analysis".to_string(),
            name: "Network Analysis Report".to_string(),
            description: "Detailed network monitoring and analysis report".to_string(),
            category: TemplateCategory::Network,
            styling: TemplateStyling {
                color_scheme: ColorScheme::GhostShellNeon,
                fonts: FontConfig {
                    header_font: "JetBrains Mono".to_string(),
                    body_font: "Space Grotesk".to_string(),
                    mono_font: "JetBrains Mono".to_string(),
                    base_size: 10,
                },
                branding: BrandingConfig {
                    organization: "Network Operations Center".to_string(),
                    logo_path: None,
                    footer_text: "Network Analysis Report - Confidential".to_string(),
                    watermark: None,
                },
                layout: LayoutConfig {
                    margins: Margins { top: 50, bottom: 50, left: 50, right: 50 },
                    header_height: 35,
                    footer_height: 20,
                    columns: 2,
                },
            },
            sections: vec![
                TemplateSection {
                    id: "interfaces".to_string(),
                    title: "Network Interfaces".to_string(),
                    section_type: SectionType::DataTable,
                    required: true,
                    order: 1,
                },
                TemplateSection {
                    id: "connections".to_string(),
                    title: "Active Connections".to_string(),
                    section_type: SectionType::DataTable,
                    required: true,
                    order: 2,
                },
                TemplateSection {
                    id: "dns".to_string(),
                    title: "DNS Configuration".to_string(),
                    section_type: SectionType::DataTable,
                    required: false,
                    order: 3,
                },
                TemplateSection {
                    id: "routes".to_string(),
                    title: "Routing Table".to_string(),
                    section_type: SectionType::DataTable,
                    required: false,
                    order: 4,
                },
            ],
            variables: HashMap::new(),
        };
        
        self.templates.insert(network_template.id.clone(), network_template);
    }
    
    /// Get all available templates
    pub fn get_templates(&self) -> Vec<&ReportTemplate> {
        self.templates.values().collect()
    }
    
    /// Get templates by category
    pub fn get_templates_by_category(&self, category: &TemplateCategory) -> Vec<&ReportTemplate> {
        self.templates.values()
            .filter(|t| &t.category == category)
            .collect()
    }
    
    /// Get a specific template
    pub fn get_template(&self, template_id: &str) -> Option<&ReportTemplate> {
        self.templates.get(template_id)
    }
    
    /// Apply template to a report job
    pub fn apply_template(&self, job: &mut ReportJob, template_id: &str) -> ReportResult<()> {
        let template = self.get_template(template_id)
            .ok_or_else(|| ReportError::Template(format!("Template not found: {}", template_id)))?;
        
        job.template = Some(template_id.to_string());
        
        // Apply template-specific configurations
        // This would modify the job based on template settings
        
        Ok(())
    }
    
    /// Create a custom template
    pub fn create_template(&mut self, template: ReportTemplate) -> ReportResult<()> {
        if self.templates.contains_key(&template.id) {
            return Err(ReportError::Template(format!("Template already exists: {}", template.id)));
        }
        
        self.templates.insert(template.id.clone(), template);
        Ok(())
    }
    
    /// Update an existing template
    pub fn update_template(&mut self, template: ReportTemplate) -> ReportResult<()> {
        if !self.templates.contains_key(&template.id) {
            return Err(ReportError::Template(format!("Template not found: {}", template.id)));
        }
        
        self.templates.insert(template.id.clone(), template);
        Ok(())
    }
    
    /// Delete a template
    pub fn delete_template(&mut self, template_id: &str) -> ReportResult<()> {
        let template = self.templates.get(template_id)
            .ok_or_else(|| ReportError::Template(format!("Template not found: {}", template_id)))?;
        
        // Don't allow deletion of built-in templates
        if matches!(template.category, TemplateCategory::Custom) {
            self.templates.remove(template_id);
            Ok(())
        } else {
            Err(ReportError::Template("Cannot delete built-in template".to_string()))
        }
    }
}

impl Default for TemplateManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get GhostShell color palette
pub fn get_ghostshell_colors() -> CustomColors {
    CustomColors {
        primary: "#AFFF00".to_string(),    // Neon green
        secondary: "#00FFD1".to_string(),  // Cyan
        accent: "#FF008C".to_string(),     // Pink
        background: "#0A0F1E".to_string(), // Dark blue
        text: "#EAEAEA".to_string(),       // Light gray
    }
}

/// Get corporate color palette
pub fn get_corporate_colors() -> CustomColors {
    CustomColors {
        primary: "#2E5BBA".to_string(),    // Professional blue
        secondary: "#8B9DC3".to_string(),  // Light blue
        accent: "#F39C12".to_string(),     // Orange
        background: "#FFFFFF".to_string(), // White
        text: "#2C3E50".to_string(),       // Dark gray
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_template_manager() {
        let manager = TemplateManager::new();
        
        let templates = manager.get_templates();
        assert!(!templates.is_empty());
        
        let security_templates = manager.get_templates_by_category(&TemplateCategory::Security);
        assert!(!security_templates.is_empty());
        
        let template = manager.get_template("ghostshell-security-audit");
        assert!(template.is_some());
        assert_eq!(template.unwrap().name, "GhostShell Security Audit");
    }
    
    #[test]
    fn test_color_schemes() {
        let ghostshell_colors = get_ghostshell_colors();
        assert_eq!(ghostshell_colors.primary, "#AFFF00");
        
        let corporate_colors = get_corporate_colors();
        assert_eq!(corporate_colors.primary, "#2E5BBA");
    }
}
