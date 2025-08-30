//! Script editor functionality with syntax highlighting and validation

use crate::{ScriptLanguage, ScriptError, ScriptResult, ValidationResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Editor configuration for different languages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditorConfig {
    /// Language-specific settings
    pub language_settings: HashMap<ScriptLanguage, LanguageSettings>,
    /// Theme configuration
    pub theme: EditorTheme,
    /// Editor behavior settings
    pub behavior: EditorBehavior,
}

/// Language-specific editor settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageSettings {
    /// Tab size for indentation
    pub tab_size: usize,
    /// Use spaces instead of tabs
    pub use_spaces: bool,
    /// Auto-indent enabled
    pub auto_indent: bool,
    /// Syntax highlighting enabled
    pub syntax_highlighting: bool,
    /// Language-specific keywords
    pub keywords: Vec<String>,
    /// Comment patterns
    pub comment_patterns: CommentPatterns,
}

/// Comment patterns for different languages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentPatterns {
    /// Single line comment prefix
    pub single_line: String,
    /// Multi-line comment start and end
    pub multi_line: Option<(String, String)>,
}

/// Editor theme configuration with GhostShell neon styling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditorTheme {
    /// Background color
    pub background: String,
    /// Text color
    pub text_color: String,
    /// Keyword color
    pub keyword_color: String,
    /// String color
    pub string_color: String,
    /// Comment color
    pub comment_color: String,
    /// Function color
    pub function_color: String,
    /// Variable color
    pub variable_color: String,
    /// Error color
    pub error_color: String,
    /// Warning color
    pub warning_color: String,
    /// Selection color
    pub selection_color: String,
    /// Cursor color
    pub cursor_color: String,
    /// Line number color
    pub line_number_color: String,
}

/// Editor behavior settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditorBehavior {
    /// Auto-save interval in seconds
    pub auto_save_interval: Option<u64>,
    /// Show line numbers
    pub show_line_numbers: bool,
    /// Show whitespace characters
    pub show_whitespace: bool,
    /// Word wrap enabled
    pub word_wrap: bool,
    /// Bracket matching
    pub bracket_matching: bool,
    /// Code folding enabled
    pub code_folding: bool,
}

impl Default for EditorConfig {
    fn default() -> Self {
        let mut language_settings = HashMap::new();
        
        // Python settings
        language_settings.insert(ScriptLanguage::Python, LanguageSettings {
            tab_size: 4,
            use_spaces: true,
            auto_indent: true,
            syntax_highlighting: true,
            keywords: vec![
                "def", "class", "if", "else", "elif", "for", "while", "try", "except",
                "finally", "import", "from", "as", "return", "yield", "lambda", "with",
                "pass", "break", "continue", "and", "or", "not", "in", "is", "None",
                "True", "False", "self", "cls"
            ].into_iter().map(String::from).collect(),
            comment_patterns: CommentPatterns {
                single_line: "#".to_string(),
                multi_line: Some(("\"\"\"".to_string(), "\"\"\"".to_string())),
            },
        });
        
        // PowerShell settings
        language_settings.insert(ScriptLanguage::PowerShell, LanguageSettings {
            tab_size: 4,
            use_spaces: true,
            auto_indent: true,
            syntax_highlighting: true,
            keywords: vec![
                "param", "function", "if", "else", "elseif", "foreach", "for", "while",
                "do", "until", "switch", "try", "catch", "finally", "throw", "return",
                "break", "continue", "and", "or", "not", "eq", "ne", "lt", "le", "gt", "ge"
            ].into_iter().map(String::from).collect(),
            comment_patterns: CommentPatterns {
                single_line: "#".to_string(),
                multi_line: Some(("<#".to_string(), "#>".to_string())),
            },
        });
        
        // Batch settings
        language_settings.insert(ScriptLanguage::Batch, LanguageSettings {
            tab_size: 4,
            use_spaces: false,
            auto_indent: true,
            syntax_highlighting: true,
            keywords: vec![
                "echo", "set", "if", "else", "for", "goto", "call", "exit", "pause",
                "rem", "cls", "cd", "dir", "copy", "move", "del", "md", "rd", "type"
            ].into_iter().map(String::from).collect(),
            comment_patterns: CommentPatterns {
                single_line: "rem ".to_string(),
                multi_line: None,
            },
        });
        
        Self {
            language_settings,
            theme: EditorTheme::ghostshell_neon(),
            behavior: EditorBehavior::default(),
        }
    }
}

impl EditorTheme {
    /// Create GhostShell neon theme
    pub fn ghostshell_neon() -> Self {
        Self {
            background: "#0A0F1E".to_string(),        // Dark background
            text_color: "#EAEAEA".to_string(),        // Light text
            keyword_color: "#FF6B9D".to_string(),     // Pink keywords
            string_color: "#AFFF00".to_string(),      // Neon green strings
            comment_color: "#6B7280".to_string(),     // Gray comments
            function_color: "#00FFD1".to_string(),    // Cyan functions
            variable_color: "#FFD700".to_string(),    // Gold variables
            error_color: "#FF4444".to_string(),       // Red errors
            warning_color: "#FFA500".to_string(),     // Orange warnings
            selection_color: "#2D3748".to_string(),   // Dark selection
            cursor_color: "#AFFF00".to_string(),      // Neon green cursor
            line_number_color: "#4A5568".to_string(), // Gray line numbers
        }
    }
    
    /// Create corporate theme
    pub fn corporate() -> Self {
        Self {
            background: "#FFFFFF".to_string(),
            text_color: "#2D3748".to_string(),
            keyword_color: "#3182CE".to_string(),
            string_color: "#38A169".to_string(),
            comment_color: "#718096".to_string(),
            function_color: "#805AD5".to_string(),
            variable_color: "#D69E2E".to_string(),
            error_color: "#E53E3E".to_string(),
            warning_color: "#DD6B20".to_string(),
            selection_color: "#BEE3F8".to_string(),
            cursor_color: "#2D3748".to_string(),
            line_number_color: "#A0AEC0".to_string(),
        }
    }
}

impl Default for EditorBehavior {
    fn default() -> Self {
        Self {
            auto_save_interval: Some(30), // 30 seconds
            show_line_numbers: true,
            show_whitespace: false,
            word_wrap: false,
            bracket_matching: true,
            code_folding: true,
        }
    }
}

/// Script editor functionality
pub struct ScriptEditor {
    config: EditorConfig,
}

impl ScriptEditor {
    /// Create a new script editor
    pub fn new(config: EditorConfig) -> Self {
        Self { config }
    }
    
    /// Get editor configuration
    pub fn config(&self) -> &EditorConfig {
        &self.config
    }
    
    /// Update editor configuration
    pub fn set_config(&mut self, config: EditorConfig) {
        self.config = config;
    }
    
    /// Get language settings for a specific language
    pub fn get_language_settings(&self, language: &ScriptLanguage) -> Option<&LanguageSettings> {
        self.config.language_settings.get(language)
    }
    
    /// Validate script content
    pub fn validate_content(&self, content: &str, language: &ScriptLanguage) -> ScriptResult<ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut suggestions = Vec::new();
        
        if content.trim().is_empty() {
            errors.push("Script content is empty".to_string());
            return Ok(ValidationResult {
                is_valid: false,
                errors,
                warnings,
                suggestions,
            });
        }
        
        // Basic validation based on language
        match language {
            ScriptLanguage::Python => {
                self.validate_python_content(content, &mut errors, &mut warnings, &mut suggestions)?;
            },
            ScriptLanguage::PowerShell => {
                self.validate_powershell_content(content, &mut errors, &mut warnings, &mut suggestions)?;
            },
            ScriptLanguage::Batch => {
                self.validate_batch_content(content, &mut errors, &mut warnings, &mut suggestions)?;
            },
        }
        
        Ok(ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            suggestions,
        })
    }
    
    /// Format script content according to language conventions
    pub fn format_content(&self, content: &str, language: &ScriptLanguage) -> ScriptResult<String> {
        match language {
            ScriptLanguage::Python => self.format_python_content(content),
            ScriptLanguage::PowerShell => self.format_powershell_content(content),
            ScriptLanguage::Batch => self.format_batch_content(content),
        }
    }
    
    /// Get syntax highlighting tokens for content
    pub fn get_syntax_tokens(&self, content: &str, language: &ScriptLanguage) -> Vec<SyntaxToken> {
        match language {
            ScriptLanguage::Python => self.tokenize_python(content),
            ScriptLanguage::PowerShell => self.tokenize_powershell(content),
            ScriptLanguage::Batch => self.tokenize_batch(content),
        }
    }
    
    // Private validation methods
    fn validate_python_content(
        &self,
        content: &str,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
        suggestions: &mut Vec<String>,
    ) -> ScriptResult<()> {
        // Check for basic Python syntax issues
        let lines: Vec<&str> = content.lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();
            
            // Check for common syntax errors
            if trimmed.ends_with(':') && !trimmed.starts_with('#') {
                // Check if next line is properly indented
                if line_num < lines.len() {
                    let next_line = lines[line_num].trim();
                    if !next_line.is_empty() && !next_line.starts_with('#') && !line.starts_with(' ') && !line.starts_with('\t') {
                        warnings.push(format!("Line {}: Expected indentation after colon", line_num + 1));
                    }
                }
            }
            
            // Check for dangerous patterns
            if trimmed.contains("eval(") || trimmed.contains("exec(") {
                warnings.push(format!("Line {}: Use of eval() or exec() can be dangerous", line_num));
            }
        }
        
        Ok(())
    }
    
    fn validate_powershell_content(
        &self,
        content: &str,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
        suggestions: &mut Vec<String>,
    ) -> ScriptResult<()> {
        let lines: Vec<&str> = content.lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();
            
            // Check for dangerous PowerShell patterns
            if trimmed.to_lowercase().contains("invoke-expression") {
                warnings.push(format!("Line {}: Invoke-Expression can be dangerous", line_num));
            }
            
            if trimmed.to_lowercase().contains("downloadstring") {
                warnings.push(format!("Line {}: DownloadString can be a security risk", line_num));
            }
        }
        
        Ok(())
    }
    
    fn validate_batch_content(
        &self,
        content: &str,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
        suggestions: &mut Vec<String>,
    ) -> ScriptResult<()> {
        let lines: Vec<&str> = content.lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();
            
            // Check for dangerous batch patterns
            if trimmed.to_lowercase().contains("format ") {
                warnings.push(format!("Line {}: FORMAT command can be destructive", line_num));
            }
            
            if trimmed.to_lowercase().contains("del /s") || trimmed.to_lowercase().contains("rd /s") {
                warnings.push(format!("Line {}: Recursive delete commands can be dangerous", line_num));
            }
        }
        
        Ok(())
    }
    
    // Private formatting methods
    fn format_python_content(&self, content: &str) -> ScriptResult<String> {
        // Basic Python formatting (in a real implementation, you'd use a proper formatter)
        let lines: Vec<&str> = content.lines().collect();
        let mut formatted_lines = Vec::new();
        
        for line in lines {
            // Basic indentation normalization
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                formatted_lines.push(trimmed.to_string());
            } else {
                formatted_lines.push(String::new());
            }
        }
        
        Ok(formatted_lines.join("\n"))
    }
    
    fn format_powershell_content(&self, content: &str) -> ScriptResult<String> {
        // Basic PowerShell formatting
        Ok(content.to_string()) // Placeholder
    }
    
    fn format_batch_content(&self, content: &str) -> ScriptResult<String> {
        // Basic Batch formatting
        Ok(content.to_string()) // Placeholder
    }
    
    // Private tokenization methods
    fn tokenize_python(&self, content: &str) -> Vec<SyntaxToken> {
        let mut tokens = Vec::new();
        // Basic Python tokenization (placeholder)
        tokens.push(SyntaxToken {
            text: content.to_string(),
            token_type: TokenType::Text,
            start: 0,
            end: content.len(),
        });
        tokens
    }
    
    fn tokenize_powershell(&self, content: &str) -> Vec<SyntaxToken> {
        let mut tokens = Vec::new();
        // Basic PowerShell tokenization (placeholder)
        tokens.push(SyntaxToken {
            text: content.to_string(),
            token_type: TokenType::Text,
            start: 0,
            end: content.len(),
        });
        tokens
    }
    
    fn tokenize_batch(&self, content: &str) -> Vec<SyntaxToken> {
        let mut tokens = Vec::new();
        // Basic Batch tokenization (placeholder)
        tokens.push(SyntaxToken {
            text: content.to_string(),
            token_type: TokenType::Text,
            start: 0,
            end: content.len(),
        });
        tokens
    }
}

/// Syntax token for highlighting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntaxToken {
    pub text: String,
    pub token_type: TokenType,
    pub start: usize,
    pub end: usize,
}

/// Token types for syntax highlighting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenType {
    Text,
    Keyword,
    String,
    Comment,
    Function,
    Variable,
    Number,
    Operator,
    Bracket,
    Whitespace,
}
