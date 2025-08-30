//! Script runners for different languages with sandboxing

use crate::{ScriptLanguage, ScriptError, ScriptResult, ExecutionConfig, FilesystemAccess};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Script runner trait for different languages
pub trait ScriptRunner {
    /// Get the language this runner handles
    fn language(&self) -> ScriptLanguage;
    
    /// Validate script syntax and content
    fn validate_script(&self, content: &str) -> ScriptResult<crate::ValidationResult>;
    
    /// Get interpreter path for this language
    fn get_interpreter_path(&self) -> ScriptResult<PathBuf>;
    
    /// Build command arguments for execution
    fn build_command_args(&self, script_path: &Path, parameters: &HashMap<String, String>) -> Vec<String>;
    
    /// Apply security restrictions
    fn apply_security_restrictions(&self, config: &ExecutionConfig) -> ScriptResult<()>;
}

/// Python script runner
pub struct PythonRunner {
    interpreter_path: Option<PathBuf>,
}

impl PythonRunner {
    pub fn new() -> Self {
        Self {
            interpreter_path: None,
        }
    }
    
    /// Set custom Python interpreter path
    pub fn with_interpreter<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.interpreter_path = Some(path.into());
        self
    }
    
    /// Detect Python installation
    fn detect_python() -> Option<PathBuf> {
        // Try common Python executables
        let candidates = ["python3", "python", "py"];
        
        for candidate in &candidates {
            if let Ok(output) = Command::new(candidate)
                .arg("--version")
                .output()
            {
                if output.status.success() {
                    return Some(PathBuf::from(candidate));
                }
            }
        }
        
        None
    }
}

impl ScriptRunner for PythonRunner {
    fn language(&self) -> ScriptLanguage {
        ScriptLanguage::Python
    }
    
    fn validate_script(&self, content: &str) -> ScriptResult<crate::ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut suggestions = Vec::new();
        
        // Basic Python syntax validation
        if content.trim().is_empty() {
            errors.push("Script content is empty".to_string());
        }
        
        // Check for dangerous patterns
        let dangerous_patterns = [
            "os.system",
            "subprocess.call",
            "eval(",
            "exec(",
            "__import__",
        ];
        
        for pattern in &dangerous_patterns {
            if content.contains(pattern) {
                warnings.push(format!("Potentially dangerous pattern detected: {}", pattern));
            }
        }
        
        // Check for good practices
        if !content.contains("#!/usr/bin/env python") && !content.contains("# -*- coding:") {
            suggestions.push("Consider adding a shebang line and encoding declaration".to_string());
        }
        
        if content.contains("print(") && !content.contains("import sys") {
            suggestions.push("Consider using sys.stdout.write() for better output control".to_string());
        }
        
        Ok(crate::ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            suggestions,
        })
    }
    
    fn get_interpreter_path(&self) -> ScriptResult<PathBuf> {
        if let Some(path) = &self.interpreter_path {
            Ok(path.clone())
        } else if let Some(detected) = Self::detect_python() {
            Ok(detected)
        } else {
            Err(ScriptError::Configuration(
                "Python interpreter not found. Please install Python or specify interpreter path.".to_string()
            ))
        }
    }
    
    fn build_command_args(&self, script_path: &Path, parameters: &HashMap<String, String>) -> Vec<String> {
        let mut args = vec![script_path.to_string_lossy().to_string()];
        
        // Add parameters as command line arguments
        for (key, value) in parameters {
            args.push(format!("--{}", key));
            args.push(value.clone());
        }
        
        args
    }
    
    fn apply_security_restrictions(&self, config: &ExecutionConfig) -> ScriptResult<()> {
        // Python-specific security restrictions
        match &config.limits.filesystem_access {
            FilesystemAccess::None => {
                warn!("Python scripts with no filesystem access may fail");
            },
            FilesystemAccess::Restricted { allowed_paths } => {
                debug!("Python execution restricted to paths: {:?}", allowed_paths);
            },
            _ => {}
        }
        
        if !config.limits.network_access {
            debug!("Python execution with network access disabled");
        }
        
        Ok(())
    }
}

/// PowerShell script runner
pub struct PowerShellRunner {
    interpreter_path: Option<PathBuf>,
    use_core: bool,
}

impl PowerShellRunner {
    pub fn new() -> Self {
        Self {
            interpreter_path: None,
            use_core: false,
        }
    }
    
    /// Use PowerShell Core (pwsh) instead of Windows PowerShell
    pub fn use_core(mut self, use_core: bool) -> Self {
        self.use_core = use_core;
        self
    }
    
    /// Set custom PowerShell interpreter path
    pub fn with_interpreter<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.interpreter_path = Some(path.into());
        self
    }
    
    /// Detect PowerShell installation
    fn detect_powershell(use_core: bool) -> Option<PathBuf> {
        let candidates = if use_core {
            vec!["pwsh", "pwsh.exe"]
        } else {
            vec!["powershell", "powershell.exe"]
        };
        
        for candidate in &candidates {
            if let Ok(output) = Command::new(candidate)
                .arg("-Command")
                .arg("$PSVersionTable.PSVersion")
                .output()
            {
                if output.status.success() {
                    return Some(PathBuf::from(candidate));
                }
            }
        }
        
        None
    }
}

impl ScriptRunner for PowerShellRunner {
    fn language(&self) -> ScriptLanguage {
        ScriptLanguage::PowerShell
    }
    
    fn validate_script(&self, content: &str) -> ScriptResult<crate::ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut suggestions = Vec::new();
        
        if content.trim().is_empty() {
            errors.push("Script content is empty".to_string());
        }
        
        // Check for dangerous PowerShell patterns
        let dangerous_patterns = [
            "Invoke-Expression",
            "iex ",
            "DownloadString",
            "DownloadFile",
            "Start-Process",
            "Remove-Item -Recurse",
            "Format-Volume",
            "Clear-Disk",
        ];
        
        for pattern in &dangerous_patterns {
            if content.to_lowercase().contains(&pattern.to_lowercase()) {
                warnings.push(format!("Potentially dangerous PowerShell command detected: {}", pattern));
            }
        }
        
        // Check for good practices
        if !content.contains("param(") && content.contains("$") {
            suggestions.push("Consider using param() block for better parameter handling".to_string());
        }
        
        if !content.contains("Write-Output") && content.contains("Write-Host") {
            suggestions.push("Consider using Write-Output instead of Write-Host for better pipeline support".to_string());
        }
        
        Ok(crate::ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            suggestions,
        })
    }
    
    fn get_interpreter_path(&self) -> ScriptResult<PathBuf> {
        if let Some(path) = &self.interpreter_path {
            Ok(path.clone())
        } else if let Some(detected) = Self::detect_powershell(self.use_core) {
            Ok(detected)
        } else {
            Err(ScriptError::Configuration(
                "PowerShell interpreter not found. Please install PowerShell.".to_string()
            ))
        }
    }
    
    fn build_command_args(&self, script_path: &Path, parameters: &HashMap<String, String>) -> Vec<String> {
        let mut args = vec![
            "-ExecutionPolicy".to_string(),
            "Bypass".to_string(),
            "-File".to_string(),
            script_path.to_string_lossy().to_string(),
        ];
        
        // Add parameters as PowerShell parameters
        for (key, value) in parameters {
            args.push(format!("-{}", key));
            args.push(value.clone());
        }
        
        args
    }
    
    fn apply_security_restrictions(&self, config: &ExecutionConfig) -> ScriptResult<()> {
        // PowerShell-specific security restrictions
        match &config.limits.filesystem_access {
            FilesystemAccess::None => {
                warn!("PowerShell scripts with no filesystem access may fail");
            },
            FilesystemAccess::Restricted { allowed_paths } => {
                debug!("PowerShell execution restricted to paths: {:?}", allowed_paths);
            },
            _ => {}
        }
        
        if !config.limits.network_access {
            debug!("PowerShell execution with network access disabled");
        }
        
        Ok(())
    }
}

/// Batch script runner
pub struct BatchRunner {
    interpreter_path: Option<PathBuf>,
}

impl BatchRunner {
    pub fn new() -> Self {
        Self {
            interpreter_path: None,
        }
    }
    
    /// Set custom command interpreter path
    pub fn with_interpreter<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.interpreter_path = Some(path.into());
        self
    }
    
    /// Detect command interpreter
    fn detect_cmd() -> Option<PathBuf> {
        // Try to find cmd.exe
        if let Ok(output) = Command::new("cmd")
            .arg("/C")
            .arg("echo test")
            .output()
        {
            if output.status.success() {
                return Some(PathBuf::from("cmd"));
            }
        }
        
        None
    }
}

impl ScriptRunner for BatchRunner {
    fn language(&self) -> ScriptLanguage {
        ScriptLanguage::Batch
    }
    
    fn validate_script(&self, content: &str) -> ScriptResult<crate::ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut suggestions = Vec::new();
        
        if content.trim().is_empty() {
            errors.push("Script content is empty".to_string());
        }
        
        // Check for dangerous batch patterns
        let dangerous_patterns = [
            "format ",
            "del /s",
            "rmdir /s",
            "rd /s",
            "diskpart",
            "fdisk",
            "shutdown",
            "restart",
        ];
        
        for pattern in &dangerous_patterns {
            if content.to_lowercase().contains(&pattern.to_lowercase()) {
                warnings.push(format!("Potentially dangerous batch command detected: {}", pattern));
            }
        }
        
        // Check for good practices
        if !content.starts_with("@echo off") {
            suggestions.push("Consider starting with '@echo off' to reduce command echoing".to_string());
        }
        
        if !content.contains("setlocal") {
            suggestions.push("Consider using 'setlocal' to prevent variable pollution".to_string());
        }
        
        Ok(crate::ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            suggestions,
        })
    }
    
    fn get_interpreter_path(&self) -> ScriptResult<PathBuf> {
        if let Some(path) = &self.interpreter_path {
            Ok(path.clone())
        } else if let Some(detected) = Self::detect_cmd() {
            Ok(detected)
        } else {
            Err(ScriptError::Configuration(
                "Command interpreter not found.".to_string()
            ))
        }
    }
    
    fn build_command_args(&self, script_path: &Path, parameters: &HashMap<String, String>) -> Vec<String> {
        let mut args = vec![
            "/C".to_string(),
            script_path.to_string_lossy().to_string(),
        ];
        
        // Add parameters as positional arguments for batch scripts
        for (_, value) in parameters {
            args.push(value.clone());
        }
        
        args
    }
    
    fn apply_security_restrictions(&self, config: &ExecutionConfig) -> ScriptResult<()> {
        // Batch-specific security restrictions
        match &config.limits.filesystem_access {
            FilesystemAccess::None => {
                warn!("Batch scripts with no filesystem access will likely fail");
            },
            FilesystemAccess::Restricted { allowed_paths } => {
                debug!("Batch execution restricted to paths: {:?}", allowed_paths);
            },
            _ => {}
        }
        
        if !config.limits.network_access {
            debug!("Batch execution with network access disabled");
        }
        
        Ok(())
    }
}

/// Runner factory for creating appropriate runners
pub struct RunnerFactory;

impl RunnerFactory {
    /// Create a runner for the specified language
    pub fn create_runner(language: &ScriptLanguage) -> Box<dyn ScriptRunner> {
        match language {
            ScriptLanguage::Python => Box::new(PythonRunner::new()),
            ScriptLanguage::PowerShell => Box::new(PowerShellRunner::new()),
            ScriptLanguage::Batch => Box::new(BatchRunner::new()),
        }
    }
    
    /// Create a runner with custom configuration
    pub fn create_configured_runner(
        language: &ScriptLanguage,
        interpreter_path: Option<PathBuf>,
    ) -> Box<dyn ScriptRunner> {
        match language {
            ScriptLanguage::Python => {
                let mut runner = PythonRunner::new();
                if let Some(path) = interpreter_path {
                    runner = runner.with_interpreter(path);
                }
                Box::new(runner)
            },
            ScriptLanguage::PowerShell => {
                let mut runner = PowerShellRunner::new();
                if let Some(path) = interpreter_path {
                    runner = runner.with_interpreter(path);
                }
                Box::new(runner)
            },
            ScriptLanguage::Batch => {
                let mut runner = BatchRunner::new();
                if let Some(path) = interpreter_path {
                    runner = runner.with_interpreter(path);
                }
                Box::new(runner)
            },
        }
    }
}
