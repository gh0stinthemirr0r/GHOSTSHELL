use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use chrono::{DateTime, Utc};
use tauri::{AppHandle, Manager, State, Window};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, sleep};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tracing::{info, warn, error, debug};

use ghost_policy::{Resource, Action};
use crate::security::PepState;
use ghost_policy::PolicyDecision;

/// Clipboard entry with metadata
#[derive(Debug, Clone, Serialize)]
pub struct ClipboardEntry {
    pub id: String,
    pub content: String,
    pub masked_preview: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub source_window: Option<String>,
    pub content_type: ClipboardContentType,
    pub size_bytes: usize,
    pub policy_rule_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClipboardContentType {
    Text,
    Password,
    SshKey,
    ApiToken,
    CreditCard,
    Email,
    Url,
    Code,
    Other,
}

/// Clipboard manager state
pub struct ClipboardManager {
    entries: Arc<RwLock<Vec<ClipboardEntry>>>,
    auto_clear_tasks: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    redaction_patterns: Arc<RwLock<Vec<RedactionPattern>>>,
    initialized: Arc<tokio::sync::RwLock<bool>>,
}

#[derive(Debug, Clone)]
pub struct RedactionPattern {
    pub name: String,
    pub pattern: regex::Regex,
    pub replacement: String,
    pub content_type: ClipboardContentType,
}

impl ClipboardManager {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            auto_clear_tasks: Arc::new(Mutex::new(HashMap::new())),
            redaction_patterns: Arc::new(RwLock::new(Vec::new())),
            initialized: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }

    /// Initialize the clipboard manager with default patterns
    /// This should be called from within a Tokio runtime context
    pub async fn initialize(&self) {
        let mut initialized = self.initialized.write().await;
        if *initialized {
            return; // Already initialized
        }
        
        // Initialize default redaction patterns
        self.init_default_patterns().await;
        *initialized = true;
    }
    
    /// Ensure the clipboard manager is initialized (lazy initialization)
    async fn ensure_initialized(&self) {
        let initialized = self.initialized.read().await;
        if !*initialized {
            drop(initialized); // Release read lock
            self.initialize().await;
        }
    }

    async fn init_default_patterns(&self) {
        let mut patterns = self.redaction_patterns.write().await;
        
        // Credit card numbers
        if let Ok(cc_regex) = regex::Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b") {
            patterns.push(RedactionPattern {
                name: "Credit Card".to_string(),
                pattern: cc_regex,
                replacement: "**** **** **** ****".to_string(),
                content_type: ClipboardContentType::CreditCard,
            });
        }

        // SSH private keys
        if let Ok(ssh_regex) = regex::Regex::new(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----") {
            patterns.push(RedactionPattern {
                name: "SSH Private Key".to_string(),
                pattern: ssh_regex,
                replacement: "[SSH PRIVATE KEY REDACTED]".to_string(),
                content_type: ClipboardContentType::SshKey,
            });
        }

        // API tokens (common patterns)
        if let Ok(token_regex) = regex::Regex::new(r"\b[A-Za-z0-9_-]{20,}\b") {
            patterns.push(RedactionPattern {
                name: "API Token".to_string(),
                pattern: token_regex,
                replacement: "[TOKEN REDACTED]".to_string(),
                content_type: ClipboardContentType::ApiToken,
            });
        }

        // Email addresses
        if let Ok(email_regex) = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b") {
            patterns.push(RedactionPattern {
                name: "Email Address".to_string(),
                pattern: email_regex,
                replacement: "[EMAIL REDACTED]".to_string(),
                content_type: ClipboardContentType::Email,
            });
        }

        info!("Initialized {} clipboard redaction patterns", patterns.len());
    }

    pub async fn copy_with_policy(
        &self,
        content: String,
        window: Option<&Window>,
        pep: &PepState,
    ) -> Result<ClipboardCopyResult, String> {
        // Ensure clipboard manager is initialized
        self.ensure_initialized().await;
        
        // Evaluate policy for clipboard copy
        let decision = pep.evaluate_access(
            Resource::Clipboard,
            Action::Copy,
            None,
            window,
        ).await.map_err(|e| e.to_string())?;

        if !decision.allowed {
            return Err("Access denied: Policy prohibits clipboard copy".to_string());
        }

        // Detect content type and apply redaction if needed
        let content_type = self.detect_content_type(&content).await;
        let masked_preview = if decision.mask_preview {
            self.create_masked_preview(&content, &content_type).await
        } else {
            content.clone()
        };

        // Create clipboard entry
        let entry = ClipboardEntry {
            id: Uuid::new_v4().to_string(),
            content: content.clone(),
            masked_preview,
            created_at: Utc::now(),
            expires_at: decision.auto_clear_clipboard_ms.map(|ms| {
                Utc::now() + chrono::Duration::milliseconds(ms as i64)
            }),
            source_window: window.map(|w| w.label().to_string()),
            content_type,
            size_bytes: content.len(),
            policy_rule_id: decision.policy_rule_id.clone(),
        };

        // Store entry
        {
            let mut entries = self.entries.write().await;
            entries.push(entry.clone());
            
            // Keep only last 100 entries
            if entries.len() > 100 {
                entries.remove(0);
            }
        }

        // Set up auto-clear if specified
        if let Some(clear_ms) = decision.auto_clear_clipboard_ms {
            self.schedule_auto_clear(entry.id.clone(), clear_ms).await;
        }

        // Actually copy to system clipboard
        self.copy_to_system_clipboard(&content).await?;

        info!(
            "Clipboard copy: {} bytes, type: {:?}, auto-clear: {:?}ms",
            content.len(),
            entry.content_type,
            decision.auto_clear_clipboard_ms
        );

        Ok(ClipboardCopyResult {
            entry_id: entry.id,
            masked_preview: entry.masked_preview,
            auto_clear_ms: decision.auto_clear_clipboard_ms,
            warning_message: decision.warning_message,
        })
    }

    pub async fn paste_with_policy(
        &self,
        window: Option<&Window>,
        pep: &PepState,
    ) -> Result<ClipboardPasteResult, String> {
        // Evaluate policy for clipboard paste
        let decision = pep.evaluate_access(
            Resource::Clipboard,
            Action::Paste,
            None,
            window,
        ).await.map_err(|e| e.to_string())?;

        if !decision.allowed {
            return Err("Access denied: Policy prohibits clipboard paste".to_string());
        }

        // Get content from system clipboard
        let content = self.get_from_system_clipboard().await?;
        
        if content.is_empty() {
            return Err("Clipboard is empty".to_string());
        }

        // Check size limits
        if let Some(size_limit_mb) = decision.size_limit_mb {
            let size_limit_bytes = (size_limit_mb * 1024 * 1024) as usize;
            if content.len() > size_limit_bytes {
                return Err(format!(
                    "Clipboard content too large: {} bytes exceeds limit of {} MB",
                    content.len(),
                    size_limit_mb
                ));
            }
        }

        // Detect content type
        let content_type = self.detect_content_type(&content).await;
        
        // Create masked preview if needed
        let preview = if decision.mask_preview {
            self.create_masked_preview(&content, &content_type).await
        } else {
            content.clone()
        };

        info!(
            "Clipboard paste: {} bytes, type: {:?}",
            content.len(),
            content_type
        );

        let content_len = content.len();
        Ok(ClipboardPasteResult {
            content,
            preview,
            content_type,
            size_bytes: content_len,
            requires_justification: decision.requires_justification,
            justification_prompt: decision.justification_prompt,
            warning_message: decision.warning_message,
        })
    }

    async fn detect_content_type(&self, content: &str) -> ClipboardContentType {
        let patterns = self.redaction_patterns.read().await;
        
        for pattern in patterns.iter() {
            if pattern.pattern.is_match(content) {
                return pattern.content_type.clone();
            }
        }

        // Additional heuristics
        if content.lines().count() > 10 && content.contains("function") || content.contains("class") {
            return ClipboardContentType::Code;
        }

        if content.starts_with("http://") || content.starts_with("https://") {
            return ClipboardContentType::Url;
        }

        if content.len() > 8 && content.chars().all(|c| c.is_alphanumeric() || "!@#$%^&*".contains(c)) {
            return ClipboardContentType::Password;
        }

        ClipboardContentType::Text
    }

    async fn create_masked_preview(&self, content: &str, content_type: &ClipboardContentType) -> String {
        match content_type {
            ClipboardContentType::Password => {
                format!("[PASSWORD: {} chars]", content.len())
            }
            ClipboardContentType::SshKey => {
                "[SSH PRIVATE KEY]".to_string()
            }
            ClipboardContentType::ApiToken => {
                format!("[API TOKEN: {} chars]", content.len())
            }
            ClipboardContentType::CreditCard => {
                "[CREDIT CARD NUMBER]".to_string()
            }
            _ => {
                // Apply redaction patterns
                let patterns = self.redaction_patterns.read().await;
                let mut masked = content.to_string();
                
                for pattern in patterns.iter() {
                    masked = pattern.pattern.replace_all(&masked, &pattern.replacement).to_string();
                }

                // Truncate if too long
                if masked.len() > 100 {
                    format!("{}...", &masked[..97])
                } else {
                    masked
                }
            }
        }
    }

    async fn schedule_auto_clear(&self, entry_id: String, clear_ms: u64) {
        let entries = Arc::clone(&self.entries);
        let tasks = Arc::clone(&self.auto_clear_tasks);
        let entry_id_clone = entry_id.clone();
        
        let task = tokio::spawn(async move {
            sleep(Duration::from_millis(clear_ms)).await;
            
            // Clear from our history
            {
                let mut entries_guard = entries.write().await;
                entries_guard.retain(|e| e.id != entry_id_clone);
            }
            
            // Remove task from tracking
            {
                let mut tasks_guard = tasks.lock().await;
                tasks_guard.remove(&entry_id_clone);
            }
            
            debug!("Auto-cleared clipboard entry: {}", entry_id_clone);
        });

        // Track the task
        {
            let mut tasks_guard = self.auto_clear_tasks.lock().await;
            tasks_guard.insert(entry_id, task);
        }
    }

    async fn copy_to_system_clipboard(&self, content: &str) -> Result<(), String> {
        // Platform-specific clipboard implementation would go here
        // For now, we'll just log it
        debug!("Copying to system clipboard: {} bytes", content.len());
        Ok(())
    }

    async fn get_from_system_clipboard(&self) -> Result<String, String> {
        // Platform-specific clipboard implementation would go here
        // For now, we'll return a placeholder
        debug!("Reading from system clipboard");
        Ok("".to_string())
    }

    pub async fn get_history(&self) -> Vec<ClipboardEntry> {
        let entries = self.entries.read().await;
        entries.clone()
    }

    pub async fn clear_entry(&self, entry_id: &str) -> Result<(), String> {
        {
            let mut entries = self.entries.write().await;
            entries.retain(|e| e.id != entry_id);
        }

        // Cancel auto-clear task if it exists
        {
            let mut tasks = self.auto_clear_tasks.lock().await;
            if let Some(task) = tasks.remove(entry_id) {
                task.abort();
            }
        }

        info!("Manually cleared clipboard entry: {}", entry_id);
        Ok(())
    }

    pub async fn clear_all(&self) -> Result<(), String> {
        {
            let mut entries = self.entries.write().await;
            entries.clear();
        }

        // Cancel all auto-clear tasks
        {
            let mut tasks = self.auto_clear_tasks.lock().await;
            for (_, task) in tasks.drain() {
                task.abort();
            }
        }

        info!("Cleared all clipboard entries");
        Ok(())
    }
}

impl Clone for ClipboardManager {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            auto_clear_tasks: Arc::clone(&self.auto_clear_tasks),
            redaction_patterns: Arc::clone(&self.redaction_patterns),
            initialized: Arc::clone(&self.initialized),
        }
    }
}

// DTOs

#[derive(Debug, Serialize)]
pub struct ClipboardCopyResult {
    pub entry_id: String,
    pub masked_preview: String,
    pub auto_clear_ms: Option<u64>,
    pub warning_message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ClipboardPasteResult {
    pub content: String,
    pub preview: String,
    pub content_type: ClipboardContentType,
    pub size_bytes: usize,
    pub requires_justification: bool,
    pub justification_prompt: Option<String>,
    pub warning_message: Option<String>,
}

// Tauri commands

#[tauri::command]
pub async fn clipboard_copy(
    content: String,
    clipboard: State<'_, ClipboardManager>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<ClipboardCopyResult, String> {
    clipboard.copy_with_policy(content, Some(&window), &pep).await
}

#[tauri::command]
pub async fn clipboard_paste(
    clipboard: State<'_, ClipboardManager>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<ClipboardPasteResult, String> {
    clipboard.paste_with_policy(Some(&window), &pep).await
}

#[tauri::command]
pub async fn clipboard_get_history(
    clipboard: State<'_, ClipboardManager>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<Vec<ClipboardEntry>, String> {
    // Check if user can read clipboard history
    let decision = pep.evaluate_access(
        Resource::Clipboard,
        Action::Read,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Policy prohibits reading clipboard history".to_string());
    }

    Ok(clipboard.get_history().await)
}

#[tauri::command]
pub async fn clipboard_clear_entry(
    entry_id: String,
    clipboard: State<'_, ClipboardManager>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Check if user can delete clipboard entries
    let decision = pep.evaluate_access(
        Resource::Clipboard,
        Action::Delete,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Policy prohibits clearing clipboard entries".to_string());
    }

    clipboard.clear_entry(&entry_id).await?;
    Ok("Entry cleared".to_string())
}

#[tauri::command]
pub async fn clipboard_clear_all(
    clipboard: State<'_, ClipboardManager>,
    pep: State<'_, PepState>,
    window: Window,
) -> Result<String, String> {
    // Check if user can delete all clipboard entries
    let decision = pep.evaluate_access(
        Resource::Clipboard,
        Action::Delete,
        None,
        Some(&window),
    ).await.map_err(|e| e.to_string())?;

    if !decision.allowed {
        return Err("Access denied: Policy prohibits clearing clipboard".to_string());
    }

    clipboard.clear_all().await?;
    Ok("All entries cleared".to_string())
}
