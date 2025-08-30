use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{State, Window};
use tokio::sync::RwLock;
use tokio::fs;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tracing::{info, warn};
use sha3::{Digest, Sha3_256};


// Policy enforcement removed for single-user mode

/// Quarantined file entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFile {
    pub id: String,
    pub original_name: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub file_hash: String,
    pub file_size: u64,
    pub mime_type: Option<String>,
    pub quarantined_at: u64, // Unix timestamp
    pub source_url: Option<String>,
    pub source_window: Option<String>,
    pub risk_level: RiskLevel,
    pub scan_results: Vec<ScanResult>,
    pub policy_rule_id: Option<String>,
    pub auto_release_at: Option<u64>, // Unix timestamp
    pub user_approved: bool,
    pub admin_approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanner: String,
    pub result: ScanResultType,
    pub details: Option<String>,
    pub scanned_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanResultType {
    Clean,
    Suspicious,
    Malicious,
    Error(String),
}

/// Download quarantine manager
pub struct QuarantineManager {
    quarantine_dir: PathBuf,
    quarantined_files: Arc<RwLock<HashMap<String, QuarantinedFile>>>,
    scanners: Vec<Box<dyn FileScanner + Send + Sync>>,
}

impl QuarantineManager {
    pub async fn new(quarantine_dir: PathBuf) -> Result<Self, String> {
        // Ensure quarantine directory exists
        fs::create_dir_all(&quarantine_dir).await
            .map_err(|e| format!("Failed to create quarantine directory: {}", e))?;

        let mut manager = Self {
            quarantine_dir,
            quarantined_files: Arc::new(RwLock::new(HashMap::new())),
            scanners: Vec::new(),
        };

        // Initialize built-in scanners
        manager.scanners.push(Box::new(HashScanner::new()));
        manager.scanners.push(Box::new(ExtensionScanner::new()));
        manager.scanners.push(Box::new(SizeScanner::new()));
        manager.scanners.push(Box::new(MimeTypeScanner::new()));

        // Load existing quarantined files
        manager.load_quarantine_state().await?;

        info!("Quarantine manager initialized with {} scanners", manager.scanners.len());
        Ok(manager)
    }

    pub async fn quarantine_download(
        &self,
        file_path: PathBuf,
        source_url: Option<String>,
        window: Option<&Window>,
        // Policy enforcement removed for single-user mode
    ) -> Result<QuarantineResult, String> {
        // Evaluate policy for download quarantine
        let mut context = HashMap::new();
        if let Some(url) = &source_url {
            context.insert("source_url".to_string(), url.clone());
        }
        context.insert("file_path".to_string(), file_path.to_string_lossy().to_string());

        // Policy removed - pep.evaluate_access

        // Policy removed - decision.allowed check

        // Policy removed - decision.quarantine_file check

        // Read file metadata
        let metadata = fs::metadata(&file_path).await
            .map_err(|e| format!("Failed to read file metadata: {}", e))?;

        let file_size = metadata.len();
        let original_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Calculate file hash
        let file_hash = self.calculate_file_hash(&file_path).await?;

        // Check if file is already quarantined
        {
            let files = self.quarantined_files.read().await;
            if let Some(existing) = files.values().find(|f| f.file_hash == file_hash) {
                return Ok(QuarantineResult {
                    quarantined: true,
                    file_id: Some(existing.id.clone()),
                    risk_level: existing.risk_level.clone(),
                    scan_results: existing.scan_results.clone(),
                    message: "File already quarantined".to_string(),
                });
            }
        }

        // Create quarantine entry
        let file_id = Uuid::new_v4().to_string();
        let quarantine_path = self.quarantine_dir.join(&file_id);

        // Move file to quarantine
        fs::rename(&file_path, &quarantine_path).await
            .map_err(|e| format!("Failed to move file to quarantine: {}", e))?;

        // Detect MIME type
        let mime_type = self.detect_mime_type(&quarantine_path).await;

        // Run security scans
        let mut scan_results = Vec::new();
        let mut max_risk = RiskLevel::Low;

        for scanner in &self.scanners {
            match scanner.scan(&quarantine_path, &original_name, file_size).await {
                Ok(result) => {
                    // Update max risk level
                    match &result.result {
                        ScanResultType::Suspicious => {
                            if matches!(max_risk, RiskLevel::Low) {
                                max_risk = RiskLevel::Medium;
                            }
                        }
                        ScanResultType::Malicious => {
                            max_risk = RiskLevel::Critical;
                        }
                        _ => {}
                    }
                    scan_results.push(result);
                }
                Err(e) => {
                    warn!("Scanner {} failed: {}", scanner.name(), e);
                    scan_results.push(ScanResult {
                        scanner: scanner.name().to_string(),
                        result: ScanResultType::Error(e),
                        details: None,
                        scanned_at: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    });
                }
            }
        }

        // Create quarantined file entry
        let quarantined_file = QuarantinedFile {
            id: file_id.clone(),
            original_name,
            original_path: file_path.to_string_lossy().to_string(),
            quarantine_path: quarantine_path.to_string_lossy().to_string(),
            file_hash,
            file_size,
            mime_type,
            quarantined_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            source_url,
            source_window: window.map(|w| w.label().to_string()),
            risk_level: max_risk.clone(),
            scan_results: scan_results.clone(),
            policy_rule_id: None, // Policy removed
            auto_release_at: None, // Policy removed
            user_approved: false,
            admin_approved: false,
        };

        let original_name = quarantined_file.original_name.clone();
        
        // Store quarantined file
        {
            let mut files = self.quarantined_files.write().await;
            files.insert(file_id.clone(), quarantined_file);
        }

        // Save state
        self.save_quarantine_state().await?;

        info!(
            "File quarantined: {} ({}), risk: {:?}, {} scan results",
            original_name,
            file_id,
            max_risk,
            scan_results.len()
        );

        Ok(QuarantineResult {
            quarantined: true,
            file_id: Some(file_id),
            risk_level: max_risk,
            scan_results,
            message: "File quarantined for security review".to_string(),
        })
    }

    pub async fn release_file(
        &self,
        file_id: &str,
        destination: Option<PathBuf>,
        window: Option<&Window>,
        // Policy enforcement removed for single-user mode
    ) -> Result<String, String> {
        // Policy removed - file release check

        let quarantined_file = {
            let files = self.quarantined_files.read().await;
            files.get(file_id).cloned()
                .ok_or_else(|| "File not found in quarantine".to_string())?
        };

        // Check if file can be released based on risk level and approvals
        match quarantined_file.risk_level {
            RiskLevel::Critical => {
                if !quarantined_file.admin_approved {
                    return Err("Critical risk files require admin approval".to_string());
                }
            }
            RiskLevel::High => {
                if !quarantined_file.user_approved && !quarantined_file.admin_approved {
                    return Err("High risk files require user or admin approval".to_string());
                }
            }
            _ => {} // Low/Medium risk files can be released
        }

        // Determine destination path
        let dest_path = destination.unwrap_or_else(|| {
            PathBuf::from(&quarantined_file.original_path)
        });

        // Ensure destination directory exists
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent).await
                .map_err(|e| format!("Failed to create destination directory: {}", e))?;
        }

        // Move file from quarantine to destination
        fs::rename(&quarantined_file.quarantine_path, &dest_path).await
            .map_err(|e| format!("Failed to release file: {}", e))?;

        // Remove from quarantine
        {
            let mut files = self.quarantined_files.write().await;
            files.remove(file_id);
        }

        // Save state
        self.save_quarantine_state().await?;

        info!(
            "File released: {} -> {}",
            quarantined_file.original_name,
            dest_path.display()
        );

        Ok(format!("File released to: {}", dest_path.display()))
    }

    pub async fn delete_quarantined_file(
        &self,
        file_id: &str,
        window: Option<&Window>,
        // Policy enforcement removed for single-user mode
    ) -> Result<String, String> {
        // Policy removed - file deletion check

        let quarantined_file = {
            let mut files = self.quarantined_files.write().await;
            files.remove(file_id)
                .ok_or_else(|| "File not found in quarantine".to_string())?
        };

        // Delete the quarantined file
        if let Err(e) = fs::remove_file(&quarantined_file.quarantine_path).await {
            warn!("Failed to delete quarantined file: {}", e);
        }

        // Save state
        self.save_quarantine_state().await?;

        info!("Quarantined file deleted: {}", quarantined_file.original_name);
        Ok("File deleted from quarantine".to_string())
    }

    pub async fn list_quarantined_files(&self) -> Vec<QuarantinedFile> {
        let files = self.quarantined_files.read().await;
        files.values().cloned().collect()
    }

    pub async fn approve_file(&self, file_id: &str, admin_approval: bool) -> Result<String, String> {
        let mut files = self.quarantined_files.write().await;
        let file = files.get_mut(file_id)
            .ok_or_else(|| "File not found in quarantine".to_string())?;

        if admin_approval {
            file.admin_approved = true;
        } else {
            file.user_approved = true;
        }

        drop(files);
        self.save_quarantine_state().await?;

        Ok(if admin_approval {
            "File approved by admin".to_string()
        } else {
            "File approved by user".to_string()
        })
    }

    async fn calculate_file_hash(&self, file_path: &Path) -> Result<String, String> {
        let content = fs::read(file_path).await
            .map_err(|e| format!("Failed to read file for hashing: {}", e))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(&content);
        Ok(hex::encode(hasher.finalize()))
    }

    async fn detect_mime_type(&self, _file_path: &Path) -> Option<String> {
        // TODO: Implement MIME type detection
        // This would typically use a library like `mime_guess` or `tree_magic`
        None
    }

    async fn load_quarantine_state(&self) -> Result<(), String> {
        let state_file = self.quarantine_dir.join("quarantine_state.json");
        
        if !state_file.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&state_file).await
            .map_err(|e| format!("Failed to read quarantine state: {}", e))?;

        let files: HashMap<String, QuarantinedFile> = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse quarantine state: {}", e))?;

        {
            let mut quarantined_files = self.quarantined_files.write().await;
            *quarantined_files = files;
        }

        Ok(())
    }

    async fn save_quarantine_state(&self) -> Result<(), String> {
        let state_file = self.quarantine_dir.join("quarantine_state.json");
        
        let files = self.quarantined_files.read().await;
        let content = serde_json::to_string_pretty(&*files)
            .map_err(|e| format!("Failed to serialize quarantine state: {}", e))?;

        fs::write(&state_file, content).await
            .map_err(|e| format!("Failed to save quarantine state: {}", e))?;

        Ok(())
    }
}

// File scanner trait and implementations

#[async_trait::async_trait]
pub trait FileScanner {
    fn name(&self) -> &str;
    async fn scan(&self, file_path: &Path, original_name: &str, file_size: u64) -> Result<ScanResult, String>;
}

pub struct HashScanner {
    known_malicious_hashes: Vec<String>,
}

impl HashScanner {
    pub fn new() -> Self {
        Self {
            known_malicious_hashes: vec![
                // Add known malicious file hashes here
            ],
        }
    }
}

#[async_trait::async_trait]
impl FileScanner for HashScanner {
    fn name(&self) -> &str {
        "Hash Scanner"
    }

    async fn scan(&self, file_path: &Path, _original_name: &str, _file_size: u64) -> Result<ScanResult, String> {
        let content = fs::read(file_path).await
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(&content);
        let hash = hex::encode(hasher.finalize());

        let result = if self.known_malicious_hashes.contains(&hash) {
            ScanResultType::Malicious
        } else {
            ScanResultType::Clean
        };

        Ok(ScanResult {
            scanner: self.name().to_string(),
            result,
            details: Some(format!("File hash: {}", hash)),
            scanned_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
}

pub struct ExtensionScanner {
    dangerous_extensions: Vec<String>,
    suspicious_extensions: Vec<String>,
}

impl ExtensionScanner {
    pub fn new() -> Self {
        Self {
            dangerous_extensions: vec![
                "exe".to_string(), "bat".to_string(), "cmd".to_string(), "com".to_string(),
                "pif".to_string(), "scr".to_string(), "vbs".to_string(), "js".to_string(),
                "jar".to_string(), "msi".to_string(),
            ],
            suspicious_extensions: vec![
                "zip".to_string(), "rar".to_string(), "7z".to_string(), "tar".to_string(),
                "gz".to_string(), "dmg".to_string(), "iso".to_string(),
            ],
        }
    }
}

#[async_trait::async_trait]
impl FileScanner for ExtensionScanner {
    fn name(&self) -> &str {
        "Extension Scanner"
    }

    async fn scan(&self, file_path: &Path, _original_name: &str, _file_size: u64) -> Result<ScanResult, String> {
        let extension = file_path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        let result = if self.dangerous_extensions.contains(&extension) {
            ScanResultType::Malicious
        } else if self.suspicious_extensions.contains(&extension) {
            ScanResultType::Suspicious
        } else {
            ScanResultType::Clean
        };

        Ok(ScanResult {
            scanner: self.name().to_string(),
            result,
            details: Some(format!("File extension: .{}", extension)),
            scanned_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
}

pub struct SizeScanner;

impl SizeScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl FileScanner for SizeScanner {
    fn name(&self) -> &str {
        "Size Scanner"
    }

    async fn scan(&self, _file_path: &Path, _original_name: &str, file_size: u64) -> Result<ScanResult, String> {
        const SUSPICIOUS_SIZE_MB: u64 = 100;
        const MALICIOUS_SIZE_MB: u64 = 1000;

        let size_mb = file_size / (1024 * 1024);

        let result = if size_mb > MALICIOUS_SIZE_MB {
            ScanResultType::Malicious
        } else if size_mb > SUSPICIOUS_SIZE_MB {
            ScanResultType::Suspicious
        } else {
            ScanResultType::Clean
        };

        Ok(ScanResult {
            scanner: self.name().to_string(),
            result,
            details: Some(format!("File size: {} MB", size_mb)),
            scanned_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
}

pub struct MimeTypeScanner;

impl MimeTypeScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl FileScanner for MimeTypeScanner {
    fn name(&self) -> &str {
        "MIME Type Scanner"
    }

    async fn scan(&self, _file_path: &Path, _original_name: &str, _file_size: u64) -> Result<ScanResult, String> {
        // TODO: Implement actual MIME type detection and risk assessment
        Ok(ScanResult {
            scanner: self.name().to_string(),
            result: ScanResultType::Clean,
            details: Some("MIME type analysis not implemented".to_string()),
            scanned_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
}

// DTOs

#[derive(Debug, Serialize)]
pub struct QuarantineResult {
    pub quarantined: bool,
    pub file_id: Option<String>,
    pub risk_level: RiskLevel,
    pub scan_results: Vec<ScanResult>,
    pub message: String,
}

// Tauri commands

#[tauri::command]
pub async fn quarantine_list_files(
    quarantine: State<'_, QuarantineManager>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<Vec<QuarantinedFile>, String> {
    // Policy removed - quarantined files view check

    Ok(quarantine.list_quarantined_files().await)
}

#[tauri::command]
pub async fn quarantine_release_file(
    file_id: String,
    destination: Option<String>,
    quarantine: State<'_, QuarantineManager>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<String, String> {
    let dest_path = destination.map(PathBuf::from);
    quarantine.release_file(&file_id, dest_path, Some(&window)).await
}

#[tauri::command]
pub async fn quarantine_delete_file(
    file_id: String,
    quarantine: State<'_, QuarantineManager>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<String, String> {
    quarantine.delete_quarantined_file(&file_id, Some(&window)).await
}

#[tauri::command]
pub async fn quarantine_approve_file(
    file_id: String,
    admin_approval: bool,
    quarantine: State<'_, QuarantineManager>,
    // Policy enforcement removed for single-user mode
    window: Window,
) -> Result<String, String> {
    // Policy removed - file approval check

    quarantine.approve_file(&file_id, admin_approval).await
}
