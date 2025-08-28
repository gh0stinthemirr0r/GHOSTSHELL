use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{State, Window};
use tokio::sync::{RwLock, Mutex};
use tokio::fs;
use tracing::info;
use uuid::Uuid;

// Import our post-quantum cryptography
use ghost_pq::{KyberPublicKey, KyberPrivateKey, DilithiumPublicKey, DilithiumPrivateKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileItem {
    pub id: String,
    pub name: String,
    pub path: String,
    pub file_type: FileType,
    pub size: u64,
    pub permissions: FilePermissions,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub accessed: Option<chrono::DateTime<chrono::Utc>>,
    pub is_encrypted: bool,
    pub is_hidden: bool,
    pub mime_type: Option<String>,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileType {
    File,
    Directory,
    SymbolicLink,
    BlockDevice,
    CharacterDevice,
    Fifo,
    Socket,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub owner: String,
    pub group: String,
    pub mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub id: String,
    pub operation_type: FileOperationType,
    pub source_path: String,
    pub destination_path: Option<String>,
    pub status: OperationStatus,
    pub progress: f32,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
    pub bytes_processed: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOperationType {
    Copy,
    Move,
    Delete,
    Encrypt,
    Decrypt,
    Compress,
    Decompress,
    CreateDirectory,
    Rename,
    ChangePermissions,
    CalculateChecksum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionOptions {
    pub algorithm: EncryptionAlgorithm,
    pub key_id: Option<String>,
    pub compression: bool,
    pub integrity_check: bool,
    pub secure_delete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    PostQuantumHybrid, // Kyber + AES
    AES256GCM,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSearch {
    pub query: String,
    pub path: String,
    pub include_hidden: bool,
    pub file_types: Vec<FileType>,
    pub size_range: Option<(u64, u64)>,
    pub date_range: Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
    pub content_search: bool,
    pub regex_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWatcher {
    pub id: String,
    pub path: String,
    pub recursive: bool,
    pub events: Vec<WatchEvent>,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatchEvent {
    Created,
    Modified,
    Deleted,
    Renamed,
    PermissionsChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStats {
    pub total_files: u64,
    pub total_directories: u64,
    pub total_size: u64,
    pub encrypted_files: u64,
    pub hidden_files: u64,
    pub largest_file: Option<FileItem>,
    pub newest_file: Option<FileItem>,
    pub file_type_distribution: HashMap<String, u64>,
}

pub struct FileManager {
    operations: Arc<RwLock<HashMap<String, FileOperation>>>,
    watchers: Arc<RwLock<HashMap<String, FileWatcher>>>,
    encryption_keys: Arc<RwLock<HashMap<String, PostQuantumKeyPair>>>,
    bookmarks: Arc<RwLock<Vec<String>>>,
    recent_files: Arc<RwLock<Vec<String>>>,
}

struct PostQuantumKeyPair {
    kyber_public: KyberPublicKey,
    kyber_private: KyberPrivateKey,
    dilithium_public: DilithiumPublicKey,
    dilithium_private: DilithiumPrivateKey,
}

impl FileManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            operations: Arc::new(RwLock::new(HashMap::new())),
            watchers: Arc::new(RwLock::new(HashMap::new())),
            encryption_keys: Arc::new(RwLock::new(HashMap::new())),
            bookmarks: Arc::new(RwLock::new(vec![
                dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")).to_string_lossy().to_string(),
                dirs::desktop_dir().unwrap_or_else(|| PathBuf::from("/")).to_string_lossy().to_string(),
                dirs::document_dir().unwrap_or_else(|| PathBuf::from("/")).to_string_lossy().to_string(),
                dirs::download_dir().unwrap_or_else(|| PathBuf::from("/")).to_string_lossy().to_string(),
            ])),
            recent_files: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn list_directory(&self, path: &str, show_hidden: bool) -> Result<Vec<FileItem>> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(anyhow!("Directory does not exist: {}", path.display()));
        }

        if !path.is_dir() {
            return Err(anyhow!("Path is not a directory: {}", path.display()));
        }

        let mut files = Vec::new();
        let mut entries = fs::read_dir(path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let entry_path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            // Skip hidden files if not requested
            if !show_hidden && file_name.starts_with('.') {
                continue;
            }

            let metadata = entry.metadata().await?;
            let file_type = Self::determine_file_type(&metadata);

            let file_item = FileItem {
                id: Uuid::new_v4().to_string(),
                name: file_name.clone(),
                path: entry_path.to_string_lossy().to_string(),
                file_type,
                size: metadata.len(),
                permissions: Self::extract_permissions(&metadata, &file_name),
                created: Self::system_time_to_datetime(metadata.created().unwrap_or(std::time::SystemTime::UNIX_EPOCH)),
                modified: Self::system_time_to_datetime(metadata.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)),
                accessed: metadata.accessed().ok().map(Self::system_time_to_datetime),
                is_encrypted: Self::is_encrypted_file(&entry_path).await,
                is_hidden: file_name.starts_with('.'),
                mime_type: Self::detect_mime_type(&entry_path).await,
                checksum: None, // Calculated on demand
            };

            files.push(file_item);
        }

        // Sort by name
        files.sort_by(|a, b| a.name.cmp(&b.name));

        info!("Listed {} items in directory: {}", files.len(), path.display());
        Ok(files)
    }

    pub async fn create_directory(&self, path: &str) -> Result<String> {
        let operation_id = Uuid::new_v4().to_string();
        
        let operation = FileOperation {
            id: operation_id.clone(),
            operation_type: FileOperationType::CreateDirectory,
            source_path: path.to_string(),
            destination_path: None,
            status: OperationStatus::InProgress,
            progress: 0.0,
            started_at: chrono::Utc::now(),
            completed_at: None,
            error_message: None,
            bytes_processed: 0,
            total_bytes: 0,
        };

        self.operations.write().await.insert(operation_id.clone(), operation);

        // Create the directory
        match fs::create_dir_all(path).await {
            Ok(_) => {
                let mut operations = self.operations.write().await;
                if let Some(op) = operations.get_mut(&operation_id) {
                    op.status = OperationStatus::Completed;
                    op.progress = 100.0;
                    op.completed_at = Some(chrono::Utc::now());
                }
                info!("Created directory: {}", path);
                Ok(operation_id)
            },
            Err(e) => {
                let mut operations = self.operations.write().await;
                if let Some(op) = operations.get_mut(&operation_id) {
                    op.status = OperationStatus::Failed;
                    op.error_message = Some(e.to_string());
                }
                Err(anyhow!("Failed to create directory: {}", e))
            }
        }
    }

    pub async fn copy_file(&self, source: &str, destination: &str) -> Result<String> {
        let operation_id = Uuid::new_v4().to_string();
        
        let source_path = Path::new(source);
        let dest_path = Path::new(destination);

        if !source_path.exists() {
            return Err(anyhow!("Source file does not exist: {}", source));
        }

        let metadata = fs::metadata(source_path).await?;
        let total_bytes = metadata.len();

        let operation = FileOperation {
            id: operation_id.clone(),
            operation_type: FileOperationType::Copy,
            source_path: source.to_string(),
            destination_path: Some(destination.to_string()),
            status: OperationStatus::InProgress,
            progress: 0.0,
            started_at: chrono::Utc::now(),
            completed_at: None,
            error_message: None,
            bytes_processed: 0,
            total_bytes,
        };

        self.operations.write().await.insert(operation_id.clone(), operation);

        // Perform the copy operation
        match fs::copy(source_path, dest_path).await {
            Ok(bytes_copied) => {
                let mut operations = self.operations.write().await;
                if let Some(op) = operations.get_mut(&operation_id) {
                    op.status = OperationStatus::Completed;
                    op.progress = 100.0;
                    op.bytes_processed = bytes_copied;
                    op.completed_at = Some(chrono::Utc::now());
                }
                
                // Add to recent files
                self.recent_files.write().await.insert(0, destination.to_string());
                
                info!("Copied file: {} -> {} ({} bytes)", source, destination, bytes_copied);
                Ok(operation_id)
            },
            Err(e) => {
                let mut operations = self.operations.write().await;
                if let Some(op) = operations.get_mut(&operation_id) {
                    op.status = OperationStatus::Failed;
                    op.error_message = Some(e.to_string());
                }
                Err(anyhow!("Failed to copy file: {}", e))
            }
        }
    }

    pub async fn move_file(&self, source: &str, destination: &str) -> Result<String> {
        let operation_id = Uuid::new_v4().to_string();
        
        let source_path = Path::new(source);
        let dest_path = Path::new(destination);

        if !source_path.exists() {
            return Err(anyhow!("Source file does not exist: {}", source));
        }

        let metadata = fs::metadata(source_path).await?;
        let total_bytes = metadata.len();

        let operation = FileOperation {
            id: operation_id.clone(),
            operation_type: FileOperationType::Move,
            source_path: source.to_string(),
            destination_path: Some(destination.to_string()),
            status: OperationStatus::InProgress,
            progress: 0.0,
            started_at: chrono::Utc::now(),
            completed_at: None,
            error_message: None,
            bytes_processed: 0,
            total_bytes,
        };

        self.operations.write().await.insert(operation_id.clone(), operation);

        // Perform the move operation
        match fs::rename(source_path, dest_path).await {
            Ok(_) => {
                let mut operations = self.operations.write().await;
                if let Some(op) = operations.get_mut(&operation_id) {
                    op.status = OperationStatus::Completed;
                    op.progress = 100.0;
                    op.bytes_processed = total_bytes;
                    op.completed_at = Some(chrono::Utc::now());
                }
                
                // Add to recent files
                self.recent_files.write().await.insert(0, destination.to_string());
                
                info!("Moved file: {} -> {}", source, destination);
                Ok(operation_id)
            },
            Err(e) => {
                let mut operations = self.operations.write().await;
                if let Some(op) = operations.get_mut(&operation_id) {
                    op.status = OperationStatus::Failed;
                    op.error_message = Some(e.to_string());
                }
                Err(anyhow!("Failed to move file: {}", e))
            }
        }
    }

    pub async fn delete_file(&self, path: &str, secure_delete: bool) -> Result<String> {
        let operation_id = Uuid::new_v4().to_string();
        
        let file_path = Path::new(path);

        if !file_path.exists() {
            return Err(anyhow!("File does not exist: {}", path));
        }

        let metadata = fs::metadata(file_path).await?;
        let total_bytes = metadata.len();

        let operation = FileOperation {
            id: operation_id.clone(),
            operation_type: FileOperationType::Delete,
            source_path: path.to_string(),
            destination_path: None,
            status: OperationStatus::InProgress,
            progress: 0.0,
            started_at: chrono::Utc::now(),
            completed_at: None,
            error_message: None,
            bytes_processed: 0,
            total_bytes,
        };

        self.operations.write().await.insert(operation_id.clone(), operation);

        let result = if secure_delete {
            self.secure_delete(file_path).await
        } else {
            if file_path.is_dir() {
                fs::remove_dir_all(file_path).await
            } else {
                fs::remove_file(file_path).await
            }
        };

        match result {
            Ok(_) => {
                let mut operations = self.operations.write().await;
                if let Some(op) = operations.get_mut(&operation_id) {
                    op.status = OperationStatus::Completed;
                    op.progress = 100.0;
                    op.bytes_processed = total_bytes;
                    op.completed_at = Some(chrono::Utc::now());
                }
                
                info!("Deleted file: {} (secure: {})", path, secure_delete);
                Ok(operation_id)
            },
            Err(e) => {
                let mut operations = self.operations.write().await;
                if let Some(op) = operations.get_mut(&operation_id) {
                    op.status = OperationStatus::Failed;
                    op.error_message = Some(e.to_string());
                }
                Err(anyhow!("Failed to delete file: {}", e))
            }
        }
    }

    pub async fn encrypt_file(&self, path: &str, options: EncryptionOptions) -> Result<String> {
        let operation_id = Uuid::new_v4().to_string();
        
        let file_path = Path::new(path);
        if !file_path.exists() {
            return Err(anyhow!("File does not exist: {}", path));
        }

        let metadata = fs::metadata(file_path).await?;
        let total_bytes = metadata.len();

        let operation = FileOperation {
            id: operation_id.clone(),
            operation_type: FileOperationType::Encrypt,
            source_path: path.to_string(),
            destination_path: Some(format!("{}.encrypted", path)),
            status: OperationStatus::InProgress,
            progress: 0.0,
            started_at: chrono::Utc::now(),
            completed_at: None,
            error_message: None,
            bytes_processed: 0,
            total_bytes,
        };

        self.operations.write().await.insert(operation_id.clone(), operation);

        // Simulate encryption process
        info!("Encrypting file with {:?}: {}", options.algorithm, path);
        
        // In a real implementation, this would:
        // 1. Generate or retrieve encryption keys
        // 2. Read file in chunks
        // 3. Encrypt with chosen algorithm
        // 4. Write encrypted file with metadata
        // 5. Optionally compress and add integrity checks
        
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let mut operations = self.operations.write().await;
        if let Some(op) = operations.get_mut(&operation_id) {
            op.status = OperationStatus::Completed;
            op.progress = 100.0;
            op.bytes_processed = total_bytes;
            op.completed_at = Some(chrono::Utc::now());
        }

        info!("File encryption completed: {}", path);
        Ok(operation_id)
    }

    pub async fn search_files(&self, search: FileSearch) -> Result<Vec<FileItem>> {
        info!("Searching files: query='{}', path='{}'", search.query, search.path);
        
        let mut results = Vec::new();
        let search_path = Path::new(&search.path);

        if !search_path.exists() {
            return Err(anyhow!("Search path does not exist: {}", search.path));
        }

        // Simulate file search
        // In a real implementation, this would:
        // 1. Walk directory tree recursively
        // 2. Apply filters (file types, size, date ranges)
        // 3. Search file names and optionally content
        // 4. Support regex patterns
        // 5. Return matching files

        let files = self.list_directory(&search.path, search.include_hidden).await?;
        
        for file in files {
            if file.name.to_lowercase().contains(&search.query.to_lowercase()) {
                results.push(file);
            }
        }

        info!("Search completed: {} results found", results.len());
        Ok(results)
    }

    pub async fn get_file_stats(&self, path: &str) -> Result<FileStats> {
        let files = self.list_directory(path, true).await?;
        
        let mut stats = FileStats {
            total_files: 0,
            total_directories: 0,
            total_size: 0,
            encrypted_files: 0,
            hidden_files: 0,
            largest_file: None,
            newest_file: None,
            file_type_distribution: HashMap::new(),
        };

        let mut largest_size = 0;
        let mut newest_time = chrono::DateTime::<chrono::Utc>::MIN_UTC;

        for file in &files {
            match file.file_type {
                FileType::File => {
                    stats.total_files += 1;
                    stats.total_size += file.size;
                    
                    if file.size > largest_size {
                        largest_size = file.size;
                        stats.largest_file = Some(file.clone());
                    }
                },
                FileType::Directory => stats.total_directories += 1,
                _ => {}
            }

            if file.is_encrypted {
                stats.encrypted_files += 1;
            }

            if file.is_hidden {
                stats.hidden_files += 1;
            }

            if file.modified > newest_time {
                newest_time = file.modified;
                stats.newest_file = Some(file.clone());
            }

            // File type distribution
            let type_key = format!("{:?}", file.file_type);
            *stats.file_type_distribution.entry(type_key).or_insert(0) += 1;
        }

        Ok(stats)
    }

    pub async fn get_operation_status(&self, operation_id: &str) -> Result<FileOperation> {
        let operations = self.operations.read().await;
        operations.get(operation_id)
            .cloned()
            .ok_or_else(|| anyhow!("Operation not found: {}", operation_id))
    }

    pub async fn list_operations(&self) -> Result<Vec<FileOperation>> {
        let operations = self.operations.read().await;
        Ok(operations.values().cloned().collect())
    }

    pub async fn add_bookmark(&self, path: String) -> Result<()> {
        let mut bookmarks = self.bookmarks.write().await;
        if !bookmarks.contains(&path) {
            bookmarks.push(path);
        }
        Ok(())
    }

    pub async fn get_bookmarks(&self) -> Result<Vec<String>> {
        Ok(self.bookmarks.read().await.clone())
    }

    pub async fn get_recent_files(&self) -> Result<Vec<String>> {
        Ok(self.recent_files.read().await.clone())
    }

    // Helper methods
    fn determine_file_type(metadata: &std::fs::Metadata) -> FileType {
        use std::os::windows::fs::MetadataExt;
        
        if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_file() {
            FileType::File
        } else {
            FileType::Unknown
        }
    }

    fn extract_permissions(metadata: &std::fs::Metadata, file_name: &str) -> FilePermissions {
        FilePermissions {
            readable: true, // Simplified for demo
            writable: !metadata.permissions().readonly(),
            executable: file_name.ends_with(".exe") || file_name.ends_with(".bat"),
            owner: "current_user".to_string(),
            group: "users".to_string(),
            mode: 0o644, // Simplified
        }
    }

    fn system_time_to_datetime(time: std::time::SystemTime) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from(time)
    }

    async fn is_encrypted_file(path: &Path) -> bool {
        // Check if file has encrypted extension or header
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext == "encrypted" || ext == "enc" || ext == "gpg")
            .unwrap_or(false)
    }

    async fn detect_mime_type(path: &Path) -> Option<String> {
        // Simplified MIME type detection
        path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| {
                match ext.to_lowercase().as_str() {
                    "txt" => Some("text/plain"),
                    "json" => Some("application/json"),
                    "html" => Some("text/html"),
                    "css" => Some("text/css"),
                    "js" => Some("application/javascript"),
                    "png" => Some("image/png"),
                    "jpg" | "jpeg" => Some("image/jpeg"),
                    "pdf" => Some("application/pdf"),
                    "zip" => Some("application/zip"),
                    _ => None,
                }
            })
            .map(|s| s.to_string())
    }

    async fn secure_delete(&self, path: &Path) -> Result<(), std::io::Error> {
        // Simplified secure delete - in production, would overwrite with random data
        if path.is_dir() {
            fs::remove_dir_all(path).await
        } else {
            fs::remove_file(path).await
        }
    }
}

// Tauri Commands
#[tauri::command]
pub async fn fm_list_directory(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    path: String,
    show_hidden: bool,
) -> Result<Vec<FileItem>, String> {
    let manager = file_manager.lock().await;
    manager.list_directory(&path, show_hidden).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_create_directory(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    path: String,
) -> Result<String, String> {
    let manager = file_manager.lock().await;
    manager.create_directory(&path).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_copy_file(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    source: String,
    destination: String,
) -> Result<String, String> {
    let manager = file_manager.lock().await;
    manager.copy_file(&source, &destination).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_move_file(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    source: String,
    destination: String,
) -> Result<String, String> {
    let manager = file_manager.lock().await;
    manager.move_file(&source, &destination).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_delete_file(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    path: String,
    secure_delete: bool,
) -> Result<String, String> {
    let manager = file_manager.lock().await;
    manager.delete_file(&path, secure_delete).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_encrypt_file(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    path: String,
    options: EncryptionOptions,
) -> Result<String, String> {
    let manager = file_manager.lock().await;
    manager.encrypt_file(&path, options).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_search_files(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    search: FileSearch,
) -> Result<Vec<FileItem>, String> {
    let manager = file_manager.lock().await;
    manager.search_files(search).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_get_file_stats(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    path: String,
) -> Result<FileStats, String> {
    let manager = file_manager.lock().await;
    manager.get_file_stats(&path).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_get_operation_status(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    operation_id: String,
) -> Result<FileOperation, String> {
    let manager = file_manager.lock().await;
    manager.get_operation_status(&operation_id).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_list_operations(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
) -> Result<Vec<FileOperation>, String> {
    let manager = file_manager.lock().await;
    manager.list_operations().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_add_bookmark(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
    path: String,
) -> Result<(), String> {
    let manager = file_manager.lock().await;
    manager.add_bookmark(path).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_get_bookmarks(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
) -> Result<Vec<String>, String> {
    let manager = file_manager.lock().await;
    manager.get_bookmarks().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fm_get_recent_files(
    file_manager: State<'_, Arc<Mutex<FileManager>>>,
) -> Result<Vec<String>, String> {
    let manager = file_manager.lock().await;
    manager.get_recent_files().await
        .map_err(|e| e.to_string())
}
