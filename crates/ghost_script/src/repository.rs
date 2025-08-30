//! Script repository management with user-configurable directories

use crate::{
    ScriptMetadata, ScriptLanguage, ScriptSearchQuery, RepositoryStats, ScriptError, ScriptResult,
    ScriptRepositoryConfig, ScriptBundle, ValidationResult,
};
use chrono::{DateTime, Utc};
use ghost_pq::{DilithiumSigner, DilithiumVariant};
use ghost_vault::Vault;
use rusqlite::{Connection, params};
use r2d2_sqlite::SqliteConnectionManager;
use r2d2::Pool;
use serde_json;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Script repository manager
pub struct ScriptRepository {
    /// Repository configuration
    config: ScriptRepositoryConfig,
    /// Database connection pool for metadata
    db_pool: Pool<SqliteConnectionManager>,
    /// Cryptographic signer for script integrity
    signer: Arc<DilithiumSigner>,
    /// Private key for signing
    private_key: Arc<ghost_pq::DilithiumPrivateKey>,
    /// Vault integration for secure storage
    vault: Option<Arc<RwLock<Vault>>>,
    /// In-memory cache of script metadata
    metadata_cache: Arc<RwLock<HashMap<String, ScriptMetadata>>>,
}

impl ScriptRepository {
    /// Create a new script repository with user-specified directory
    pub fn new(config: ScriptRepositoryConfig) -> ScriptResult<Self> {
        // Ensure scripts directory exists
        fs::create_dir_all(&config.scripts_directory)?;
        
        // Create subdirectories for each language
        for lang in &config.allowed_languages {
            let lang_dir = config.scripts_directory.join(lang.extension());
            fs::create_dir_all(&lang_dir)?;
        }
        
        // Database path in scripts directory
        let db_path = config.scripts_directory.join("metadata.db");
        
        // Initialize connection pool
        let manager = SqliteConnectionManager::file(&db_path);
        let db_pool = Pool::new(manager)
            .map_err(|e| ScriptError::Database(format!("Failed to create connection pool: {}", e)))?;
        
        // Initialize cryptographic signer
        let signer = Arc::new(
            DilithiumSigner::new(DilithiumVariant::Dilithium2)
                .map_err(|e| ScriptError::Crypto(e))?
        );
        
        // Generate keypair for signing
        let keypair = signer.generate_keypair()
            .map_err(|e| ScriptError::Crypto(e))?;
        let private_key = Arc::new(keypair.private_key);
        
        let repository = Self {
            config,
            db_pool,
            signer,
            private_key,
            vault: None,
            metadata_cache: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Initialize database
        repository.initialize_database()?;
        
        Ok(repository)
    }
    
    /// Set vault integration
    pub fn set_vault(&mut self, vault: Arc<RwLock<Vault>>) {
        self.vault = Some(vault);
    }
    
    /// Initialize the metadata database
    fn initialize_database(&self) -> ScriptResult<()> {
        let conn = self.db_pool.get()
            .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scripts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                language TEXT NOT NULL,
                tags TEXT NOT NULL,
                created_by TEXT NOT NULL,
                modified_by TEXT NOT NULL,
                created TEXT NOT NULL,
                modified TEXT NOT NULL,
                file_path TEXT NOT NULL,
                hash TEXT NOT NULL,
                signature TEXT,
                parameters TEXT,
                rollback_script_id TEXT
            )",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scripts_name ON scripts(name)",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scripts_language ON scripts(language)",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scripts_created_by ON scripts(created_by)",
            [],
        ).map_err(|e| ScriptError::Database(e.to_string()))?;
        
        info!("Initialized script repository database with connection pool");
        Ok(())
    }
    
    /// Get repository configuration
    pub fn config(&self) -> &ScriptRepositoryConfig {
        &self.config
    }
    
    /// Get scripts directory path
    pub fn scripts_directory(&self) -> &Path {
        &self.config.scripts_directory
    }
    
    /// Store a new script in the repository
    pub async fn store_script(
        &self,
        name: String,
        description: Option<String>,
        language: ScriptLanguage,
        content: String,
        tags: Vec<String>,
        created_by: String,
        parameters: Vec<crate::ScriptParameter>,
    ) -> ScriptResult<String> {
        // Validate language is allowed
        if !self.config.allowed_languages.contains(&language) {
            return Err(ScriptError::Configuration(
                format!("Language {:?} not allowed in this repository", language)
            ));
        }
        
        // Validate content size
        if content.len() > self.config.max_file_size as usize {
            return Err(ScriptError::Validation(
                format!("Script content exceeds maximum size of {} bytes", self.config.max_file_size)
            ));
        }
        
        // Generate unique ID
        let id = Uuid::new_v4().to_string();
        
        // Calculate content hash
        let mut hasher = Sha3_256::new();
        hasher.update(content.as_bytes());
        let hash = hex::encode(hasher.finalize());
        
        // Create file path
        let filename = format!("{}-{}.{}", name.replace(" ", "_"), id, language.extension());
        let file_path = self.config.scripts_directory
            .join(language.extension())
            .join(&filename);
        
        // Write script content to file
        fs::write(&file_path, &content)?;
        
        // Generate signature if required
        let signature = if self.config.require_signatures {
            let signature_data = format!("{}{}{}", id, hash, content);
            let sig = self.signer.sign(&self.private_key, signature_data.as_bytes())
                .map_err(|e| ScriptError::Crypto(e))?;
            Some(hex::encode(&sig.signature))
        } else {
            None
        };
        
        let now = Utc::now();
        
        // Create metadata
        let metadata = ScriptMetadata {
            id: id.clone(),
            name,
            description,
            language,
            tags,
            created_by: created_by.clone(),
            modified_by: created_by,
            created: now,
            modified: now,
            file_path,
            hash,
            signature,
            parameters,
            rollback_script_id: None,
        };
        
        // Store in database
        self.store_metadata(&metadata).await?;
        
        // Update cache
        let mut cache = self.metadata_cache.write().await;
        cache.insert(id.clone(), metadata.clone());
        
        info!("Stored script '{}' with ID: {}", metadata.name, id);
        Ok(id)
    }
    
    /// Update an existing script
    pub async fn update_script(
        &self,
        id: String,
        name: Option<String>,
        description: Option<String>,
        content: Option<String>,
        tags: Option<Vec<String>>,
        modified_by: String,
        parameters: Option<Vec<crate::ScriptParameter>>,
    ) -> ScriptResult<()> {
        let mut metadata = self.get_script_metadata(&id).await?
            .ok_or_else(|| ScriptError::ScriptNotFound(id.clone()))?;
        
        let mut content_changed = false;
        
        // Update fields if provided
        if let Some(new_name) = name {
            metadata.name = new_name;
        }
        if let Some(new_description) = description {
            metadata.description = Some(new_description);
        }
        if let Some(new_tags) = tags {
            metadata.tags = new_tags;
        }
        if let Some(new_parameters) = parameters {
            metadata.parameters = new_parameters;
        }
        
        // Update content if provided
        if let Some(new_content) = content {
            // Validate content size
            if new_content.len() > self.config.max_file_size as usize {
                return Err(ScriptError::Validation(
                    format!("Script content exceeds maximum size of {} bytes", self.config.max_file_size)
                ));
            }
            
            // Calculate new hash
            let mut hasher = Sha3_256::new();
            hasher.update(new_content.as_bytes());
            let new_hash = hex::encode(hasher.finalize());
            
            // Only update if content actually changed
            if new_hash != metadata.hash {
                // Write new content
                fs::write(&metadata.file_path, &new_content)?;
                
                // Update hash
                metadata.hash = new_hash;
                content_changed = true;
                
                // Generate new signature if required
                if self.config.require_signatures {
                    let signature_data = format!("{}{}{}", id, metadata.hash, new_content);
                    let sig = self.signer.sign(&self.private_key, signature_data.as_bytes())
                        .map_err(|e| ScriptError::Crypto(e))?;
                    metadata.signature = Some(hex::encode(&sig.signature));
                }
            }
        }
        
        // Update modification info
        metadata.modified_by = modified_by;
        metadata.modified = Utc::now();
        
        // Store updated metadata
        self.store_metadata(&metadata).await?;
        
        // Update cache
        let mut cache = self.metadata_cache.write().await;
        cache.insert(id.clone(), metadata);
        
        info!("Updated script with ID: {} (content changed: {})", id, content_changed);
        Ok(())
    }
    
    /// Get script metadata by ID
    pub async fn get_script_metadata(&self, id: &str) -> ScriptResult<Option<ScriptMetadata>> {
        // Check cache first
        {
            let cache = self.metadata_cache.read().await;
            if let Some(metadata) = cache.get(id) {
                return Ok(Some(metadata.clone()));
            }
        }
        
        // Load from database - perform all DB operations in a single scope
        let metadata_result = {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            let mut stmt = conn.prepare(
                "SELECT id, name, description, language, tags, created_by, modified_by, 
                        created, modified, file_path, hash, signature, parameters, rollback_script_id
                 FROM scripts WHERE id = ?1"
            ).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            stmt.query_row(params![id], |row| {
                let tags_json: String = row.get(4)?;
                let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                
                let parameters_json: Option<String> = row.get(12)?;
                let parameters = if let Some(params_str) = parameters_json {
                    serde_json::from_str(&params_str).unwrap_or_default()
                } else {
                    Vec::new()
                };
                
                let language_str: String = row.get(3)?;
                let language = match language_str.as_str() {
                    "Python" => ScriptLanguage::Python,
                    "PowerShell" => ScriptLanguage::PowerShell,
                    "Batch" => ScriptLanguage::Batch,
                    _ => ScriptLanguage::Python, // Default fallback
                };
                
                Ok(ScriptMetadata {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    language,
                    tags,
                    created_by: row.get(5)?,
                    modified_by: row.get(6)?,
                    created: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                        .unwrap().with_timezone(&Utc),
                    modified: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                        .unwrap().with_timezone(&Utc),
                    file_path: PathBuf::from(row.get::<_, String>(9)?),
                    hash: row.get(10)?,
                    signature: row.get(11)?,
                    parameters,
                    rollback_script_id: row.get(13)?,
                })
            })
        };
        
        match metadata_result {
            Ok(metadata) => {
                // Update cache
                let mut cache = self.metadata_cache.write().await;
                cache.insert(id.to_string(), metadata.clone());
                Ok(Some(metadata))
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ScriptError::Database(e.to_string())),
        }
    }
    
    /// Get script content by ID
    pub async fn get_script_content(&self, id: &str) -> ScriptResult<Option<String>> {
        if let Some(metadata) = self.get_script_metadata(id).await? {
            let content = fs::read_to_string(&metadata.file_path)?;
            
            // Verify content integrity if signature exists
            if let Some(signature) = &metadata.signature {
                let signature_data = format!("{}{}{}", id, metadata.hash, content);
                let sig_bytes = hex::decode(signature)
                    .map_err(|e| ScriptError::Validation(format!("Invalid signature format: {}", e)))?;
                
                // Note: In a full implementation, we'd verify the signature here
                // For now, we'll just validate the hash
                let mut hasher = Sha3_256::new();
                hasher.update(content.as_bytes());
                let computed_hash = hex::encode(hasher.finalize());
                
                if computed_hash != metadata.hash {
                    return Err(ScriptError::Validation(
                        "Script content hash mismatch - file may be corrupted".to_string()
                    ));
                }
            }
            
            Ok(Some(content))
        } else {
            Ok(None)
        }
    }
    
    /// Search scripts based on query
    pub async fn search_scripts(&self, query: ScriptSearchQuery) -> ScriptResult<Vec<ScriptMetadata>> {
        // Perform all DB operations in a single scope
        let mut results = {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            let mut sql = "SELECT id, name, description, language, tags, created_by, modified_by, 
                                  created, modified, file_path, hash, signature, parameters, rollback_script_id
                           FROM scripts WHERE 1=1".to_string();
            let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
            
            // Add text search
            if let Some(text) = &query.text {
                sql.push_str(" AND (name LIKE ?1 OR description LIKE ?1)");
                params.push(Box::new(format!("%{}%", text)));
            }
            
            // Add language filter
            if let Some(language) = &query.language {
                sql.push_str(&format!(" AND language = ?{}", params.len() + 1));
                params.push(Box::new(format!("{:?}", language)));
            }
            
            // Add author filter
            if let Some(author) = &query.author {
                sql.push_str(&format!(" AND created_by = ?{}", params.len() + 1));
                params.push(Box::new(author.clone()));
            }
            
            // Add ordering and limits
            sql.push_str(" ORDER BY modified DESC");
            
            if let Some(limit) = query.limit {
                sql.push_str(&format!(" LIMIT {}", limit));
            }
            
            if let Some(offset) = query.offset {
                sql.push_str(&format!(" OFFSET {}", offset));
            }
            
            let mut stmt = conn.prepare(&sql)
                .map_err(|e| ScriptError::Database(e.to_string()))?;
            
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            
            let rows = stmt.query_map(&param_refs[..], |row| {
                let tags_json: String = row.get(4)?;
                let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                
                let parameters_json: Option<String> = row.get(12)?;
                let parameters = if let Some(params_str) = parameters_json {
                    serde_json::from_str(&params_str).unwrap_or_default()
                } else {
                    Vec::new()
                };
                
                let language_str: String = row.get(3)?;
                let language = match language_str.as_str() {
                    "Python" => ScriptLanguage::Python,
                    "PowerShell" => ScriptLanguage::PowerShell,
                    "Batch" => ScriptLanguage::Batch,
                    _ => ScriptLanguage::Python,
                };
                
                Ok(ScriptMetadata {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    language,
                    tags,
                    created_by: row.get(5)?,
                    modified_by: row.get(6)?,
                    created: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                        .unwrap().with_timezone(&Utc),
                    modified: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                        .unwrap().with_timezone(&Utc),
                    file_path: PathBuf::from(row.get::<_, String>(9)?),
                    hash: row.get(10)?,
                    signature: row.get(11)?,
                    parameters,
                    rollback_script_id: row.get(13)?,
                })
            }).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            let mut results = Vec::new();
            for row in rows {
                results.push(row.map_err(|e| ScriptError::Database(e.to_string()))?);
            }
            
            results
        };
        
        // Filter by tags if specified
        if let Some(required_tags) = &query.tags {
            results.retain(|script| {
                required_tags.iter().all(|tag| script.tags.contains(tag))
            });
        }
        
        Ok(results)
    }
    
    /// Delete a script from the repository
    pub async fn delete_script(&self, id: &str) -> ScriptResult<()> {
        let metadata = self.get_script_metadata(id).await?
            .ok_or_else(|| ScriptError::ScriptNotFound(id.to_string()))?;
        
        // Delete file
        if metadata.file_path.exists() {
            fs::remove_file(&metadata.file_path)?;
        }
        
        // Delete from database - perform all DB operations in a single scope
        {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            conn.execute("DELETE FROM scripts WHERE id = ?1", params![id])
                .map_err(|e| ScriptError::Database(e.to_string()))?;
        }
        
        // Remove from cache
        let mut cache = self.metadata_cache.write().await;
        cache.remove(id);
        
        info!("Deleted script with ID: {}", id);
        Ok(())
    }
    
    /// Get repository statistics
    pub async fn get_stats(&self) -> ScriptResult<RepositoryStats> {
        // Perform all DB operations in a single scope
        let (total_scripts, scripts_by_language) = {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            // Total scripts
            let total_scripts: usize = conn.query_row(
                "SELECT COUNT(*) FROM scripts",
                [],
                |row| row.get(0)
            ).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            // Scripts by language
            let mut scripts_by_language = HashMap::new();
            let mut stmt = conn.prepare("SELECT language, COUNT(*) FROM scripts GROUP BY language")
                .map_err(|e| ScriptError::Database(e.to_string()))?;
            
            let rows = stmt.query_map([], |row| {
                let language_str: String = row.get(0)?;
                let count: usize = row.get(1)?;
                Ok((language_str, count))
            }).map_err(|e| ScriptError::Database(e.to_string()))?;
            
            for row in rows {
                let (lang_str, count) = row.map_err(|e| ScriptError::Database(e.to_string()))?;
                let language = match lang_str.as_str() {
                    "Python" => ScriptLanguage::Python,
                    "PowerShell" => ScriptLanguage::PowerShell,
                    "Batch" => ScriptLanguage::Batch,
                    _ => continue,
                };
                scripts_by_language.insert(language, count);
            }
            
            (total_scripts, scripts_by_language)
        };
        
        // Calculate storage size
        let storage_size_bytes = self.calculate_storage_size()?;
        
        Ok(RepositoryStats {
            total_scripts,
            scripts_by_language,
            total_executions: 0, // Will be filled by execution engine
            recent_executions: 0,
            success_rate: 0.0,
            average_runtime_ms: 0.0,
            storage_size_bytes,
        })
    }
    
    /// Store metadata in database
    async fn store_metadata(&self, metadata: &ScriptMetadata) -> ScriptResult<()> {
        // Perform all DB operations in a single scope
        {
            let conn = self.db_pool.get()
                .map_err(|e| ScriptError::Database(format!("Failed to get database connection: {}", e)))?;
            
            let tags_json = serde_json::to_string(&metadata.tags)?;
            let parameters_json = serde_json::to_string(&metadata.parameters)?;
            
            conn.execute(
                "INSERT OR REPLACE INTO scripts 
                 (id, name, description, language, tags, created_by, modified_by, 
                  created, modified, file_path, hash, signature, parameters, rollback_script_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    metadata.id,
                    metadata.name,
                    metadata.description,
                    format!("{:?}", metadata.language),
                    tags_json,
                    metadata.created_by,
                    metadata.modified_by,
                    metadata.created.to_rfc3339(),
                    metadata.modified.to_rfc3339(),
                    metadata.file_path.to_string_lossy().to_string(),
                    metadata.hash,
                    metadata.signature,
                    parameters_json,
                    metadata.rollback_script_id,
                ]
            ).map_err(|e| ScriptError::Database(e.to_string()))?;
        }
        
        Ok(())
    }
    
    /// Calculate total storage size
    fn calculate_storage_size(&self) -> ScriptResult<u64> {
        let mut total_size = 0u64;
        
        fn visit_dir(dir: &Path, total: &mut u64) -> std::io::Result<()> {
            if dir.is_dir() {
                for entry in fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        visit_dir(&path, total)?;
                    } else {
                        *total += entry.metadata()?.len();
                    }
                }
            }
            Ok(())
        }
        
        visit_dir(&self.config.scripts_directory, &mut total_size)?;
        Ok(total_size)
    }
}
