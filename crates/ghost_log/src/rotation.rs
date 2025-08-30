//! Log rotation system for GhostLog
//! 
//! Handles automatic rotation of log files based on size and time,
//! with PQ signing and manifest creation.

use crate::{LogError, Result, LogManifest};
use chrono::{DateTime, Utc};
use ghost_pq::{DilithiumSigner, DilithiumVariant, DilithiumKeyPair};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info, warn};

/// Rotation policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Maximum file size before rotation (bytes)
    pub max_size: u64,
    /// Maximum age before rotation (hours)
    pub max_age_hours: u64,
    /// Whether to compress rotated files
    pub compress: bool,
    /// Retention period in days (0 = keep forever)
    pub retention_days: u32,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_size: 100 * 1024 * 1024, // 100MB
            max_age_hours: 24, // Daily rotation
            compress: true,
            retention_days: 90,
        }
    }
}

/// Log rotation manager
pub struct LogRotator {
    policy: RotationPolicy,
    signer: DilithiumSigner,
    private_key: ghost_pq::DilithiumPrivateKey,
    base_directory: PathBuf,
}

impl LogRotator {
    /// Create a new log rotator
    pub fn new(policy: RotationPolicy, base_directory: PathBuf) -> Result<Self> {
        let signer = DilithiumSigner::new(DilithiumVariant::Dilithium2)
            .map_err(|e| LogError::CryptoError(e))?;
        let keypair = signer.generate_keypair()
            .map_err(|e| LogError::CryptoError(e))?;

        Ok(Self {
            policy,
            signer,
            private_key: keypair.private_key,
            base_directory,
        })
    }

    /// Check if a log file needs rotation
    pub async fn needs_rotation(&self, log_file: &Path) -> Result<bool> {
        if !log_file.exists() {
            return Ok(false);
        }

        let metadata = fs::metadata(log_file).await?;
        
        // Check size
        if metadata.len() >= self.policy.max_size {
            debug!("Log file {:?} needs rotation due to size: {} bytes", log_file, metadata.len());
            return Ok(true);
        }

        // Check age
        if let Ok(created) = metadata.created() {
            let created_dt = DateTime::<Utc>::from(created);
            let age_hours = Utc::now().signed_duration_since(created_dt).num_hours();
            
            if age_hours >= self.policy.max_age_hours as i64 {
                debug!("Log file {:?} needs rotation due to age: {} hours", log_file, age_hours);
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Rotate a log file
    pub async fn rotate_file(
        &self,
        current_file: &Path,
        entry_count: u64,
        start_time: DateTime<Utc>,
    ) -> Result<PathBuf> {
        info!("Rotating log file: {:?}", current_file);

        // Create manifest
        let mut manifest = LogManifest::new(
            current_file.to_path_buf(),
            entry_count,
            start_time,
            Utc::now(),
        );

        // Sign the manifest
        manifest.sign(&self.signer, &self.private_key)?;

        // Save manifest
        let manifest_path = current_file.with_extension("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(&manifest_path, manifest_json).await?;

        // Optionally compress the log file
        if self.policy.compress {
            self.compress_file(current_file).await?;
        }

        info!("Log rotation completed: {:?}", current_file);
        Ok(manifest_path)
    }

    /// Compress a log file using gzip
    async fn compress_file(&self, file_path: &Path) -> Result<()> {
        // TODO: Implement compression
        // For now, just log that compression would happen
        debug!("Would compress file: {:?}", file_path);
        Ok(())
    }

    /// Clean up old log files based on retention policy
    pub async fn cleanup_old_files(&self) -> Result<()> {
        if self.policy.retention_days == 0 {
            return Ok(()); // Keep forever
        }

        let cutoff_date = Utc::now() - chrono::Duration::days(self.policy.retention_days as i64);
        
        // Walk through all module directories
        let mut entries = fs::read_dir(&self.base_directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                self.cleanup_module_directory(&entry.path(), cutoff_date).await?;
            }
        }

        Ok(())
    }

    async fn cleanup_module_directory(&self, module_dir: &Path, cutoff_date: DateTime<Utc>) -> Result<()> {
        let mut entries = fs::read_dir(module_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if let Some(extension) = path.extension() {
                if extension == "log" || extension == "manifest" {
                    if let Ok(metadata) = fs::metadata(&path).await {
                        if let Ok(created) = metadata.created() {
                            let created_dt = DateTime::<Utc>::from(created);
                            if created_dt < cutoff_date {
                                info!("Removing old log file: {:?}", path);
                                if let Err(e) = fs::remove_file(&path).await {
                                    warn!("Failed to remove old log file {:?}: {}", path, e);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get rotation statistics
    pub async fn get_stats(&self) -> Result<RotationStats> {
        let mut stats = RotationStats::default();

        // Walk through all files and collect statistics
        let mut entries = fs::read_dir(&self.base_directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let module_stats = self.get_module_stats(&entry.path()).await?;
                stats.total_files += module_stats.log_files;
                stats.total_size += module_stats.total_size;
                stats.modules.insert(
                    entry.file_name().to_string_lossy().to_string(),
                    module_stats,
                );
            }
        }

        Ok(stats)
    }

    async fn get_module_stats(&self, module_dir: &Path) -> Result<ModuleStats> {
        let mut stats = ModuleStats::default();

        let mut entries = fs::read_dir(module_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if let Some(extension) = path.extension() {
                if extension == "log" {
                    stats.log_files += 1;
                    if let Ok(metadata) = fs::metadata(&path).await {
                        stats.total_size += metadata.len();
                    }
                } else if extension == "manifest" {
                    stats.manifest_files += 1;
                }
            }
        }

        Ok(stats)
    }
}

/// Statistics about log rotation
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RotationStats {
    pub total_files: u64,
    pub total_size: u64,
    pub modules: std::collections::HashMap<String, ModuleStats>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ModuleStats {
    pub log_files: u64,
    pub manifest_files: u64,
    pub total_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_rotation_policy() {
        let temp_dir = TempDir::new().unwrap();
        let policy = RotationPolicy {
            max_size: 1024, // 1KB for testing
            max_age_hours: 1,
            compress: false,
            retention_days: 7,
        };

        let rotator = LogRotator::new(policy, temp_dir.path().to_path_buf()).unwrap();

        // Create a test file
        let test_file = temp_dir.path().join("test.log");
        fs::write(&test_file, "x".repeat(2048)).await.unwrap(); // 2KB file

        // Should need rotation due to size
        assert!(rotator.needs_rotation(&test_file).await.unwrap());
    }
}
