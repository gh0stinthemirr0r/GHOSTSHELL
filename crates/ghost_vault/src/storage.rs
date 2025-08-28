use sqlx::{SqlitePool, Row};
use serde_json;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::{
    Secret, SecretSummary, SecretFilter, MfaSetup, MfaSession, SealedVmk,
    VaultError, Result,
};

/// SQLite-based storage backend for the vault
pub struct VaultStorage {
    pool: SqlitePool,
}

impl VaultStorage {
    /// Create new storage instance
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;
        let storage = Self { pool };
        storage.initialize().await?;
        Ok(storage)
    }

    /// Create in-memory storage for testing
    pub async fn in_memory() -> Result<Self> {
        Self::new(":memory:").await
    }

    /// Initialize database schema
    async fn initialize(&self) -> Result<()> {
        // Create secrets table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                secret_type TEXT NOT NULL,
                tags TEXT NOT NULL, -- JSON array
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                accessed_at TEXT,
                expires_at TEXT,
                version INTEGER NOT NULL DEFAULT 1,
                encrypted_data BLOB NOT NULL,
                metadata TEXT NOT NULL -- JSON object
            )
        "#).execute(&self.pool).await?;

        // Create MFA setups table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS mfa_setups (
                user_id TEXT PRIMARY KEY,
                method TEXT NOT NULL,
                secret TEXT,
                backup_codes TEXT, -- JSON array
                qr_code BLOB,
                created_at TEXT NOT NULL
            )
        "#).execute(&self.pool).await?;

        // Create MFA sessions table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS mfa_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                verified_methods TEXT NOT NULL, -- JSON array
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_verified TEXT NOT NULL
            )
        "#).execute(&self.pool).await?;

        // Create vault master key table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS vault_master_keys (
                id INTEGER PRIMARY KEY CHECK (id = 1), -- Only one VMK
                kyber_ciphertext BLOB NOT NULL,
                kyber_public_key BLOB NOT NULL,
                envelope_header BLOB NOT NULL,
                salt BLOB NOT NULL,
                iterations INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        "#).execute(&self.pool).await?;

        // Create indexes for better performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(secret_type)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_secrets_created ON secrets(created_at)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_mfa_sessions_user ON mfa_sessions(user_id)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_mfa_sessions_expires ON mfa_sessions(expires_at)")
            .execute(&self.pool).await?;

        Ok(())
    }

    /// Store a secret
    pub async fn store_secret(&self, secret: &Secret) -> Result<()> {
        let tags_json = serde_json::to_string(&secret.tags)?;
        let metadata_json = serde_json::to_string(&secret.metadata)?;

        sqlx::query(r#"
            INSERT OR REPLACE INTO secrets (
                id, name, description, secret_type, tags, created_at, updated_at,
                accessed_at, expires_at, version, encrypted_data, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(secret.id.to_string())
        .bind(&secret.name)
        .bind(&secret.description)
        .bind(serde_json::to_string(&secret.secret_type)?)
        .bind(tags_json)
        .bind(secret.created_at.to_rfc3339())
        .bind(secret.updated_at.to_rfc3339())
        .bind(secret.accessed_at.map(|dt| dt.to_rfc3339()))
        .bind(secret.expires_at.map(|dt| dt.to_rfc3339()))
        .bind(secret.version as i64)
        .bind(&secret.encrypted_data)
        .bind(metadata_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Retrieve a secret by ID
    pub async fn get_secret(&self, id: &Uuid) -> Result<Option<Secret>> {
        let row = sqlx::query(r#"
            SELECT id, name, description, secret_type, tags, created_at, updated_at,
                   accessed_at, expires_at, version, encrypted_data, metadata
            FROM secrets WHERE id = ?
        "#)
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(self.row_to_secret(row)?))
        } else {
            Ok(None)
        }
    }

    /// List secrets with optional filtering
    pub async fn list_secrets(&self, filter: &SecretFilter) -> Result<Vec<SecretSummary>> {
        let mut query = "SELECT id, name, description, secret_type, tags, created_at, updated_at, accessed_at, expires_at, version FROM secrets WHERE 1=1".to_string();
        let mut bind_values: Vec<String> = Vec::new();

        // Build dynamic query based on filter
        if let Some(ref secret_type) = filter.secret_type {
            query.push_str(" AND secret_type = ?");
            bind_values.push(serde_json::to_string(secret_type)?);
        }

        if let Some(ref pattern) = filter.name_pattern {
            query.push_str(" AND name LIKE ?");
            bind_values.push(format!("%{}%", pattern));
        }

        if let Some(created_after) = filter.created_after {
            query.push_str(" AND created_at > ?");
            bind_values.push(created_after.to_rfc3339());
        }

        if let Some(created_before) = filter.created_before {
            query.push_str(" AND created_at < ?");
            bind_values.push(created_before.to_rfc3339());
        }

        if let Some(expires_after) = filter.expires_after {
            query.push_str(" AND expires_at > ?");
            bind_values.push(expires_after.to_rfc3339());
        }

        if let Some(expires_before) = filter.expires_before {
            query.push_str(" AND expires_at < ?");
            bind_values.push(expires_before.to_rfc3339());
        }

        query.push_str(" ORDER BY updated_at DESC");

        if let Some(limit) = filter.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        if let Some(offset) = filter.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        let mut sqlx_query = sqlx::query(&query);
        for value in bind_values {
            sqlx_query = sqlx_query.bind(value);
        }

        let rows = sqlx_query.fetch_all(&self.pool).await?;
        let mut summaries = Vec::new();

        for row in rows {
            let summary = self.row_to_summary(&row)?;
            
            // Apply tag filtering (SQLite doesn't have good JSON support)
            if !filter.tags.is_empty() {
                let tags: Vec<String> = serde_json::from_str(
                    &row.try_get::<String, _>("tags").unwrap_or_default()
                )?;
                
                let has_all_tags = filter.tags.iter().all(|filter_tag| tags.contains(filter_tag));
                if !has_all_tags {
                    continue;
                }
            }
            
            summaries.push(summary);
        }

        Ok(summaries)
    }

    /// Delete a secret
    pub async fn delete_secret(&self, id: &Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM secrets WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update secret access time
    pub async fn mark_secret_accessed(&self, id: &Uuid) -> Result<()> {
        sqlx::query("UPDATE secrets SET accessed_at = ? WHERE id = ?")
            .bind(Utc::now().to_rfc3339())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Store MFA setup
    pub async fn store_mfa_setup(&self, user_id: &str, setup: &MfaSetup) -> Result<()> {
        let backup_codes_json = serde_json::to_string(&setup.backup_codes)?;

        sqlx::query(r#"
            INSERT OR REPLACE INTO mfa_setups (
                user_id, method, secret, backup_codes, qr_code, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        "#)
        .bind(user_id)
        .bind(serde_json::to_string(&setup.method)?)
        .bind(&setup.secret)
        .bind(backup_codes_json)
        .bind(&setup.qr_code)
        .bind(setup.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get MFA setup for user
    pub async fn get_mfa_setup(&self, user_id: &str) -> Result<Option<MfaSetup>> {
        let row = sqlx::query(r#"
            SELECT method, secret, backup_codes, qr_code, created_at
            FROM mfa_setups WHERE user_id = ?
        "#)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let method: String = row.try_get("method")?;
            let method = serde_json::from_str(&method)?;
            let backup_codes: String = row.try_get("backup_codes")?;
            let backup_codes = serde_json::from_str(&backup_codes)?;
            let created_at: String = row.try_get("created_at")?;
            let created_at = DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc);

            Ok(Some(MfaSetup {
                method,
                secret: row.try_get("secret")?,
                backup_codes,
                qr_code: row.try_get("qr_code")?,
                created_at,
            }))
        } else {
            Ok(None)
        }
    }

    /// Store MFA session
    pub async fn store_mfa_session(&self, session: &MfaSession) -> Result<()> {
        let verified_methods_json = serde_json::to_string(&session.verified_methods)?;

        sqlx::query(r#"
            INSERT OR REPLACE INTO mfa_sessions (
                session_id, user_id, verified_methods, created_at, expires_at, last_verified
            ) VALUES (?, ?, ?, ?, ?, ?)
        "#)
        .bind(&session.session_id)
        .bind(&session.user_id)
        .bind(verified_methods_json)
        .bind(session.created_at.to_rfc3339())
        .bind(session.expires_at.to_rfc3339())
        .bind(session.last_verified.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get MFA session
    pub async fn get_mfa_session(&self, session_id: &str) -> Result<Option<MfaSession>> {
        let row = sqlx::query(r#"
            SELECT session_id, user_id, verified_methods, created_at, expires_at, last_verified
            FROM mfa_sessions WHERE session_id = ?
        "#)
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let verified_methods: String = row.try_get("verified_methods")?;
            let verified_methods = serde_json::from_str(&verified_methods)?;
            let created_at: String = row.try_get("created_at")?;
            let created_at = DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc);
            let expires_at: String = row.try_get("expires_at")?;
            let expires_at = DateTime::parse_from_rfc3339(&expires_at)?.with_timezone(&Utc);
            let last_verified: String = row.try_get("last_verified")?;
            let last_verified = DateTime::parse_from_rfc3339(&last_verified)?.with_timezone(&Utc);

            Ok(Some(MfaSession {
                session_id: row.try_get("session_id")?,
                user_id: row.try_get("user_id")?,
                verified_methods,
                created_at,
                expires_at,
                last_verified,
            }))
        } else {
            Ok(None)
        }
    }

    /// Delete MFA session
    pub async fn delete_mfa_session(&self, session_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM mfa_sessions WHERE session_id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Clean up expired MFA sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u64> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query("DELETE FROM mfa_sessions WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Store sealed VMK
    pub async fn store_sealed_vmk(&self, sealed_vmk: &SealedVmk) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        sqlx::query(r#"
            INSERT OR REPLACE INTO vault_master_keys (
                id, kyber_ciphertext, kyber_public_key, envelope_header, salt, iterations, created_at, updated_at
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(&sealed_vmk.kyber_ciphertext)
        .bind(&sealed_vmk.kyber_public_key)
        .bind(&sealed_vmk.envelope_header)
        .bind(&sealed_vmk.salt)
        .bind(sealed_vmk.iterations as i64)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get sealed VMK
    pub async fn get_sealed_vmk(&self) -> Result<Option<SealedVmk>> {
        let row = sqlx::query(r#"
            SELECT kyber_ciphertext, kyber_public_key, envelope_header, salt, iterations
            FROM vault_master_keys WHERE id = 1
        "#)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(SealedVmk {
                kyber_ciphertext: row.try_get("kyber_ciphertext")?,
                kyber_public_key: row.try_get("kyber_public_key")?,
                envelope_header: row.try_get("envelope_header")?,
                salt: row.try_get("salt")?,
                iterations: row.try_get::<i64, _>("iterations")? as u32,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> Result<VaultStats> {
        let secrets_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secrets")
            .fetch_one(&self.pool)
            .await?;

        let expired_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secrets WHERE expires_at IS NOT NULL AND expires_at < ?"
        )
        .bind(Utc::now().to_rfc3339())
        .fetch_one(&self.pool)
        .await?;

        let mfa_users_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mfa_setups")
            .fetch_one(&self.pool)
            .await?;

        let active_sessions_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mfa_sessions WHERE expires_at > ?"
        )
        .bind(Utc::now().to_rfc3339())
        .fetch_one(&self.pool)
        .await?;

        Ok(VaultStats {
            total_secrets: secrets_count as u64,
            expired_secrets: expired_count as u64,
            mfa_users: mfa_users_count as u64,
            active_sessions: active_sessions_count as u64,
        })
    }

    /// Convert database row to Secret
    fn row_to_secret(&self, row: sqlx::sqlite::SqliteRow) -> Result<Secret> {
        let id: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id).map_err(|e| VaultError::InvalidInput(format!("Invalid UUID: {}", e)))?;
        
        let secret_type: String = row.try_get("secret_type")?;
        let secret_type = serde_json::from_str(&secret_type)?;
        
        let tags: String = row.try_get("tags")?;
        let tags = serde_json::from_str(&tags)?;
        
        let metadata: String = row.try_get("metadata")?;
        let metadata = serde_json::from_str(&metadata)?;
        
        let created_at: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc);
        
        let updated_at: String = row.try_get("updated_at")?;
        let updated_at = DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc);
        
        let accessed_at: Option<String> = row.try_get("accessed_at")?;
        let accessed_at = accessed_at.map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc))).transpose()?;
        
        let expires_at: Option<String> = row.try_get("expires_at")?;
        let expires_at = expires_at.map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc))).transpose()?;

        Ok(Secret {
            id,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            secret_type,
            tags,
            created_at,
            updated_at,
            accessed_at,
            expires_at,
            version: row.try_get::<i64, _>("version")? as u32,
            encrypted_data: row.try_get("encrypted_data")?,
            metadata,
        })
    }

    /// Convert database row to SecretSummary
    fn row_to_summary(&self, row: &sqlx::sqlite::SqliteRow) -> Result<SecretSummary> {
        let id: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id).map_err(|e| VaultError::InvalidInput(format!("Invalid UUID: {}", e)))?;
        
        let secret_type: String = row.try_get("secret_type")?;
        let secret_type = serde_json::from_str(&secret_type)?;
        
        let tags: String = row.try_get("tags")?;
        let tags = serde_json::from_str(&tags)?;
        
        let created_at: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc);
        
        let updated_at: String = row.try_get("updated_at")?;
        let updated_at = DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc);
        
        let expires_at: Option<String> = row.try_get("expires_at")?;
        let expires_at = expires_at.map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc))).transpose()?;

        let is_expired = expires_at.map_or(false, |exp| Utc::now() > exp);

        Ok(SecretSummary {
            id,
            name: row.try_get("name")?,
            secret_type,
            tags,
            created_at,
            updated_at,
            expires_at,
            is_expired,
        })
    }
}

/// Vault storage statistics
#[derive(Debug, Clone)]
pub struct VaultStats {
    pub total_secrets: u64,
    pub expired_secrets: u64,
    pub mfa_users: u64,
    pub active_sessions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreateSecretRequest, SecretData, SecretType, SecretMetadata};

    #[tokio::test]
    async fn test_storage_initialization() {
        let storage = VaultStorage::in_memory().await.unwrap();
        let stats = storage.get_stats().await.unwrap();
        assert_eq!(stats.total_secrets, 0);
    }

    #[tokio::test]
    async fn test_secret_storage() {
        let storage = VaultStorage::in_memory().await.unwrap();
        
        let request = CreateSecretRequest {
            name: "Test Secret".to_string(),
            description: Some("A test secret".to_string()),
            secret_type: SecretType::Password,
            data: SecretData::Password {
                password: "secret123".to_string(),
            },
            tags: vec!["test".to_string()],
            expires_at: None,
            metadata: SecretMetadata::default(),
        };

        let mut secret = Secret::new(request);
        secret.encrypted_data = b"encrypted_data".to_vec();
        
        storage.store_secret(&secret).await.unwrap();
        
        let retrieved = storage.get_secret(&secret.id).await.unwrap().unwrap();
        assert_eq!(retrieved.name, secret.name);
        assert_eq!(retrieved.secret_type, secret.secret_type);
        assert_eq!(retrieved.encrypted_data, secret.encrypted_data);
    }

    #[tokio::test]
    async fn test_secret_listing() {
        let storage = VaultStorage::in_memory().await.unwrap();
        
        // Store multiple secrets
        for i in 0..5 {
            let request = CreateSecretRequest {
                name: format!("Secret {}", i),
                description: None,
                secret_type: SecretType::Password,
                data: SecretData::Password {
                    password: format!("password{}", i),
                },
                tags: vec!["test".to_string()],
                expires_at: None,
                metadata: SecretMetadata::default(),
            };

            let mut secret = Secret::new(request);
            secret.encrypted_data = format!("encrypted_{}", i).into_bytes();
            storage.store_secret(&secret).await.unwrap();
        }

        let filter = SecretFilter::default();
        let summaries = storage.list_secrets(&filter).await.unwrap();
        assert_eq!(summaries.len(), 5);
    }

    #[tokio::test]
    async fn test_mfa_setup_storage() {
        let storage = VaultStorage::in_memory().await.unwrap();
        
        let setup = MfaSetup {
            method: crate::MfaMethod::Totp,
            secret: Some("JBSWY3DPEHPK3PXP".to_string()),
            backup_codes: vec!["12345678".to_string(), "87654321".to_string()],
            qr_code: Some(b"fake_qr_code".to_vec()),
            created_at: Utc::now(),
        };

        storage.store_mfa_setup("user123", &setup).await.unwrap();
        
        let retrieved = storage.get_mfa_setup("user123").await.unwrap().unwrap();
        assert_eq!(retrieved.method, setup.method);
        assert_eq!(retrieved.secret, setup.secret);
        assert_eq!(retrieved.backup_codes, setup.backup_codes);
    }
}
