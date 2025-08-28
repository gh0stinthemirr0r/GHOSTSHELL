use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::{VaultError, Result};

/// Types of secrets that can be stored in the vault
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretType {
    Password,
    ApiToken,
    SshKey,
    Certificate,
    DatabaseCredentials,
    CloudCredentials,
    ConfigProfile,
    Theme,
    Note,
    Custom(String),
}

/// Secret metadata and encrypted content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub secret_type: SecretType,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub accessed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub version: u32,
    pub encrypted_data: Vec<u8>,
    pub metadata: SecretMetadata,
}

/// Additional metadata for different secret types
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretMetadata {
    // Common fields
    pub url: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    
    // SSH key specific
    pub ssh_key_type: Option<String>,
    pub ssh_public_key: Option<String>,
    
    // Certificate specific
    pub certificate_type: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub serial_number: Option<String>,
    
    // API token specific
    pub api_endpoint: Option<String>,
    pub token_type: Option<String>,
    pub scopes: Vec<String>,
    
    // Database specific
    pub database_type: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub database_name: Option<String>,
    
    // Custom fields
    pub custom_fields: std::collections::HashMap<String, String>,
}

/// Secret data that gets encrypted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretData {
    Password {
        password: String,
    },
    ApiToken {
        token: String,
        refresh_token: Option<String>,
    },
    SshKey {
        private_key: String,
        public_key: String,
        passphrase: Option<String>,
    },
    Certificate {
        certificate: String,
        private_key: Option<String>,
        certificate_chain: Option<Vec<String>>,
    },
    DatabaseCredentials {
        username: String,
        password: String,
        connection_string: Option<String>,
    },
    CloudCredentials {
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
        region: Option<String>,
    },
    ConfigProfile {
        config_data: serde_json::Value,
    },
    Theme {
        theme_data: serde_json::Value,
    },
    Note {
        content: String,
    },
    Custom {
        data: serde_json::Value,
    },
}

/// Secret search and filtering
#[derive(Debug, Clone, Default)]
pub struct SecretFilter {
    pub secret_type: Option<SecretType>,
    pub tags: Vec<String>,
    pub name_pattern: Option<String>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    pub expires_after: Option<DateTime<Utc>>,
    pub expires_before: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Secret creation request
#[derive(Debug, Clone)]
pub struct CreateSecretRequest {
    pub name: String,
    pub description: Option<String>,
    pub secret_type: SecretType,
    pub data: SecretData,
    pub tags: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: SecretMetadata,
}

/// Secret update request
#[derive(Debug, Clone)]
pub struct UpdateSecretRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub data: Option<SecretData>,
    pub tags: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<SecretMetadata>,
}

impl Secret {
    /// Create a new secret
    pub fn new(request: CreateSecretRequest) -> Self {
        let now = Utc::now();
        
        Self {
            id: Uuid::new_v4(),
            name: request.name,
            description: request.description,
            secret_type: request.secret_type,
            tags: request.tags,
            created_at: now,
            updated_at: now,
            accessed_at: None,
            expires_at: request.expires_at,
            version: 1,
            encrypted_data: Vec::new(), // Will be set during encryption
            metadata: request.metadata,
        }
    }

    /// Update secret with new data
    pub fn update(&mut self, request: UpdateSecretRequest) {
        if let Some(name) = request.name {
            self.name = name;
        }
        
        if let Some(description) = request.description {
            self.description = Some(description);
        }
        
        if let Some(tags) = request.tags {
            self.tags = tags;
        }
        
        if let Some(expires_at) = request.expires_at {
            self.expires_at = Some(expires_at);
        }
        
        if let Some(metadata) = request.metadata {
            self.metadata = metadata;
        }
        
        self.updated_at = Utc::now();
        self.version += 1;
    }

    /// Mark secret as accessed
    pub fn mark_accessed(&mut self) {
        self.accessed_at = Some(Utc::now());
    }

    /// Check if secret is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Check if secret matches filter
    pub fn matches_filter(&self, filter: &SecretFilter) -> bool {
        // Check secret type
        if let Some(ref filter_type) = filter.secret_type {
            if &self.secret_type != filter_type {
                return false;
            }
        }

        // Check tags (secret must have all filter tags)
        for filter_tag in &filter.tags {
            if !self.tags.contains(filter_tag) {
                return false;
            }
        }

        // Check name pattern
        if let Some(ref pattern) = filter.name_pattern {
            if !self.name.to_lowercase().contains(&pattern.to_lowercase()) {
                return false;
            }
        }

        // Check creation date range
        if let Some(after) = filter.created_after {
            if self.created_at <= after {
                return false;
            }
        }

        if let Some(before) = filter.created_before {
            if self.created_at >= before {
                return false;
            }
        }

        // Check expiration date range
        if let Some(after) = filter.expires_after {
            if let Some(expires_at) = self.expires_at {
                if expires_at <= after {
                    return false;
                }
            } else {
                return false; // No expiration date, doesn't match filter
            }
        }

        if let Some(before) = filter.expires_before {
            if let Some(expires_at) = self.expires_at {
                if expires_at >= before {
                    return false;
                }
            }
        }

        true
    }

    /// Get display name for UI
    pub fn display_name(&self) -> String {
        if self.name.is_empty() {
            format!("{:?} ({})", self.secret_type, self.id)
        } else {
            self.name.clone()
        }
    }

    /// Get summary for listing
    pub fn summary(&self) -> SecretSummary {
        SecretSummary {
            id: self.id,
            name: self.name.clone(),
            secret_type: self.secret_type.clone(),
            tags: self.tags.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.expires_at,
            is_expired: self.is_expired(),
        }
    }
}

/// Secret summary for listing (without sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSummary {
    pub id: Uuid,
    pub name: String,
    pub secret_type: SecretType,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_expired: bool,
}

impl SecretData {
    /// Get the secret type for this data
    pub fn secret_type(&self) -> SecretType {
        match self {
            SecretData::Password { .. } => SecretType::Password,
            SecretData::ApiToken { .. } => SecretType::ApiToken,
            SecretData::SshKey { .. } => SecretType::SshKey,
            SecretData::Certificate { .. } => SecretType::Certificate,
            SecretData::DatabaseCredentials { .. } => SecretType::DatabaseCredentials,
            SecretData::CloudCredentials { .. } => SecretType::CloudCredentials,
            SecretData::ConfigProfile { .. } => SecretType::ConfigProfile,
            SecretData::Theme { .. } => SecretType::Theme,
            SecretData::Note { .. } => SecretType::Note,
            SecretData::Custom { .. } => SecretType::Custom("custom".to_string()),
        }
    }

    /// Validate secret data
    pub fn validate(&self) -> Result<()> {
        match self {
            SecretData::Password { password } => {
                if password.is_empty() {
                    return Err(VaultError::InvalidInput("Password cannot be empty".to_string()));
                }
            }
            SecretData::ApiToken { token, .. } => {
                if token.is_empty() {
                    return Err(VaultError::InvalidInput("API token cannot be empty".to_string()));
                }
            }
            SecretData::SshKey { private_key, public_key, .. } => {
                if private_key.is_empty() {
                    return Err(VaultError::InvalidInput("SSH private key cannot be empty".to_string()));
                }
                if public_key.is_empty() {
                    return Err(VaultError::InvalidInput("SSH public key cannot be empty".to_string()));
                }
            }
            SecretData::Certificate { certificate, .. } => {
                if certificate.is_empty() {
                    return Err(VaultError::InvalidInput("Certificate cannot be empty".to_string()));
                }
            }
            SecretData::DatabaseCredentials { username, password, .. } => {
                if username.is_empty() {
                    return Err(VaultError::InvalidInput("Database username cannot be empty".to_string()));
                }
                if password.is_empty() {
                    return Err(VaultError::InvalidInput("Database password cannot be empty".to_string()));
                }
            }
            SecretData::CloudCredentials { access_key, secret_key, .. } => {
                if access_key.is_empty() {
                    return Err(VaultError::InvalidInput("Cloud access key cannot be empty".to_string()));
                }
                if secret_key.is_empty() {
                    return Err(VaultError::InvalidInput("Cloud secret key cannot be empty".to_string()));
                }
            }
            SecretData::Note { content } => {
                if content.is_empty() {
                    return Err(VaultError::InvalidInput("Note content cannot be empty".to_string()));
                }
            }
            _ => {} // Other types are always valid
        }
        
        Ok(())
    }

    /// Get a masked version for display
    pub fn masked(&self) -> SecretData {
        match self {
            SecretData::Password { .. } => SecretData::Password {
                password: "********".to_string(),
            },
            SecretData::ApiToken { token, refresh_token } => SecretData::ApiToken {
                token: Self::mask_token(token),
                refresh_token: refresh_token.as_ref().map(|t| Self::mask_token(t)),
            },
            SecretData::SshKey { private_key, public_key, .. } => SecretData::SshKey {
                private_key: "*** PRIVATE KEY ***".to_string(),
                public_key: public_key.clone(), // Public keys are safe to show
                passphrase: Some("***".to_string()),
            },
            SecretData::DatabaseCredentials { username, password, connection_string } => {
                SecretData::DatabaseCredentials {
                    username: username.clone(), // Username is usually not sensitive
                    password: "********".to_string(),
                    connection_string: connection_string.as_ref().map(|cs| Self::mask_connection_string(cs)),
                }
            }
            SecretData::CloudCredentials { access_key, secret_key, session_token, region } => {
                SecretData::CloudCredentials {
                    access_key: Self::mask_token(access_key),
                    secret_key: "********".to_string(),
                    session_token: session_token.as_ref().map(|t| Self::mask_token(t)),
                    region: region.clone(),
                }
            }
            _ => self.clone(), // Other types don't need masking
        }
    }

    fn mask_token(token: &str) -> String {
        if token.len() <= 8 {
            "***".to_string()
        } else {
            format!("{}***{}", &token[..4], &token[token.len()-4..])
        }
    }

    fn mask_connection_string(cs: &str) -> String {
        // Simple masking for connection strings - replace passwords
        let masked = cs
            .replace(|c: char| c.is_ascii_alphanumeric() && cs.contains("password"), "*");
        masked
    }
}

/// Builder for creating secrets
pub struct SecretBuilder {
    name: String,
    description: Option<String>,
    secret_type: SecretType,
    data: Option<SecretData>,
    tags: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
    metadata: SecretMetadata,
}

impl SecretBuilder {
    pub fn new(name: String, secret_type: SecretType) -> Self {
        Self {
            name,
            description: None,
            secret_type,
            data: None,
            tags: Vec::new(),
            expires_at: None,
            metadata: SecretMetadata::default(),
        }
    }

    pub fn description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn data(mut self, data: SecretData) -> Self {
        self.data = Some(data);
        self
    }

    pub fn tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn metadata(mut self, metadata: SecretMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn build(self) -> Result<CreateSecretRequest> {
        let data = self.data.ok_or_else(|| VaultError::InvalidInput("Secret data is required".to_string()))?;
        
        // Validate that secret type matches data type
        if self.secret_type != data.secret_type() {
            return Err(VaultError::InvalidInput(
                format!("Secret type {:?} doesn't match data type {:?}", 
                    self.secret_type, data.secret_type())
            ));
        }

        data.validate()?;

        Ok(CreateSecretRequest {
            name: self.name,
            description: self.description,
            secret_type: self.secret_type,
            data,
            tags: self.tags,
            expires_at: self.expires_at,
            metadata: self.metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_creation() {
        let request = CreateSecretRequest {
            name: "Test Password".to_string(),
            description: Some("A test password".to_string()),
            secret_type: SecretType::Password,
            data: SecretData::Password {
                password: "secret123".to_string(),
            },
            tags: vec!["test".to_string()],
            expires_at: None,
            metadata: SecretMetadata::default(),
        };

        let secret = Secret::new(request);
        assert_eq!(secret.name, "Test Password");
        assert_eq!(secret.secret_type, SecretType::Password);
        assert!(secret.tags.contains(&"test".to_string()));
        assert!(!secret.is_expired());
    }

    #[test]
    fn test_secret_builder() {
        let request = SecretBuilder::new("API Key".to_string(), SecretType::ApiToken)
            .description("GitHub API key".to_string())
            .data(SecretData::ApiToken {
                token: "ghp_1234567890".to_string(),
                refresh_token: None,
            })
            .tag("github".to_string())
            .tag("api".to_string())
            .build()
            .unwrap();

        assert_eq!(request.name, "API Key");
        assert_eq!(request.tags, vec!["github", "api"]);
    }

    #[test]
    fn test_secret_filtering() {
        let secret = Secret::new(CreateSecretRequest {
            name: "Test Secret".to_string(),
            description: None,
            secret_type: SecretType::Password,
            data: SecretData::Password {
                password: "test".to_string(),
            },
            tags: vec!["work".to_string(), "important".to_string()],
            expires_at: None,
            metadata: SecretMetadata::default(),
        });

        let filter = SecretFilter {
            tags: vec!["work".to_string()],
            ..Default::default()
        };

        assert!(secret.matches_filter(&filter));

        let filter = SecretFilter {
            tags: vec!["personal".to_string()],
            ..Default::default()
        };

        assert!(!secret.matches_filter(&filter));
    }

    #[test]
    fn test_secret_masking() {
        let data = SecretData::Password {
            password: "supersecret".to_string(),
        };

        let masked = data.masked();
        if let SecretData::Password { password } = masked {
            assert_eq!(password, "********");
        } else {
            panic!("Expected masked password");
        }
    }

    #[test]
    fn test_secret_validation() {
        let valid_data = SecretData::Password {
            password: "valid_password".to_string(),
        };
        assert!(valid_data.validate().is_ok());

        let invalid_data = SecretData::Password {
            password: "".to_string(),
        };
        assert!(invalid_data.validate().is_err());
    }
}
