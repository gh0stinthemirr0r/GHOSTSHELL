use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use rand::Rng;
use crate::{VaultError, Result};

/// Multi-Factor Authentication manager
#[derive(Debug, Clone)]
pub struct MfaManager {
    config: MfaConfig,
}

/// MFA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub enabled: bool,
    pub required_methods: Vec<MfaMethod>,
    pub backup_codes_count: u32,
    pub totp_window: u32, // Time window in seconds for TOTP validation
    pub session_timeout_minutes: u32,
}

/// Available MFA methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MfaMethod {
    Totp,        // Time-based One-Time Password
    BackupCode,  // Static backup codes
    Yubikey,     // Hardware security key (future)
    Biometric,   // Fingerprint/face recognition (future)
}

/// MFA setup data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSetup {
    pub method: MfaMethod,
    pub secret: Option<String>,      // TOTP secret
    pub backup_codes: Vec<String>,   // Backup codes
    pub qr_code: Option<Vec<u8>>,    // QR code image for TOTP setup
    pub created_at: DateTime<Utc>,
}

/// MFA verification request
#[derive(Debug, Clone)]
pub struct MfaChallenge {
    pub method: MfaMethod,
    pub code: String,
    pub timestamp: DateTime<Utc>,
}

/// MFA session tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSession {
    pub session_id: String,
    pub user_id: String,
    pub verified_methods: Vec<MfaMethod>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_verified: DateTime<Utc>,
}

impl MfaManager {
    /// Create new MFA manager with configuration
    pub fn new(config: MfaConfig) -> Self {
        Self { config }
    }

    /// Create default MFA configuration
    pub fn default_config() -> MfaConfig {
        MfaConfig {
            enabled: true,
            required_methods: vec![MfaMethod::Totp],
            backup_codes_count: 10,
            totp_window: 30,
            session_timeout_minutes: 30,
        }
    }

    /// Setup TOTP for a user
    pub fn setup_totp(&self, user_id: &str, issuer: &str) -> Result<MfaSetup> {
        use totp_rs::{Algorithm, TOTP, Secret};
        
        // Generate random secret
        let secret = Secret::Raw(rand::thread_rng().gen::<[u8; 20]>().to_vec());
        let secret_str = secret.to_encoded().to_string();
        
        // Create TOTP instance
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,  // 6 digits
            1,  // 1 step
            30, // 30 second window
            secret.to_bytes().unwrap(),
        ).map_err(|e| VaultError::InvalidInput(format!("TOTP setup failed: {}", e)))?;

        // Generate QR code
        let qr_code = self.generate_qr_code(&totp)?;
        
        // Generate backup codes
        let backup_codes = self.generate_backup_codes()?;

        Ok(MfaSetup {
            method: MfaMethod::Totp,
            secret: Some(secret_str),
            backup_codes,
            qr_code: Some(qr_code),
            created_at: Utc::now(),
        })
    }

    /// Verify TOTP code
    pub fn verify_totp(&self, secret: &str, code: &str) -> Result<bool> {
        use totp_rs::{Algorithm, TOTP, Secret};
        
        let secret_bytes = Secret::Encoded(secret.to_string())
            .to_bytes()
            .map_err(|e| VaultError::InvalidInput(format!("Invalid TOTP secret: {}", e)))?;
        
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
        ).map_err(|e| VaultError::InvalidInput(format!("TOTP creation failed: {}", e)))?;

        let is_valid = totp.check_current(code)
            .map_err(|e| VaultError::MfaFailed)?;
        
        Ok(is_valid)
    }

    /// Verify backup code
    pub fn verify_backup_code(&self, backup_codes: &[String], code: &str) -> Result<bool> {
        // Use constant-time comparison to prevent timing attacks
        let code_hash = self.hash_backup_code(code)?;
        
        for stored_code in backup_codes {
            if self.constant_time_compare(&code_hash, stored_code) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    /// Process MFA challenge
    pub fn verify_challenge(&self, challenge: &MfaChallenge, setup: &MfaSetup) -> Result<bool> {
        // Check if challenge is recent (prevent replay attacks)
        let now = Utc::now();
        let max_age = Duration::seconds(self.config.totp_window as i64);
        
        if now - challenge.timestamp > max_age {
            return Err(VaultError::MfaFailed);
        }

        match challenge.method {
            MfaMethod::Totp => {
                let secret = setup.secret.as_ref()
                    .ok_or_else(|| VaultError::InvalidInput("No TOTP secret configured".to_string()))?;
                self.verify_totp(secret, &challenge.code)
            }
            MfaMethod::BackupCode => {
                self.verify_backup_code(&setup.backup_codes, &challenge.code)
            }
            _ => Err(VaultError::InvalidInput(format!("Unsupported MFA method: {:?}", challenge.method))),
        }
    }

    /// Create MFA session after successful verification
    pub fn create_session(&self, user_id: &str, verified_method: MfaMethod) -> Result<MfaSession> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::minutes(self.config.session_timeout_minutes as i64);

        Ok(MfaSession {
            session_id,
            user_id: user_id.to_string(),
            verified_methods: vec![verified_method],
            created_at: now,
            expires_at,
            last_verified: now,
        })
    }

    /// Validate existing MFA session
    pub fn validate_session(&self, session: &MfaSession) -> Result<bool> {
        let now = Utc::now();
        
        // Check if session is expired
        if now > session.expires_at {
            return Ok(false);
        }

        // Check if all required methods are verified
        for required_method in &self.config.required_methods {
            if !session.verified_methods.contains(required_method) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Refresh MFA session (extend expiration)
    pub fn refresh_session(&self, session: &mut MfaSession) -> Result<()> {
        let now = Utc::now();
        session.expires_at = now + Duration::minutes(self.config.session_timeout_minutes as i64);
        session.last_verified = now;
        Ok(())
    }

    /// Generate backup codes
    fn generate_backup_codes(&self) -> Result<Vec<String>> {
        use rand::Rng;
        let mut codes = Vec::new();
        let mut rng = rand::thread_rng();
        
        for _ in 0..self.config.backup_codes_count {
            // Generate 8-digit backup code
            let code = format!("{:08}", rng.gen_range(10000000..99999999));
            let hashed_code = self.hash_backup_code(&code)?;
            codes.push(hashed_code);
        }
        
        Ok(codes)
    }

    /// Hash backup code for secure storage
    fn hash_backup_code(&self, code: &str) -> Result<String> {
        use argon2::{Argon2, PasswordHasher};
        use argon2::password_hash::{PasswordHash, SaltString, rand_core::OsRng};
        
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2.hash_password(code.as_bytes(), &salt)
            .map_err(|e| VaultError::EncryptionError(format!("Backup code hashing failed: {}", e)))?;
        
        Ok(password_hash.to_string())
    }

    /// Constant-time string comparison
    fn constant_time_compare(&self, a: &str, b: &str) -> bool {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        use argon2::Argon2;
        
        if let (Ok(hash_a), Ok(hash_b)) = (PasswordHash::new(a), PasswordHash::new(b)) {
            let argon2 = Argon2::default();
            argon2.verify_password(a.as_bytes(), &hash_b).is_ok()
        } else {
            false
        }
    }

    /// Generate QR code for TOTP setup
    fn generate_qr_code(&self, totp: &totp_rs::TOTP) -> Result<Vec<u8>> {
        use qrcode::QrCode;
        use image::{ImageBuffer, Rgb};
        
        let url = format!("otpauth://totp/GHOSTSHELL:user?secret={}&issuer=GHOSTSHELL", 
                         totp.get_secret_base32());
        let qr_code = QrCode::new(&url)
            .map_err(|e| VaultError::InvalidInput(format!("QR code generation failed: {}", e)))?;
        
        // Convert to simple string representation for now
        // In a real implementation, you'd want proper QR code image generation
        let qr_string = qr_code.render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        
        // For demo purposes, return the URL as bytes
        let png_bytes = url.as_bytes().to_vec();
        
        Ok(png_bytes)
    }

    /// Check if MFA is required for the current configuration
    pub fn is_required(&self) -> bool {
        self.config.enabled && !self.config.required_methods.is_empty()
    }

    /// Get required MFA methods
    pub fn required_methods(&self) -> &[MfaMethod] {
        &self.config.required_methods
    }

    /// Update MFA configuration
    pub fn update_config(&mut self, config: MfaConfig) {
        self.config = config;
    }
}

/// MFA challenge builder
pub struct MfaChallengeBuilder {
    method: Option<MfaMethod>,
    code: Option<String>,
}

impl MfaChallengeBuilder {
    pub fn new() -> Self {
        Self {
            method: None,
            code: None,
        }
    }

    pub fn method(mut self, method: MfaMethod) -> Self {
        self.method = Some(method);
        self
    }

    pub fn code(mut self, code: String) -> Self {
        self.code = Some(code);
        self
    }

    pub fn build(self) -> Result<MfaChallenge> {
        let method = self.method.ok_or_else(|| VaultError::InvalidInput("MFA method required".to_string()))?;
        let code = self.code.ok_or_else(|| VaultError::InvalidInput("MFA code required".to_string()))?;

        Ok(MfaChallenge {
            method,
            code,
            timestamp: Utc::now(),
        })
    }
}

impl Default for MfaChallengeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_manager_creation() {
        let config = MfaManager::default_config();
        let manager = MfaManager::new(config);
        
        assert!(manager.is_required());
        assert_eq!(manager.required_methods(), &[MfaMethod::Totp]);
    }

    #[test]
    fn test_totp_setup() {
        let config = MfaManager::default_config();
        let manager = MfaManager::new(config);
        
        let setup = manager.setup_totp("test@example.com", "GHOSTSHELL").unwrap();
        
        assert_eq!(setup.method, MfaMethod::Totp);
        assert!(setup.secret.is_some());
        assert!(!setup.backup_codes.is_empty());
        assert!(setup.qr_code.is_some());
    }

    #[test]
    fn test_mfa_session() {
        let config = MfaManager::default_config();
        let manager = MfaManager::new(config);
        
        let session = manager.create_session("user123", MfaMethod::Totp).unwrap();
        
        assert_eq!(session.user_id, "user123");
        assert!(session.verified_methods.contains(&MfaMethod::Totp));
        assert!(manager.validate_session(&session).unwrap());
    }

    #[test]
    fn test_challenge_builder() {
        let challenge = MfaChallengeBuilder::new()
            .method(MfaMethod::Totp)
            .code("123456".to_string())
            .build()
            .unwrap();
        
        assert_eq!(challenge.method, MfaMethod::Totp);
        assert_eq!(challenge.code, "123456");
    }

    #[test]
    fn test_backup_code_generation() {
        let config = MfaManager::default_config();
        let manager = MfaManager::new(config);
        
        let codes = manager.generate_backup_codes().unwrap();
        
        assert_eq!(codes.len(), 10);
        for code in codes {
            assert!(!code.is_empty());
        }
    }
}
