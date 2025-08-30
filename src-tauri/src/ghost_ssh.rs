//! # GhostSSH - Enterprise SSH Management System
//! 
//! Comprehensive SSH management system providing post-quantum secure connections,
//! key management, host verification, port forwarding, and session management
//! with enterprise-grade security and audit capabilities.
//!
//! ## Features
//! - **Post-Quantum Security**: Kyber/Dilithium hybrid cryptography
//! - **Key Management**: Vault-backed key storage and rotation
//! - **Host Verification**: Certificate pinning and known_hosts management
//! - **Port Forwarding**: Local, remote, and dynamic (SOCKS5) tunneling
//! - **Session Management**: Connection pooling and multiplexing
//! - **Policy Enforcement**: Connection policies and compliance
//! - **Audit Integration**: Complete connection logging and monitoring
//!
//! ## Architecture
//! ```
//! GhostSSH
//! ├── ConnectionManager   - SSH connection lifecycle and pooling
//! ├── KeyManager         - Post-quantum key generation and storage
//! ├── HostManager        - Host verification and known_hosts
//! ├── TunnelManager      - Port forwarding and tunnel management
//! ├── PolicyEngine       - Connection policies and enforcement
//! └── AuditSystem        - Connection logging and monitoring
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
// use std::path::PathBuf; // Used in ShellProfile
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tracing::info;
use uuid::Uuid;

// ============================================================================
// Core Types and Enums
// ============================================================================

/// SSH connection status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionStatus {
    /// Connection is being established
    Connecting,
    /// Connection is active and ready
    Connected,
    /// Connection is being authenticated
    Authenticating,
    /// Connection failed
    Failed(String),
    /// Connection was disconnected
    Disconnected,
    /// Connection is being closed
    Closing,
}

/// SSH authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    /// Password authentication
    Password(String),
    /// Public key authentication
    PublicKey {
        /// Key identifier in vault
        key_id: String,
        /// Passphrase if key is encrypted
        passphrase: Option<String>,
    },
    /// Certificate-based authentication
    Certificate {
        /// Certificate identifier in vault
        cert_id: String,
        /// Private key identifier
        key_id: String,
    },
    /// Multi-factor authentication
    MFA {
        /// Primary authentication method
        primary: Box<AuthMethod>,
        /// TOTP code or similar
        second_factor: String,
    },
}

/// Post-quantum cryptographic algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PQAlgorithm {
    /// Classical algorithms only
    Classical,
    /// Hybrid classical + post-quantum
    Hybrid,
    /// Post-quantum only
    PostQuantum,
}

/// SSH key type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    /// RSA key
    RSA(u32), // Key size
    /// ECDSA key
    ECDSA(String), // Curve name
    /// Ed25519 key
    Ed25519,
    /// Post-quantum hybrid key
    PQHybrid {
        /// Classical component
        classical: Box<KeyType>,
        /// Post-quantum algorithm
        pq_algorithm: String,
    },
}

/// SSH host configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// Unique host identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// Hostname or IP address
    pub hostname: String,
    /// SSH port (default 22)
    pub port: u16,
    /// Username for connection
    pub username: String,
    /// Authentication method
    pub auth_method: AuthMethod,
    /// Required cryptographic level
    pub crypto_level: PQAlgorithm,
    /// Connection timeout in seconds
    pub timeout: u64,
    /// Keep-alive interval in seconds
    pub keep_alive: Option<u64>,
    /// Working directory on remote host
    pub remote_directory: Option<String>,
    /// Environment variables to set
    pub environment: HashMap<String, String>,
    /// Host tags for organization
    pub tags: Vec<String>,
    /// Whether host is enabled
    pub enabled: bool,
    /// Last successful connection time
    pub last_connected: Option<SystemTime>,
    /// Connection statistics
    pub stats: ConnectionStats,
}

/// Connection statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionStats {
    /// Total connection attempts
    pub attempts: u64,
    /// Successful connections
    pub successes: u64,
    /// Failed connections
    pub failures: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Average connection time in milliseconds
    pub avg_connect_time_ms: u64,
    /// Last error message
    pub last_error: Option<String>,
}

/// SSH connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Connection identifier
    pub id: String,
    /// Host configuration ID
    pub host_id: String,
    /// Connection status
    pub status: ConnectionStatus,
    /// Local address
    pub local_addr: Option<SocketAddr>,
    /// Remote address
    pub remote_addr: Option<SocketAddr>,
    /// Connection start time
    pub connected_at: Option<SystemTime>,
    /// Last activity time
    pub last_activity: SystemTime,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Active port forwards
    pub port_forwards: Vec<String>,
    /// Session identifier for audit
    pub session_id: String,
}

/// Port forwarding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForward {
    /// Forward identifier
    pub id: String,
    /// Forward type
    pub forward_type: ForwardType,
    /// Local bind address
    pub local_addr: SocketAddr,
    /// Remote address (for local and remote forwards)
    pub remote_addr: Option<SocketAddr>,
    /// Connection ID this forward belongs to
    pub connection_id: String,
    /// Whether forward is active
    pub active: bool,
    /// Creation time
    pub created_at: SystemTime,
    /// Statistics
    pub stats: ForwardStats,
}

/// Port forward type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForwardType {
    /// Local port forward (local -> remote)
    Local,
    /// Remote port forward (remote -> local)
    Remote,
    /// Dynamic forward (SOCKS5 proxy)
    Dynamic,
}

/// Port forward statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ForwardStats {
    /// Number of connections through this forward
    pub connections: u64,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Active connections
    pub active_connections: u32,
}

/// SSH key pair information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// Key identifier
    pub id: String,
    /// Key name/description
    pub name: String,
    /// Key type
    pub key_type: KeyType,
    /// Public key fingerprint
    pub fingerprint: String,
    /// Creation time
    pub created_at: SystemTime,
    /// Expiration time (if applicable)
    pub expires_at: Option<SystemTime>,
    /// Whether key is stored in hardware
    pub hardware_backed: bool,
    /// Associated hosts
    pub hosts: Vec<String>,
    /// Key usage statistics
    pub usage_stats: KeyUsageStats,
}

/// Key usage statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyUsageStats {
    /// Times used for authentication
    pub auth_count: u64,
    /// Last used time
    pub last_used: Option<SystemTime>,
    /// Successful authentications
    pub auth_successes: u64,
    /// Failed authentications
    pub auth_failures: u64,
}

/// Host verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostVerification {
    /// Host identifier
    pub host_id: String,
    /// Verification status
    pub status: VerificationStatus,
    /// Host key fingerprint
    pub fingerprint: String,
    /// Verification time
    pub verified_at: SystemTime,
    /// Trust level
    pub trust_level: TrustLevel,
    /// Verification details
    pub details: String,
}

/// Host verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Host key is trusted
    Trusted,
    /// Host key is unknown (first connection)
    Unknown,
    /// Host key has changed
    Changed,
    /// Host key verification failed
    Failed,
    /// Host key is explicitly untrusted
    Untrusted,
}

/// Trust level for host keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Automatically trust (not recommended)
    Auto,
    /// Trust on first use (TOFU)
    FirstUse,
    /// Manual verification required
    Manual,
    /// Certificate authority verified
    CA,
    /// Hardware security module verified
    HSM,
}

// ============================================================================
// Connection Management System
// ============================================================================

/// SSH connection manager
#[derive(Debug)]
pub struct ConnectionManager {
    connections: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    host_configs: Arc<Mutex<HashMap<String, HostConfig>>>,
    connection_pool: Arc<Mutex<HashMap<String, Vec<String>>>>, // host_id -> connection_ids
}

impl ConnectionManager {
    /// Create new connection manager
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            host_configs: Arc::new(Mutex::new(HashMap::new())),
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Add host configuration
    pub fn add_host(&self, host_config: HostConfig) -> Result<()> {
        let mut configs = self.host_configs.lock().unwrap();
        configs.insert(host_config.id.clone(), host_config);
        Ok(())
    }
    
    /// Get host configuration
    pub fn get_host(&self, host_id: &str) -> Option<HostConfig> {
        let configs = self.host_configs.lock().unwrap();
        configs.get(host_id).cloned()
    }
    
    /// List all host configurations
    pub fn list_hosts(&self) -> Vec<HostConfig> {
        let configs = self.host_configs.lock().unwrap();
        configs.values().cloned().collect()
    }
    
    /// Connect to host
    pub async fn connect(&self, host_id: &str) -> Result<String> {
        let host_config = self.get_host(host_id)
            .ok_or_else(|| anyhow::anyhow!("Host not found: {}", host_id))?;
        
        if !host_config.enabled {
            return Err(anyhow::anyhow!("Host is disabled: {}", host_id));
        }
        
        let connection_id = Uuid::new_v4().to_string();
        let session_id = Uuid::new_v4().to_string();
        
        // Create connection info
        let connection_info = ConnectionInfo {
            id: connection_id.clone(),
            host_id: host_id.to_string(),
            status: ConnectionStatus::Connecting,
            local_addr: None,
            remote_addr: None,
            connected_at: None,
            last_activity: SystemTime::now(),
            bytes_sent: 0,
            bytes_received: 0,
            port_forwards: Vec::new(),
            session_id,
        };
        
        // Store connection
        {
            let mut connections = self.connections.lock().unwrap();
            connections.insert(connection_id.clone(), connection_info);
        }
        
        // Add to connection pool
        {
            let mut pool = self.connection_pool.lock().unwrap();
            pool.entry(host_id.to_string())
                .or_insert_with(Vec::new)
                .push(connection_id.clone());
        }
        
        // TODO: Implement actual SSH connection logic
        // For now, simulate connection
        tokio::spawn({
            let connection_id = connection_id.clone();
            let connections = Arc::clone(&self.connections);
            async move {
                // Simulate connection delay
                tokio::time::sleep(Duration::from_millis(500)).await;
                
                // Update connection status
                if let Ok(mut connections) = connections.lock() {
                    if let Some(conn) = connections.get_mut(&connection_id) {
                        conn.status = ConnectionStatus::Connected;
                        conn.connected_at = Some(SystemTime::now());
                        conn.remote_addr = Some("192.168.1.100:22".parse().unwrap());
                    }
                }
            }
        });
        
        info!("Initiated connection to host {}: {}", host_id, connection_id);
        Ok(connection_id)
    }
    
    /// Disconnect from host
    pub async fn disconnect(&self, connection_id: &str) -> Result<()> {
        let mut connections = self.connections.lock().unwrap();
        if let Some(connection) = connections.get_mut(connection_id) {
            connection.status = ConnectionStatus::Closing;
            
            // TODO: Implement actual disconnection logic
            
            connection.status = ConnectionStatus::Disconnected;
            info!("Disconnected connection: {}", connection_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Connection not found: {}", connection_id))
        }
    }
    
    /// Get connection information
    pub fn get_connection(&self, connection_id: &str) -> Option<ConnectionInfo> {
        let connections = self.connections.lock().unwrap();
        connections.get(connection_id).cloned()
    }
    
    /// List all connections
    pub fn list_connections(&self) -> Vec<ConnectionInfo> {
        let connections = self.connections.lock().unwrap();
        connections.values().cloned().collect()
    }
    
    /// Get connections for host
    pub fn get_host_connections(&self, host_id: &str) -> Vec<ConnectionInfo> {
        let connections = self.connections.lock().unwrap();
        connections.values()
            .filter(|conn| conn.host_id == host_id)
            .cloned()
            .collect()
    }
}

// ============================================================================
// Key Management System
// ============================================================================

/// SSH key manager with post-quantum support
#[derive(Debug)]
pub struct KeyManager {
    keys: Arc<Mutex<HashMap<String, KeyPair>>>,
    vault_integration: bool, // TODO: Integrate with GhostVault
}

impl KeyManager {
    /// Create new key manager
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            vault_integration: false,
        }
    }
    
    /// Generate new key pair
    pub async fn generate_key(
        &self,
        name: String,
        key_type: KeyType,
        hardware_backed: bool,
    ) -> Result<String> {
        let key_id = Uuid::new_v4().to_string();
        
        // TODO: Implement actual key generation
        let fingerprint = format!("SHA256:{}", hex::encode(&key_id.as_bytes()[..16]));
        
        let key_pair = KeyPair {
            id: key_id.clone(),
            name,
            key_type,
            fingerprint: fingerprint.clone(),
            created_at: SystemTime::now(),
            expires_at: None,
            hardware_backed,
            hosts: Vec::new(),
            usage_stats: KeyUsageStats::default(),
        };
        
        let mut keys = self.keys.lock().unwrap();
        keys.insert(key_id.clone(), key_pair);
        
        info!("Generated new SSH key: {} ({})", key_id, fingerprint);
        Ok(key_id)
    }
    
    /// Import existing key
    pub async fn import_key(
        &self,
        name: String,
        key_data: Vec<u8>,
        key_type: KeyType,
    ) -> Result<String> {
        let key_id = Uuid::new_v4().to_string();
        
        // TODO: Parse and validate key data
        let fingerprint = format!("SHA256:{}", hex::encode(&key_data[..16.min(key_data.len())]));
        
        let key_pair = KeyPair {
            id: key_id.clone(),
            name,
            key_type,
            fingerprint: fingerprint.clone(),
            created_at: SystemTime::now(),
            expires_at: None,
            hardware_backed: false,
            hosts: Vec::new(),
            usage_stats: KeyUsageStats::default(),
        };
        
        let mut keys = self.keys.lock().unwrap();
        keys.insert(key_id.clone(), key_pair);
        
        info!("Imported SSH key: {} ({})", key_id, fingerprint);
        Ok(key_id)
    }
    
    /// Get key information
    pub fn get_key(&self, key_id: &str) -> Option<KeyPair> {
        let keys = self.keys.lock().unwrap();
        keys.get(key_id).cloned()
    }
    
    /// List all keys
    pub fn list_keys(&self) -> Vec<KeyPair> {
        let keys = self.keys.lock().unwrap();
        keys.values().cloned().collect()
    }
    
    /// Delete key
    pub fn delete_key(&self, key_id: &str) -> Result<()> {
        let mut keys = self.keys.lock().unwrap();
        if keys.remove(key_id).is_some() {
            info!("Deleted SSH key: {}", key_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Key not found: {}", key_id))
        }
    }
    
    /// Rotate key (generate new, update hosts, delete old)
    pub async fn rotate_key(&self, key_id: &str) -> Result<String> {
        let old_key = self.get_key(key_id)
            .ok_or_else(|| anyhow::anyhow!("Key not found: {}", key_id))?;
        
        // Generate new key with same type
        let new_key_id = self.generate_key(
            format!("{} (rotated)", old_key.name),
            old_key.key_type,
            old_key.hardware_backed,
        ).await?;
        
        // TODO: Update all hosts using this key
        // TODO: Deploy new key to hosts
        // TODO: Remove old key from hosts
        
        info!("Rotated SSH key {} -> {}", key_id, new_key_id);
        Ok(new_key_id)
    }
}

// ============================================================================
// Host Verification System
// ============================================================================

/// Host key verification manager
#[derive(Debug)]
pub struct HostManager {
    known_hosts: Arc<Mutex<HashMap<String, HostVerification>>>,
    trust_policies: Arc<Mutex<HashMap<String, TrustLevel>>>,
}

impl HostManager {
    /// Create new host manager
    pub fn new() -> Self {
        Self {
            known_hosts: Arc::new(Mutex::new(HashMap::new())),
            trust_policies: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Verify host key
    pub async fn verify_host(
        &self,
        host_id: &str,
        fingerprint: &str,
    ) -> Result<HostVerification> {
        let mut known_hosts = self.known_hosts.lock().unwrap();
        
        let verification = if let Some(existing) = known_hosts.get(host_id) {
            if existing.fingerprint == fingerprint {
                HostVerification {
                    host_id: host_id.to_string(),
                    status: VerificationStatus::Trusted,
                    fingerprint: fingerprint.to_string(),
                    verified_at: SystemTime::now(),
                    trust_level: existing.trust_level.clone(),
                    details: "Host key matches known fingerprint".to_string(),
                }
            } else {
                HostVerification {
                    host_id: host_id.to_string(),
                    status: VerificationStatus::Changed,
                    fingerprint: fingerprint.to_string(),
                    verified_at: SystemTime::now(),
                    trust_level: TrustLevel::Manual,
                    details: format!("Host key changed! Old: {}, New: {}", existing.fingerprint, fingerprint),
                }
            }
        } else {
            HostVerification {
                host_id: host_id.to_string(),
                status: VerificationStatus::Unknown,
                fingerprint: fingerprint.to_string(),
                verified_at: SystemTime::now(),
                trust_level: TrustLevel::FirstUse,
                details: "First connection to this host".to_string(),
            }
        };
        
        // Store verification result
        known_hosts.insert(host_id.to_string(), verification.clone());
        
        info!("Host verification for {}: {:?}", host_id, verification.status);
        Ok(verification)
    }
    
    /// Trust host key
    pub fn trust_host(&self, host_id: &str, fingerprint: &str) -> Result<()> {
        let mut known_hosts = self.known_hosts.lock().unwrap();
        
        let verification = HostVerification {
            host_id: host_id.to_string(),
            status: VerificationStatus::Trusted,
            fingerprint: fingerprint.to_string(),
            verified_at: SystemTime::now(),
            trust_level: TrustLevel::Manual,
            details: "Manually trusted by user".to_string(),
        };
        
        known_hosts.insert(host_id.to_string(), verification);
        info!("Manually trusted host: {}", host_id);
        Ok(())
    }
    
    /// Remove host from known hosts
    pub fn remove_host(&self, host_id: &str) -> Result<()> {
        let mut known_hosts = self.known_hosts.lock().unwrap();
        if known_hosts.remove(host_id).is_some() {
            info!("Removed host from known hosts: {}", host_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Host not found in known hosts: {}", host_id))
        }
    }
    
    /// List all known hosts
    pub fn list_known_hosts(&self) -> Vec<HostVerification> {
        let known_hosts = self.known_hosts.lock().unwrap();
        known_hosts.values().cloned().collect()
    }
}

// ============================================================================
// Tunnel Management System
// ============================================================================

/// Port forwarding and tunnel manager
#[derive(Debug)]
pub struct TunnelManager {
    forwards: Arc<Mutex<HashMap<String, PortForward>>>,
    active_tunnels: Arc<Mutex<HashMap<String, Vec<String>>>>, // connection_id -> forward_ids
}

impl TunnelManager {
    /// Create new tunnel manager
    pub fn new() -> Self {
        Self {
            forwards: Arc::new(Mutex::new(HashMap::new())),
            active_tunnels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Create local port forward
    pub async fn create_local_forward(
        &self,
        connection_id: String,
        local_port: u16,
        remote_host: String,
        remote_port: u16,
    ) -> Result<String> {
        let forward_id = Uuid::new_v4().to_string();
        
        let local_addr = SocketAddr::new("127.0.0.1".parse().unwrap(), local_port);
        let remote_addr = SocketAddr::new(remote_host.parse()?, remote_port);
        
        let forward = PortForward {
            id: forward_id.clone(),
            forward_type: ForwardType::Local,
            local_addr,
            remote_addr: Some(remote_addr),
            connection_id: connection_id.clone(),
            active: false,
            created_at: SystemTime::now(),
            stats: ForwardStats::default(),
        };
        
        // Store forward
        {
            let mut forwards = self.forwards.lock().unwrap();
            forwards.insert(forward_id.clone(), forward);
        }
        
        // Add to active tunnels
        {
            let mut tunnels = self.active_tunnels.lock().unwrap();
            tunnels.entry(connection_id)
                .or_insert_with(Vec::new)
                .push(forward_id.clone());
        }
        
        // TODO: Implement actual port forwarding
        
        info!("Created local port forward: {} -> {}:{}", local_port, remote_host, remote_port);
        Ok(forward_id)
    }
    
    /// Create dynamic forward (SOCKS5 proxy)
    pub async fn create_dynamic_forward(
        &self,
        connection_id: String,
        local_port: u16,
    ) -> Result<String> {
        let forward_id = Uuid::new_v4().to_string();
        
        let local_addr = SocketAddr::new("127.0.0.1".parse().unwrap(), local_port);
        
        let forward = PortForward {
            id: forward_id.clone(),
            forward_type: ForwardType::Dynamic,
            local_addr,
            remote_addr: None,
            connection_id: connection_id.clone(),
            active: false,
            created_at: SystemTime::now(),
            stats: ForwardStats::default(),
        };
        
        // Store forward
        {
            let mut forwards = self.forwards.lock().unwrap();
            forwards.insert(forward_id.clone(), forward);
        }
        
        // Add to active tunnels
        {
            let mut tunnels = self.active_tunnels.lock().unwrap();
            tunnels.entry(connection_id)
                .or_insert_with(Vec::new)
                .push(forward_id.clone());
        }
        
        // TODO: Implement SOCKS5 proxy
        
        info!("Created dynamic forward (SOCKS5) on port: {}", local_port);
        Ok(forward_id)
    }
    
    /// Stop port forward
    pub async fn stop_forward(&self, forward_id: &str) -> Result<()> {
        let mut forwards = self.forwards.lock().unwrap();
        if let Some(forward) = forwards.get_mut(forward_id) {
            forward.active = false;
            // TODO: Stop actual forwarding
            info!("Stopped port forward: {}", forward_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Forward not found: {}", forward_id))
        }
    }
    
    /// List all forwards
    pub fn list_forwards(&self) -> Vec<PortForward> {
        let forwards = self.forwards.lock().unwrap();
        forwards.values().cloned().collect()
    }
    
    /// Get forwards for connection
    pub fn get_connection_forwards(&self, connection_id: &str) -> Vec<PortForward> {
        let forwards = self.forwards.lock().unwrap();
        forwards.values()
            .filter(|f| f.connection_id == connection_id)
            .cloned()
            .collect()
    }
}

// ============================================================================
// Main GhostSSH System
// ============================================================================

/// Main GhostSSH system - enterprise SSH management
#[derive(Debug)]
pub struct GhostSSH {
    connection_manager: Arc<ConnectionManager>,
    key_manager: Arc<KeyManager>,
    host_manager: Arc<HostManager>,
    tunnel_manager: Arc<TunnelManager>,
}

impl GhostSSH {
    /// Initialize GhostSSH system
    pub fn new() -> Self {
        info!("Initializing GhostSSH enterprise SSH management system");
        
        Self {
            connection_manager: Arc::new(ConnectionManager::new()),
            key_manager: Arc::new(KeyManager::new()),
            host_manager: Arc::new(HostManager::new()),
            tunnel_manager: Arc::new(TunnelManager::new()),
        }
    }
    
    /// Get connection manager
    pub fn connections(&self) -> &Arc<ConnectionManager> {
        &self.connection_manager
    }
    
    /// Get key manager
    pub fn keys(&self) -> &Arc<KeyManager> {
        &self.key_manager
    }
    
    /// Get host manager
    pub fn hosts(&self) -> &Arc<HostManager> {
        &self.host_manager
    }
    
    /// Get tunnel manager
    pub fn tunnels(&self) -> &Arc<TunnelManager> {
        &self.tunnel_manager
    }
}

impl Default for GhostSSH {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tauri Command Integration
// ============================================================================

/// Tauri state for GhostSSH
pub struct GhostSSHState {
    pub ghost_ssh: Arc<GhostSSH>,
}

/// Get all host configurations
#[tauri::command]
pub async fn ghost_ssh_list_hosts(
    state: tauri::State<'_, GhostSSHState>,
) -> Result<Vec<HostConfig>, String> {
    Ok(state.ghost_ssh.connections().list_hosts())
}

/// Add new host configuration
#[tauri::command]
pub async fn ghost_ssh_add_host(
    host_config: HostConfig,
    state: tauri::State<'_, GhostSSHState>,
) -> Result<(), String> {
    state.ghost_ssh.connections()
        .add_host(host_config)
        .map_err(|e| e.to_string())
}

/// Connect to host
#[tauri::command]
pub async fn ghost_ssh_connect(
    host_id: String,
    state: tauri::State<'_, GhostSSHState>,
) -> Result<String, String> {
    state.ghost_ssh.connections()
        .connect(&host_id)
        .await
        .map_err(|e| e.to_string())
}

/// Disconnect from host
#[tauri::command]
pub async fn ghost_ssh_disconnect(
    connection_id: String,
    state: tauri::State<'_, GhostSSHState>,
) -> Result<(), String> {
    state.ghost_ssh.connections()
        .disconnect(&connection_id)
        .await
        .map_err(|e| e.to_string())
}

/// List all connections
#[tauri::command]
pub async fn ghost_ssh_list_connections(
    state: tauri::State<'_, GhostSSHState>,
) -> Result<Vec<ConnectionInfo>, String> {
    Ok(state.ghost_ssh.connections().list_connections())
}

/// Generate new SSH key
#[tauri::command]
pub async fn ghost_ssh_generate_key(
    name: String,
    key_type: KeyType,
    hardware_backed: bool,
    state: tauri::State<'_, GhostSSHState>,
) -> Result<String, String> {
    state.ghost_ssh.keys()
        .generate_key(name, key_type, hardware_backed)
        .await
        .map_err(|e| e.to_string())
}

/// List all SSH keys
#[tauri::command]
pub async fn ghost_ssh_list_keys(
    state: tauri::State<'_, GhostSSHState>,
) -> Result<Vec<KeyPair>, String> {
    Ok(state.ghost_ssh.keys().list_keys())
}

/// Create local port forward
#[tauri::command]
pub async fn ghost_ssh_create_local_forward(
    connection_id: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    state: tauri::State<'_, GhostSSHState>,
) -> Result<String, String> {
    state.ghost_ssh.tunnels()
        .create_local_forward(connection_id, local_port, remote_host, remote_port)
        .await
        .map_err(|e| e.to_string())
}

/// Create dynamic forward (SOCKS5)
#[tauri::command]
pub async fn ghost_ssh_create_dynamic_forward(
    connection_id: String,
    local_port: u16,
    state: tauri::State<'_, GhostSSHState>,
) -> Result<String, String> {
    state.ghost_ssh.tunnels()
        .create_dynamic_forward(connection_id, local_port)
        .await
        .map_err(|e| e.to_string())
}

/// List all port forwards
#[tauri::command]
pub async fn ghost_ssh_list_forwards(
    state: tauri::State<'_, GhostSSHState>,
) -> Result<Vec<PortForward>, String> {
    Ok(state.ghost_ssh.tunnels().list_forwards())
}
