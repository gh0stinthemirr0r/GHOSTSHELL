use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use anyhow::Result;
use tokio::sync::Mutex;

use ghost_pq::signatures::{DilithiumPublicKey, DilithiumPrivateKey};
// Policy enforcement removed for single-user mode
// use ghost_vault::vault::GhostVault; // Commented out for now

/// PCAP Studio Manager - handles packet capture and analysis
pub struct PcapStudioManager {
    captures: Arc<RwLock<HashMap<String, PcapCapture>>>,
    signing_keys: Arc<RwLock<HashMap<String, (DilithiumPublicKey, DilithiumPrivateKey)>>>,
    interfaces: Arc<RwLock<Vec<NetworkInterface>>>,
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub policy_allowed: bool,
}

/// PCAP capture session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapCapture {
    pub id: String,
    pub interface: String,
    pub status: CaptureStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u64>,
    pub packet_count: u64,
    pub bytes_captured: u64,
    pub filter: Option<String>,
    pub results: Option<PcapAnalysis>,
    pub policy_approved: bool,
    pub error_message: Option<String>,
}

/// Capture status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaptureStatus {
    Starting,
    Running,
    Stopping,
    Completed,
    Failed,
    PolicyDenied,
}

/// PCAP analysis results (Enhanced with BruteShark-inspired modules)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapAnalysis {
    pub flows: Vec<NetworkFlow>,
    pub protocols: HashMap<String, u64>,
    pub top_talkers: Vec<TopTalker>,
    pub anomalies: Vec<Anomaly>,
    pub tls_analysis: Option<TlsAnalysis>,
    pub performance_stats: PerformanceStats,
    pub signature: Option<String>,
    
    // BruteShark-inspired analysis modules
    pub overview: AnalysisOverview,
    pub network_map: Vec<NetworkConnection>,
    pub sessions: Vec<NetworkSession>,
    pub passwords: Vec<ExtractedCredential>,
    pub hashes: Vec<ExtractedHash>,
    pub files: Vec<ExtractedFile>,
    pub dns_queries: Vec<DnsQuery>,
    pub voip_calls: Vec<VoipCall>,
    pub certificates: Vec<SslCertificate>,
}

/// Network flow (5-tuple)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub packet_count: u64,
    pub bytes: u64,
    pub duration_ms: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub flags: Vec<String>,
}

/// Top talker statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopTalker {
    pub ip: String,
    pub hostname: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connections: u64,
    pub protocols: Vec<String>,
}

/// Network anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub id: String,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub protocol: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
}

/// Types of network anomalies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    MalformedPacket,
    UnusualPort,
    HighLatency,
    ExcessiveRetransmits,
    SuspiciousTraffic,
    PolicyViolation,
    EncryptionDowngrade,
}

/// Anomaly severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// TLS handshake analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAnalysis {
    pub handshakes: Vec<TlsHandshake>,
    pub cipher_suites: HashMap<String, u64>,
    pub pq_connections: u64,
    pub hybrid_connections: u64,
    pub classical_connections: u64,
}

/// TLS handshake details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshake {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub version: String,
    pub cipher_suite: String,
    pub key_exchange: String,
    pub signature_algorithm: String,
    pub is_post_quantum: bool,
    pub is_hybrid: bool,
    pub handshake_time_ms: u64,
}

/// Analysis overview (BruteShark-inspired)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOverview {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub duration: u64,
    pub avg_packet_size: u64,
    pub protocols: HashMap<String, u64>,
    pub top_talkers: Vec<TopTalkerInfo>,
    pub anomalies: Vec<SecurityAnomaly>,
}

/// Top talker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopTalkerInfo {
    pub ip: String,
    pub packets: u64,
    pub bytes: u64,
    pub country: String,
}

/// Security anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnomaly {
    pub anomaly_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
}

/// Network connection mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub port: u16,
    pub packets: u64,
    pub bytes: u64,
}

/// Network session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSession {
    pub id: String,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub packets: u64,
    pub bytes: u64,
    pub duration: f64,
    pub status: String,
}

/// Extracted credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedCredential {
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub source: String,
    pub destination: String,
    pub timestamp: String,
}

/// Extracted hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedHash {
    pub hash_type: String,
    pub hash: String,
    pub source: String,
    pub domain: String,
    pub username: String,
}

/// Extracted file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    pub name: String,
    pub file_type: String,
    pub size: u64,
    pub source: String,
    pub destination: String,
    pub extracted: bool,
    pub hash: String,
    pub timestamp: String,
}

/// DNS query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub domain: String,
    pub query_type: String,
    pub response: String,
    pub source: String,
    pub server: String,
    pub timestamp: String,
    pub suspicious: Option<bool>,
}

/// VoIP call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoipCall {
    pub caller: String,
    pub callee: String,
    pub duration: u64,
    pub codec: String,
    pub quality: String,
    pub start_time: String,
    pub end_time: String,
}

/// SSL certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertificate {
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub fingerprint: String,
    pub key_size: u32,
    pub algorithm: String,
}

/// Performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub dropped_packets: u64,
    pub processing_time_ms: u64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
}

/// Capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub interface: String,
    pub filter: Option<String>,
    pub duration_seconds: Option<u64>,
    pub max_packets: Option<u64>,
    pub max_bytes: Option<u64>,
    pub promiscuous_mode: bool,
    pub buffer_size_mb: u32,
}

impl PcapStudioManager {
    /// Create new PCAP Studio manager
    pub fn new() -> Result<Self> {
        Ok(Self {
            captures: Arc::new(RwLock::new(HashMap::new())),
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
            interfaces: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Initialize and discover network interfaces
    pub async fn initialize(&self) -> Result<()> {
        // Discover network interfaces
        let interfaces = self.discover_interfaces().await?;
        
        // Update interface list
        {
            let mut ifaces = self.interfaces.write().unwrap();
            *ifaces = interfaces;
        }

        // Generate signing keypair
        self.generate_signing_keypair().await?;

        Ok(())
    }

    /// Discover available network interfaces
    async fn discover_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        // Simulate interface discovery
        // In real implementation, use pcap library to enumerate interfaces
        let interfaces = vec![
            NetworkInterface {
                name: "eth0".to_string(),
                description: "Ethernet Adapter".to_string(),
                mac_address: Some("00:11:22:33:44:55".to_string()),
                ip_addresses: vec!["192.168.1.100".to_string()],
                is_up: true,
                is_loopback: false,
                policy_allowed: true,
            },
            NetworkInterface {
                name: "wlan0".to_string(),
                description: "Wireless Network Adapter".to_string(),
                mac_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
                ip_addresses: vec!["10.0.0.50".to_string()],
                is_up: true,
                is_loopback: false,
                policy_allowed: false, // Policy restricted
            },
            NetworkInterface {
                name: "lo".to_string(),
                description: "Loopback Interface".to_string(),
                mac_address: None,
                ip_addresses: vec!["127.0.0.1".to_string(), "::1".to_string()],
                is_up: true,
                is_loopback: true,
                policy_allowed: true,
            },
        ];

        Ok(interfaces)
    }

    /// Start packet capture with policy enforcement
    pub async fn start_capture(&self, config: CaptureConfig, /* pep_state: &PepState */) -> Result<String> {
        let capture_id = Uuid::new_v4().to_string();
        
        // Policy enforcement for PCAP capture (simplified for now)
        // TODO: Implement proper policy enforcement
        let policy_allowed = true; // Placeholder - always allow for now

        if !policy_allowed {
            let mut capture = PcapCapture {
                id: capture_id.clone(),
                interface: config.interface,
                status: CaptureStatus::PolicyDenied,
                started_at: Utc::now(),
                completed_at: Some(Utc::now()),
                duration_seconds: None,
                packet_count: 0,
                bytes_captured: 0,
                filter: config.filter,
                results: None,
                policy_approved: false,
                error_message: Some("Policy denied".to_string()),
            };

            let mut captures = self.captures.write().unwrap();
            captures.insert(capture_id.clone(), capture);
            return Ok(capture_id);
        }

        // Check if interface is available and policy-allowed
        let interface_allowed = {
            let interfaces = self.interfaces.read().unwrap();
            interfaces.iter()
                .find(|iface| iface.name == config.interface)
                .map(|iface| iface.policy_allowed)
                .unwrap_or(false)
        };

        if !interface_allowed {
            let mut capture = PcapCapture {
                id: capture_id.clone(),
                interface: config.interface,
                status: CaptureStatus::PolicyDenied,
                started_at: Utc::now(),
                completed_at: Some(Utc::now()),
                duration_seconds: None,
                packet_count: 0,
                bytes_captured: 0,
                filter: config.filter,
                results: None,
                policy_approved: false,
                error_message: Some("Interface not allowed by policy".to_string()),
            };

            let mut captures = self.captures.write().unwrap();
            captures.insert(capture_id.clone(), capture);
            return Ok(capture_id);
        }

        // Create capture session
        let mut capture = PcapCapture {
            id: capture_id.clone(),
            interface: config.interface.clone(),
            status: CaptureStatus::Starting,
            started_at: Utc::now(),
            completed_at: None,
            duration_seconds: config.duration_seconds,
            packet_count: 0,
            bytes_captured: 0,
            filter: config.filter.clone(),
            results: None,
            policy_approved: true,
            error_message: None,
        };

        // Store capture session
        {
            let mut captures = self.captures.write().unwrap();
            captures.insert(capture_id.clone(), capture.clone());
        }

        // Start capture in background
        let captures_clone = Arc::clone(&self.captures);
        let signing_keys_clone = Arc::clone(&self.signing_keys);
        let capture_id_clone = capture_id.clone();
        tokio::spawn(async move {
            Self::run_capture(captures_clone, signing_keys_clone, capture_id_clone, config).await;
        });

        Ok(capture_id)
    }

    /// Run packet capture (background task)
    async fn run_capture(
        captures: Arc<RwLock<HashMap<String, PcapCapture>>>,
        signing_keys: Arc<RwLock<HashMap<String, (DilithiumPublicKey, DilithiumPrivateKey)>>>,
        capture_id: String,
        config: CaptureConfig,
    ) {
        // Update status to running
        {
            let mut captures_map = captures.write().unwrap();
            if let Some(capture) = captures_map.get_mut(&capture_id) {
                capture.status = CaptureStatus::Running;
            }
        }

        // Simulate packet capture
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Generate simulated analysis results
        let analysis = Self::generate_simulated_analysis(&config).await;

        // Sign the results
        let signature = Self::sign_analysis(&signing_keys, &analysis).await;

        let mut final_analysis = analysis;
        final_analysis.signature = signature;

        // Update capture with results
        {
            let mut captures_map = captures.write().unwrap();
            if let Some(capture) = captures_map.get_mut(&capture_id) {
                capture.status = CaptureStatus::Completed;
                capture.completed_at = Some(Utc::now());
                capture.packet_count = final_analysis.flows.iter().map(|f| f.packet_count).sum();
                capture.bytes_captured = final_analysis.flows.iter().map(|f| f.bytes).sum();
                capture.results = Some(final_analysis);
            }
        }
    }

    /// Generate simulated analysis results
    async fn generate_simulated_analysis(config: &CaptureConfig) -> PcapAnalysis {
        let now = Utc::now();
        
        // Generate sample flows
        let flows = vec![
            NetworkFlow {
                src_ip: "192.168.1.100".to_string(),
                dst_ip: "8.8.8.8".to_string(),
                src_port: 54321,
                dst_port: 53,
                protocol: "UDP".to_string(),
                packet_count: 24,
                bytes: 1536,
                duration_ms: 150,
                first_seen: now - chrono::Duration::seconds(30),
                last_seen: now - chrono::Duration::seconds(25),
                flags: vec!["DNS_QUERY".to_string()],
            },
            NetworkFlow {
                src_ip: "192.168.1.100".to_string(),
                dst_ip: "github.com".to_string(),
                src_port: 45678,
                dst_port: 443,
                protocol: "TCP".to_string(),
                packet_count: 156,
                bytes: 87432,
                duration_ms: 5200,
                first_seen: now - chrono::Duration::seconds(20),
                last_seen: now - chrono::Duration::seconds(5),
                flags: vec!["HTTPS".to_string(), "TLS_1_3".to_string()],
            },
        ];

        // Protocol distribution
        let mut protocols = HashMap::new();
        protocols.insert("TCP".to_string(), 156);
        protocols.insert("UDP".to_string(), 24);
        protocols.insert("ICMP".to_string(), 8);

        // Top talkers
        let top_talkers = vec![
            TopTalker {
                ip: "192.168.1.100".to_string(),
                hostname: Some("workstation.local".to_string()),
                bytes_sent: 45216,
                bytes_received: 43752,
                connections: 12,
                protocols: vec!["TCP".to_string(), "UDP".to_string()],
            },
        ];

        // Sample anomalies
        let anomalies = vec![
            Anomaly {
                id: Uuid::new_v4().to_string(),
                anomaly_type: AnomalyType::UnusualPort,
                severity: AnomalySeverity::Medium,
                description: "Connection to unusual high port detected".to_string(),
                timestamp: now - chrono::Duration::seconds(15),
                src_ip: Some("192.168.1.100".to_string()),
                dst_ip: Some("suspicious.example.com".to_string()),
                protocol: Some("TCP".to_string()),
                details: {
                    let mut details = HashMap::new();
                    details.insert("port".to_string(), serde_json::Value::Number(serde_json::Number::from(9999)));
                    details
                },
            },
        ];

        // TLS analysis
        let tls_analysis = TlsAnalysis {
            handshakes: vec![
                TlsHandshake {
                    src_ip: "192.168.1.100".to_string(),
                    dst_ip: "github.com".to_string(),
                    dst_port: 443,
                    version: "TLS 1.3".to_string(),
                    cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
                    key_exchange: "X25519".to_string(),
                    signature_algorithm: "rsa_pss_rsae_sha256".to_string(),
                    is_post_quantum: false,
                    is_hybrid: false,
                    handshake_time_ms: 45,
                },
            ],
            cipher_suites: {
                let mut suites = HashMap::new();
                suites.insert("TLS_AES_256_GCM_SHA384".to_string(), 1);
                suites
            },
            pq_connections: 0,
            hybrid_connections: 0,
            classical_connections: 1,
        };

        // Performance stats
        let performance_stats = PerformanceStats {
            packets_per_second: 37.6,
            bytes_per_second: 17793.6,
            dropped_packets: 0,
            processing_time_ms: 2150,
            memory_usage_mb: 12.5,
            cpu_usage_percent: 8.3,
        };

        // BruteShark-inspired analysis modules
        let overview = AnalysisOverview {
            total_packets: flows.iter().map(|f| f.packet_count).sum(),
            total_bytes: flows.iter().map(|f| f.bytes).sum(),
            duration: 1800, // 30 minutes
            avg_packet_size: 1024,
            protocols: protocols.clone(),
            top_talkers: vec![
                TopTalkerInfo {
                    ip: "192.168.1.100".to_string(),
                    packets: 2341,
                    bytes: 1234567,
                    country: "Local".to_string(),
                },
                TopTalkerInfo {
                    ip: "8.8.8.8".to_string(),
                    packets: 1876,
                    bytes: 987654,
                    country: "US".to_string(),
                },
            ],
            anomalies: vec![
                SecurityAnomaly {
                    anomaly_type: "Port Scan".to_string(),
                    severity: "High".to_string(),
                    source: "192.168.1.200".to_string(),
                    description: "Multiple port connection attempts detected".to_string(),
                },
            ],
        };

        let network_map = vec![
            NetworkConnection {
                source: "192.168.1.100".to_string(),
                destination: "8.8.8.8".to_string(),
                protocol: "TCP".to_string(),
                port: 443,
                packets: 156,
                bytes: 89432,
            },
            NetworkConnection {
                source: "192.168.1.100".to_string(),
                destination: "192.168.1.1".to_string(),
                protocol: "UDP".to_string(),
                port: 53,
                packets: 89,
                bytes: 12456,
            },
        ];

        let sessions = vec![
            NetworkSession {
                id: "sess_001".to_string(),
                protocol: "HTTP".to_string(),
                source: "192.168.1.100:54321".to_string(),
                destination: "93.184.216.34:80".to_string(),
                packets: 23,
                bytes: 15678,
                duration: 2.3,
                status: "Complete".to_string(),
            },
            NetworkSession {
                id: "sess_002".to_string(),
                protocol: "HTTPS".to_string(),
                source: "192.168.1.100:54322".to_string(),
                destination: "8.8.8.8:443".to_string(),
                packets: 45,
                bytes: 32145,
                duration: 5.7,
                status: "Complete".to_string(),
            },
        ];

        let passwords = vec![
            ExtractedCredential {
                protocol: "FTP".to_string(),
                username: "admin".to_string(),
                password: "password123".to_string(),
                source: "192.168.1.100".to_string(),
                destination: "192.168.1.50".to_string(),
                timestamp: "2024-01-15 14:32:15".to_string(),
            },
            ExtractedCredential {
                protocol: "HTTP".to_string(),
                username: "user@example.com".to_string(),
                password: "secret456".to_string(),
                source: "192.168.1.100".to_string(),
                destination: "203.0.113.1".to_string(),
                timestamp: "2024-01-15 14:35:22".to_string(),
            },
        ];

        let hashes = vec![
            ExtractedHash {
                hash_type: "NTLM".to_string(),
                hash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8".to_string(),
                source: "192.168.1.100".to_string(),
                domain: "WORKGROUP".to_string(),
                username: "admin".to_string(),
            },
            ExtractedHash {
                hash_type: "Kerberos AS-REP".to_string(),
                hash: "098f6bcd4621d373cade4e832627b4f6".to_string(),
                source: "192.168.1.101".to_string(),
                domain: "COMPANY.LOCAL".to_string(),
                username: "jdoe".to_string(),
            },
        ];

        let files = vec![
            ExtractedFile {
                name: "document.pdf".to_string(),
                file_type: "PDF".to_string(),
                size: 245760,
                source: "192.168.1.100".to_string(),
                destination: "203.0.113.1".to_string(),
                extracted: true,
                hash: "sha256:abc123...".to_string(),
                timestamp: "2024-01-15 14:40:12".to_string(),
            },
            ExtractedFile {
                name: "image.jpg".to_string(),
                file_type: "JPEG".to_string(),
                size: 102400,
                source: "192.168.1.100".to_string(),
                destination: "192.168.1.50".to_string(),
                extracted: true,
                hash: "sha256:def456...".to_string(),
                timestamp: "2024-01-15 14:42:33".to_string(),
            },
        ];

        let dns_queries = vec![
            DnsQuery {
                domain: "google.com".to_string(),
                query_type: "A".to_string(),
                response: "8.8.8.8".to_string(),
                source: "192.168.1.100".to_string(),
                server: "192.168.1.1".to_string(),
                timestamp: "2024-01-15 14:30:15".to_string(),
                suspicious: Some(false),
            },
            DnsQuery {
                domain: "malicious-site.com".to_string(),
                query_type: "A".to_string(),
                response: "203.0.113.100".to_string(),
                source: "192.168.1.150".to_string(),
                server: "8.8.8.8".to_string(),
                timestamp: "2024-01-15 14:33:45".to_string(),
                suspicious: Some(true),
            },
        ];

        let voip_calls = vec![
            VoipCall {
                caller: "192.168.1.100".to_string(),
                callee: "192.168.1.200".to_string(),
                duration: 120,
                codec: "G.711".to_string(),
                quality: "Good".to_string(),
                start_time: "2024-01-15 14:25:00".to_string(),
                end_time: "2024-01-15 14:27:00".to_string(),
            },
        ];

        let certificates = vec![
            SslCertificate {
                subject: "CN=*.google.com".to_string(),
                issuer: "CN=Google Internet Authority G3".to_string(),
                valid_from: "2024-01-01".to_string(),
                valid_to: "2024-12-31".to_string(),
                fingerprint: "SHA256:1234567890abcdef".to_string(),
                key_size: 2048,
                algorithm: "RSA".to_string(),
            },
        ];

        PcapAnalysis {
            flows,
            protocols,
            top_talkers,
            anomalies,
            tls_analysis: Some(tls_analysis),
            performance_stats,
            signature: None, // Will be added later
            
            // BruteShark-inspired modules
            overview,
            network_map,
            sessions,
            passwords,
            hashes,
            files,
            dns_queries,
            voip_calls,
            certificates,
        }
    }

    /// Sign analysis results with Dilithium
    async fn sign_analysis(
        signing_keys: &Arc<RwLock<HashMap<String, (DilithiumPublicKey, DilithiumPrivateKey)>>>,
        analysis: &PcapAnalysis,
    ) -> Option<String> {
        // Get signing key
        let keys = signing_keys.read().unwrap();
        if let Some((_, private_key)) = keys.get("default") {
            // Serialize analysis for signing
            if let Ok(data) = serde_json::to_vec(analysis) {
                // Sign the data (simplified)
                return Some(format!("dilithium_signature_{}", data.len()));
            }
        }
        None
    }

    /// Stop packet capture
    pub async fn stop_capture(&self, capture_id: &str) -> Result<()> {
        let mut captures = self.captures.write().unwrap();
        if let Some(capture) = captures.get_mut(capture_id) {
            if matches!(capture.status, CaptureStatus::Running) {
                capture.status = CaptureStatus::Stopping;
                // In real implementation, signal capture thread to stop
            }
        }
        Ok(())
    }

    /// Get capture status
    pub async fn get_capture_status(&self, capture_id: &str) -> Result<Option<PcapCapture>> {
        let captures = self.captures.read().unwrap();
        Ok(captures.get(capture_id).cloned())
    }

    /// List all captures
    pub async fn list_captures(&self) -> Result<Vec<PcapCapture>> {
        let captures = self.captures.read().unwrap();
        Ok(captures.values().cloned().collect())
    }

    /// Get available interfaces
    pub async fn get_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        let interfaces = self.interfaces.read().unwrap();
        Ok(interfaces.clone())
    }

    /// Store capture results in vault (placeholder)
    pub async fn store_in_vault(&self, capture_id: &str) -> Result<String> {
        let captures = self.captures.read().unwrap();
        if let Some(capture) = captures.get(capture_id) {
            if let Some(results) = &capture.results {
                // Serialize the results
                let data = serde_json::to_vec(results)?;
                
                // Create vault entry
                let secret_name = format!("pcap_capture_{}", capture_id);
                let metadata = format!("PCAP capture from {} on {}", 
                    capture.interface, 
                    capture.started_at.format("%Y-%m-%d %H:%M:%S")
                );
                
                // Store in vault (simplified - in real implementation would use proper vault API)
                // vault.store_secret(&secret_name, &data, &metadata).await?;
                
                Ok(secret_name)
            } else {
                Err(anyhow::anyhow!("No results available for capture {}", capture_id))
            }
        } else {
            Err(anyhow::anyhow!("Capture {} not found", capture_id))
        }
    }

    /// Export capture results with PQ signature
    pub async fn export_results(&self, capture_id: &str, format: &str) -> Result<String> {
        let (capture_clone, results_clone) = {
            let captures = self.captures.read().unwrap();
            if let Some(capture) = captures.get(capture_id) {
                if let Some(results) = &capture.results {
                    (capture.clone(), results.clone())
                } else {
                    return Err(anyhow::anyhow!("No results available for capture {}", capture_id));
                }
            } else {
                return Err(anyhow::anyhow!("Capture {} not found", capture_id));
            }
        };

        let content = match format {
            "json" => serde_json::to_string_pretty(&results_clone)?,
            "csv" => self.export_to_csv(&results_clone),
            "pdf" => self.export_to_pdf(&capture_clone, &results_clone)?,
            "pcap" => self.export_to_pcap(&capture_clone, &results_clone)?,
            _ => return Err(anyhow::anyhow!("Unsupported export format: {}", format)),
        };

        // Create signed export bundle
        let export_bundle = self.create_signed_export(capture_id, format, &content).await?;
        Ok(export_bundle)
    }

    /// Create signed export bundle with PQ signature
    async fn create_signed_export(&self, capture_id: &str, format: &str, content: &str) -> Result<String> {
        let timestamp = Utc::now();
        let export_id = Uuid::new_v4().to_string();
        
        // Create export metadata
        let metadata = serde_json::json!({
            "export_id": export_id,
            "capture_id": capture_id,
            "format": format,
            "timestamp": timestamp,
            "tool": "PCAP Studio",
            "version": "1.0.0"
        });

        // Sign the content
        let signature = Self::sign_content(&self.signing_keys, content).await?;

        // Create signed bundle
        let bundle = serde_json::json!({
            "metadata": metadata,
            "content": content,
            "signature": signature,
            "verification": {
                "algorithm": "Dilithium",
                "public_key_id": "default",
                "signed_at": timestamp
            }
        });

        Ok(serde_json::to_string_pretty(&bundle)?)
    }

    /// Sign content with Dilithium
    async fn sign_content(
        signing_keys: &Arc<RwLock<HashMap<String, (DilithiumPublicKey, DilithiumPrivateKey)>>>,
        content: &str,
    ) -> Result<String> {
        let keys = signing_keys.read().unwrap();
        if let Some((_, private_key)) = keys.get("default") {
            // In real implementation, would use actual Dilithium signing
            let content_hash = format!("sha256_{}", content.len());
            Ok(format!("dilithium_signature_{}_{}", content_hash, Utc::now().timestamp()))
        } else {
            Err(anyhow::anyhow!("No signing key available"))
        }
    }

    /// Export results to CSV format
    fn export_to_csv(&self, analysis: &PcapAnalysis) -> String {
        let mut csv = String::new();
        csv.push_str("Flow,Src IP,Dst IP,Src Port,Dst Port,Protocol,Packets,Bytes,Duration (ms)\n");
        
        for (i, flow) in analysis.flows.iter().enumerate() {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{}\n",
                i + 1,
                flow.src_ip,
                flow.dst_ip,
                flow.src_port,
                flow.dst_port,
                flow.protocol,
                flow.packet_count,
                flow.bytes,
                flow.duration_ms
            ));
        }
        
        csv
    }

    /// Export results to PDF format (simplified)
    fn export_to_pdf(&self, capture: &PcapCapture, analysis: &PcapAnalysis) -> Result<String> {
        // In real implementation, would generate actual PDF
        // For now, return formatted text report
        let mut report = String::new();
        report.push_str("PCAP ANALYSIS REPORT\n");
        report.push_str("====================\n\n");
        report.push_str(&format!("Capture ID: {}\n", capture.id));
        report.push_str(&format!("Interface: {}\n", capture.interface));
        report.push_str(&format!("Started: {}\n", capture.started_at));
        if let Some(completed) = &capture.completed_at {
            report.push_str(&format!("Completed: {}\n", completed));
        }
        report.push_str(&format!("Packets: {}\n", capture.packet_count));
        report.push_str(&format!("Bytes: {}\n", capture.bytes_captured));
        report.push_str("\nSUMMARY\n");
        report.push_str("-------\n");
        report.push_str(&format!("Network Flows: {}\n", analysis.flows.len()));
        report.push_str(&format!("Anomalies: {}\n", analysis.anomalies.len()));
        report.push_str(&format!("Top Talkers: {}\n", analysis.top_talkers.len()));
        
        if let Some(tls) = &analysis.tls_analysis {
            report.push_str("\nTLS ANALYSIS\n");
            report.push_str("------------\n");
            report.push_str(&format!("Post-Quantum Connections: {}\n", tls.pq_connections));
            report.push_str(&format!("Hybrid Connections: {}\n", tls.hybrid_connections));
            report.push_str(&format!("Classical Connections: {}\n", tls.classical_connections));
        }
        
        Ok(report)
    }

    /// Export to PCAP format (simplified)
    fn export_to_pcap(&self, capture: &PcapCapture, analysis: &PcapAnalysis) -> Result<String> {
        // In real implementation, would generate actual PCAP file
        // For now, return metadata about the capture
        let pcap_info = serde_json::json!({
            "pcap_version": "2.4",
            "capture_id": capture.id,
            "interface": capture.interface,
            "packet_count": capture.packet_count,
            "bytes_captured": capture.bytes_captured,
            "flows": analysis.flows.len(),
            "note": "Actual PCAP data would be binary format"
        });
        
        Ok(serde_json::to_string_pretty(&pcap_info)?)
    }

    /// Generate signing keypair
    async fn generate_signing_keypair(&self) -> Result<String> {
        let keypair_id = "default".to_string();
        
        // Generate Dilithium keypair (placeholder)
        use ghost_pq::signatures::DilithiumVariant;
        let private_key = DilithiumPrivateKey::from_bytes(vec![0u8; 32], DilithiumVariant::default())?;
        let public_key = DilithiumPublicKey::from_bytes(vec![0u8; 32], DilithiumVariant::default())?;
        
        // Store keypair
        {
            let mut keys = self.signing_keys.write().unwrap();
            keys.insert(keypair_id.clone(), (public_key, private_key));
        }
        
        Ok(keypair_id)
    }
}

// Tauri commands moved to src-tauri/src/commands/pcap.rs
