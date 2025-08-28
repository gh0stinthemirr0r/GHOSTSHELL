use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tauri::{State, Window};
use tokio::sync::{RwLock, Mutex};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub id: String,
    pub name: String,
    pub ip_address: IpAddr,
    pub mac_address: Option<String>,
    pub node_type: NodeType,
    pub status: NodeStatus,
    pub location: Option<NodeLocation>,
    pub services: Vec<NetworkService>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub first_discovered: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Router,
    Switch,
    AccessPoint,
    Server,
    Workstation,
    Laptop,
    Mobile,
    IoTDevice,
    Printer,
    Camera,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Online,
    Offline,
    Unreachable,
    Suspicious,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLocation {
    pub x: f64,
    pub y: f64,
    pub z: Option<f64>,
    pub floor: Option<String>,
    pub building: Option<String>,
    pub room: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkService {
    pub port: u16,
    pub protocol: ServiceProtocol,
    pub service_name: String,
    pub version: Option<String>,
    pub status: ServiceStatus,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceProtocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    SSH,
    FTP,
    SMTP,
    DNS,
    DHCP,
    SNMP,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Filtered,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    Secure,
    Warning,
    Vulnerable,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub id: String,
    pub source_node_id: String,
    pub destination_node_id: String,
    pub connection_type: ConnectionType,
    pub protocol: String,
    pub port: Option<u16>,
    pub bandwidth: Option<u64>,
    pub latency: Option<u32>,
    pub packet_loss: Option<f32>,
    pub status: ConnectionStatus,
    pub established_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionType {
    Ethernet,
    WiFi,
    Bluetooth,
    VPN,
    Internet,
    Logical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Active,
    Idle,
    Closed,
    Blocked,
    Monitored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScan {
    pub id: String,
    pub scan_type: ScanType,
    pub target_range: String,
    pub status: ScanStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub progress: f32,
    pub nodes_discovered: u32,
    pub services_discovered: u32,
    pub vulnerabilities_found: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Discovery,
    PortScan,
    ServiceDetection,
    VulnerabilityAssessment,
    Performance,
    Security,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAlert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub source_node_id: Option<String>,
    pub destination_node_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub acknowledged: bool,
    pub resolved: bool,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    NewDevice,
    DeviceOffline,
    SuspiciousActivity,
    SecurityThreat,
    PerformanceIssue,
    ConfigurationChange,
    PolicyViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub total_nodes: u32,
    pub online_nodes: u32,
    pub total_connections: u32,
    pub active_connections: u32,
    pub total_bandwidth: u64,
    pub used_bandwidth: u64,
    pub average_latency: f32,
    pub packet_loss_rate: f32,
    pub security_score: f32,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyLayout {
    pub id: String,
    pub name: String,
    pub layout_type: LayoutType,
    pub auto_arrange: bool,
    pub show_connections: bool,
    pub show_labels: bool,
    pub color_scheme: String,
    pub zoom_level: f32,
    pub center_point: (f64, f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LayoutType {
    Hierarchical,
    Force,
    Circular,
    Grid,
    Geographic,
    Custom,
}

pub struct NetworkTopologyManager {
    nodes: Arc<RwLock<HashMap<String, NetworkNode>>>,
    connections: Arc<RwLock<HashMap<String, NetworkConnection>>>,
    scans: Arc<RwLock<HashMap<String, NetworkScan>>>,
    alerts: Arc<RwLock<Vec<NetworkAlert>>>,
    metrics_history: Arc<RwLock<Vec<NetworkMetrics>>>,
    layouts: Arc<RwLock<HashMap<String, TopologyLayout>>>,
    monitoring_active: Arc<RwLock<bool>>,
}

impl NetworkTopologyManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            scans: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            layouts: Arc::new(RwLock::new(HashMap::new())),
            monitoring_active: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start_network_discovery(&self, target_range: String) -> Result<String> {
        let scan_id = Uuid::new_v4().to_string();
        
        let scan = NetworkScan {
            id: scan_id.clone(),
            scan_type: ScanType::Discovery,
            target_range: target_range.clone(),
            status: ScanStatus::Running,
            started_at: chrono::Utc::now(),
            completed_at: None,
            progress: 0.0,
            nodes_discovered: 0,
            services_discovered: 0,
            vulnerabilities_found: 0,
        };

        self.scans.write().await.insert(scan_id.clone(), scan);

        info!("Starting network discovery for range: {}", target_range);

        // Simulate network discovery
        tokio::spawn({
            let nodes = self.nodes.clone();
            let connections = self.connections.clone();
            let scans = self.scans.clone();
            let alerts = self.alerts.clone();
            let scan_id = scan_id.clone();

            async move {
                // Simulate discovering nodes
                let discovered_nodes = Self::simulate_network_discovery(&target_range).await;
                
                let mut nodes_guard = nodes.write().await;
                let mut connections_guard = connections.write().await;
                let mut alerts_guard = alerts.write().await;

                for node in discovered_nodes {
                    // Check if this is a new node
                    if !nodes_guard.contains_key(&node.id) {
                        // Generate alert for new device
                        let alert = NetworkAlert {
                            id: Uuid::new_v4().to_string(),
                            alert_type: AlertType::NewDevice,
                            severity: AlertSeverity::Info,
                            title: format!("New device discovered: {}", node.name),
                            description: format!("Device {} ({}) has been discovered on the network", node.name, node.ip_address),
                            source_node_id: Some(node.id.clone()),
                            destination_node_id: None,
                            timestamp: chrono::Utc::now(),
                            acknowledged: false,
                            resolved: false,
                            metadata: HashMap::new(),
                        };
                        alerts_guard.push(alert);
                    }

                    nodes_guard.insert(node.id.clone(), node);
                }

                // Simulate discovering connections
                let node_ids: Vec<String> = nodes_guard.keys().cloned().collect();
                for i in 0..node_ids.len() {
                    for j in (i + 1)..node_ids.len() {
                        if rand::random::<f32>() < 0.3 { // 30% chance of connection
                            let connection = NetworkConnection {
                                id: Uuid::new_v4().to_string(),
                                source_node_id: node_ids[i].clone(),
                                destination_node_id: node_ids[j].clone(),
                                connection_type: ConnectionType::Ethernet,
                                protocol: "TCP".to_string(),
                                port: Some(80),
                                bandwidth: Some(1000000000), // 1 Gbps
                                latency: Some(rand::random::<u32>() % 50 + 1),
                                packet_loss: Some(rand::random::<f32>() * 0.01),
                                status: ConnectionStatus::Active,
                                established_at: chrono::Utc::now(),
                                last_activity: chrono::Utc::now(),
                                bytes_sent: rand::random::<u64>() % 1000000,
                                bytes_received: rand::random::<u64>() % 1000000,
                            };
                            connections_guard.insert(connection.id.clone(), connection);
                        }
                    }
                }

                // Update scan status
                let mut scans_guard = scans.write().await;
                if let Some(scan) = scans_guard.get_mut(&scan_id) {
                    scan.status = ScanStatus::Completed;
                    scan.completed_at = Some(chrono::Utc::now());
                    scan.progress = 100.0;
                    scan.nodes_discovered = nodes_guard.len() as u32;
                    scan.services_discovered = nodes_guard.values()
                        .map(|n| n.services.len() as u32)
                        .sum();
                }

                info!("Network discovery completed for scan: {}", scan_id);
            }
        });

        Ok(scan_id)
    }

    async fn simulate_network_discovery(target_range: &str) -> Vec<NetworkNode> {
        info!("Simulating network discovery for: {}", target_range);
        
        // Simulate delay
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;

        let mut nodes = Vec::new();

        // Create some sample nodes
        let sample_nodes = vec![
            ("Router", "192.168.1.1", NodeType::Router),
            ("Switch", "192.168.1.2", NodeType::Switch),
            ("Server", "192.168.1.10", NodeType::Server),
            ("Workstation-1", "192.168.1.100", NodeType::Workstation),
            ("Workstation-2", "192.168.1.101", NodeType::Workstation),
            ("Laptop", "192.168.1.150", NodeType::Laptop),
            ("Printer", "192.168.1.200", NodeType::Printer),
        ];

        for (name, ip, node_type) in sample_nodes {
            let node = NetworkNode {
                id: Uuid::new_v4().to_string(),
                name: name.to_string(),
                ip_address: IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap()),
                mac_address: Some(format!("00:{}:{}:{}:{}:{}", 
                    rand::random::<u8>(), rand::random::<u8>(), 
                    rand::random::<u8>(), rand::random::<u8>(), rand::random::<u8>())),
                node_type: node_type.clone(),
                status: NodeStatus::Online,
                location: Some(NodeLocation {
                    x: rand::random::<f64>() * 800.0,
                    y: rand::random::<f64>() * 600.0,
                    z: None,
                    floor: Some("1".to_string()),
                    building: Some("Main".to_string()),
                    room: None,
                }),
                services: Self::generate_sample_services(&node_type),
                last_seen: chrono::Utc::now(),
                first_discovered: chrono::Utc::now(),
                metadata: HashMap::new(),
            };
            nodes.push(node);
        }

        nodes
    }

    fn generate_sample_services(node_type: &NodeType) -> Vec<NetworkService> {
        match node_type {
            NodeType::Router => vec![
                NetworkService {
                    port: 22,
                    protocol: ServiceProtocol::SSH,
                    service_name: "SSH".to_string(),
                    version: Some("OpenSSH 8.0".to_string()),
                    status: ServiceStatus::Running,
                    security_level: SecurityLevel::Secure,
                },
                NetworkService {
                    port: 80,
                    protocol: ServiceProtocol::HTTP,
                    service_name: "Web Management".to_string(),
                    version: Some("nginx/1.18".to_string()),
                    status: ServiceStatus::Running,
                    security_level: SecurityLevel::Warning,
                },
            ],
            NodeType::Server => vec![
                NetworkService {
                    port: 22,
                    protocol: ServiceProtocol::SSH,
                    service_name: "SSH".to_string(),
                    version: Some("OpenSSH 8.0".to_string()),
                    status: ServiceStatus::Running,
                    security_level: SecurityLevel::Secure,
                },
                NetworkService {
                    port: 443,
                    protocol: ServiceProtocol::HTTPS,
                    service_name: "HTTPS".to_string(),
                    version: Some("Apache/2.4".to_string()),
                    status: ServiceStatus::Running,
                    security_level: SecurityLevel::Secure,
                },
                NetworkService {
                    port: 3306,
                    protocol: ServiceProtocol::TCP,
                    service_name: "MySQL".to_string(),
                    version: Some("8.0".to_string()),
                    status: ServiceStatus::Running,
                    security_level: SecurityLevel::Warning,
                },
            ],
            _ => vec![],
        }
    }

    pub async fn start_monitoring(&self) -> Result<()> {
        *self.monitoring_active.write().await = true;
        
        info!("Starting network monitoring");

        // Spawn monitoring task
        tokio::spawn({
            let nodes = self.nodes.clone();
            let connections = self.connections.clone();
            let metrics_history = self.metrics_history.clone();
            let alerts = self.alerts.clone();
            let monitoring_active = self.monitoring_active.clone();

            async move {
                while *monitoring_active.read().await {
                    // Collect current metrics
                    let nodes_guard = nodes.read().await;
                    let connections_guard = connections.read().await;

                    let total_nodes = nodes_guard.len() as u32;
                    let online_nodes = nodes_guard.values()
                        .filter(|n| matches!(n.status, NodeStatus::Online))
                        .count() as u32;

                    let total_connections = connections_guard.len() as u32;
                    let active_connections = connections_guard.values()
                        .filter(|c| matches!(c.status, ConnectionStatus::Active))
                        .count() as u32;

                    let total_bandwidth: u64 = connections_guard.values()
                        .filter_map(|c| c.bandwidth)
                        .sum();

                    let used_bandwidth = total_bandwidth / 10; // Simulate 10% usage

                    let average_latency = connections_guard.values()
                        .filter_map(|c| c.latency)
                        .map(|l| l as f32)
                        .sum::<f32>() / connections_guard.len().max(1) as f32;

                    let packet_loss_rate = connections_guard.values()
                        .filter_map(|c| c.packet_loss)
                        .sum::<f32>() / connections_guard.len().max(1) as f32;

                    let security_score = Self::calculate_security_score(&nodes_guard);
                    let threat_level = Self::determine_threat_level(security_score);

                    let metrics = NetworkMetrics {
                        timestamp: chrono::Utc::now(),
                        total_nodes,
                        online_nodes,
                        total_connections,
                        active_connections,
                        total_bandwidth,
                        used_bandwidth,
                        average_latency,
                        packet_loss_rate,
                        security_score,
                        threat_level,
                    };

                    metrics_history.write().await.push(metrics);

                    // Keep only last 1000 metrics
                    let mut history = metrics_history.write().await;
                    if history.len() > 1000 {
                        let len = history.len();
                        history.drain(0..len - 1000);
                    }
                    drop(history);

                    // Check for alerts
                    Self::check_for_alerts(&nodes_guard, &connections_guard, &alerts).await;

                    drop(nodes_guard);
                    drop(connections_guard);

                    // Wait before next monitoring cycle
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                }
            }
        });

        Ok(())
    }

    pub async fn stop_monitoring(&self) -> Result<()> {
        *self.monitoring_active.write().await = false;
        info!("Stopped network monitoring");
        Ok(())
    }

    fn calculate_security_score(nodes: &HashMap<String, NetworkNode>) -> f32 {
        let mut total_score = 0.0;
        let mut node_count = 0;

        for node in nodes.values() {
            let mut node_score: f32 = 100.0;

            // Deduct points for insecure services
            for service in &node.services {
                match service.security_level {
                    SecurityLevel::Vulnerable => node_score -= 20.0,
                    SecurityLevel::Critical => node_score -= 40.0,
                    SecurityLevel::Warning => node_score -= 10.0,
                    SecurityLevel::Secure => {},
                }
            }

            // Deduct points for suspicious status
            if matches!(node.status, NodeStatus::Suspicious) {
                node_score -= 30.0;
            }

            total_score += node_score.max(0.0);
            node_count += 1;
        }

        if node_count > 0 {
            total_score / node_count as f32
        } else {
            100.0
        }
    }

    fn determine_threat_level(security_score: f32) -> ThreatLevel {
        match security_score {
            s if s >= 90.0 => ThreatLevel::None,
            s if s >= 70.0 => ThreatLevel::Low,
            s if s >= 50.0 => ThreatLevel::Medium,
            s if s >= 30.0 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }

    async fn check_for_alerts(
        nodes: &HashMap<String, NetworkNode>,
        connections: &HashMap<String, NetworkConnection>,
        alerts: &Arc<RwLock<Vec<NetworkAlert>>>,
    ) {
        let mut new_alerts = Vec::new();

        // Check for offline nodes
        for node in nodes.values() {
            if matches!(node.status, NodeStatus::Offline) {
                let alert = NetworkAlert {
                    id: Uuid::new_v4().to_string(),
                    alert_type: AlertType::DeviceOffline,
                    severity: AlertSeverity::Medium,
                    title: format!("Device offline: {}", node.name),
                    description: format!("Device {} ({}) is no longer responding", node.name, node.ip_address),
                    source_node_id: Some(node.id.clone()),
                    destination_node_id: None,
                    timestamp: chrono::Utc::now(),
                    acknowledged: false,
                    resolved: false,
                    metadata: HashMap::new(),
                };
                new_alerts.push(alert);
            }
        }

        // Check for high latency connections
        for connection in connections.values() {
            if let Some(latency) = connection.latency {
                if latency > 100 { // High latency threshold
                    let alert = NetworkAlert {
                        id: Uuid::new_v4().to_string(),
                        alert_type: AlertType::PerformanceIssue,
                        severity: AlertSeverity::Low,
                        title: "High latency detected".to_string(),
                        description: format!("Connection has high latency: {}ms", latency),
                        source_node_id: Some(connection.source_node_id.clone()),
                        destination_node_id: Some(connection.destination_node_id.clone()),
                        timestamp: chrono::Utc::now(),
                        acknowledged: false,
                        resolved: false,
                        metadata: HashMap::new(),
                    };
                    new_alerts.push(alert);
                }
            }
        }

        if !new_alerts.is_empty() {
            alerts.write().await.extend(new_alerts);
        }
    }

    pub async fn get_topology(&self) -> Result<(Vec<NetworkNode>, Vec<NetworkConnection>)> {
        let nodes = self.nodes.read().await.values().cloned().collect();
        let connections = self.connections.read().await.values().cloned().collect();
        Ok((nodes, connections))
    }

    pub async fn get_network_metrics(&self) -> Result<Option<NetworkMetrics>> {
        let metrics = self.metrics_history.read().await;
        Ok(metrics.last().cloned())
    }

    pub async fn get_alerts(&self, unacknowledged_only: bool) -> Result<Vec<NetworkAlert>> {
        let alerts = self.alerts.read().await;
        if unacknowledged_only {
            Ok(alerts.iter().filter(|a| !a.acknowledged).cloned().collect())
        } else {
            Ok(alerts.clone())
        }
    }

    pub async fn acknowledge_alert(&self, alert_id: &str) -> Result<()> {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            info!("Alert acknowledged: {}", alert_id);
        }
        Ok(())
    }

    pub async fn get_scan_status(&self, scan_id: &str) -> Result<NetworkScan> {
        let scans = self.scans.read().await;
        scans.get(scan_id)
            .cloned()
            .ok_or_else(|| anyhow!("Scan not found: {}", scan_id))
    }

    pub async fn list_scans(&self) -> Result<Vec<NetworkScan>> {
        Ok(self.scans.read().await.values().cloned().collect())
    }
}

// Tauri Commands
#[tauri::command]
pub async fn nt_start_discovery(
    network_manager: State<'_, Arc<Mutex<NetworkTopologyManager>>>,
    target_range: String,
) -> Result<String, String> {
    let manager = network_manager.lock().await;
    manager.start_network_discovery(target_range).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn nt_start_monitoring(
    network_manager: State<'_, Arc<Mutex<NetworkTopologyManager>>>,
) -> Result<(), String> {
    let manager = network_manager.lock().await;
    manager.start_monitoring().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn nt_stop_monitoring(
    network_manager: State<'_, Arc<Mutex<NetworkTopologyManager>>>,
) -> Result<(), String> {
    let manager = network_manager.lock().await;
    manager.stop_monitoring().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn nt_get_topology(
    network_manager: State<'_, Arc<Mutex<NetworkTopologyManager>>>,
) -> Result<(Vec<NetworkNode>, Vec<NetworkConnection>), String> {
    let manager = network_manager.lock().await;
    manager.get_topology().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn nt_get_metrics(
    network_manager: State<'_, Arc<Mutex<NetworkTopologyManager>>>,
) -> Result<Option<NetworkMetrics>, String> {
    let manager = network_manager.lock().await;
    manager.get_network_metrics().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn nt_get_alerts(
    network_manager: State<'_, Arc<Mutex<NetworkTopologyManager>>>,
    unacknowledged_only: bool,
) -> Result<Vec<NetworkAlert>, String> {
    let manager = network_manager.lock().await;
    manager.get_alerts(unacknowledged_only).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn nt_acknowledge_alert(
    network_manager: State<'_, Arc<Mutex<NetworkTopologyManager>>>,
    alert_id: String,
) -> Result<(), String> {
    let manager = network_manager.lock().await;
    manager.acknowledge_alert(&alert_id).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn nt_get_scan_status(
    network_manager: State<'_, Arc<Mutex<NetworkTopologyManager>>>,
    scan_id: String,
) -> Result<NetworkScan, String> {
    let manager = network_manager.lock().await;
    manager.get_scan_status(&scan_id).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn nt_list_scans(
    network_manager: State<'_, Arc<Mutex<NetworkTopologyManager>>>,
) -> Result<Vec<NetworkScan>, String> {
    let manager = network_manager.lock().await;
    manager.list_scans().await
        .map_err(|e| e.to_string())
}
