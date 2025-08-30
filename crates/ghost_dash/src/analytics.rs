//! Network analytics and performance metrics
//! 
//! Provides real-time network analytics, throughput monitoring, and performance insights

use crate::{DashError, Result, NetworkSnapshot, InterfaceInfo, ConnectionInfo};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// Network analytics data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalytics {
    /// Overall network health score (0-100)
    pub health_score: f32,
    /// Total bandwidth utilization
    pub bandwidth_utilization: BandwidthStats,
    /// Interface utilization breakdown
    pub interface_utilization: HashMap<String, InterfaceUtilization>,
    /// Connection statistics
    pub connection_stats: ConnectionStats,
    /// Performance metrics
    pub performance_metrics: PerformanceMetrics,
    /// Network topology insights
    pub topology_insights: TopologyInsights,
    /// Timestamp of analysis
    pub timestamp: DateTime<Utc>,
}

/// Bandwidth utilization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthStats {
    /// Total bytes received per second
    pub rx_bytes_per_sec: u64,
    /// Total bytes transmitted per second
    pub tx_bytes_per_sec: u64,
    /// Total packets received per second
    pub rx_packets_per_sec: u64,
    /// Total packets transmitted per second
    pub tx_packets_per_sec: u64,
    /// Error rate (errors per second)
    pub error_rate: f32,
    /// Utilization percentage (0-100)
    pub utilization_percent: f32,
}

/// Per-interface utilization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceUtilization {
    /// Interface name
    pub interface_name: String,
    /// Bytes received per second
    pub rx_bps: u64,
    /// Bytes transmitted per second
    pub tx_bps: u64,
    /// Utilization percentage
    pub utilization_percent: f32,
    /// Interface capacity in Mbps
    pub capacity_mbps: Option<u64>,
    /// Interface status
    pub status: String,
    /// Error count
    pub error_count: u64,
}

/// Connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Total active connections
    pub total_connections: usize,
    /// Connections by protocol
    pub by_protocol: HashMap<String, usize>,
    /// Connections by state
    pub by_state: HashMap<String, usize>,
    /// Top processes by connection count
    pub top_processes: Vec<ProcessConnectionCount>,
    /// Port usage statistics
    pub port_usage: PortUsageStats,
}

/// Process connection count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConnectionCount {
    /// Process name
    pub process_name: String,
    /// Process ID
    pub pid: Option<u32>,
    /// Number of connections
    pub connection_count: usize,
    /// Percentage of total connections
    pub percentage: f32,
}

/// Port usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortUsageStats {
    /// Most used ports
    pub top_ports: Vec<PortUsage>,
    /// Well-known ports in use
    pub well_known_ports: Vec<PortUsage>,
    /// Ephemeral ports in use count
    pub ephemeral_port_count: usize,
}

/// Port usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortUsage {
    /// Port number
    pub port: u16,
    /// Protocol (TCP/UDP)
    pub protocol: String,
    /// Number of connections/bindings
    pub usage_count: usize,
    /// Port description (if well-known)
    pub description: Option<String>,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Average latency in milliseconds
    pub avg_latency_ms: Option<f32>,
    /// Packet loss percentage
    pub packet_loss_percent: f32,
    /// Jitter in milliseconds
    pub jitter_ms: Option<f32>,
    /// Throughput efficiency score (0-100)
    pub throughput_efficiency: f32,
    /// Connection establishment rate (connections per second)
    pub connection_rate: f32,
    /// DNS resolution time in milliseconds
    pub dns_resolution_time_ms: Option<f32>,
}

/// Network topology insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyInsights {
    /// Number of unique remote hosts
    pub unique_remote_hosts: usize,
    /// Number of different subnets
    pub subnet_count: usize,
    /// Gateway utilization
    pub gateway_utilization: Vec<GatewayUsage>,
    /// Network segmentation score (0-100)
    pub segmentation_score: f32,
    /// Detected network patterns
    pub patterns: Vec<NetworkPattern>,
}

/// Gateway usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayUsage {
    /// Gateway address
    pub gateway: String,
    /// Associated interface
    pub interface: String,
    /// Traffic volume through this gateway
    pub traffic_volume: u64,
    /// Number of routes using this gateway
    pub route_count: usize,
}

/// Detected network pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPattern {
    /// Pattern type
    pub pattern_type: NetworkPatternType,
    /// Pattern description
    pub description: String,
    /// Confidence score (0-100)
    pub confidence: f32,
    /// Associated data
    pub data: HashMap<String, serde_json::Value>,
}

/// Network pattern types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkPatternType {
    HighTrafficHost,
    UnusualPortUsage,
    ConnectionSpike,
    LatencyAnomaly,
    SecurityConcern,
    PerformanceBottleneck,
}

/// Network analytics engine
pub struct NetworkAnalyticsEngine {
    historical_snapshots: Vec<NetworkSnapshot>,
    max_history: usize,
    well_known_ports: HashMap<u16, String>,
}

impl NetworkAnalyticsEngine {
    /// Create a new analytics engine
    pub fn new() -> Self {
        let mut well_known_ports = HashMap::new();
        
        // Add common well-known ports
        well_known_ports.insert(21, "FTP".to_string());
        well_known_ports.insert(22, "SSH".to_string());
        well_known_ports.insert(23, "Telnet".to_string());
        well_known_ports.insert(25, "SMTP".to_string());
        well_known_ports.insert(53, "DNS".to_string());
        well_known_ports.insert(80, "HTTP".to_string());
        well_known_ports.insert(110, "POP3".to_string());
        well_known_ports.insert(143, "IMAP".to_string());
        well_known_ports.insert(443, "HTTPS".to_string());
        well_known_ports.insert(993, "IMAPS".to_string());
        well_known_ports.insert(995, "POP3S".to_string());
        well_known_ports.insert(3389, "RDP".to_string());
        well_known_ports.insert(5432, "PostgreSQL".to_string());
        well_known_ports.insert(3306, "MySQL".to_string());
        well_known_ports.insert(1433, "SQL Server".to_string());
        well_known_ports.insert(6379, "Redis".to_string());
        well_known_ports.insert(27017, "MongoDB".to_string());

        Self {
            historical_snapshots: Vec::new(),
            max_history: 100, // Keep last 100 snapshots
            well_known_ports,
        }
    }

    /// Analyze network snapshot and generate analytics
    pub fn analyze_snapshot(&mut self, snapshot: &NetworkSnapshot) -> Result<NetworkAnalytics> {
        debug!("Analyzing network snapshot from {}", snapshot.timestamp);

        // Add to historical data
        self.add_historical_snapshot(snapshot.clone());

        // Generate analytics
        let bandwidth_utilization = self.calculate_bandwidth_stats(snapshot)?;
        let interface_utilization = self.calculate_interface_utilization(snapshot)?;
        let connection_stats = self.calculate_connection_stats(snapshot)?;
        let performance_metrics = self.calculate_performance_metrics(snapshot)?;
        let topology_insights = self.calculate_topology_insights(snapshot)?;

        // Calculate overall health score
        let health_score = self.calculate_health_score(
            &bandwidth_utilization,
            &interface_utilization,
            &connection_stats,
            &performance_metrics,
        );

        let analytics = NetworkAnalytics {
            health_score,
            bandwidth_utilization,
            interface_utilization,
            connection_stats,
            performance_metrics,
            topology_insights,
            timestamp: Utc::now(),
        };

        info!("Network analysis completed: health score {:.1}", health_score);
        Ok(analytics)
    }

    /// Add snapshot to historical data
    fn add_historical_snapshot(&mut self, snapshot: NetworkSnapshot) {
        self.historical_snapshots.push(snapshot);
        
        // Keep only the most recent snapshots
        if self.historical_snapshots.len() > self.max_history {
            self.historical_snapshots.remove(0);
        }
    }

    /// Calculate bandwidth statistics
    fn calculate_bandwidth_stats(&self, snapshot: &NetworkSnapshot) -> Result<BandwidthStats> {
        // This is a simplified implementation
        // In production, would calculate actual rates based on historical data
        
        let total_interfaces = snapshot.interfaces.len() as u64;
        let active_interfaces = snapshot.interfaces.iter()
            .filter(|iface| matches!(iface.status, crate::collectors::InterfaceStatus::Up))
            .count() as u64;

        // Placeholder calculations - would use actual network statistics
        let rx_bytes_per_sec = total_interfaces * 1024 * 10; // 10KB/s per interface
        let tx_bytes_per_sec = total_interfaces * 1024 * 8;  // 8KB/s per interface
        let rx_packets_per_sec = total_interfaces * 50;
        let tx_packets_per_sec = total_interfaces * 40;
        let error_rate = if active_interfaces > 0 { 0.1 } else { 0.0 };
        let utilization_percent = (active_interfaces as f32 / total_interfaces.max(1) as f32) * 100.0;

        Ok(BandwidthStats {
            rx_bytes_per_sec,
            tx_bytes_per_sec,
            rx_packets_per_sec,
            tx_packets_per_sec,
            error_rate,
            utilization_percent,
        })
    }

    /// Calculate per-interface utilization
    fn calculate_interface_utilization(&self, snapshot: &NetworkSnapshot) -> Result<HashMap<String, InterfaceUtilization>> {
        let mut utilization = HashMap::new();

        for interface in &snapshot.interfaces {
            let status = format!("{:?}", interface.status);
            let capacity_mbps = interface.speed;
            
            // Placeholder calculations
            let rx_bps = if matches!(interface.status, crate::collectors::InterfaceStatus::Up) {
                1024 * 10 // 10KB/s
            } else {
                0
            };
            let tx_bps = if matches!(interface.status, crate::collectors::InterfaceStatus::Up) {
                1024 * 8 // 8KB/s
            } else {
                0
            };

            let utilization_percent = if let Some(capacity) = capacity_mbps {
                let capacity_bps = capacity * 1024 * 1024 / 8; // Convert Mbps to bytes per second
                ((rx_bps + tx_bps) as f32 / capacity_bps as f32) * 100.0
            } else {
                0.0
            };

            utilization.insert(interface.name.clone(), InterfaceUtilization {
                interface_name: interface.name.clone(),
                rx_bps,
                tx_bps,
                utilization_percent,
                capacity_mbps,
                status,
                error_count: 0, // Placeholder
            });
        }

        Ok(utilization)
    }

    /// Calculate connection statistics
    fn calculate_connection_stats(&self, snapshot: &NetworkSnapshot) -> Result<ConnectionStats> {
        let connections = &snapshot.connections;
        let total_connections = connections.len();

        // Group by protocol
        let mut by_protocol = HashMap::new();
        for conn in connections {
            *by_protocol.entry(conn.protocol.clone()).or_insert(0) += 1;
        }

        // Group by state
        let mut by_state = HashMap::new();
        for conn in connections {
            let state_str = format!("{:?}", conn.state);
            *by_state.entry(state_str).or_insert(0) += 1;
        }

        // Top processes
        let mut process_counts = HashMap::new();
        for conn in connections {
            if let Some(ref process) = conn.process {
                *process_counts.entry(process.clone()).or_insert(0) += 1;
            }
        }

        let mut top_processes: Vec<ProcessConnectionCount> = process_counts
            .into_iter()
            .map(|(process_name, count)| {
                let percentage = if total_connections > 0 {
                    (count as f32 / total_connections as f32) * 100.0
                } else {
                    0.0
                };

                ProcessConnectionCount {
                    process_name,
                    pid: None, // Would need to correlate with actual PIDs
                    connection_count: count,
                    percentage,
                }
            })
            .collect();

        top_processes.sort_by(|a, b| b.connection_count.cmp(&a.connection_count));
        top_processes.truncate(10); // Top 10

        // Port usage
        let port_usage = self.calculate_port_usage(connections)?;

        Ok(ConnectionStats {
            total_connections,
            by_protocol,
            by_state,
            top_processes,
            port_usage,
        })
    }

    /// Calculate port usage statistics
    fn calculate_port_usage(&self, connections: &[ConnectionInfo]) -> Result<PortUsageStats> {
        let mut port_counts = HashMap::new();

        for conn in connections {
            // Extract port from local address
            if let Some(port_str) = conn.local_address.split(':').last() {
                if let Ok(port) = port_str.parse::<u16>() {
                    let key = (port, conn.protocol.clone());
                    *port_counts.entry(key).or_insert(0) += 1;
                }
            }
        }

        // Convert to PortUsage structs
        let mut all_ports: Vec<PortUsage> = port_counts
            .into_iter()
            .map(|((port, protocol), count)| {
                let description = self.well_known_ports.get(&port).cloned();
                PortUsage {
                    port,
                    protocol,
                    usage_count: count,
                    description,
                }
            })
            .collect();

        all_ports.sort_by(|a, b| b.usage_count.cmp(&a.usage_count));

        let top_ports = all_ports.iter().take(10).cloned().collect();
        let well_known_ports = all_ports.iter()
            .filter(|p| p.description.is_some())
            .cloned()
            .collect();

        let ephemeral_port_count = all_ports.iter()
            .filter(|p| p.port >= 32768) // Typical ephemeral port range start
            .map(|p| p.usage_count)
            .sum();

        Ok(PortUsageStats {
            top_ports,
            well_known_ports,
            ephemeral_port_count,
        })
    }

    /// Calculate performance metrics
    fn calculate_performance_metrics(&self, _snapshot: &NetworkSnapshot) -> Result<PerformanceMetrics> {
        // Placeholder implementation - would use actual network measurements
        Ok(PerformanceMetrics {
            avg_latency_ms: Some(15.5),
            packet_loss_percent: 0.1,
            jitter_ms: Some(2.3),
            throughput_efficiency: 85.0,
            connection_rate: 10.5,
            dns_resolution_time_ms: Some(8.2),
        })
    }

    /// Calculate topology insights
    fn calculate_topology_insights(&self, snapshot: &NetworkSnapshot) -> Result<TopologyInsights> {
        let connections = &snapshot.connections;
        
        // Count unique remote hosts
        let unique_remote_hosts: std::collections::HashSet<String> = connections
            .iter()
            .map(|conn| {
                conn.remote_address.split(':').next().unwrap_or("").to_string()
            })
            .filter(|addr| !addr.is_empty() && addr != "0.0.0.0")
            .collect();

        // Count subnets (simplified)
        let subnet_count = snapshot.interfaces.len(); // Placeholder

        // Gateway utilization
        let mut gateway_usage = Vec::new();
        for interface in &snapshot.interfaces {
            if let Some(ref gateway) = interface.gateway {
                gateway_usage.push(GatewayUsage {
                    gateway: gateway.clone(),
                    interface: interface.name.clone(),
                    traffic_volume: 1024 * 1024, // Placeholder
                    route_count: 1, // Placeholder
                });
            }
        }

        // Network patterns (simplified detection)
        let mut patterns = Vec::new();
        
        // High connection count pattern
        if connections.len() > 100 {
            patterns.push(NetworkPattern {
                pattern_type: NetworkPatternType::ConnectionSpike,
                description: format!("High number of connections detected: {}", connections.len()),
                confidence: 80.0,
                data: HashMap::from([
                    ("connection_count".to_string(), serde_json::Value::Number(connections.len().into())),
                ]),
            });
        }

        // Unusual port usage
        let listening_ports: Vec<u16> = connections
            .iter()
            .filter(|conn| matches!(conn.state, crate::collectors::ConnectionState::Listen))
            .filter_map(|conn| {
                conn.local_address.split(':').last()?.parse().ok()
            })
            .collect();

        for &port in &listening_ports {
            if port > 10000 && port < 32768 && !self.well_known_ports.contains_key(&port) {
                patterns.push(NetworkPattern {
                    pattern_type: NetworkPatternType::UnusualPortUsage,
                    description: format!("Unusual port {} is listening", port),
                    confidence: 60.0,
                    data: HashMap::from([
                        ("port".to_string(), serde_json::Value::Number(port.into())),
                    ]),
                });
            }
        }

        let segmentation_score = if unique_remote_hosts.len() > 50 {
            30.0 // Low segmentation
        } else if unique_remote_hosts.len() > 20 {
            60.0 // Medium segmentation
        } else {
            90.0 // High segmentation
        };

        Ok(TopologyInsights {
            unique_remote_hosts: unique_remote_hosts.len(),
            subnet_count,
            gateway_utilization: gateway_usage,
            segmentation_score,
            patterns,
        })
    }

    /// Calculate overall network health score
    fn calculate_health_score(
        &self,
        bandwidth: &BandwidthStats,
        interfaces: &HashMap<String, InterfaceUtilization>,
        connections: &ConnectionStats,
        performance: &PerformanceMetrics,
    ) -> f32 {
        let mut score = 100.0;

        // Bandwidth utilization impact
        if bandwidth.utilization_percent > 90.0 {
            score -= 20.0;
        } else if bandwidth.utilization_percent > 75.0 {
            score -= 10.0;
        }

        // Error rate impact
        if bandwidth.error_rate > 1.0 {
            score -= 15.0;
        } else if bandwidth.error_rate > 0.5 {
            score -= 5.0;
        }

        // Interface health impact
        let down_interfaces = interfaces.values()
            .filter(|iface| iface.status != "Up")
            .count();
        
        if down_interfaces > 0 {
            score -= (down_interfaces as f32 * 10.0).min(30.0);
        }

        // Performance impact
        if performance.packet_loss_percent > 1.0 {
            score -= 20.0;
        } else if performance.packet_loss_percent > 0.5 {
            score -= 10.0;
        }

        if let Some(latency) = performance.avg_latency_ms {
            if latency > 100.0 {
                score -= 15.0;
            } else if latency > 50.0 {
                score -= 5.0;
            }
        }

        // Connection health
        if connections.total_connections > 1000 {
            score -= 10.0;
        }

        // Ensure score is within bounds
        score.max(0.0).min(100.0)
    }

    /// Get historical analytics data
    pub fn get_historical_analytics(&self, hours: u32) -> Vec<NetworkAnalytics> {
        // Placeholder - would implement actual historical analysis
        Vec::new()
    }
}

impl Default for NetworkAnalyticsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InterfaceStatus, DnsStatus, RouteType, ConnectionState};

    fn create_test_snapshot() -> NetworkSnapshot {
        NetworkSnapshot {
            interfaces: vec![
                InterfaceInfo {
                    id: "if-001".to_string(),
                    name: "Ethernet0".to_string(),
                    mac: Some("00:1c:42:2e:60:4a".to_string()),
                    ipv4: Some("192.168.1.100".to_string()),
                    ipv6: None,
                    mask: Some("255.255.255.0".to_string()),
                    gateway: Some("192.168.1.1".to_string()),
                    dhcp: true,
                    dns_suffix: None,
                    status: InterfaceStatus::Up,
                    interface_type: "Ethernet".to_string(),
                    mtu: Some(1500),
                    speed: Some(1000),
                }
            ],
            dns_servers: vec![],
            routes: vec![],
            connections: vec![
                ConnectionInfo {
                    protocol: "TCP".to_string(),
                    local_address: "192.168.1.100:80".to_string(),
                    remote_address: "192.168.1.50:12345".to_string(),
                    state: ConnectionState::Established,
                    pid: Some(1234),
                    process: Some("nginx".to_string()),
                    timestamp: Utc::now(),
                },
                ConnectionInfo {
                    protocol: "TCP".to_string(),
                    local_address: "0.0.0.0:22".to_string(),
                    remote_address: "0.0.0.0:0".to_string(),
                    state: ConnectionState::Listen,
                    pid: Some(5678),
                    process: Some("sshd".to_string()),
                    timestamp: Utc::now(),
                }
            ],
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_analytics_engine() {
        let mut engine = NetworkAnalyticsEngine::new();
        let snapshot = create_test_snapshot();
        
        let analytics = engine.analyze_snapshot(&snapshot).unwrap();
        
        assert!(analytics.health_score >= 0.0 && analytics.health_score <= 100.0);
        assert_eq!(analytics.connection_stats.total_connections, 2);
        assert!(analytics.interface_utilization.contains_key("Ethernet0"));
    }

    #[test]
    fn test_port_usage_calculation() {
        let engine = NetworkAnalyticsEngine::new();
        let connections = vec![
            ConnectionInfo {
                protocol: "TCP".to_string(),
                local_address: "0.0.0.0:80".to_string(),
                remote_address: "0.0.0.0:0".to_string(),
                state: ConnectionState::Listen,
                pid: Some(1234),
                process: Some("nginx".to_string()),
                timestamp: Utc::now(),
            },
            ConnectionInfo {
                protocol: "TCP".to_string(),
                local_address: "0.0.0.0:443".to_string(),
                remote_address: "0.0.0.0:0".to_string(),
                state: ConnectionState::Listen,
                pid: Some(1234),
                process: Some("nginx".to_string()),
                timestamp: Utc::now(),
            }
        ];

        let port_usage = engine.calculate_port_usage(&connections).unwrap();
        
        assert_eq!(port_usage.top_ports.len(), 2);
        assert_eq!(port_usage.well_known_ports.len(), 2);
        assert!(port_usage.well_known_ports.iter().any(|p| p.port == 80));
        assert!(port_usage.well_known_ports.iter().any(|p| p.port == 443));
    }

    #[test]
    fn test_health_score_calculation() {
        let engine = NetworkAnalyticsEngine::new();
        
        let bandwidth = BandwidthStats {
            rx_bytes_per_sec: 1000,
            tx_bytes_per_sec: 800,
            rx_packets_per_sec: 50,
            tx_packets_per_sec: 40,
            error_rate: 0.1,
            utilization_percent: 50.0,
        };

        let interfaces = HashMap::new();
        
        let connections = ConnectionStats {
            total_connections: 10,
            by_protocol: HashMap::new(),
            by_state: HashMap::new(),
            top_processes: Vec::new(),
            port_usage: PortUsageStats {
                top_ports: Vec::new(),
                well_known_ports: Vec::new(),
                ephemeral_port_count: 0,
            },
        };

        let performance = PerformanceMetrics {
            avg_latency_ms: Some(20.0),
            packet_loss_percent: 0.1,
            jitter_ms: Some(2.0),
            throughput_efficiency: 90.0,
            connection_rate: 5.0,
            dns_resolution_time_ms: Some(10.0),
        };

        let score = engine.calculate_health_score(&bandwidth, &interfaces, &connections, &performance);
        
        assert!(score >= 80.0); // Should be a good score with these metrics
        assert!(score <= 100.0);
    }
}
