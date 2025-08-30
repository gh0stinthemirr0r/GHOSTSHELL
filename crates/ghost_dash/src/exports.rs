//! Export system for network data with PQ signatures
//! 
//! Provides JSON, CSV, and PDF export capabilities with Dilithium signatures

use crate::{DashError, Result, NetworkSnapshot, InterfaceInfo, DnsInfo, RouteInfo, ConnectionInfo};
use chrono::{DateTime, Utc};
use ghost_pq::{DilithiumSigner, DilithiumVariant, DilithiumKeyPair};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info, warn};

/// Export format options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Pdf,
}

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Export format
    pub format: ExportFormat,
    /// Include PQ signature
    pub include_signature: bool,
    /// Include metadata
    pub include_metadata: bool,
    /// Output file path (optional, will generate if not provided)
    pub output_path: Option<PathBuf>,
    /// Data to export
    pub data_type: ExportDataType,
    /// Additional export options
    pub options: ExportOptions,
}

/// Type of data to export
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExportDataType {
    Interfaces,
    DnsServers,
    Routes,
    Connections,
    Complete,
}

/// Additional export options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOptions {
    /// Include sensitive data (PIDs, process names)
    pub include_sensitive: bool,
    /// Compress output
    pub compress: bool,
    /// Custom metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            include_sensitive: false,
            compress: false,
            metadata: std::collections::HashMap::new(),
        }
    }
}

/// Export result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    /// Path to exported file
    pub file_path: PathBuf,
    /// Export format used
    pub format: ExportFormat,
    /// File size in bytes
    pub file_size: u64,
    /// Number of records exported
    pub record_count: usize,
    /// Export timestamp
    pub timestamp: DateTime<Utc>,
    /// File hash for integrity
    pub file_hash: String,
    /// PQ signature (if enabled)
    pub signature: Option<String>,
    /// Export metadata
    pub metadata: ExportMetadata,
}

/// Export metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    /// Exporter version
    pub exporter_version: String,
    /// Data source timestamp
    pub source_timestamp: DateTime<Utc>,
    /// Export configuration used
    pub config: ExportConfig,
    /// System information
    pub system_info: SystemExportInfo,
}

/// System information for exports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemExportInfo {
    /// Hostname
    pub hostname: String,
    /// Operating system
    pub os: String,
    /// GhostShell version
    pub ghostshell_version: String,
    /// Export user (if available)
    pub user: Option<String>,
}

/// Network data exporter
pub struct NetworkExporter {
    signer: DilithiumSigner,
    private_key: ghost_pq::DilithiumPrivateKey,
    output_directory: PathBuf,
}

impl NetworkExporter {
    /// Create a new network exporter
    pub fn new(output_directory: PathBuf) -> Result<Self> {
        // Initialize PQ signer
        let signer = DilithiumSigner::new(DilithiumVariant::Dilithium2)
            .map_err(|e| DashError::CryptoError(e))?;
        let keypair = signer.generate_keypair()
            .map_err(|e| DashError::CryptoError(e))?;

        // Ensure output directory exists
        std::fs::create_dir_all(&output_directory)
            .map_err(|e| DashError::IoError(e))?;

        Ok(Self {
            signer,
            private_key: keypair.private_key,
            output_directory,
        })
    }

    /// Export network snapshot
    pub async fn export_snapshot(
        &self,
        snapshot: &NetworkSnapshot,
        config: &ExportConfig,
    ) -> Result<ExportResult> {
        info!("Exporting network snapshot: {:?} format", config.format);

        // Generate output path if not provided
        let output_path = if let Some(ref path) = config.output_path {
            path.clone()
        } else {
            self.generate_output_path(&config.format, &config.data_type)?
        };

        // Export data based on format
        let (file_size, record_count) = match config.format {
            ExportFormat::Json => self.export_json(snapshot, config, &output_path).await?,
            ExportFormat::Csv => self.export_csv(snapshot, config, &output_path).await?,
            ExportFormat::Pdf => self.export_pdf(snapshot, config, &output_path).await?,
        };

        // Calculate file hash
        let file_hash = self.calculate_file_hash(&output_path).await?;

        // Generate signature if requested
        let signature = if config.include_signature {
            Some(self.sign_file(&output_path).await?)
        } else {
            None
        };

        // Create metadata
        let metadata = ExportMetadata {
            exporter_version: "1.0.0".to_string(),
            source_timestamp: snapshot.timestamp,
            config: config.clone(),
            system_info: SystemExportInfo {
                hostname: "localhost".to_string(), // TODO: Get actual hostname
                os: std::env::consts::OS.to_string(),
                ghostshell_version: "1.0.0".to_string(),
                user: std::env::var("USER").or_else(|_| std::env::var("USERNAME")).ok(),
            },
        };

        let result = ExportResult {
            file_path: output_path,
            format: config.format.clone(),
            file_size,
            record_count,
            timestamp: Utc::now(),
            file_hash,
            signature,
            metadata,
        };

        info!("Export completed: {} records, {} bytes", record_count, file_size);
        Ok(result)
    }

    /// Export as JSON
    async fn export_json(
        &self,
        snapshot: &NetworkSnapshot,
        config: &ExportConfig,
        output_path: &Path,
    ) -> Result<(u64, usize)> {
        debug!("Exporting to JSON: {:?}", output_path);

        let data = match config.data_type {
            ExportDataType::Interfaces => {
                let interfaces = if config.options.include_sensitive {
                    snapshot.interfaces.clone()
                } else {
                    self.sanitize_interfaces(&snapshot.interfaces)
                };
                serde_json::to_value(interfaces)?
            }
            ExportDataType::DnsServers => {
                serde_json::to_value(&snapshot.dns_servers)?
            }
            ExportDataType::Routes => {
                serde_json::to_value(&snapshot.routes)?
            }
            ExportDataType::Connections => {
                let connections = if config.options.include_sensitive {
                    snapshot.connections.clone()
                } else {
                    self.sanitize_connections(&snapshot.connections)
                };
                serde_json::to_value(connections)?
            }
            ExportDataType::Complete => {
                let mut complete_data = serde_json::Map::new();
                
                let interfaces = if config.options.include_sensitive {
                    snapshot.interfaces.clone()
                } else {
                    self.sanitize_interfaces(&snapshot.interfaces)
                };
                
                let connections = if config.options.include_sensitive {
                    snapshot.connections.clone()
                } else {
                    self.sanitize_connections(&snapshot.connections)
                };

                complete_data.insert("interfaces".to_string(), serde_json::to_value(interfaces)?);
                complete_data.insert("dns_servers".to_string(), serde_json::to_value(&snapshot.dns_servers)?);
                complete_data.insert("routes".to_string(), serde_json::to_value(&snapshot.routes)?);
                complete_data.insert("connections".to_string(), serde_json::to_value(connections)?);
                complete_data.insert("timestamp".to_string(), serde_json::to_value(snapshot.timestamp)?);
                
                serde_json::Value::Object(complete_data)
            }
        };

        let json_string = if config.include_metadata {
            serde_json::to_string_pretty(&data)?
        } else {
            serde_json::to_string(&data)?
        };

        fs::write(output_path, &json_string).await?;
        
        let file_size = json_string.len() as u64;
        let record_count = self.count_records(&data);

        Ok((file_size, record_count))
    }

    /// Export as CSV
    async fn export_csv(
        &self,
        snapshot: &NetworkSnapshot,
        config: &ExportConfig,
        output_path: &Path,
    ) -> Result<(u64, usize)> {
        debug!("Exporting to CSV: {:?}", output_path);

        let csv_content = match config.data_type {
            ExportDataType::Interfaces => {
                self.interfaces_to_csv(&snapshot.interfaces, config.options.include_sensitive)?
            }
            ExportDataType::DnsServers => {
                self.dns_servers_to_csv(&snapshot.dns_servers)?
            }
            ExportDataType::Routes => {
                self.routes_to_csv(&snapshot.routes)?
            }
            ExportDataType::Connections => {
                self.connections_to_csv(&snapshot.connections, config.options.include_sensitive)?
            }
            ExportDataType::Complete => {
                return Err(DashError::ExportError("CSV export does not support complete data type".to_string()));
            }
        };

        fs::write(output_path, &csv_content).await?;
        
        let file_size = csv_content.len() as u64;
        let record_count = csv_content.lines().count().saturating_sub(1); // Subtract header

        Ok((file_size, record_count))
    }

    /// Export as PDF (placeholder implementation)
    async fn export_pdf(
        &self,
        _snapshot: &NetworkSnapshot,
        _config: &ExportConfig,
        output_path: &Path,
    ) -> Result<(u64, usize)> {
        debug!("Exporting to PDF: {:?}", output_path);

        // TODO: Implement actual PDF generation
        // For now, create a placeholder PDF-like text file
        let pdf_content = "PDF Export Placeholder\nThis would contain formatted network data in PDF format.";
        fs::write(output_path, pdf_content).await?;
        
        let file_size = pdf_content.len() as u64;
        let record_count = 1;

        Ok((file_size, record_count))
    }

    /// Generate output file path
    fn generate_output_path(&self, format: &ExportFormat, data_type: &ExportDataType) -> Result<PathBuf> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let extension = match format {
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
            ExportFormat::Pdf => "pdf",
        };
        
        let data_type_str = match data_type {
            ExportDataType::Interfaces => "interfaces",
            ExportDataType::DnsServers => "dns",
            ExportDataType::Routes => "routes",
            ExportDataType::Connections => "connections",
            ExportDataType::Complete => "complete",
        };

        let filename = format!("ghostdash_{}_{}.{}", data_type_str, timestamp, extension);
        Ok(self.output_directory.join(filename))
    }

    /// Calculate file hash
    async fn calculate_file_hash(&self, file_path: &Path) -> Result<String> {
        let content = fs::read(file_path).await?;
        let hash = sha2::Sha256::digest(&content);
        Ok(hex::encode(hash))
    }

    /// Sign file with PQ signature
    async fn sign_file(&self, file_path: &Path) -> Result<String> {
        let content = fs::read(file_path).await?;
        let signature = self.signer.sign(&self.private_key, &content)
            .map_err(|e| DashError::CryptoError(e))?;
        Ok(hex::encode(&signature.signature))
    }

    /// Count records in JSON data
    fn count_records(&self, data: &serde_json::Value) -> usize {
        match data {
            serde_json::Value::Array(arr) => arr.len(),
            serde_json::Value::Object(obj) => {
                obj.values()
                    .filter_map(|v| v.as_array())
                    .map(|arr| arr.len())
                    .sum()
            }
            _ => 1,
        }
    }

    /// Sanitize interfaces (remove sensitive data)
    fn sanitize_interfaces(&self, interfaces: &[InterfaceInfo]) -> Vec<InterfaceInfo> {
        interfaces.iter()
            .map(|interface| {
                let mut sanitized = interface.clone();
                // Could remove MAC addresses or other sensitive info based on policy
                sanitized
            })
            .collect()
    }

    /// Sanitize connections (remove PIDs and process names)
    fn sanitize_connections(&self, connections: &[ConnectionInfo]) -> Vec<ConnectionInfo> {
        connections.iter()
            .map(|conn| {
                let mut sanitized = conn.clone();
                sanitized.pid = None;
                sanitized.process = None;
                sanitized
            })
            .collect()
    }

    /// Convert interfaces to CSV
    fn interfaces_to_csv(&self, interfaces: &[InterfaceInfo], _include_sensitive: bool) -> Result<String> {
        let mut csv = String::new();
        csv.push_str("ID,Name,MAC,IPv4,IPv6,Gateway,DHCP,Status,Type\n");

        for interface in interfaces {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{:?},{}\n",
                interface.id,
                interface.name,
                interface.mac.as_deref().unwrap_or(""),
                interface.ipv4.as_deref().unwrap_or(""),
                interface.ipv6.as_deref().unwrap_or(""),
                interface.gateway.as_deref().unwrap_or(""),
                interface.dhcp,
                interface.status,
                interface.interface_type
            ));
        }

        Ok(csv)
    }

    /// Convert DNS servers to CSV
    fn dns_servers_to_csv(&self, dns_servers: &[DnsInfo]) -> Result<String> {
        let mut csv = String::new();
        csv.push_str("Interface,Server,Primary,Status,ResponseTime\n");

        for dns in dns_servers {
            csv.push_str(&format!(
                "{},{},{},{:?},{}\n",
                dns.interface,
                dns.server,
                dns.is_primary,
                dns.status,
                dns.response_time_ms.map(|t| t.to_string()).unwrap_or_else(|| "".to_string())
            ));
        }

        Ok(csv)
    }

    /// Convert routes to CSV
    fn routes_to_csv(&self, routes: &[RouteInfo]) -> Result<String> {
        let mut csv = String::new();
        csv.push_str("Destination,Mask,Gateway,Interface,Metric,Type\n");

        for route in routes {
            csv.push_str(&format!(
                "{},{},{},{},{},{:?}\n",
                route.destination,
                route.mask,
                route.gateway,
                route.interface,
                route.metric,
                route.route_type
            ));
        }

        Ok(csv)
    }

    /// Convert connections to CSV
    fn connections_to_csv(&self, connections: &[ConnectionInfo], include_sensitive: bool) -> Result<String> {
        let mut csv = String::new();
        
        if include_sensitive {
            csv.push_str("Protocol,Local,Remote,State,PID,Process\n");
            for conn in connections {
                csv.push_str(&format!(
                    "{},{},{},{:?},{},{}\n",
                    conn.protocol,
                    conn.local_address,
                    conn.remote_address,
                    conn.state,
                    conn.pid.map(|p| p.to_string()).unwrap_or_else(|| "".to_string()),
                    conn.process.as_deref().unwrap_or("")
                ));
            }
        } else {
            csv.push_str("Protocol,Local,Remote,State\n");
            for conn in connections {
                csv.push_str(&format!(
                    "{},{},{},{:?}\n",
                    conn.protocol,
                    conn.local_address,
                    conn.remote_address,
                    conn.state
                ));
            }
        }

        Ok(csv)
    }
}

// Add missing import for sha2
use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InterfaceStatus, DnsStatus, RouteType, ConnectionState};
    use tempfile::TempDir;

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
            dns_servers: vec![
                DnsInfo {
                    interface: "Ethernet0".to_string(),
                    server: "8.8.8.8".to_string(),
                    is_primary: true,
                    status: DnsStatus::Reachable,
                    response_time_ms: Some(10),
                }
            ],
            routes: vec![
                RouteInfo {
                    destination: "0.0.0.0".to_string(),
                    mask: "0.0.0.0".to_string(),
                    gateway: "192.168.1.1".to_string(),
                    interface: "Ethernet0".to_string(),
                    metric: 25,
                    route_type: RouteType::Default,
                }
            ],
            connections: vec![
                ConnectionInfo {
                    protocol: "TCP".to_string(),
                    local_address: "192.168.1.100:80".to_string(),
                    remote_address: "0.0.0.0:0".to_string(),
                    state: ConnectionState::Listen,
                    pid: Some(1234),
                    process: Some("nginx".to_string()),
                    timestamp: Utc::now(),
                }
            ],
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_json_export() {
        let temp_dir = TempDir::new().unwrap();
        let exporter = NetworkExporter::new(temp_dir.path().to_path_buf()).unwrap();
        
        let snapshot = create_test_snapshot();
        let config = ExportConfig {
            format: ExportFormat::Json,
            include_signature: false,
            include_metadata: true,
            output_path: None,
            data_type: ExportDataType::Interfaces,
            options: ExportOptions::default(),
        };

        let result = exporter.export_snapshot(&snapshot, &config).await.unwrap();
        
        assert_eq!(result.format, ExportFormat::Json);
        assert_eq!(result.record_count, 1);
        assert!(result.file_size > 0);
        assert!(result.file_path.exists());
    }

    #[tokio::test]
    async fn test_csv_export() {
        let temp_dir = TempDir::new().unwrap();
        let exporter = NetworkExporter::new(temp_dir.path().to_path_buf()).unwrap();
        
        let snapshot = create_test_snapshot();
        let config = ExportConfig {
            format: ExportFormat::Csv,
            include_signature: false,
            include_metadata: false,
            output_path: None,
            data_type: ExportDataType::Connections,
            options: ExportOptions {
                include_sensitive: true,
                ..Default::default()
            },
        };

        let result = exporter.export_snapshot(&snapshot, &config).await.unwrap();
        
        assert_eq!(result.format, ExportFormat::Csv);
        assert_eq!(result.record_count, 1);
        assert!(result.file_size > 0);
    }

    #[test]
    fn test_interfaces_to_csv() {
        let temp_dir = TempDir::new().unwrap();
        let exporter = NetworkExporter::new(temp_dir.path().to_path_buf()).unwrap();
        
        let interfaces = vec![
            InterfaceInfo {
                id: "if-001".to_string(),
                name: "eth0".to_string(),
                mac: Some("00:11:22:33:44:55".to_string()),
                ipv4: Some("192.168.1.100".to_string()),
                ipv6: None,
                mask: None,
                gateway: Some("192.168.1.1".to_string()),
                dhcp: true,
                dns_suffix: None,
                status: InterfaceStatus::Up,
                interface_type: "Ethernet".to_string(),
                mtu: None,
                speed: None,
            }
        ];

        let csv = exporter.interfaces_to_csv(&interfaces, true).unwrap();
        
        assert!(csv.contains("ID,Name,MAC"));
        assert!(csv.contains("if-001,eth0"));
        assert!(csv.contains("192.168.1.100"));
    }
}
