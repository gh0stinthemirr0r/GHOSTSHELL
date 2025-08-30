//! Simplified system information collection
//! 
//! Provides basic system telemetry that works with current sysinfo API

use crate::{DashError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tracing::{debug, info};

/// System information snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// System hostname
    pub hostname: String,
    /// Operating system name and version
    pub os_name: String,
    /// OS version details
    pub os_version: String,
    /// System uptime in seconds
    pub uptime: u64,
    /// Boot time
    pub boot_time: DateTime<Utc>,
    /// Total RAM in bytes
    pub total_memory: u64,
    /// Available RAM in bytes
    pub available_memory: u64,
    /// Used RAM in bytes
    pub used_memory: u64,
    /// Memory usage percentage
    pub memory_usage_percent: f32,
    /// CPU usage percentage (average across cores)
    pub cpu_usage_percent: f32,
    /// Number of CPU cores
    pub cpu_cores: usize,
    /// CPU brand/model
    pub cpu_brand: String,
    /// Disk information
    pub disks: Vec<DiskInfo>,
    /// Network interfaces summary
    pub network_summary: NetworkSummary,
    /// Running processes count
    pub process_count: usize,
    /// Timestamp of this snapshot
    pub timestamp: DateTime<Utc>,
}

/// Disk information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    /// Disk name/mount point
    pub name: String,
    /// File system type
    pub file_system: String,
    /// Total space in bytes
    pub total_space: u64,
    /// Available space in bytes
    pub available_space: u64,
    /// Used space in bytes
    pub used_space: u64,
    /// Usage percentage
    pub usage_percent: f32,
    /// Whether the disk is removable
    pub is_removable: bool,
}

/// Network interfaces summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// Total number of interfaces
    pub interface_count: usize,
    /// Total bytes received across all interfaces
    pub total_bytes_received: u64,
    /// Total bytes transmitted across all interfaces
    pub total_bytes_transmitted: u64,
    /// Total packets received
    pub total_packets_received: u64,
    /// Total packets transmitted
    pub total_packets_transmitted: u64,
    /// Total errors received
    pub total_errors_received: u64,
    /// Total errors transmitted
    pub total_errors_transmitted: u64,
}

/// System resource monitor
pub struct SystemMonitor {
    system: System,
    last_update: Option<DateTime<Utc>>,
}

impl SystemMonitor {
    /// Create a new system monitor
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        
        Self {
            system,
            last_update: None,
        }
    }

    /// Refresh system information
    pub fn refresh(&mut self) -> Result<()> {
        debug!("Refreshing system information");
        
        self.system.refresh_all();
        self.last_update = Some(Utc::now());
        
        Ok(())
    }

    /// Get current system information
    pub fn get_system_info(&mut self) -> Result<SystemInfo> {
        // Ensure we have fresh data
        if self.last_update.is_none() || 
           Utc::now().signed_duration_since(self.last_update.unwrap()).num_seconds() > 5 {
            self.refresh()?;
        }

        let hostname = System::host_name()
            .unwrap_or_else(|| "unknown".to_string());
        
        let os_name = System::name()
            .unwrap_or_else(|| "unknown".to_string());
        
        let os_version = System::os_version()
            .unwrap_or_else(|| "unknown".to_string());

        let uptime = System::uptime();
        let boot_time = Utc::now() - chrono::Duration::seconds(uptime as i64);

        let total_memory = self.system.total_memory();
        let used_memory = self.system.used_memory();
        let available_memory = total_memory - used_memory;
        let memory_usage_percent = if total_memory > 0 {
            (used_memory as f32 / total_memory as f32) * 100.0
        } else {
            0.0
        };

        // Calculate average CPU usage
        let cpus = self.system.cpus();
        let cpu_usage_percent = if !cpus.is_empty() {
            cpus.iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / cpus.len() as f32
        } else {
            0.0
        };

        let cpu_cores = cpus.len();
        let cpu_brand = cpus.first()
            .map(|cpu| cpu.brand().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Collect disk information (simplified for compatibility)
        let disks: Vec<DiskInfo> = Vec::new(); // Placeholder - would implement actual disk collection

        // Simplified network summary (placeholder values)
        let network_summary = NetworkSummary {
            interface_count: 1, // Simplified
            total_bytes_received: 0,
            total_bytes_transmitted: 0,
            total_packets_received: 0,
            total_packets_transmitted: 0,
            total_errors_received: 0,
            total_errors_transmitted: 0,
        };

        let process_count = self.system.processes().len();

        let system_info = SystemInfo {
            hostname,
            os_name,
            os_version,
            uptime,
            boot_time,
            total_memory,
            available_memory,
            used_memory,
            memory_usage_percent,
            cpu_usage_percent,
            cpu_cores,
            cpu_brand,
            disks,
            network_summary,
            process_count,
            timestamp: Utc::now(),
        };

        debug!("System info collected: {} cores, {:.1}% CPU, {:.1}% memory", 
               cpu_cores, cpu_usage_percent, memory_usage_percent);

        Ok(system_info)
    }

    /// Get system alerts based on thresholds
    pub fn get_system_alerts(&mut self) -> Result<Vec<SystemAlert>> {
        let system_info = self.get_system_info()?;
        let mut alerts = Vec::new();

        // CPU usage alert
        if system_info.cpu_usage_percent > 90.0 {
            alerts.push(SystemAlert {
                id: "high-cpu".to_string(),
                severity: AlertSeverity::Critical,
                title: "High CPU Usage".to_string(),
                message: format!("CPU usage is {:.1}%", system_info.cpu_usage_percent),
                timestamp: Utc::now(),
                category: AlertCategory::Performance,
            });
        } else if system_info.cpu_usage_percent > 75.0 {
            alerts.push(SystemAlert {
                id: "elevated-cpu".to_string(),
                severity: AlertSeverity::Warning,
                title: "Elevated CPU Usage".to_string(),
                message: format!("CPU usage is {:.1}%", system_info.cpu_usage_percent),
                timestamp: Utc::now(),
                category: AlertCategory::Performance,
            });
        }

        // Memory usage alert
        if system_info.memory_usage_percent > 95.0 {
            alerts.push(SystemAlert {
                id: "high-memory".to_string(),
                severity: AlertSeverity::Critical,
                title: "High Memory Usage".to_string(),
                message: format!("Memory usage is {:.1}%", system_info.memory_usage_percent),
                timestamp: Utc::now(),
                category: AlertCategory::Performance,
            });
        } else if system_info.memory_usage_percent > 85.0 {
            alerts.push(SystemAlert {
                id: "elevated-memory".to_string(),
                severity: AlertSeverity::Warning,
                title: "Elevated Memory Usage".to_string(),
                message: format!("Memory usage is {:.1}%", system_info.memory_usage_percent),
                timestamp: Utc::now(),
                category: AlertCategory::Performance,
            });
        }

        // Disk usage alerts
        for disk in &system_info.disks {
            if disk.usage_percent > 95.0 {
                alerts.push(SystemAlert {
                    id: format!("disk-full-{}", disk.name),
                    severity: AlertSeverity::Critical,
                    title: "Disk Nearly Full".to_string(),
                    message: format!("Disk {} is {:.1}% full", disk.name, disk.usage_percent),
                    timestamp: Utc::now(),
                    category: AlertCategory::Storage,
                });
            } else if disk.usage_percent > 85.0 {
                alerts.push(SystemAlert {
                    id: format!("disk-high-{}", disk.name),
                    severity: AlertSeverity::Warning,
                    title: "High Disk Usage".to_string(),
                    message: format!("Disk {} is {:.1}% full", disk.name, disk.usage_percent),
                    timestamp: Utc::now(),
                    category: AlertCategory::Storage,
                });
            }
        }

        if !alerts.is_empty() {
            info!("Generated {} system alerts", alerts.len());
        }

        Ok(alerts)
    }
}

impl Default for SystemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// System alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemAlert {
    /// Unique alert ID
    pub id: String,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert title
    pub title: String,
    /// Alert message
    pub message: String,
    /// Alert timestamp
    pub timestamp: DateTime<Utc>,
    /// Alert category
    pub category: AlertCategory,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Alert categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertCategory {
    Performance,
    Storage,
    Network,
    Security,
    System,
}
