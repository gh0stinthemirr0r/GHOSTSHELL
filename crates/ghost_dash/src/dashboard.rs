//! Main GhostDash dashboard system
//! 
//! Coordinates system monitoring, network collection, and data presentation

use crate::{
    DashError, Result, SystemMonitor, SystemInfo, SystemAlert, NetworkCollector, NetworkSnapshot,
    NetworkTableManager, NetworkExporter, ExportConfig, ExportResult, TableQuery, TableResult,
    InterfaceInfo, DnsInfo, RouteInfo, ConnectionInfo, TableStats,
};
use chrono::{DateTime, Utc};
use ghost_log::{get_ghost_log, LogSeverity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Update interval in seconds
    pub update_interval_seconds: u64,
    /// Enable system monitoring
    pub enable_system_monitoring: bool,
    /// Enable network monitoring
    pub enable_network_monitoring: bool,
    /// Enable automatic exports
    pub enable_auto_export: bool,
    /// Export directory
    pub export_directory: PathBuf,
    /// Maximum number of alerts to keep
    pub max_alerts: usize,
    /// Alert thresholds
    pub alert_thresholds: AlertThresholds,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            update_interval_seconds: 5,
            enable_system_monitoring: true,
            enable_network_monitoring: true,
            enable_auto_export: false,
            export_directory: PathBuf::from("exports"),
            max_alerts: 100,
            alert_thresholds: AlertThresholds::default(),
        }
    }
}

/// Alert threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// CPU usage warning threshold (percentage)
    pub cpu_warning: f32,
    /// CPU usage critical threshold (percentage)
    pub cpu_critical: f32,
    /// Memory usage warning threshold (percentage)
    pub memory_warning: f32,
    /// Memory usage critical threshold (percentage)
    pub memory_critical: f32,
    /// Disk usage warning threshold (percentage)
    pub disk_warning: f32,
    /// Disk usage critical threshold (percentage)
    pub disk_critical: f32,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            cpu_warning: 75.0,
            cpu_critical: 90.0,
            memory_warning: 85.0,
            memory_critical: 95.0,
            disk_warning: 85.0,
            disk_critical: 95.0,
        }
    }
}

/// Complete dashboard state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardState {
    /// System information
    pub system_info: Option<SystemInfo>,
    /// Network snapshot
    pub network_snapshot: Option<NetworkSnapshot>,
    /// Active alerts
    pub alerts: Vec<SystemAlert>,
    /// Dashboard statistics
    pub stats: DashboardStats,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    /// Total number of updates performed
    pub total_updates: u64,
    /// Number of failed updates
    pub failed_updates: u64,
    /// Average update time in milliseconds
    pub avg_update_time_ms: u64,
    /// Number of exports performed
    pub total_exports: u64,
    /// Dashboard uptime in seconds
    pub uptime_seconds: u64,
}

impl Default for DashboardStats {
    fn default() -> Self {
        Self {
            total_updates: 0,
            failed_updates: 0,
            avg_update_time_ms: 0,
            total_exports: 0,
            uptime_seconds: 0,
        }
    }
}

/// Main GhostDash system
pub struct GhostDash {
    config: DashboardConfig,
    system_monitor: Arc<Mutex<SystemMonitor>>,
    network_collector: Arc<Mutex<NetworkCollector>>,
    table_manager: Arc<RwLock<NetworkTableManager>>,
    exporter: Arc<NetworkExporter>,
    state: Arc<RwLock<DashboardState>>,
    start_time: DateTime<Utc>,
}

impl GhostDash {
    /// Create a new GhostDash instance
    pub async fn new(config: DashboardConfig) -> Result<Self> {
        info!("Initializing GhostDash with config: {:?}", config);

        // Initialize components
        let system_monitor = Arc::new(Mutex::new(SystemMonitor::new()));
        let network_collector = Arc::new(Mutex::new(NetworkCollector::new()));
        let table_manager = Arc::new(RwLock::new(NetworkTableManager::new()));
        let exporter = Arc::new(NetworkExporter::new(config.export_directory.clone())?);

        // Initialize state
        let state = Arc::new(RwLock::new(DashboardState {
            system_info: None,
            network_snapshot: None,
            alerts: Vec::new(),
            stats: DashboardStats::default(),
            last_update: Utc::now(),
        }));

        let dashboard = Self {
            config,
            system_monitor,
            network_collector,
            table_manager,
            exporter,
            state,
            start_time: Utc::now(),
        };

        // Log initialization
        if let Some(ghost_log) = get_ghost_log() {
            let _ = ghost_log.log(
                "ghostdash",
                LogSeverity::Info,
                "dashboard-initialized",
                "GhostDash dashboard system initialized successfully"
            );
        }

        Ok(dashboard)
    }

    /// Start the dashboard monitoring loop
    pub async fn start(&self) -> Result<()> {
        info!("Starting GhostDash monitoring loop");

        let mut update_interval = interval(Duration::from_secs(self.config.update_interval_seconds));

        loop {
            update_interval.tick().await;

            let update_start = std::time::Instant::now();
            
            match self.update_all().await {
                Ok(()) => {
                    let update_time = update_start.elapsed().as_millis() as u64;
                    self.update_stats(update_time, false).await;
                    debug!("Dashboard update completed in {}ms", update_time);
                }
                Err(e) => {
                    error!("Dashboard update failed: {}", e);
                    self.update_stats(0, true).await;
                    
                    // Log error
                    if let Some(ghost_log) = get_ghost_log() {
                        let _ = ghost_log.log(
                            "ghostdash",
                            LogSeverity::Error,
                            "dashboard-update-failed",
                            &format!("Dashboard update failed: {}", e)
                        );
                    }
                }
            }
        }
    }

    /// Update all dashboard data
    pub async fn update_all(&self) -> Result<()> {
        debug!("Updating all dashboard data");

        // Update system information
        let system_info = if self.config.enable_system_monitoring {
            let mut monitor = self.system_monitor.lock().await;
            Some(monitor.get_system_info()?)
        } else {
            None
        };

        // Update network information
        let network_snapshot = if self.config.enable_network_monitoring {
            let mut collector = self.network_collector.lock().await;
            Some(collector.collect_all().await?)
        } else {
            None
        };

        // Update table manager with new network data
        if let Some(ref snapshot) = network_snapshot {
            let mut table_manager = self.table_manager.write().await;
            table_manager.update_snapshot(snapshot.clone());
        }

        // Generate alerts
        let alerts = if let Some(ref sys_info) = system_info {
            self.generate_alerts(sys_info).await?
        } else {
            Vec::new()
        };

        // Update state
        {
            let mut state = self.state.write().await;
            state.system_info = system_info;
            state.network_snapshot = network_snapshot;
            state.alerts = alerts;
            state.last_update = Utc::now();
        }

        Ok(())
    }

    /// Get current dashboard state
    pub async fn get_state(&self) -> DashboardState {
        let state = self.state.read().await;
        state.clone()
    }

    /// Get system information
    pub async fn get_system_info(&self) -> Result<Option<SystemInfo>> {
        if !self.config.enable_system_monitoring {
            return Ok(None);
        }

        let mut monitor = self.system_monitor.lock().await;
        Ok(Some(monitor.get_system_info()?))
    }

    /// Get network snapshot
    pub async fn get_network_snapshot(&self) -> Result<Option<NetworkSnapshot>> {
        if !self.config.enable_network_monitoring {
            return Ok(None);
        }

        let mut collector = self.network_collector.lock().await;
        Ok(Some(collector.collect_all().await?))
    }

    /// Query interfaces table
    pub async fn query_interfaces(&self, query: &TableQuery) -> Result<TableResult<InterfaceInfo>> {
        let table_manager = self.table_manager.read().await;
        table_manager.query_interfaces(query)
    }

    /// Query DNS servers table
    pub async fn query_dns_servers(&self, query: &TableQuery) -> Result<TableResult<DnsInfo>> {
        let table_manager = self.table_manager.read().await;
        table_manager.query_dns_servers(query)
    }

    /// Query routes table
    pub async fn query_routes(&self, query: &TableQuery) -> Result<TableResult<RouteInfo>> {
        let table_manager = self.table_manager.read().await;
        table_manager.query_routes(query)
    }

    /// Query connections table
    pub async fn query_connections(&self, query: &TableQuery) -> Result<TableResult<ConnectionInfo>> {
        let table_manager = self.table_manager.read().await;
        table_manager.query_connections(query)
    }

    /// Export network data
    pub async fn export_data(&self, config: &ExportConfig) -> Result<ExportResult> {
        let state = self.state.read().await;
        
        let snapshot = state.network_snapshot.as_ref()
            .ok_or_else(|| DashError::InvalidInput("No network snapshot available for export".to_string()))?;

        let result = self.exporter.export_snapshot(snapshot, config).await?;

        // Update export statistics
        {
            let mut state = self.state.write().await;
            state.stats.total_exports += 1;
        }

        // Log export
        if let Some(ghost_log) = get_ghost_log() {
            let context = std::collections::HashMap::from([
                ("format".to_string(), serde_json::Value::String(format!("{:?}", config.format))),
                ("data_type".to_string(), serde_json::Value::String(format!("{:?}", config.data_type))),
                ("file_size".to_string(), serde_json::Value::Number(result.file_size.into())),
                ("record_count".to_string(), serde_json::Value::Number(result.record_count.into())),
            ]);

            let _ = ghost_log.log_with_context(
                "ghostdash",
                LogSeverity::Info,
                "data-exported",
                &format!("Network data exported: {} records", result.record_count),
                context
            );
        }

        Ok(result)
    }

    /// Get table statistics
    pub async fn get_table_stats(&self) -> Result<TableStats> {
        let table_manager = self.table_manager.read().await;
        table_manager.get_table_stats()
    }

    /// Get dashboard statistics
    pub async fn get_dashboard_stats(&self) -> DashboardStats {
        let mut state = self.state.read().await;
        let mut stats = state.stats.clone();
        
        // Update uptime
        stats.uptime_seconds = Utc::now().signed_duration_since(self.start_time).num_seconds() as u64;
        
        stats
    }

    /// Generate system alerts
    async fn generate_alerts(&self, system_info: &SystemInfo) -> Result<Vec<SystemAlert>> {
        let mut alerts = Vec::new();

        // CPU alerts
        if system_info.cpu_usage_percent > self.config.alert_thresholds.cpu_critical {
            alerts.push(SystemAlert {
                id: "high-cpu".to_string(),
                severity: crate::system::AlertSeverity::Critical,
                title: "Critical CPU Usage".to_string(),
                message: format!("CPU usage is {:.1}%", system_info.cpu_usage_percent),
                timestamp: Utc::now(),
                category: crate::system::AlertCategory::Performance,
            });
        } else if system_info.cpu_usage_percent > self.config.alert_thresholds.cpu_warning {
            alerts.push(SystemAlert {
                id: "elevated-cpu".to_string(),
                severity: crate::system::AlertSeverity::Warning,
                title: "High CPU Usage".to_string(),
                message: format!("CPU usage is {:.1}%", system_info.cpu_usage_percent),
                timestamp: Utc::now(),
                category: crate::system::AlertCategory::Performance,
            });
        }

        // Memory alerts
        if system_info.memory_usage_percent > self.config.alert_thresholds.memory_critical {
            alerts.push(SystemAlert {
                id: "high-memory".to_string(),
                severity: crate::system::AlertSeverity::Critical,
                title: "Critical Memory Usage".to_string(),
                message: format!("Memory usage is {:.1}%", system_info.memory_usage_percent),
                timestamp: Utc::now(),
                category: crate::system::AlertCategory::Performance,
            });
        } else if system_info.memory_usage_percent > self.config.alert_thresholds.memory_warning {
            alerts.push(SystemAlert {
                id: "elevated-memory".to_string(),
                severity: crate::system::AlertSeverity::Warning,
                title: "High Memory Usage".to_string(),
                message: format!("Memory usage is {:.1}%", system_info.memory_usage_percent),
                timestamp: Utc::now(),
                category: crate::system::AlertCategory::Performance,
            });
        }

        // Disk alerts
        for disk in &system_info.disks {
            if disk.usage_percent > self.config.alert_thresholds.disk_critical {
                alerts.push(SystemAlert {
                    id: format!("disk-critical-{}", disk.name),
                    severity: crate::system::AlertSeverity::Critical,
                    title: "Critical Disk Usage".to_string(),
                    message: format!("Disk {} is {:.1}% full", disk.name, disk.usage_percent),
                    timestamp: Utc::now(),
                    category: crate::system::AlertCategory::Storage,
                });
            } else if disk.usage_percent > self.config.alert_thresholds.disk_warning {
                alerts.push(SystemAlert {
                    id: format!("disk-warning-{}", disk.name),
                    severity: crate::system::AlertSeverity::Warning,
                    title: "High Disk Usage".to_string(),
                    message: format!("Disk {} is {:.1}% full", disk.name, disk.usage_percent),
                    timestamp: Utc::now(),
                    category: crate::system::AlertCategory::Storage,
                });
            }
        }

        // Network alerts (placeholder - could add network-specific alerts)
        // TODO: Add network latency, packet loss, interface down alerts

        // Limit number of alerts
        if alerts.len() > self.config.max_alerts {
            alerts.truncate(self.config.max_alerts);
        }

        Ok(alerts)
    }

    /// Update dashboard statistics
    async fn update_stats(&self, update_time_ms: u64, failed: bool) {
        let mut state = self.state.write().await;
        
        state.stats.total_updates += 1;
        
        if failed {
            state.stats.failed_updates += 1;
        } else {
            // Update average update time (simple moving average)
            let total_successful = state.stats.total_updates - state.stats.failed_updates;
            if total_successful > 0 {
                state.stats.avg_update_time_ms = 
                    ((state.stats.avg_update_time_ms * (total_successful - 1)) + update_time_ms) / total_successful;
            }
        }
    }

    /// Create a snapshot of current state for vault storage
    pub async fn create_snapshot(&self) -> Result<DashboardSnapshot> {
        let state = self.state.read().await;
        
        Ok(DashboardSnapshot {
            timestamp: Utc::now(),
            system_info: state.system_info.clone(),
            network_snapshot: state.network_snapshot.clone(),
            alerts: state.alerts.clone(),
            stats: state.stats.clone(),
            config: self.config.clone(),
        })
    }
}

/// Dashboard snapshot for vault storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    /// Snapshot timestamp
    pub timestamp: DateTime<Utc>,
    /// System information at time of snapshot
    pub system_info: Option<SystemInfo>,
    /// Network snapshot
    pub network_snapshot: Option<NetworkSnapshot>,
    /// Active alerts
    pub alerts: Vec<SystemAlert>,
    /// Dashboard statistics
    pub stats: DashboardStats,
    /// Dashboard configuration
    pub config: DashboardConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_dashboard_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = DashboardConfig {
            export_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let dashboard = GhostDash::new(config).await.unwrap();
        let state = dashboard.get_state().await;
        
        assert!(state.system_info.is_none());
        assert!(state.network_snapshot.is_none());
        assert_eq!(state.alerts.len(), 0);
    }

    #[tokio::test]
    async fn test_dashboard_update() {
        let temp_dir = TempDir::new().unwrap();
        let config = DashboardConfig {
            export_directory: temp_dir.path().to_path_buf(),
            enable_system_monitoring: true,
            enable_network_monitoring: true,
            ..Default::default()
        };

        let dashboard = GhostDash::new(config).await.unwrap();
        dashboard.update_all().await.unwrap();
        
        let state = dashboard.get_state().await;
        assert!(state.system_info.is_some());
        assert!(state.network_snapshot.is_some());
    }

    #[tokio::test]
    async fn test_dashboard_stats() {
        let temp_dir = TempDir::new().unwrap();
        let config = DashboardConfig {
            export_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let dashboard = GhostDash::new(config).await.unwrap();
        let stats = dashboard.get_dashboard_stats().await;
        
        assert_eq!(stats.total_updates, 0);
        assert_eq!(stats.failed_updates, 0);
        assert!(stats.uptime_seconds >= 0);
    }
}
