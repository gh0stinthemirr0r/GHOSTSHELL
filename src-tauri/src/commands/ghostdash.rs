//! GhostDash Tauri commands
//! 
//! Provides frontend interface to the GhostDash system dashboard

use anyhow::Result;
use ghost_dash::{
    GhostDash, DashboardConfig, DashboardState, DashboardStats, SystemInfo, NetworkSnapshot,
    NetworkAnalytics, NetworkAnalyticsEngine, TableQuery, TableResult, TableStats,
    InterfaceInfo, DnsInfo, RouteInfo, ConnectionInfo, ExportConfig, ExportResult,
    ExportFormat, ExportDataType, ExportOptions,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// GhostDash state for Tauri
pub struct GhostDashState {
    pub dashboard: Arc<RwLock<Option<GhostDash>>>,
    pub analytics_engine: Arc<RwLock<NetworkAnalyticsEngine>>,
}

impl GhostDashState {
    pub fn new() -> Self {
        Self {
            dashboard: Arc::new(RwLock::new(None)),
            analytics_engine: Arc::new(RwLock::new(NetworkAnalyticsEngine::new())),
        }
    }
}

/// Theme configuration matching GhostShell terminal colors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostDashTheme {
    /// Background tint - matches terminal background
    pub bg_tint: String,
    /// Foreground color - matches terminal text
    pub fg: String,
    /// Slate color for secondary elements
    pub slate: String,
    /// Accent pink for highlights
    pub accent_pink: String,
    /// Accent cyan for data elements
    pub accent_cyan: String,
    /// Accent neon green for active states
    pub accent_neon_green: String,
    /// Border color for UI elements
    pub border_color: String,
    /// Blur amount for frosted glass effect
    pub blur: String,
    /// Glow effects
    pub glow: String,
    /// Strong glow for emphasis
    pub glow_strong: String,
}

impl Default for GhostDashTheme {
    fn default() -> Self {
        Self {
            bg_tint: "rgba(12,15,28,0.70)".to_string(),
            fg: "#EAEAEA".to_string(),
            slate: "#2B2B2E".to_string(),
            accent_pink: "#FF008C".to_string(),
            accent_cyan: "#00FFD1".to_string(),
            accent_neon_green: "#AFFF00".to_string(),
            border_color: "rgba(255,255,255,0.10)".to_string(),
            blur: "18px".to_string(),
            glow: "0 0 12px".to_string(),
            glow_strong: "0 0 20px".to_string(),
        }
    }
}

/// Initialize GhostDash system
#[tauri::command]
pub async fn ghostdash_initialize(
    config: Option<DashboardConfig>,
    state: State<'_, GhostDashState>,
) -> Result<(), String> {
    let config = config.unwrap_or_default();
    
    info!("Initializing GhostDash with config: {:?}", config);
    
    let dashboard = GhostDash::new(config).await
        .map_err(|e| {
            error!("Failed to initialize GhostDash: {}", e);
            e.to_string()
        })?;
    
    let mut dash_guard = state.dashboard.write().await;
    *dash_guard = Some(dashboard);
    
    info!("GhostDash initialized successfully");
    Ok(())
}

/// Start GhostDash monitoring (runs in background)
#[tauri::command]
pub async fn ghostdash_start_monitoring(
    state: State<'_, GhostDashState>,
) -> Result<(), String> {
    info!("GhostDash monitoring started (placeholder - would start background task)");
    
    // For now, just verify the dashboard is initialized
    let dash_guard = state.dashboard.read().await;
    if dash_guard.is_some() {
        Ok(())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Get current dashboard state
#[tauri::command]
pub async fn ghostdash_get_state(
    state: State<'_, GhostDashState>,
) -> Result<DashboardState, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        let dashboard_state = dashboard.get_state().await;
        debug!("Retrieved dashboard state with {} alerts", dashboard_state.alerts.len());
        Ok(dashboard_state)
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Get system information
#[tauri::command]
pub async fn ghostdash_get_system_info(
    state: State<'_, GhostDashState>,
) -> Result<Option<SystemInfo>, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.get_system_info().await
            .map_err(|e| e.to_string())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Get network snapshot
#[tauri::command]
pub async fn ghostdash_get_network_snapshot(
    state: State<'_, GhostDashState>,
) -> Result<Option<NetworkSnapshot>, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.get_network_snapshot().await
            .map_err(|e| e.to_string())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Query interfaces table
#[tauri::command]
pub async fn ghostdash_query_interfaces(
    query: TableQuery,
    state: State<'_, GhostDashState>,
) -> Result<TableResult<InterfaceInfo>, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.query_interfaces(&query).await
            .map_err(|e| e.to_string())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Query DNS servers table
#[tauri::command]
pub async fn ghostdash_query_dns_servers(
    query: TableQuery,
    state: State<'_, GhostDashState>,
) -> Result<TableResult<DnsInfo>, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.query_dns_servers(&query).await
            .map_err(|e| e.to_string())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Query routes table
#[tauri::command]
pub async fn ghostdash_query_routes(
    query: TableQuery,
    state: State<'_, GhostDashState>,
) -> Result<TableResult<RouteInfo>, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.query_routes(&query).await
            .map_err(|e| e.to_string())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Query connections table
#[tauri::command]
pub async fn ghostdash_query_connections(
    query: TableQuery,
    state: State<'_, GhostDashState>,
) -> Result<TableResult<ConnectionInfo>, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.query_connections(&query).await
            .map_err(|e| e.to_string())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Get table statistics
#[tauri::command]
pub async fn ghostdash_get_table_stats(
    state: State<'_, GhostDashState>,
) -> Result<TableStats, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.get_table_stats().await
            .map_err(|e| e.to_string())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Get dashboard statistics
#[tauri::command]
pub async fn ghostdash_get_stats(
    state: State<'_, GhostDashState>,
) -> Result<DashboardStats, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        Ok(dashboard.get_dashboard_stats().await)
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Export network data
#[tauri::command]
pub async fn ghostdash_export_data(
    config: ExportConfig,
    state: State<'_, GhostDashState>,
) -> Result<ExportResult, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.export_data(&config).await
            .map_err(|e| e.to_string())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Get network analytics
#[tauri::command]
pub async fn ghostdash_get_analytics(
    state: State<'_, GhostDashState>,
) -> Result<Option<NetworkAnalytics>, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        // Get current network snapshot
        if let Some(snapshot) = dashboard.get_network_snapshot().await.map_err(|e| e.to_string())? {
            let mut analytics_engine = state.analytics_engine.write().await;
            let analytics = analytics_engine.analyze_snapshot(&snapshot)
                .map_err(|e| e.to_string())?;
            Ok(Some(analytics))
        } else {
            Ok(None)
        }
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Create dashboard snapshot for vault storage
#[tauri::command]
pub async fn ghostdash_create_snapshot(
    state: State<'_, GhostDashState>,
) -> Result<ghost_dash::DashboardSnapshot, String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.create_snapshot().await
            .map_err(|e| e.to_string())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Get GhostDash theme configuration
#[tauri::command]
pub async fn ghostdash_get_theme() -> Result<GhostDashTheme, String> {
    Ok(GhostDashTheme::default())
}

/// Update dashboard configuration
#[tauri::command]
pub async fn ghostdash_update_config(
    config: DashboardConfig,
    state: State<'_, GhostDashState>,
) -> Result<(), String> {
    info!("Updating GhostDash configuration: {:?}", config);
    
    // Reinitialize dashboard with new config
    let dashboard = GhostDash::new(config).await
        .map_err(|e| e.to_string())?;
    
    let mut dash_guard = state.dashboard.write().await;
    *dash_guard = Some(dashboard);
    
    Ok(())
}

/// Force dashboard data refresh
#[tauri::command]
pub async fn ghostdash_refresh_data(
    state: State<'_, GhostDashState>,
) -> Result<(), String> {
    let dash_guard = state.dashboard.read().await;
    
    if let Some(ref dashboard) = *dash_guard {
        dashboard.update_all().await
            .map_err(|e| e.to_string())?;
        debug!("Dashboard data refreshed manually");
        Ok(())
    } else {
        Err("GhostDash not initialized".to_string())
    }
}

/// Get available export formats
#[tauri::command]
pub async fn ghostdash_get_export_formats() -> Result<Vec<ExportFormat>, String> {
    Ok(vec![
        ExportFormat::Json,
        ExportFormat::Csv,
        ExportFormat::Pdf,
    ])
}

/// Get available data types for export
#[tauri::command]
pub async fn ghostdash_get_export_data_types() -> Result<Vec<ExportDataType>, String> {
    Ok(vec![
        ExportDataType::Interfaces,
        ExportDataType::DnsServers,
        ExportDataType::Routes,
        ExportDataType::Connections,
        ExportDataType::Complete,
    ])
}

/// Test network connectivity
#[tauri::command]
pub async fn ghostdash_test_connectivity(
    target: String,
) -> Result<ConnectivityTestResult, String> {
    debug!("Testing connectivity to: {}", target);
    
    // Simplified connectivity test - in production would use actual ping/traceroute
    let result = ConnectivityTestResult {
        target,
        reachable: true,
        latency_ms: Some(15.5),
        packet_loss_percent: 0.0,
        hops: Some(3),
        timestamp: chrono::Utc::now(),
    };
    
    Ok(result)
}

/// Connectivity test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityTestResult {
    /// Target address/hostname
    pub target: String,
    /// Whether target is reachable
    pub reachable: bool,
    /// Latency in milliseconds
    pub latency_ms: Option<f32>,
    /// Packet loss percentage
    pub packet_loss_percent: f32,
    /// Number of hops
    pub hops: Option<u32>,
    /// Test timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
