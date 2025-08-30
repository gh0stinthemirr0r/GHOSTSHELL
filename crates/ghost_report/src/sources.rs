//! Data source collectors for reports
//! 
//! Collects data from GhostLog and GhostDash for report generation

use crate::{ReportSource, ReportFilters, ReportError, ReportResult, PreviewStats};
use anyhow::Result;
use chrono::{DateTime, Utc};
use ghost_dash::{GhostDash, SystemInfo, NetworkSnapshot};
use ghost_log::{GhostLogDaemon, SearchQuery, LogSeverity};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Data collector that interfaces with various GhostShell systems
pub struct DataCollector {
    /// GhostLog daemon for log data
    ghost_log: Arc<RwLock<Option<Arc<GhostLogDaemon>>>>,
    /// GhostDash for system/network analytics
    ghost_dash: Arc<RwLock<Option<Arc<GhostDash>>>>,
}

impl DataCollector {
    /// Create a new data collector
    pub fn new() -> Self {
        Self {
            ghost_log: Arc::new(RwLock::new(None)),
            ghost_dash: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Initialize with GhostLog daemon
    pub async fn set_ghost_log(&self, ghost_log: Arc<GhostLogDaemon>) {
        let mut guard = self.ghost_log.write().await;
        *guard = Some(ghost_log);
    }
    
    /// Initialize with GhostDash
    pub async fn set_ghost_dash(&self, ghost_dash: Arc<GhostDash>) {
        let mut guard = self.ghost_dash.write().await;
        *guard = Some(ghost_dash);
    }
    
    /// Collect data from multiple sources
    pub async fn collect_data(
        &self,
        sources: &[ReportSource],
        filters: &ReportFilters,
    ) -> Result<Vec<HashMap<String, Value>>> {
        let mut all_data = Vec::new();
        
        for source in sources {
            let source_data = self.collect_from_source(source, filters).await?;
            all_data.extend(source_data);
        }
        
        debug!("Collected {} total data points from {} sources", 
               all_data.len(), sources.len());
        
        Ok(all_data)
    }
    
    /// Collect sample data for preview (limited rows)
    pub async fn collect_sample_data(
        &self,
        sources: &[ReportSource],
        filters: &ReportFilters,
        limit: usize,
    ) -> Result<Vec<HashMap<String, Value>>> {
        let mut all_data = Vec::new();
        let per_source_limit = limit / sources.len().max(1);
        
        for source in sources {
            let mut source_data = self.collect_from_source(source, filters).await?;
            source_data.truncate(per_source_limit);
            all_data.extend(source_data);
        }
        
        all_data.truncate(limit);
        Ok(all_data)
    }
    
    /// Get statistics about data without collecting it all
    pub async fn get_data_stats(
        &self,
        sources: &[ReportSource],
        filters: &ReportFilters,
    ) -> Result<PreviewStats> {
        let mut total_rows = 0u64;
        let mut rows_by_source = HashMap::new();
        let mut unique_entities = HashMap::new();
        let mut date_range: Option<(DateTime<Utc>, DateTime<Utc>)> = None;
        
        for source in sources {
            let source_stats = self.get_source_stats(source, filters).await?;
            let source_name = format!("{:?}", source);
            
            total_rows += source_stats.row_count;
            rows_by_source.insert(source_name, source_stats.row_count);
            
            // Update date range
            if let (Some(start), Some(end)) = (source_stats.date_start, source_stats.date_end) {
                date_range = Some(match date_range {
                    None => (start, end),
                    Some((existing_start, existing_end)) => (
                        start.min(existing_start),
                        end.max(existing_end),
                    ),
                });
            }
            
            // Merge unique entities
            for (key, count) in source_stats.unique_entities {
                *unique_entities.entry(key).or_insert(0) += count;
            }
        }
        
        Ok(PreviewStats {
            total_rows,
            rows_by_source,
            date_range,
            unique_entities,
        })
    }
    
    /// Collect data from a single source
    async fn collect_from_source(
        &self,
        source: &ReportSource,
        filters: &ReportFilters,
    ) -> Result<Vec<HashMap<String, Value>>> {
        match source {
            ReportSource::GhostLog { modules } => {
                self.collect_ghostlog_data(modules, filters).await
            }
            ReportSource::GhostDashSystem => {
                self.collect_ghostdash_system_data(filters).await
            }
            ReportSource::GhostDashNetwork => {
                self.collect_ghostdash_network_data(filters).await
            }
            ReportSource::GhostDashInterfaces => {
                self.collect_ghostdash_interfaces_data(filters).await
            }
            ReportSource::GhostDashDns => {
                self.collect_ghostdash_dns_data(filters).await
            }
            ReportSource::GhostDashRoutes => {
                self.collect_ghostdash_routes_data(filters).await
            }
            ReportSource::GhostDashConnections => {
                self.collect_ghostdash_connections_data(filters).await
            }
        }
    }
    
    /// Get statistics for a single source
    async fn get_source_stats(
        &self,
        source: &ReportSource,
        filters: &ReportFilters,
    ) -> Result<SourceStats> {
        // Simplified stats calculation - in production would query without full data retrieval
        let data = self.collect_from_source(source, filters).await?;
        
        let mut unique_entities = HashMap::new();
        let mut date_start: Option<DateTime<Utc>> = None;
        let mut date_end: Option<DateTime<Utc>> = None;
        
        for row in &data {
            // Extract timestamps if available
            if let Some(timestamp_val) = row.get("timestamp") {
                if let Ok(timestamp_str) = serde_json::from_value::<String>(timestamp_val.clone()) {
                    if let Ok(timestamp) = DateTime::parse_from_rfc3339(&timestamp_str) {
                        let utc_timestamp = timestamp.with_timezone(&Utc);
                        date_start = Some(date_start.map_or(utc_timestamp, |d| d.min(utc_timestamp)));
                        date_end = Some(date_end.map_or(utc_timestamp, |d| d.max(utc_timestamp)));
                    }
                }
            }
            
            // Count unique modules/interfaces/etc
            if let Some(module_val) = row.get("module") {
                if let Ok(module) = serde_json::from_value::<String>(module_val.clone()) {
                    *unique_entities.entry(format!("module:{}", module)).or_insert(0) += 1;
                }
            }
            
            if let Some(interface_val) = row.get("interface") {
                if let Ok(interface) = serde_json::from_value::<String>(interface_val.clone()) {
                    *unique_entities.entry(format!("interface:{}", interface)).or_insert(0) += 1;
                }
            }
        }
        
        Ok(SourceStats {
            row_count: data.len() as u64,
            unique_entities,
            date_start,
            date_end,
        })
    }
    
    /// Collect GhostLog data
    async fn collect_ghostlog_data(
        &self,
        modules: &[String],
        filters: &ReportFilters,
    ) -> Result<Vec<HashMap<String, Value>>> {
        // For now, create sample data since direct search isn't available
        let mut data = Vec::new();
        
        // Create sample log entries
        for i in 0..10 {
            let mut row = HashMap::new();
            
            row.insert("source".to_string(), Value::String("ghostlog".to_string()));
            row.insert("timestamp".to_string(), Value::String(Utc::now().to_rfc3339()));
            row.insert("module".to_string(), Value::String(
                if modules.is_empty() { 
                    format!("sample_module_{}", i) 
                } else { 
                    modules[i % modules.len()].clone() 
                }
            ));
            row.insert("severity".to_string(), Value::String("Info".to_string()));
            row.insert("event_id".to_string(), Value::String(format!("event_{}", i)));
            row.insert("message".to_string(), Value::String(format!("Sample log message {}", i)));
            
            data.push(row);
        }
        
        debug!("Collected {} sample GhostLog entries", data.len());
        Ok(data)
    }
    
    /// Collect GhostDash system data
    async fn collect_ghostdash_system_data(
        &self,
        _filters: &ReportFilters,
    ) -> Result<Vec<HashMap<String, Value>>> {
        let ghost_dash_guard = self.ghost_dash.read().await;
        let ghost_dash = ghost_dash_guard.as_ref()
            .ok_or_else(|| anyhow::anyhow!("GhostDash not initialized"))?;
        
        // Get system info
        let system_info = ghost_dash.get_system_info().await
            .map_err(|e| anyhow::anyhow!("Failed to get system info: {}", e))?;
        
        let mut data = Vec::new();
        
        if let Some(info) = system_info {
            let mut row = HashMap::new();
            
            row.insert("source".to_string(), Value::String("ghostdash-system".to_string()));
            row.insert("timestamp".to_string(), Value::String(Utc::now().to_rfc3339()));
            row.insert("hostname".to_string(), Value::String(info.hostname));
            row.insert("os_name".to_string(), Value::String(info.os_name));
            row.insert("os_version".to_string(), Value::String(info.os_version));
            row.insert("uptime".to_string(), Value::Number(serde_json::Number::from(info.uptime)));
            row.insert("cpu_usage_percent".to_string(), Value::Number(
                serde_json::Number::from_f64(info.cpu_usage_percent as f64).unwrap_or(serde_json::Number::from(0))
            ));
            row.insert("cpu_cores".to_string(), Value::Number(serde_json::Number::from(info.cpu_cores)));
            row.insert("memory_usage_percent".to_string(), Value::Number(
                serde_json::Number::from_f64(info.memory_usage_percent as f64).unwrap_or(serde_json::Number::from(0))
            ));
            row.insert("total_memory".to_string(), Value::Number(serde_json::Number::from(info.total_memory)));
            row.insert("used_memory".to_string(), Value::Number(serde_json::Number::from(info.used_memory)));
            row.insert("process_count".to_string(), Value::Number(serde_json::Number::from(info.process_count)));
            
            data.push(row);
        }
        
        debug!("Collected GhostDash system data: {} entries", data.len());
        Ok(data)
    }
    
    /// Collect GhostDash network data
    async fn collect_ghostdash_network_data(
        &self,
        _filters: &ReportFilters,
    ) -> Result<Vec<HashMap<String, Value>>> {
        let ghost_dash_guard = self.ghost_dash.read().await;
        let ghost_dash = ghost_dash_guard.as_ref()
            .ok_or_else(|| anyhow::anyhow!("GhostDash not initialized"))?;
        
        // Get network snapshot
        let network_snapshot = ghost_dash.get_network_snapshot().await
            .map_err(|e| anyhow::anyhow!("Failed to get network snapshot: {}", e))?;
        
        let mut data = Vec::new();
        
        if let Some(snapshot) = network_snapshot {
            let mut row = HashMap::new();
            
            row.insert("source".to_string(), Value::String("ghostdash-network".to_string()));
            row.insert("timestamp".to_string(), Value::String(Utc::now().to_rfc3339()));
            row.insert("interface_count".to_string(), Value::Number(
                serde_json::Number::from(snapshot.interfaces.len())
            ));
            row.insert("dns_server_count".to_string(), Value::Number(
                serde_json::Number::from(snapshot.dns_servers.len())
            ));
            row.insert("route_count".to_string(), Value::Number(
                serde_json::Number::from(snapshot.routes.len())
            ));
            row.insert("connection_count".to_string(), Value::Number(
                serde_json::Number::from(snapshot.connections.len())
            ));
            
            data.push(row);
        }
        
        debug!("Collected GhostDash network data: {} entries", data.len());
        Ok(data)
    }
    
    /// Collect GhostDash interfaces data
    async fn collect_ghostdash_interfaces_data(
        &self,
        _filters: &ReportFilters,
    ) -> Result<Vec<HashMap<String, Value>>> {
        // Create sample interface data for now
        let mut data = Vec::new();
        
        for i in 0..3 {
            let mut row = HashMap::new();
            
            row.insert("source".to_string(), Value::String("ghostdash-interfaces".to_string()));
            row.insert("timestamp".to_string(), Value::String(Utc::now().to_rfc3339()));
            row.insert("interface".to_string(), Value::String(format!("eth{}", i)));
            row.insert("status".to_string(), Value::String("Active".to_string()));
            row.insert("ipv4".to_string(), Value::String(format!("192.168.1.{}", 100 + i)));
            row.insert("mac".to_string(), Value::String(format!("00:11:22:33:44:{:02x}", i)));
            
            data.push(row);
        }
        
        debug!("Collected sample GhostDash interfaces data: {} entries", data.len());
        Ok(data)
    }
    
    /// Collect GhostDash DNS data
    async fn collect_ghostdash_dns_data(
        &self,
        _filters: &ReportFilters,
    ) -> Result<Vec<HashMap<String, Value>>> {
        // Create sample DNS data for now
        let mut data = Vec::new();
        
        let dns_servers = vec!["8.8.8.8", "8.8.4.4", "1.1.1.1"];
        for (i, server) in dns_servers.iter().enumerate() {
            let mut row = HashMap::new();
            
            row.insert("source".to_string(), Value::String("ghostdash-dns".to_string()));
            row.insert("timestamp".to_string(), Value::String(Utc::now().to_rfc3339()));
            row.insert("server".to_string(), Value::String(server.to_string()));
            row.insert("interface".to_string(), Value::String(format!("eth{}", i % 2)));
            row.insert("status".to_string(), Value::String("Active".to_string()));
            row.insert("response_time_ms".to_string(), Value::Number(
                serde_json::Number::from(10 + i * 5)
            ));
            
            data.push(row);
        }
        
        debug!("Collected sample GhostDash DNS data: {} entries", data.len());
        Ok(data)
    }
    
    /// Collect GhostDash routes data
    async fn collect_ghostdash_routes_data(
        &self,
        _filters: &ReportFilters,
    ) -> Result<Vec<HashMap<String, Value>>> {
        let ghost_dash_guard = self.ghost_dash.read().await;
        let ghost_dash = ghost_dash_guard.as_ref()
            .ok_or_else(|| anyhow::anyhow!("GhostDash not initialized"))?;
        
        // Get network snapshot
        let network_snapshot = ghost_dash.get_network_snapshot().await
            .map_err(|e| anyhow::anyhow!("Failed to get network snapshot: {}", e))?;
        
        let mut data = Vec::new();
        
        if let Some(snapshot) = network_snapshot {
            for route in snapshot.routes {
                let mut row = HashMap::new();
                
                row.insert("source".to_string(), Value::String("ghostdash-routes".to_string()));
                row.insert("timestamp".to_string(), Value::String(Utc::now().to_rfc3339()));
                row.insert("destination".to_string(), Value::String(route.destination));
                row.insert("gateway".to_string(), Value::String(route.gateway));
                row.insert("interface".to_string(), Value::String(route.interface));
                row.insert("metric".to_string(), Value::Number(serde_json::Number::from(route.metric)));
                
                data.push(row);
            }
        }
        
        debug!("Collected GhostDash routes data: {} entries", data.len());
        Ok(data)
    }
    
    /// Collect GhostDash connections data
    async fn collect_ghostdash_connections_data(
        &self,
        _filters: &ReportFilters,
    ) -> Result<Vec<HashMap<String, Value>>> {
        // Create sample connection data for now
        let mut data = Vec::new();
        
        let connections = vec![
            ("TCP", "127.0.0.1", 8080, "192.168.1.100", 443, "ESTABLISHED", "chrome.exe", 1234),
            ("TCP", "0.0.0.0", 22, "0.0.0.0", 0, "LISTENING", "sshd", 567),
            ("UDP", "127.0.0.1", 53, "0.0.0.0", 0, "LISTENING", "dns.exe", 890),
        ];
        
        for (protocol, local_addr, local_port, remote_addr, remote_port, state, process, pid) in connections {
            let mut row = HashMap::new();
            
            row.insert("source".to_string(), Value::String("ghostdash-connections".to_string()));
            row.insert("timestamp".to_string(), Value::String(Utc::now().to_rfc3339()));
            row.insert("protocol".to_string(), Value::String(protocol.to_string()));
            row.insert("local_address".to_string(), Value::String(local_addr.to_string()));
            row.insert("local_port".to_string(), Value::Number(serde_json::Number::from(local_port)));
            row.insert("remote_address".to_string(), Value::String(remote_addr.to_string()));
            row.insert("remote_port".to_string(), Value::Number(serde_json::Number::from(remote_port)));
            row.insert("state".to_string(), Value::String(state.to_string()));
            row.insert("process_name".to_string(), Value::String(process.to_string()));
            row.insert("pid".to_string(), Value::Number(serde_json::Number::from(pid)));
            
            data.push(row);
        }
        
        debug!("Collected sample GhostDash connections data: {} entries", data.len());
        Ok(data)
    }
}

impl Default for DataCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for a single data source
#[derive(Debug)]
struct SourceStats {
    /// Number of rows
    row_count: u64,
    /// Unique entities (modules, interfaces, etc.)
    unique_entities: HashMap<String, u64>,
    /// Earliest timestamp
    date_start: Option<DateTime<Utc>>,
    /// Latest timestamp
    date_end: Option<DateTime<Utc>>,
}
