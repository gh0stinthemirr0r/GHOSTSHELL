//! Queryable table system for network data
//! 
//! Provides search, filter, sort, and pagination capabilities for network information

use crate::{DashError, Result, NetworkSnapshot, InterfaceInfo, DnsInfo, RouteInfo, ConnectionInfo};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// Table query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableQuery {
    /// Search text (searches across all columns)
    pub search: Option<String>,
    /// Column-specific filters
    pub filters: HashMap<String, String>,
    /// Sort configuration
    pub sort: Option<SortConfig>,
    /// Pagination
    pub pagination: Option<PaginationConfig>,
    /// Enable regex search
    pub regex: bool,
}

impl Default for TableQuery {
    fn default() -> Self {
        Self {
            search: None,
            filters: HashMap::new(),
            sort: None,
            pagination: Some(PaginationConfig::default()),
            regex: false,
        }
    }
}

/// Sort configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortConfig {
    /// Column to sort by
    pub column: String,
    /// Sort direction
    pub direction: SortDirection,
}

/// Sort direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

/// Pagination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationConfig {
    /// Page number (0-based)
    pub page: usize,
    /// Items per page
    pub per_page: usize,
}

impl Default for PaginationConfig {
    fn default() -> Self {
        Self {
            page: 0,
            per_page: 100,
        }
    }
}

/// Table query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableResult<T> {
    /// Filtered and sorted data
    pub data: Vec<T>,
    /// Total number of items (before pagination)
    pub total_count: usize,
    /// Current page
    pub page: usize,
    /// Items per page
    pub per_page: usize,
    /// Total pages
    pub total_pages: usize,
    /// Query execution time in milliseconds
    pub execution_time_ms: u64,
    /// Whether results were truncated
    pub truncated: bool,
}

/// Network table manager
pub struct NetworkTableManager {
    last_snapshot: Option<NetworkSnapshot>,
}

impl NetworkTableManager {
    /// Create a new table manager
    pub fn new() -> Self {
        Self {
            last_snapshot: None,
        }
    }

    /// Update the network snapshot
    pub fn update_snapshot(&mut self, snapshot: NetworkSnapshot) {
        debug!("Updating network snapshot for tables");
        self.last_snapshot = Some(snapshot);
    }

    /// Query interfaces table
    pub fn query_interfaces(&self, query: &TableQuery) -> Result<TableResult<InterfaceInfo>> {
        let start_time = std::time::Instant::now();
        
        let snapshot = self.last_snapshot.as_ref()
            .ok_or_else(|| DashError::InvalidInput("No network snapshot available".to_string()))?;

        let mut interfaces = snapshot.interfaces.clone();

        // Apply search filter
        if let Some(ref search_term) = query.search {
            interfaces = self.filter_interfaces_by_search(&interfaces, search_term, query.regex)?;
        }

        // Apply column filters
        for (column, filter_value) in &query.filters {
            interfaces = self.filter_interfaces_by_column(&interfaces, column, filter_value)?;
        }

        let total_count = interfaces.len();

        // Apply sorting
        if let Some(ref sort_config) = query.sort {
            self.sort_interfaces(&mut interfaces, sort_config)?;
        }

        // Apply pagination
        let (page, per_page, total_pages) = if let Some(ref pagination) = query.pagination {
            let total_pages = (total_count + pagination.per_page - 1) / pagination.per_page;
            let start_idx = pagination.page * pagination.per_page;
            let end_idx = std::cmp::min(start_idx + pagination.per_page, interfaces.len());
            
            if start_idx < interfaces.len() {
                interfaces = interfaces[start_idx..end_idx].to_vec();
            } else {
                interfaces.clear();
            }
            
            (pagination.page, pagination.per_page, total_pages)
        } else {
            (0, interfaces.len(), 1)
        };

        let execution_time = start_time.elapsed();
        let truncated = interfaces.len() < total_count;

        Ok(TableResult {
            data: interfaces,
            total_count,
            page,
            per_page,
            total_pages,
            execution_time_ms: execution_time.as_millis() as u64,
            truncated,
        })
    }

    /// Query DNS servers table
    pub fn query_dns_servers(&self, query: &TableQuery) -> Result<TableResult<DnsInfo>> {
        let start_time = std::time::Instant::now();
        
        let snapshot = self.last_snapshot.as_ref()
            .ok_or_else(|| DashError::InvalidInput("No network snapshot available".to_string()))?;

        let mut dns_servers = snapshot.dns_servers.clone();

        // Apply search filter
        if let Some(ref search_term) = query.search {
            dns_servers = self.filter_dns_by_search(&dns_servers, search_term, query.regex)?;
        }

        // Apply column filters
        for (column, filter_value) in &query.filters {
            dns_servers = self.filter_dns_by_column(&dns_servers, column, filter_value)?;
        }

        let total_count = dns_servers.len();

        // Apply sorting
        if let Some(ref sort_config) = query.sort {
            self.sort_dns_servers(&mut dns_servers, sort_config)?;
        }

        // Apply pagination
        let (page, per_page, total_pages) = if let Some(ref pagination) = query.pagination {
            let total_pages = (total_count + pagination.per_page - 1) / pagination.per_page;
            let start_idx = pagination.page * pagination.per_page;
            let end_idx = std::cmp::min(start_idx + pagination.per_page, dns_servers.len());
            
            if start_idx < dns_servers.len() {
                dns_servers = dns_servers[start_idx..end_idx].to_vec();
            } else {
                dns_servers.clear();
            }
            
            (pagination.page, pagination.per_page, total_pages)
        } else {
            (0, dns_servers.len(), 1)
        };

        let execution_time = start_time.elapsed();
        let truncated = dns_servers.len() < total_count;

        Ok(TableResult {
            data: dns_servers,
            total_count,
            page,
            per_page,
            total_pages,
            execution_time_ms: execution_time.as_millis() as u64,
            truncated,
        })
    }

    /// Query routes table
    pub fn query_routes(&self, query: &TableQuery) -> Result<TableResult<RouteInfo>> {
        let start_time = std::time::Instant::now();
        
        let snapshot = self.last_snapshot.as_ref()
            .ok_or_else(|| DashError::InvalidInput("No network snapshot available".to_string()))?;

        let mut routes = snapshot.routes.clone();

        // Apply search filter
        if let Some(ref search_term) = query.search {
            routes = self.filter_routes_by_search(&routes, search_term, query.regex)?;
        }

        // Apply column filters
        for (column, filter_value) in &query.filters {
            routes = self.filter_routes_by_column(&routes, column, filter_value)?;
        }

        let total_count = routes.len();

        // Apply sorting
        if let Some(ref sort_config) = query.sort {
            self.sort_routes(&mut routes, sort_config)?;
        }

        // Apply pagination
        let (page, per_page, total_pages) = if let Some(ref pagination) = query.pagination {
            let total_pages = (total_count + pagination.per_page - 1) / pagination.per_page;
            let start_idx = pagination.page * pagination.per_page;
            let end_idx = std::cmp::min(start_idx + pagination.per_page, routes.len());
            
            if start_idx < routes.len() {
                routes = routes[start_idx..end_idx].to_vec();
            } else {
                routes.clear();
            }
            
            (pagination.page, pagination.per_page, total_pages)
        } else {
            (0, routes.len(), 1)
        };

        let execution_time = start_time.elapsed();
        let truncated = routes.len() < total_count;

        Ok(TableResult {
            data: routes,
            total_count,
            page,
            per_page,
            total_pages,
            execution_time_ms: execution_time.as_millis() as u64,
            truncated,
        })
    }

    /// Query connections table
    pub fn query_connections(&self, query: &TableQuery) -> Result<TableResult<ConnectionInfo>> {
        let start_time = std::time::Instant::now();
        
        let snapshot = self.last_snapshot.as_ref()
            .ok_or_else(|| DashError::InvalidInput("No network snapshot available".to_string()))?;

        let mut connections = snapshot.connections.clone();

        // Apply search filter
        if let Some(ref search_term) = query.search {
            connections = self.filter_connections_by_search(&connections, search_term, query.regex)?;
        }

        // Apply column filters
        for (column, filter_value) in &query.filters {
            connections = self.filter_connections_by_column(&connections, column, filter_value)?;
        }

        let total_count = connections.len();

        // Apply sorting
        if let Some(ref sort_config) = query.sort {
            self.sort_connections(&mut connections, sort_config)?;
        }

        // Apply pagination
        let (page, per_page, total_pages) = if let Some(ref pagination) = query.pagination {
            let total_pages = (total_count + pagination.per_page - 1) / pagination.per_page;
            let start_idx = pagination.page * pagination.per_page;
            let end_idx = std::cmp::min(start_idx + pagination.per_page, connections.len());
            
            if start_idx < connections.len() {
                connections = connections[start_idx..end_idx].to_vec();
            } else {
                connections.clear();
            }
            
            (pagination.page, pagination.per_page, total_pages)
        } else {
            (0, connections.len(), 1)
        };

        let execution_time = start_time.elapsed();
        let truncated = connections.len() < total_count;

        Ok(TableResult {
            data: connections,
            total_count,
            page,
            per_page,
            total_pages,
            execution_time_ms: execution_time.as_millis() as u64,
            truncated,
        })
    }

    // Interface filtering and sorting methods
    fn filter_interfaces_by_search(&self, interfaces: &[InterfaceInfo], search_term: &str, regex: bool) -> Result<Vec<InterfaceInfo>> {
        let search_term = if regex {
            search_term.to_string()
        } else {
            search_term.to_lowercase()
        };

        let filtered = interfaces.iter()
            .filter(|interface| {
                let searchable_text = format!("{} {} {} {} {}",
                    interface.name,
                    interface.mac.as_deref().unwrap_or(""),
                    interface.ipv4.as_deref().unwrap_or(""),
                    interface.ipv6.as_deref().unwrap_or(""),
                    interface.interface_type
                ).to_lowercase();

                if regex {
                    // Simplified regex - in production would use proper regex crate
                    searchable_text.contains(&search_term)
                } else {
                    searchable_text.contains(&search_term)
                }
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn filter_interfaces_by_column(&self, interfaces: &[InterfaceInfo], column: &str, filter_value: &str) -> Result<Vec<InterfaceInfo>> {
        let filter_value = filter_value.to_lowercase();
        
        let filtered = interfaces.iter()
            .filter(|interface| {
                match column {
                    "name" => interface.name.to_lowercase().contains(&filter_value),
                    "status" => format!("{:?}", interface.status).to_lowercase().contains(&filter_value),
                    "type" => interface.interface_type.to_lowercase().contains(&filter_value),
                    "dhcp" => interface.dhcp.to_string().contains(&filter_value),
                    _ => true, // Unknown column, don't filter
                }
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn sort_interfaces(&self, interfaces: &mut [InterfaceInfo], sort_config: &SortConfig) -> Result<()> {
        interfaces.sort_by(|a, b| {
            let comparison = match sort_config.column.as_str() {
                "name" => a.name.cmp(&b.name),
                "ipv4" => a.ipv4.cmp(&b.ipv4),
                "mac" => a.mac.cmp(&b.mac),
                "type" => a.interface_type.cmp(&b.interface_type),
                _ => std::cmp::Ordering::Equal,
            };

            match sort_config.direction {
                SortDirection::Ascending => comparison,
                SortDirection::Descending => comparison.reverse(),
            }
        });

        Ok(())
    }

    // DNS filtering and sorting methods
    fn filter_dns_by_search(&self, dns_servers: &[DnsInfo], search_term: &str, _regex: bool) -> Result<Vec<DnsInfo>> {
        let search_term = search_term.to_lowercase();

        let filtered = dns_servers.iter()
            .filter(|dns| {
                let searchable_text = format!("{} {} {}",
                    dns.interface,
                    dns.server,
                    format!("{:?}", dns.status)
                ).to_lowercase();

                searchable_text.contains(&search_term)
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn filter_dns_by_column(&self, dns_servers: &[DnsInfo], column: &str, filter_value: &str) -> Result<Vec<DnsInfo>> {
        let filter_value = filter_value.to_lowercase();
        
        let filtered = dns_servers.iter()
            .filter(|dns| {
                match column {
                    "interface" => dns.interface.to_lowercase().contains(&filter_value),
                    "server" => dns.server.to_lowercase().contains(&filter_value),
                    "status" => format!("{:?}", dns.status).to_lowercase().contains(&filter_value),
                    "primary" => dns.is_primary.to_string().contains(&filter_value),
                    _ => true,
                }
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn sort_dns_servers(&self, dns_servers: &mut [DnsInfo], sort_config: &SortConfig) -> Result<()> {
        dns_servers.sort_by(|a, b| {
            let comparison = match sort_config.column.as_str() {
                "interface" => a.interface.cmp(&b.interface),
                "server" => a.server.cmp(&b.server),
                "primary" => a.is_primary.cmp(&b.is_primary),
                _ => std::cmp::Ordering::Equal,
            };

            match sort_config.direction {
                SortDirection::Ascending => comparison,
                SortDirection::Descending => comparison.reverse(),
            }
        });

        Ok(())
    }

    // Route filtering and sorting methods
    fn filter_routes_by_search(&self, routes: &[RouteInfo], search_term: &str, _regex: bool) -> Result<Vec<RouteInfo>> {
        let search_term = search_term.to_lowercase();

        let filtered = routes.iter()
            .filter(|route| {
                let searchable_text = format!("{} {} {} {}",
                    route.destination,
                    route.gateway,
                    route.interface,
                    format!("{:?}", route.route_type)
                ).to_lowercase();

                searchable_text.contains(&search_term)
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn filter_routes_by_column(&self, routes: &[RouteInfo], column: &str, filter_value: &str) -> Result<Vec<RouteInfo>> {
        let filter_value = filter_value.to_lowercase();
        
        let filtered = routes.iter()
            .filter(|route| {
                match column {
                    "destination" => route.destination.to_lowercase().contains(&filter_value),
                    "gateway" => route.gateway.to_lowercase().contains(&filter_value),
                    "interface" => route.interface.to_lowercase().contains(&filter_value),
                    "type" => format!("{:?}", route.route_type).to_lowercase().contains(&filter_value),
                    _ => true,
                }
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn sort_routes(&self, routes: &mut [RouteInfo], sort_config: &SortConfig) -> Result<()> {
        routes.sort_by(|a, b| {
            let comparison = match sort_config.column.as_str() {
                "destination" => a.destination.cmp(&b.destination),
                "gateway" => a.gateway.cmp(&b.gateway),
                "interface" => a.interface.cmp(&b.interface),
                "metric" => a.metric.cmp(&b.metric),
                _ => std::cmp::Ordering::Equal,
            };

            match sort_config.direction {
                SortDirection::Ascending => comparison,
                SortDirection::Descending => comparison.reverse(),
            }
        });

        Ok(())
    }

    // Connection filtering and sorting methods
    fn filter_connections_by_search(&self, connections: &[ConnectionInfo], search_term: &str, _regex: bool) -> Result<Vec<ConnectionInfo>> {
        let search_term = search_term.to_lowercase();

        let filtered = connections.iter()
            .filter(|conn| {
                let searchable_text = format!("{} {} {} {} {}",
                    conn.protocol,
                    conn.local_address,
                    conn.remote_address,
                    format!("{:?}", conn.state),
                    conn.process.as_deref().unwrap_or("")
                ).to_lowercase();

                searchable_text.contains(&search_term)
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn filter_connections_by_column(&self, connections: &[ConnectionInfo], column: &str, filter_value: &str) -> Result<Vec<ConnectionInfo>> {
        let filter_value = filter_value.to_lowercase();
        
        let filtered = connections.iter()
            .filter(|conn| {
                match column {
                    "protocol" => conn.protocol.to_lowercase().contains(&filter_value),
                    "local" => conn.local_address.to_lowercase().contains(&filter_value),
                    "remote" => conn.remote_address.to_lowercase().contains(&filter_value),
                    "state" => format!("{:?}", conn.state).to_lowercase().contains(&filter_value),
                    "process" => conn.process.as_deref().unwrap_or("").to_lowercase().contains(&filter_value),
                    _ => true,
                }
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn sort_connections(&self, connections: &mut [ConnectionInfo], sort_config: &SortConfig) -> Result<()> {
        connections.sort_by(|a, b| {
            let comparison = match sort_config.column.as_str() {
                "protocol" => a.protocol.cmp(&b.protocol),
                "local" => a.local_address.cmp(&b.local_address),
                "remote" => a.remote_address.cmp(&b.remote_address),
                "state" => format!("{:?}", a.state).cmp(&format!("{:?}", b.state)),
                "process" => a.process.cmp(&b.process),
                "pid" => a.pid.cmp(&b.pid),
                _ => std::cmp::Ordering::Equal,
            };

            match sort_config.direction {
                SortDirection::Ascending => comparison,
                SortDirection::Descending => comparison.reverse(),
            }
        });

        Ok(())
    }

    /// Get table statistics
    pub fn get_table_stats(&self) -> Result<TableStats> {
        let snapshot = self.last_snapshot.as_ref()
            .ok_or_else(|| DashError::InvalidInput("No network snapshot available".to_string()))?;

        Ok(TableStats {
            interfaces_count: snapshot.interfaces.len(),
            dns_servers_count: snapshot.dns_servers.len(),
            routes_count: snapshot.routes.len(),
            connections_count: snapshot.connections.len(),
            last_update: snapshot.timestamp,
        })
    }
}

impl Default for NetworkTableManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Table statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableStats {
    /// Number of interfaces
    pub interfaces_count: usize,
    /// Number of DNS servers
    pub dns_servers_count: usize,
    /// Number of routes
    pub routes_count: usize,
    /// Number of connections
    pub connections_count: usize,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
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

    #[test]
    fn test_table_manager() {
        let mut manager = NetworkTableManager::new();
        let snapshot = create_test_snapshot();
        
        manager.update_snapshot(snapshot);
        
        let query = TableQuery::default();
        let result = manager.query_interfaces(&query).unwrap();
        
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.total_count, 1);
        assert_eq!(result.data[0].name, "Ethernet0");
    }

    #[test]
    fn test_interface_search() {
        let mut manager = NetworkTableManager::new();
        let snapshot = create_test_snapshot();
        
        manager.update_snapshot(snapshot);
        
        let query = TableQuery {
            search: Some("ethernet".to_string()),
            ..Default::default()
        };
        
        let result = manager.query_interfaces(&query).unwrap();
        assert_eq!(result.data.len(), 1);
    }

    #[test]
    fn test_pagination() {
        let mut manager = NetworkTableManager::new();
        let snapshot = create_test_snapshot();
        
        manager.update_snapshot(snapshot);
        
        let query = TableQuery {
            pagination: Some(PaginationConfig {
                page: 0,
                per_page: 10,
            }),
            ..Default::default()
        };
        
        let result = manager.query_interfaces(&query).unwrap();
        assert_eq!(result.per_page, 10);
        assert_eq!(result.page, 0);
    }
}
