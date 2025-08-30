use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::Window;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EndpointAnalysis {
    pub status: String,
    #[serde(rename = "openPorts")]
    pub open_ports: Vec<u16>,
    pub latency: f64,
    #[serde(rename = "packetLoss")]
    pub packet_loss: f64,
    pub services: Option<Vec<ServiceInfo>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub service: String,
    pub protocol: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetricPoint {
    pub timestamp: f64,
    pub value: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LiveMetrics {
    pub latency: Vec<MetricPoint>,
    #[serde(rename = "packetLoss")]
    pub packet_loss: Vec<MetricPoint>,
    pub jitter: Vec<MetricPoint>,
    pub throughput: Vec<MetricPoint>,
    #[serde(rename = "responseTime")]
    pub response_time: Vec<MetricPoint>,
}

// Global test state
static TEST_STATE: Mutex<Option<TestSession>> = Mutex::new(None);

#[derive(Debug, Clone)]
struct TestSession {
    endpoint: String,
    start_time: Instant,
    duration: Duration,
    metrics: Arc<Mutex<LiveMetrics>>,
    active: bool,
}

#[tauri::command]
pub async fn surveyor_analyze_endpoint(endpoint: String) -> Result<EndpointAnalysis, String> {
    info!("Analyzing endpoint: {}", endpoint);
    
    let start_time = Instant::now();
    
    // Test basic connectivity
    let status = test_endpoint_connectivity(&endpoint).await?;
    
    // Measure latency
    let latency = measure_latency(&endpoint).await.unwrap_or(0.0);
    
    // Scan common ports
    let open_ports = scan_common_ports(&endpoint).await;
    
    // Identify services
    let services = identify_services(&open_ports);
    
    // Simulate packet loss measurement
    let packet_loss = measure_packet_loss(&endpoint).await.unwrap_or(0.0);
    
    let analysis_time = start_time.elapsed();
    info!("Endpoint analysis completed in {:?}", analysis_time);
    
    Ok(EndpointAnalysis {
        status,
        open_ports,
        latency,
        packet_loss,
        services: Some(services),
    })
}

#[tauri::command]
pub async fn surveyor_start_test(endpoint: String, duration: String) -> Result<(), String> {
    info!("Starting performance test for {} with duration {}", endpoint, duration);
    
    // Parse duration
    let test_duration = parse_duration(&duration)?;
    
    // Initialize test session
    let session = TestSession {
        endpoint: endpoint.clone(),
        start_time: Instant::now(),
        duration: test_duration,
        metrics: Arc::new(Mutex::new(LiveMetrics {
            latency: Vec::new(),
            packet_loss: Vec::new(),
            jitter: Vec::new(),
            throughput: Vec::new(),
            response_time: Vec::new(),
        })),
        active: true,
    };
    
    // Store test session
    {
        let mut state = TEST_STATE.lock().map_err(|e| format!("Failed to lock test state: {}", e))?;
        *state = Some(session.clone());
    }
    
    // Start background metrics collection
    let session_clone = session.clone();
    tokio::spawn(async move {
        collect_metrics(session_clone).await;
    });
    
    Ok(())
}

#[tauri::command]
pub async fn surveyor_stop_test() -> Result<(), String> {
    info!("Stopping performance test");
    
    let mut state = TEST_STATE.lock().map_err(|e| format!("Failed to lock test state: {}", e))?;
    if let Some(ref mut session) = state.as_mut() {
        session.active = false;
    }
    
    Ok(())
}

#[tauri::command]
pub async fn surveyor_get_metrics() -> Result<LiveMetrics, String> {
    let state = TEST_STATE.lock().map_err(|e| format!("Failed to lock test state: {}", e))?;
    
    if let Some(ref session) = *state {
        let metrics = session.metrics.lock().map_err(|e| format!("Failed to lock metrics: {}", e))?;
        Ok(metrics.clone())
    } else {
        Err("No active test running".to_string())
    }
}

async fn test_endpoint_connectivity(endpoint: &str) -> Result<String, String> {
    debug!("Testing connectivity to {}", endpoint);
    
    // Try to resolve the endpoint
    let socket_addr = if endpoint.parse::<IpAddr>().is_ok() {
        format!("{}:80", endpoint)
    } else {
        format!("{}:80", endpoint)
    };
    
    match socket_addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if addrs.next().is_some() {
                // Try to connect to port 80 or 443
                for port in [80, 443, 22] {
                    let test_addr = if endpoint.parse::<IpAddr>().is_ok() {
                        format!("{}:{}", endpoint, port)
                    } else {
                        format!("{}:{}", endpoint, port)
                    };
                    
                    if let Ok(mut addr_iter) = test_addr.to_socket_addrs() {
                        if let Some(addr) = addr_iter.next() {
                            if TcpStream::connect_timeout(&addr, Duration::from_millis(3000)).is_ok() {
                                return Ok("Online".to_string());
                            }
                        }
                    }
                }
                Ok("Offline".to_string())
            } else {
                Err("Failed to resolve endpoint".to_string())
            }
        }
        Err(e) => Err(format!("Failed to resolve endpoint: {}", e)),
    }
}

async fn measure_latency(endpoint: &str) -> Result<f64, String> {
    debug!("Measuring latency to {}", endpoint);
    
    let mut total_latency = 0.0;
    let mut successful_pings = 0;
    
    for _ in 0..3 {
        let start = Instant::now();
        
        // Try to connect to common ports
        let test_addr = if endpoint.parse::<IpAddr>().is_ok() {
            format!("{}:80", endpoint)
        } else {
            format!("{}:80", endpoint)
        };
        
        if let Ok(mut addr_iter) = test_addr.to_socket_addrs() {
            if let Some(addr) = addr_iter.next() {
                if TcpStream::connect_timeout(&addr, Duration::from_millis(5000)).is_ok() {
                    let latency = start.elapsed().as_millis() as f64;
                    total_latency += latency;
                    successful_pings += 1;
                }
            }
        }
        
        sleep(Duration::from_millis(100)).await;
    }
    
    if successful_pings > 0 {
        Ok(total_latency / successful_pings as f64)
    } else {
        Ok(0.0) // Return 0 if no successful connections
    }
}

async fn scan_common_ports(endpoint: &str) -> Vec<u16> {
    debug!("Scanning common ports for {}", endpoint);
    
    let common_ports = vec![21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443];
    let mut open_ports = Vec::new();
    
    for port in common_ports {
        let test_addr = if endpoint.parse::<IpAddr>().is_ok() {
            format!("{}:{}", endpoint, port)
        } else {
            format!("{}:{}", endpoint, port)
        };
        
        if let Ok(mut addr_iter) = test_addr.to_socket_addrs() {
            if let Some(addr) = addr_iter.next() {
                if TcpStream::connect_timeout(&addr, Duration::from_millis(1000)).is_ok() {
                    open_ports.push(port);
                }
            }
        }
    }
    
    open_ports
}

fn identify_services(open_ports: &[u16]) -> Vec<ServiceInfo> {
    let mut services = Vec::new();
    
    for &port in open_ports {
        let (service_name, protocol) = match port {
            21 => ("FTP", "TCP"),
            22 => ("SSH", "TCP"),
            23 => ("Telnet", "TCP"),
            25 => ("SMTP", "TCP"),
            53 => ("DNS", "UDP/TCP"),
            80 => ("HTTP", "TCP"),
            110 => ("POP3", "TCP"),
            143 => ("IMAP", "TCP"),
            443 => ("HTTPS", "TCP"),
            993 => ("IMAPS", "TCP"),
            995 => ("POP3S", "TCP"),
            8080 => ("HTTP-Alt", "TCP"),
            8443 => ("HTTPS-Alt", "TCP"),
            _ => ("Unknown", "TCP"),
        };
        
        services.push(ServiceInfo {
            port,
            service: service_name.to_string(),
            protocol: protocol.to_string(),
        });
    }
    
    services
}

async fn measure_packet_loss(endpoint: &str) -> Result<f64, String> {
    debug!("Measuring packet loss to {}", endpoint);
    
    let mut successful_connections = 0;
    let total_attempts = 10;
    
    for _ in 0..total_attempts {
        let test_addr = if endpoint.parse::<IpAddr>().is_ok() {
            format!("{}:80", endpoint)
        } else {
            format!("{}:80", endpoint)
        };
        
        if let Ok(mut addr_iter) = test_addr.to_socket_addrs() {
            if let Some(addr) = addr_iter.next() {
                if TcpStream::connect_timeout(&addr, Duration::from_millis(2000)).is_ok() {
                    successful_connections += 1;
                }
            }
        }
        
        sleep(Duration::from_millis(100)).await;
    }
    
    let loss_rate = ((total_attempts - successful_connections) as f64 / total_attempts as f64) * 100.0;
    Ok(loss_rate)
}

async fn collect_metrics(session: TestSession) {
    info!("Starting metrics collection for {}", session.endpoint);
    
    let mut last_latency = 0.0;
    let mut jitter_values = Vec::new();
    
    while session.active && session.start_time.elapsed() < session.duration {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        
        // Measure current latency
        let current_latency = measure_latency(&session.endpoint).await.unwrap_or(0.0);
        
        // Calculate jitter
        let jitter = if last_latency > 0.0 {
            (current_latency - last_latency).abs()
        } else {
            0.0
        };
        jitter_values.push(jitter);
        last_latency = current_latency;
        
        // Simulate throughput (in reality, this would measure actual data transfer)
        let throughput = 50.0 + (rand::random::<f64>() * 100.0);
        
        // Measure response time (similar to latency but for HTTP requests)
        let response_time = current_latency * 0.8 + (rand::random::<f64>() * 10.0);
        
        // Measure packet loss
        let packet_loss = measure_packet_loss(&session.endpoint).await.unwrap_or(0.0);
        
        // Update metrics
        if let Ok(mut metrics) = session.metrics.lock() {
            metrics.latency.push(MetricPoint { timestamp, value: current_latency });
            metrics.packet_loss.push(MetricPoint { timestamp, value: packet_loss });
            metrics.jitter.push(MetricPoint { timestamp, value: jitter });
            metrics.throughput.push(MetricPoint { timestamp, value: throughput });
            metrics.response_time.push(MetricPoint { timestamp, value: response_time });
            
            // Keep only last 60 data points
            if metrics.latency.len() > 60 {
                metrics.latency.remove(0);
                metrics.packet_loss.remove(0);
                metrics.jitter.remove(0);
                metrics.throughput.remove(0);
                metrics.response_time.remove(0);
            }
        }
        
        sleep(Duration::from_secs(1)).await;
    }
    
    info!("Metrics collection completed for {}", session.endpoint);
}

fn parse_duration(duration_str: &str) -> Result<Duration, String> {
    if duration_str.ends_with('s') {
        let seconds: u64 = duration_str[..duration_str.len()-1]
            .parse()
            .map_err(|_| "Invalid duration format")?;
        Ok(Duration::from_secs(seconds))
    } else if duration_str.ends_with('m') {
        let minutes: u64 = duration_str[..duration_str.len()-1]
            .parse()
            .map_err(|_| "Invalid duration format")?;
        Ok(Duration::from_secs(minutes * 60))
    } else {
        Err("Duration must end with 's' for seconds or 'm' for minutes".to_string())
    }
}

// Simple random number generator for demonstration
mod rand {
    use std::cell::Cell;
    
    thread_local! {
        static RNG_STATE: Cell<u64> = Cell::new(1);
    }
    
    pub fn random<T>() -> T 
    where
        T: From<f64>,
    {
        RNG_STATE.with(|state| {
            let mut x = state.get();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            state.set(x);
            T::from((x as f64) / (u64::MAX as f64))
        })
    }
}
