use tauri::State;
use std::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct VpnStatus {
    pub connected: bool,
    pub endpoint: Option<String>,
    pub ip_address: Option<String>,
}

/// Check VPN connection status
#[tauri::command]
pub async fn check_vpn_status() -> Result<VpnStatus, String> {
    // Check for common VPN interfaces and connections
    let status = check_vpn_connection().await;
    
    Ok(status)
}

async fn check_vpn_connection() -> VpnStatus {
    // Check for VPN interfaces on different platforms
    #[cfg(target_os = "windows")]
    {
        check_windows_vpn().await
    }
    
    #[cfg(target_os = "macos")]
    {
        check_macos_vpn().await
    }
    
    #[cfg(target_os = "linux")]
    {
        check_linux_vpn().await
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        VpnStatus {
            connected: false,
            endpoint: None,
            ip_address: None,
        }
    }
}

#[cfg(target_os = "windows")]
async fn check_windows_vpn() -> VpnStatus {
    // Check for VPN adapters using netsh or wmi
    let output = Command::new("netsh")
        .args(&["interface", "show", "interface"])
        .output();
    
    match output {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            // Look for common VPN interface names
            let vpn_keywords = ["VPN", "TAP", "TUN", "WireGuard", "OpenVPN", "Cisco", "Pulse"];
            let connected = vpn_keywords.iter().any(|keyword| {
                output_str.lines().any(|line| {
                    line.contains(keyword) && line.contains("Connected")
                })
            });
            
            VpnStatus {
                connected,
                endpoint: if connected { Some("Unknown".to_string()) } else { None },
                ip_address: None,
            }
        }
        Err(_) => VpnStatus {
            connected: false,
            endpoint: None,
            ip_address: None,
        }
    }
}

#[cfg(target_os = "macos")]
async fn check_macos_vpn() -> VpnStatus {
    // Check for VPN connections using scutil
    let output = Command::new("scutil")
        .args(&["--nwi"])
        .output();
    
    match output {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            // Look for VPN interfaces
            let connected = output_str.contains("utun") || output_str.contains("ppp");
            
            VpnStatus {
                connected,
                endpoint: if connected { Some("Unknown".to_string()) } else { None },
                ip_address: None,
            }
        }
        Err(_) => VpnStatus {
            connected: false,
            endpoint: None,
            ip_address: None,
        }
    }
}

#[cfg(target_os = "linux")]
async fn check_linux_vpn() -> VpnStatus {
    // Check for VPN interfaces using ip command
    let output = Command::new("ip")
        .args(&["route", "show"])
        .output();
    
    match output {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            // Look for VPN interfaces
            let vpn_interfaces = ["tun", "tap", "wg", "ppp"];
            let connected = vpn_interfaces.iter().any(|interface| {
                output_str.contains(interface)
            });
            
            VpnStatus {
                connected,
                endpoint: if connected { Some("Unknown".to_string()) } else { None },
                ip_address: None,
            }
        }
        Err(_) => VpnStatus {
            connected: false,
            endpoint: None,
            ip_address: None,
        }
    }
}
