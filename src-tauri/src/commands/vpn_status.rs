use serde::{Deserialize, Serialize};
use crate::windows_api_network::WindowsVpnDetector;

/// Check VPN connection status using Windows API
#[tauri::command]
pub async fn check_vpn_status() -> Result<crate::windows_api_network::VpnStatus, String> {
    let detector = WindowsVpnDetector::new();
    detector.check_vpn_status().await.map_err(|e| e.to_string())
}