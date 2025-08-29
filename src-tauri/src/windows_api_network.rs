use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};

#[cfg(windows)]
use windows::{
    core::{PWSTR, PCWSTR},
    Win32::{
        Foundation::{ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR},
        System::Registry::{
            RegOpenKeyExW, RegQueryValueExW, RegCloseKey,
            HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, REG_DWORD, HKEY,
        },
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct VpnStatus {
    pub connected: bool,
    pub endpoint: Option<String>,
    pub ip_address: Option<String>,
    pub adapter_name: Option<String>,
    pub vpn_type: Option<String>,
}

/// Windows API-based VPN detection
pub struct WindowsVpnDetector;

impl WindowsVpnDetector {
    pub fn new() -> Self {
        Self
    }

    /// Check VPN connection status using Windows Registry APIs
    pub async fn check_vpn_status(&self) -> Result<VpnStatus> {
        debug!("Checking VPN status using Windows Registry APIs");

        // Method 1: Check Windows registry for VPN connections
        if let Ok(status) = self.check_vpn_registry().await {
            if status.connected {
                return Ok(status);
            }
        }

        // Method 2: Check for common VPN software registry entries
        if let Ok(status) = self.check_vpn_software_registry().await {
            if status.connected {
                return Ok(status);
            }
        }

        Ok(VpnStatus {
            connected: false,
            endpoint: None,
            ip_address: None,
            adapter_name: None,
            vpn_type: None,
        })
    }

    /// Check Windows registry for VPN connections
    #[cfg(windows)]
    async fn check_vpn_registry(&self) -> Result<VpnStatus> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        // Check RAS (Remote Access Service) connections in registry
        let ras_reg_path = r"SOFTWARE\Microsoft\RAS\Protocols";
        let wide_path: Vec<u16> = OsStr::new(ras_reg_path).encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey_result = HKEY::default();
            
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide_path.as_ptr()),
                0,
                KEY_READ,
                &mut hkey_result
            ).is_ok() {
                let _ = RegCloseKey(hkey_result);
                
                // If RAS key exists, there might be VPN capability
                // This is a simplified check - in practice, you'd enumerate connections
                return Ok(VpnStatus {
                    connected: false, // Would need more detailed checking
                    endpoint: None,
                    ip_address: None,
                    adapter_name: None,
                    vpn_type: Some("RAS VPN".to_string()),
                });
            }
        }

        Ok(VpnStatus {
            connected: false,
            endpoint: None,
            ip_address: None,
            adapter_name: None,
            vpn_type: None,
        })
    }

    #[cfg(not(windows))]
    async fn check_vpn_registry(&self) -> Result<VpnStatus> {
        Ok(VpnStatus {
            connected: false,
            endpoint: None,
            ip_address: None,
            adapter_name: None,
            vpn_type: None,
        })
    }

    /// Check for common VPN software in registry
    #[cfg(windows)]
    async fn check_vpn_software_registry(&self) -> Result<VpnStatus> {
        let vpn_software = [
            ("OpenVPN", r"SOFTWARE\OpenVPN"),
            ("WireGuard", r"SOFTWARE\WireGuard"),
            ("Cisco AnyConnect", r"SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client"),
            ("NordVPN", r"SOFTWARE\NordVPN"),
            ("ExpressVPN", r"SOFTWARE\ExpressVPN"),
        ];

        for (vpn_name, reg_path) in &vpn_software {
            if self.check_registry_key_exists(HKEY_LOCAL_MACHINE, reg_path) {
                return Ok(VpnStatus {
                    connected: false, // Would need process/service checking for actual connection status
                    endpoint: None,
                    ip_address: None,
                    adapter_name: None,
                    vpn_type: Some(vpn_name.to_string()),
                });
            }
        }

        Ok(VpnStatus {
            connected: false,
            endpoint: None,
            ip_address: None,
            adapter_name: None,
            vpn_type: None,
        })
    }

    #[cfg(not(windows))]
    async fn check_vpn_software_registry(&self) -> Result<VpnStatus> {
        Ok(VpnStatus {
            connected: false,
            endpoint: None,
            ip_address: None,
            adapter_name: None,
            vpn_type: None,
        })
    }

    /// Check if a registry key exists
    #[cfg(windows)]
    fn check_registry_key_exists(&self, hkey: HKEY, path: &str) -> bool {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey_result = HKEY::default();
            
            let result = RegOpenKeyExW(
                hkey,
                PCWSTR(wide_path.as_ptr()),
                0,
                KEY_READ,
                &mut hkey_result
            );

            if result.is_ok() {
                let _ = RegCloseKey(hkey_result);
                true
            } else {
                false
            }
        }
    }

    #[cfg(not(windows))]
    fn check_registry_key_exists(&self, _hkey: HKEY, _path: &str) -> bool {
        false
    }
}