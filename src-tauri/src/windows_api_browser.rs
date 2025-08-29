use anyhow::{Result, anyhow};
use tracing::{info, warn, error, debug};

#[cfg(windows)]
use windows::{
    core::{PWSTR, PCWSTR},
    Win32::{
        Foundation::{HWND, HANDLE},
        UI::{
            Shell::{ShellExecuteW},
            WindowsAndMessaging::{SW_SHOWNORMAL, SW_HIDE},
        },
        System::Registry::{
            RegOpenKeyExW, RegQueryValueExW, RegCloseKey,
            HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, KEY_READ, REG_SZ, HKEY,
        },
    },
};

/// Windows API-based browser launcher
pub struct WindowsBrowserLauncher;

impl WindowsBrowserLauncher {
    pub fn new() -> Self {
        Self
    }

    /// Open URL in external browser using Windows Shell API
    pub async fn open_url(&self, url: &str) -> Result<()> {
        debug!("Opening URL using Windows Shell API: {}", url);

        // Validate URL first
        url::Url::parse(url)
            .map_err(|e| anyhow!("Invalid URL: {}", e))?;

        #[cfg(windows)]
        {
            self.open_with_shell_execute(url).await
        }

        #[cfg(not(windows))]
        {
            Err(anyhow!("Windows browser launcher only works on Windows"))
        }
    }

    /// Open URL using ShellExecuteW API
    #[cfg(windows)]
    async fn open_with_shell_execute(&self, url: &str) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let wide_url: Vec<u16> = OsStr::new(url).encode_wide().chain(std::iter::once(0)).collect();
        let wide_open: Vec<u16> = OsStr::new("open").encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let result = ShellExecuteW(
                HWND::default(),                              // Parent window
                PCWSTR(wide_open.as_ptr()),                  // Operation
                PCWSTR(wide_url.as_ptr()),                   // File/URL
                PCWSTR::null(),                              // Parameters
                PCWSTR::null(),                              // Directory
                SW_SHOWNORMAL,                               // Show command
            );

            // ShellExecuteW returns a value > 32 on success
            if result.0 as i32 > 32 {
                info!("Successfully opened URL in default browser: {}", url);
                Ok(())
            } else {
                let error_code = result.0 as i32;
                error!("ShellExecuteW failed with error code: {}", error_code);
                
                // Try alternative method
                self.open_with_registry_lookup(url).await
            }
        }
    }

    /// Alternative method: Look up default browser in registry and launch directly
    #[cfg(windows)]
    async fn open_with_registry_lookup(&self, url: &str) -> Result<()> {
        if let Ok(browser_path) = self.get_default_browser_from_registry().await {
            debug!("Found default browser: {}", browser_path);
            self.launch_browser_directly(&browser_path, url).await
        } else {
            // Final fallback: try common browser locations
            self.try_common_browsers(url).await
        }
    }

    /// Get default browser from Windows registry
    #[cfg(windows)]
    async fn get_default_browser_from_registry(&self) -> Result<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        // Check HKEY_CURRENT_USER first (user preference)
        if let Ok(browser) = self.query_browser_registry(HKEY_CURRENT_USER).await {
            return Ok(browser);
        }

        // Fallback to HKEY_CLASSES_ROOT (system default)
        self.query_browser_registry(HKEY_CLASSES_ROOT).await
    }

    #[cfg(windows)]
    async fn query_browser_registry(&self, hkey: HKEY) -> Result<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        // Path to HTTP protocol handler
        let reg_paths = [
            r"SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice",
            r"http\shell\open\command",
        ];

        for reg_path in &reg_paths {
            if let Ok(browser_path) = self.query_registry_path(hkey, reg_path).await {
                return Ok(browser_path);
            }
        }

        Err(anyhow!("Default browser not found in registry"))
    }

    #[cfg(windows)]
    async fn query_registry_path(&self, hkey: HKEY, path: &str) -> Result<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey_result = HKEY::default();
            
            if RegOpenKeyExW(
                hkey,
                PCWSTR(wide_path.as_ptr()),
                0,
                KEY_READ,
                &mut hkey_result
            ).is_err() {
                return Err(anyhow!("Failed to open registry key"));
            }

            // Try to read the default value or "ProgId" value
            let value_names = ["", "ProgId"];
            
            for value_name in &value_names {
                if let Ok(value) = self.read_registry_string(&hkey_result, value_name) {
                    let _ = RegCloseKey(hkey_result);
                    
                    // If we got a ProgId, resolve it to the actual command
                    if !value_name.is_empty() && !value.is_empty() {
                        if let Ok(command) = self.resolve_progid_to_command(&value) {
                            return Ok(command);
                        }
                    } else if !value.is_empty() {
                        return Ok(value);
                    }
                }
            }

            let _ = RegCloseKey(hkey_result);
        }

        Err(anyhow!("Registry value not found"))
    }

    #[cfg(windows)]
    fn read_registry_string(&self, hkey: &HKEY, value_name: &str) -> Result<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let wide_value_name: Vec<u16> = if value_name.is_empty() {
            vec![0]
        } else {
            OsStr::new(value_name).encode_wide().chain(std::iter::once(0)).collect()
        };

        unsafe {
            let mut buffer = vec![0u16; 1024];
            let mut buffer_size = (buffer.len() * 2) as u32;
            let mut reg_type = REG_SZ;

            if RegQueryValueExW(
                *hkey,
                PCWSTR(wide_value_name.as_ptr()),
                None,
                Some(&mut reg_type),
                Some(buffer.as_mut_ptr() as *mut u8),
                Some(&mut buffer_size),
            ).is_ok() {
                let string_len = (buffer_size / 2) as usize;
                if string_len > 0 {
                    buffer.truncate(string_len - 1); // Remove null terminator
                    return Ok(String::from_utf16_lossy(&buffer));
                }
            }
        }

        Err(anyhow!("Failed to read registry string"))
    }

    #[cfg(windows)]
    fn resolve_progid_to_command(&self, progid: &str) -> Result<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let command_path = format!("{}\\shell\\open\\command", progid);
        let wide_path: Vec<u16> = OsStr::new(&command_path).encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey_result = HKEY::default();
            
            if RegOpenKeyExW(
                HKEY_CLASSES_ROOT,
                PCWSTR(wide_path.as_ptr()),
                0,
                KEY_READ,
                &mut hkey_result
            ).is_err() {
                return Err(anyhow!("Failed to open registry key"));
            }

            // Try to read the default value
            if let Ok(value) = self.read_registry_string(&hkey_result, "") {
                let _ = RegCloseKey(hkey_result);
                if !value.is_empty() {
                    return Ok(value);
                }
            }

            let _ = RegCloseKey(hkey_result);
        }

        Err(anyhow!("Registry value not found"))
    }

    /// Launch browser directly with the executable path
    #[cfg(windows)]
    async fn launch_browser_directly(&self, browser_path: &str, url: &str) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        // Clean up the browser path (remove quotes and parameters)
        let clean_path = browser_path
            .trim_matches('"')
            .split_whitespace()
            .next()
            .unwrap_or(browser_path);

        let wide_path: Vec<u16> = OsStr::new(clean_path).encode_wide().chain(std::iter::once(0)).collect();
        let wide_url: Vec<u16> = OsStr::new(url).encode_wide().chain(std::iter::once(0)).collect();
        let wide_open: Vec<u16> = OsStr::new("open").encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let result = ShellExecuteW(
                HWND::default(),
                PCWSTR(wide_open.as_ptr()),
                PCWSTR(wide_path.as_ptr()),
                PCWSTR(wide_url.as_ptr()),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );

            if result.0 as i32 > 32 {
                info!("Successfully launched browser directly: {}", clean_path);
                Ok(())
            } else {
                Err(anyhow!("Failed to launch browser directly: error code {}", result.0 as i32))
            }
        }
    }

    /// Try common browser locations as final fallback
    #[cfg(windows)]
    async fn try_common_browsers(&self, url: &str) -> Result<()> {
        let common_browsers = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        ];

        for browser_path in &common_browsers {
            if std::path::Path::new(browser_path).exists() {
                debug!("Trying common browser: {}", browser_path);
                if let Ok(_) = self.launch_browser_directly(browser_path, url).await {
                    return Ok(());
                }
            }
        }

        Err(anyhow!("No browsers found in common locations"))
    }

    /// Get list of installed browsers from registry
    #[cfg(windows)]
    pub async fn get_installed_browsers(&self) -> Result<Vec<String>> {
        // This would enumerate installed browsers from the registry
        // Implementation would be similar to the shell discovery
        Ok(vec![])
    }

    #[cfg(not(windows))]
    pub async fn get_installed_browsers(&self) -> Result<Vec<String>> {
        Ok(vec![])
    }
}
