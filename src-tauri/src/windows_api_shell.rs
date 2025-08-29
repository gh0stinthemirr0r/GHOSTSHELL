use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn, error, debug};

#[cfg(windows)]
use windows::{
    core::{PWSTR, PCWSTR},
    Win32::{
        Foundation::{ERROR_SUCCESS, MAX_PATH, WIN32_ERROR},
        System::{
            Registry::{
                RegOpenKeyExW, RegQueryValueExW, RegEnumKeyExW, RegCloseKey,
                HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, KEY_READ, REG_SZ, HKEY
            },
            Environment::{GetEnvironmentVariableW, ExpandEnvironmentStringsW},
        },
        Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES},
    },
};

/// Windows API-based shell discovery
pub struct WindowsShellDiscovery {
    known_shells: HashMap<String, Vec<String>>,
}

impl WindowsShellDiscovery {
    pub fn new() -> Self {
        let mut known_shells = HashMap::new();
        
        // Define known shell locations and registry paths
        known_shells.insert("pwsh".to_string(), vec![
            r"C:\Program Files\PowerShell\7\pwsh.exe".to_string(),
            r"C:\Program Files\WindowsApps\Microsoft.PowerShell_*\pwsh.exe".to_string(),
            r"%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe".to_string(),
        ]);
        
        known_shells.insert("powershell".to_string(), vec![
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe".to_string(),
        ]);
        
        known_shells.insert("cmd".to_string(), vec![
            r"C:\Windows\System32\cmd.exe".to_string(),
            r"C:\Windows\SysWOW64\cmd.exe".to_string(),
        ]);
        
        known_shells.insert("wsl".to_string(), vec![
            r"C:\Windows\System32\wsl.exe".to_string(),
        ]);
        
        known_shells.insert("bash".to_string(), vec![
            r"C:\Program Files\Git\bin\bash.exe".to_string(),
            r"C:\Program Files (x86)\Git\bin\bash.exe".to_string(),
        ]);

        Self { known_shells }
    }

    /// Find executable using Windows API methods
    pub async fn find_executable(&self, name: &str) -> Result<String> {
        debug!("Finding executable: {}", name);

        // First, try known locations
        if let Some(paths) = self.known_shells.get(name) {
            for path in paths {
                if let Ok(expanded_path) = self.expand_environment_string(path) {
                    if self.file_exists(&expanded_path) {
                        info!("Found {} at: {}", name, expanded_path);
                        return Ok(expanded_path);
                    }
                }
            }
        }

        // Second, search PATH environment variable
        if let Ok(path_from_env) = self.search_in_path(name).await {
            return Ok(path_from_env);
        }

        // Third, search Windows Registry for installed applications
        if let Ok(path_from_registry) = self.search_in_registry(name).await {
            return Ok(path_from_registry);
        }

        Err(anyhow!("Executable '{}' not found", name))
    }

    /// Expand environment variables in path using Windows API
    #[cfg(windows)]
    fn expand_environment_string(&self, path: &str) -> Result<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
        let mut buffer = vec![0u16; 32767]; // MAX_PATH extended

        unsafe {
            let result = ExpandEnvironmentStringsW(
                PCWSTR(wide_path.as_ptr()),
                Some(&mut buffer),
            );

            if result > 0 && result <= buffer.len() as u32 {
                buffer.truncate(result as usize - 1); // Remove null terminator
                let expanded = String::from_utf16_lossy(&buffer);
                Ok(expanded)
            } else {
                Ok(path.to_string()) // Return original if expansion fails
            }
        }
    }

    #[cfg(not(windows))]
    fn expand_environment_string(&self, path: &str) -> Result<String> {
        Ok(path.to_string())
    }

    /// Check if file exists using Windows API
    #[cfg(windows)]
    fn file_exists(&self, path: &str) -> bool {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
        
        unsafe {
            let attributes = GetFileAttributesW(PCWSTR(wide_path.as_ptr()));
            attributes != INVALID_FILE_ATTRIBUTES
        }
    }

    #[cfg(not(windows))]
    fn file_exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    /// Search in PATH environment variable using Windows API
    #[cfg(windows)]
    async fn search_in_path(&self, name: &str) -> Result<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let exe_name = format!("{}.exe", name);
        let wide_var_name: Vec<u16> = OsStr::new("PATH").encode_wide().chain(std::iter::once(0)).collect();
        let mut buffer = vec![0u16; 32767];

        unsafe {
            let result = GetEnvironmentVariableW(
                PCWSTR(wide_var_name.as_ptr()),
                Some(&mut buffer),
            );

            if result > 0 && result <= buffer.len() as u32 {
                buffer.truncate(result as usize);
                let path_env = String::from_utf16_lossy(&buffer);
                
                for path_dir in path_env.split(';') {
                    if !path_dir.is_empty() {
                        let full_path = format!("{}\\{}", path_dir.trim(), exe_name);
                        if self.file_exists(&full_path) {
                            return Ok(full_path);
                        }
                    }
                }
            }
        }

        Err(anyhow!("Not found in PATH"))
    }

    #[cfg(not(windows))]
    async fn search_in_path(&self, _name: &str) -> Result<String> {
        Err(anyhow!("PATH search not implemented for non-Windows"))
    }

    /// Search Windows Registry for installed applications
    #[cfg(windows)]
    async fn search_in_registry(&self, name: &str) -> Result<String> {
        // Search common registry locations for installed software
        let registry_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
        ];

        for reg_path in &registry_paths {
            if let Ok(path) = self.search_registry_path(HKEY_LOCAL_MACHINE, reg_path, name) {
                return Ok(path);
            }
        }

        // Also search HKEY_CURRENT_USER
        for reg_path in &registry_paths {
            if let Ok(path) = self.search_registry_path(HKEY_CURRENT_USER, reg_path, name) {
                return Ok(path);
            }
        }

        Err(anyhow!("Not found in registry"))
    }

    #[cfg(not(windows))]
    async fn search_in_registry(&self, _name: &str) -> Result<String> {
        Err(anyhow!("Registry search not implemented for non-Windows"))
    }

    #[cfg(windows)]
    fn search_registry_path(&self, hkey: HKEY, path: &str, name: &str) -> Result<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let exe_name = format!("{}.exe", name);
        let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
        let wide_exe_name: Vec<u16> = OsStr::new(&exe_name).encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey_result = HKEY::default();
            
            // Open the registry key
            if RegOpenKeyExW(hkey, PCWSTR(wide_path.as_ptr()), 0, KEY_READ, &mut hkey_result).is_err() {
                return Err(anyhow!("Failed to open registry key"));
            }

            // Try to open the specific executable subkey
            let mut hkey_exe = HKEY::default();
            if RegOpenKeyExW(hkey_result, PCWSTR(wide_exe_name.as_ptr()), 0, KEY_READ, &mut hkey_exe).is_ok() {
                // Query the default value (executable path)
                let mut buffer = vec![0u16; MAX_PATH as usize];
                let mut buffer_size = (buffer.len() * 2) as u32; // Size in bytes
                let mut reg_type = REG_SZ;

                if RegQueryValueExW(
                    hkey_exe,
                    PCWSTR::null(),
                    None,
                    Some(&mut reg_type),
                    Some(buffer.as_mut_ptr() as *mut u8),
                    Some(&mut buffer_size),
                ).is_ok() {
                    let path_len = (buffer_size / 2) as usize;
                    if path_len > 0 {
                        buffer.truncate(path_len - 1); // Remove null terminator
                        let exe_path = String::from_utf16_lossy(&buffer);
                        
                        let _ = RegCloseKey(hkey_exe);
                        let _ = RegCloseKey(hkey_result);
                        
                        if self.file_exists(&exe_path) {
                            return Ok(exe_path);
                        }
                    }
                }
                
                let _ = RegCloseKey(hkey_exe);
            }
            
            let _ = RegCloseKey(hkey_result);
        }

        Err(anyhow!("Not found in registry path"))
    }

    /// Discover WSL distributions using Windows API
    #[cfg(windows)]
    pub async fn discover_wsl_distributions(&self) -> Result<Vec<String>> {
        let mut distributions = Vec::new();

        // WSL distributions are stored in the registry
        let wsl_reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss";
        
        if let Ok(distros) = self.enumerate_wsl_from_registry(wsl_reg_path) {
            distributions.extend(distros);
        }

        Ok(distributions)
    }

    #[cfg(not(windows))]
    pub async fn discover_wsl_distributions(&self) -> Result<Vec<String>> {
        Ok(vec![])
    }

    #[cfg(windows)]
    fn enumerate_wsl_from_registry(&self, reg_path: &str) -> Result<Vec<String>> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let mut distributions = Vec::new();
        let wide_path: Vec<u16> = OsStr::new(reg_path).encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey_result = HKEY::default();
            
            if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(wide_path.as_ptr()), 0, KEY_READ, &mut hkey_result).is_err() {
                return Err(anyhow!("Failed to open WSL registry key"));
            }

            let mut index = 0u32;
            loop {
                let mut name_buffer = vec![0u16; 256];
                let mut name_size = name_buffer.len() as u32;

                let result = RegEnumKeyExW(
                    hkey_result,
                    index,
                    PWSTR(name_buffer.as_mut_ptr()),
                    &mut name_size,
                    None,
                    PWSTR::null(),
                    None,
                    None,
                );

                if result.is_err() {
                    break;
                }

                if name_size > 0 {
                    name_buffer.truncate(name_size as usize);
                    let distro_guid = String::from_utf16_lossy(&name_buffer);
                    
                    // Get the distribution name from the subkey
                    if let Ok(distro_name) = self.get_wsl_distro_name(&hkey_result, &distro_guid) {
                        distributions.push(distro_name);
                    }
                }

                index += 1;
            }

            let _ = RegCloseKey(hkey_result);
        }

        Ok(distributions)
    }

    #[cfg(windows)]
    fn get_wsl_distro_name(&self, parent_key: &HKEY, guid: &str) -> Result<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let wide_guid: Vec<u16> = OsStr::new(guid).encode_wide().chain(std::iter::once(0)).collect();
        let wide_distro_name: Vec<u16> = OsStr::new("DistributionName").encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey_distro = HKEY::default();
            
            if RegOpenKeyExW(*parent_key, PCWSTR(wide_guid.as_ptr()), 0, KEY_READ, &mut hkey_distro).is_err() {
                return Err(anyhow!("Failed to open distro key"));
            }

            let mut buffer = vec![0u16; 256];
            let mut buffer_size = (buffer.len() * 2) as u32;
            let mut reg_type = REG_SZ;

            if RegQueryValueExW(
                hkey_distro,
                PCWSTR(wide_distro_name.as_ptr()),
                None,
                Some(&mut reg_type),
                Some(buffer.as_mut_ptr() as *mut u8),
                Some(&mut buffer_size),
            ).is_ok() {
                let name_len = (buffer_size / 2) as usize;
                if name_len > 0 {
                    buffer.truncate(name_len - 1);
                    let distro_name = String::from_utf16_lossy(&buffer);
                    
                    let _ = RegCloseKey(hkey_distro);
                    return Ok(distro_name);
                }
            }

            let _ = RegCloseKey(hkey_distro);
        }

        Err(anyhow!("Failed to get distro name"))
    }

    /// Test shell availability using Windows API
    pub async fn test_shell_availability(&self, executable_path: &str) -> bool {
        self.file_exists(executable_path)
    }
}
