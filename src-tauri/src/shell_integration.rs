use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use tracing::{info, warn, error, debug};
use crate::console_manager::ConsoleManager;
use crate::windows_api_shell::WindowsShellDiscovery;

/// Shell types available in the system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ShellType {
    PowerShell,
    PowerShellCore,
    Cmd,
    WSL,
    WSLDistro(String),
    GitBash,
    Custom(String),
}

impl ShellType {
    pub fn display_name(&self) -> &str {
        match self {
            ShellType::PowerShell => "Windows PowerShell",
            ShellType::PowerShellCore => "PowerShell Core",
            ShellType::Cmd => "Command Prompt",
            ShellType::WSL => "WSL (Default)",
            ShellType::WSLDistro(name) => name,
            ShellType::GitBash => "Git Bash",
            ShellType::Custom(name) => name,
        }
    }

    pub fn icon(&self) -> &str {
        match self {
            ShellType::PowerShell | ShellType::PowerShellCore => "terminal",
            ShellType::Cmd => "square",
            ShellType::WSL | ShellType::WSLDistro(_) => "monitor",
            ShellType::GitBash => "git-branch",
            ShellType::Custom(_) => "terminal",
        }
    }
}

/// Shell configuration for launching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellConfig {
    pub shell_type: ShellType,
    pub executable_path: String,
    pub args: Vec<String>,
    pub working_directory: Option<String>,
    pub environment_vars: HashMap<String, String>,
    pub is_available: bool,
}

/// Shell discovery and management system
pub struct ShellManager {
    available_shells: Vec<ShellConfig>,
    default_shell: Option<ShellType>,
    windows_discovery: WindowsShellDiscovery,
}

impl ShellManager {
    pub fn new() -> Self {
        Self {
            available_shells: Vec::new(),
            default_shell: None,
            windows_discovery: WindowsShellDiscovery::new(),
        }
    }

    /// Discover all available shells on the system
    pub async fn discover_shells(&mut self) -> Result<()> {
        info!("Discovering available shells...");
        
        let mut shells = Vec::new();

        // Discover PowerShell variants
        shells.extend(self.discover_powershell_shells().await?);
        
        // Discover WSL distributions
        shells.extend(self.discover_wsl_distributions().await?);
        
        // Discover other shells
        shells.extend(self.discover_other_shells().await?);

        self.available_shells = shells;
        
        // Set default shell (prefer PowerShell Core, then PowerShell, then CMD)
        if let Some(shell) = self.available_shells.iter().find(|s| s.shell_type == ShellType::PowerShellCore) {
            self.default_shell = Some(shell.shell_type.clone());
        } else if let Some(shell) = self.available_shells.iter().find(|s| s.shell_type == ShellType::PowerShell) {
            self.default_shell = Some(shell.shell_type.clone());
        } else if let Some(shell) = self.available_shells.iter().find(|s| s.shell_type == ShellType::Cmd) {
            self.default_shell = Some(shell.shell_type.clone());
        }

        info!("Discovered {} shells", self.available_shells.len());
        for shell in &self.available_shells {
            info!("  - {} at {}", shell.shell_type.display_name(), shell.executable_path);
        }

        Ok(())
    }

    /// Discover PowerShell variants
    async fn discover_powershell_shells(&self) -> Result<Vec<ShellConfig>> {
        let mut shells = Vec::new();

        // PowerShell Core (pwsh.exe)
        if let Ok(pwsh_path) = self.find_executable("pwsh").await {
            shells.push(ShellConfig {
                shell_type: ShellType::PowerShellCore,
                executable_path: pwsh_path,
                args: vec![
                    "-NoExit".to_string(),
                    "-ExecutionPolicy".to_string(),
                    "Bypass".to_string(),
                ],
                working_directory: None,
                environment_vars: HashMap::new(),
                is_available: true,
            });
        }

        // Windows PowerShell (powershell.exe)
        if let Ok(ps_path) = self.find_executable("powershell").await {
            shells.push(ShellConfig {
                shell_type: ShellType::PowerShell,
                executable_path: ps_path,
                args: vec![
                    "-NoExit".to_string(),
                    "-ExecutionPolicy".to_string(),
                    "Bypass".to_string(),
                ],
                working_directory: None,
                environment_vars: HashMap::new(),
                is_available: true,
            });
        }

        Ok(shells)
    }

    /// Discover WSL distributions using Windows API
    async fn discover_wsl_distributions(&self) -> Result<Vec<ShellConfig>> {
        let mut shells = Vec::new();

        // Check if WSL is available
        if let Ok(wsl_path) = self.find_executable("wsl").await {
            // Get WSL distributions from Windows Registry
            match self.windows_discovery.discover_wsl_distributions().await {
                Ok(distributions) => {
                    for distro in distributions {
                        if distro == "docker-desktop" || distro == "docker-desktop-data" {
                            continue; // Skip Docker WSL instances
                        }

                        shells.push(ShellConfig {
                            shell_type: if distro == "default" {
                                ShellType::WSL
                            } else {
                                ShellType::WSLDistro(distro.clone())
                            },
                            executable_path: wsl_path.clone(),
                            args: if distro == "default" {
                                vec![]
                            } else {
                                vec!["-d".to_string(), distro]
                            },
                            working_directory: None,
                            environment_vars: HashMap::new(),
                            is_available: true,
                        });
                    }
                }
                Err(e) => {
                    warn!("Failed to discover WSL distributions from registry: {}", e);
                }
            }
        }

        Ok(shells)
    }

    /// Discover other shells (CMD, Git Bash, etc.)
    async fn discover_other_shells(&self) -> Result<Vec<ShellConfig>> {
        let mut shells = Vec::new();

        // Command Prompt
        if let Ok(cmd_path) = self.find_executable("cmd").await {
            shells.push(ShellConfig {
                shell_type: ShellType::Cmd,
                executable_path: cmd_path,
                args: vec![],
                working_directory: None,
                environment_vars: HashMap::new(),
                is_available: true,
            });
        }

        // Git Bash
        let git_bash_paths = vec![
            "C:\\Program Files\\Git\\bin\\bash.exe",
            "C:\\Program Files (x86)\\Git\\bin\\bash.exe",
        ];

        for path in git_bash_paths {
            if std::path::Path::new(path).exists() {
                shells.push(ShellConfig {
                    shell_type: ShellType::GitBash,
                    executable_path: path.to_string(),
                    args: vec!["--login".to_string(), "-i".to_string()],
                    working_directory: None,
                    environment_vars: HashMap::new(),
                    is_available: true,
                });
                break;
            }
        }

        Ok(shells)
    }

    /// Find executable using Windows API
    async fn find_executable(&self, name: &str) -> Result<String> {
        self.windows_discovery.find_executable(name).await
    }

    /// Parse WSL distribution list output
    fn parse_wsl_distributions(&self, output: &str) -> Vec<String> {
        let mut distributions = Vec::new();
        
        for line in output.lines().skip(1) { // Skip header line
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Parse WSL output format: "  NAME                   STATE           VERSION"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(name) = parts.first() {
                let name = name.trim_start_matches('*').trim(); // Remove default marker
                if !name.is_empty() && name != "NAME" {
                    distributions.push(name.to_string());
                }
            }
        }

        distributions
    }

    /// Get all available shells
    pub fn get_available_shells(&self) -> &[ShellConfig] {
        &self.available_shells
    }

    /// Get shell configuration by type
    pub fn get_shell_config(&self, shell_type: &ShellType) -> Option<&ShellConfig> {
        self.available_shells.iter().find(|s| &s.shell_type == shell_type)
    }

    /// Get default shell
    pub fn get_default_shell(&self) -> Option<&ShellType> {
        self.default_shell.as_ref()
    }

    /// Launch a shell process
    pub async fn launch_shell(&self, shell_type: &ShellType, working_dir: Option<String>) -> Result<ShellProcess> {
        let config = self.get_shell_config(shell_type)
            .ok_or_else(|| anyhow::anyhow!("Shell type not available: {:?}", shell_type))?;

        let mut cmd = Command::new(&config.executable_path);
        cmd.args(&config.args);

        // Set working directory
        if let Some(dir) = working_dir.or_else(|| config.working_directory.clone()) {
            cmd.current_dir(dir);
        }

        // Set environment variables
        for (key, value) in &config.environment_vars {
            cmd.env(key, value);
        }

        // Configure for PTY usage with console suppression
        cmd.stdin(Stdio::piped())
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        // Hide console window on Windows
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        debug!("Launching shell: {} with args: {:?}", config.executable_path, config.args);

        let child = cmd.spawn()
            .map_err(|e| anyhow::anyhow!("Failed to launch shell: {}", e))?;

        Ok(ShellProcess {
            shell_type: shell_type.clone(),
            process: child,
        })
    }

    /// Test shell availability using Windows API
    pub async fn test_shell(&self, shell_type: &ShellType) -> bool {
        if let Some(config) = self.get_shell_config(shell_type) {
            self.windows_discovery.test_shell_availability(&config.executable_path).await
        } else {
            false
        }
    }
}

/// Represents a running shell process
pub struct ShellProcess {
    pub shell_type: ShellType,
    pub process: std::process::Child,
}

impl ShellProcess {
    /// Get the process ID
    pub fn pid(&self) -> Option<u32> {
        Some(self.process.id())
    }

    /// Kill the shell process
    pub fn kill(&mut self) -> Result<()> {
        self.process.kill()
            .map_err(|e| anyhow::anyhow!("Failed to kill shell process: {}", e))
    }

    /// Wait for the process to exit
    pub fn wait(&mut self) -> Result<std::process::ExitStatus> {
        self.process.wait()
            .map_err(|e| anyhow::anyhow!("Failed to wait for shell process: {}", e))
    }
}

/// Shell integration for terminal sessions
pub struct TerminalShellIntegration {
    shell_manager: ShellManager,
    active_sessions: HashMap<String, ShellProcess>,
}

impl TerminalShellIntegration {
    pub async fn new() -> Result<Self> {
        let mut shell_manager = ShellManager::new();
        shell_manager.discover_shells().await?;

        Ok(Self {
            shell_manager,
            active_sessions: HashMap::new(),
        })
    }

    /// Get available shells for UI
    pub fn get_shell_options(&self) -> Vec<(ShellType, String, String)> {
        self.shell_manager
            .get_available_shells()
            .iter()
            .map(|config| (
                config.shell_type.clone(),
                config.shell_type.display_name().to_string(),
                config.shell_type.icon().to_string(),
            ))
            .collect()
    }

    /// Create a new terminal session with specified shell
    pub async fn create_session(&mut self, session_id: String, shell_type: ShellType, working_dir: Option<String>) -> Result<()> {
        let shell_process = self.shell_manager.launch_shell(&shell_type, working_dir).await?;
        self.active_sessions.insert(session_id, shell_process);
        Ok(())
    }

    /// Get session process ID
    pub fn get_session_pid(&self, session_id: &str) -> Option<u32> {
        self.active_sessions.get(session_id)?.pid()
    }

    /// Close a terminal session
    pub fn close_session(&mut self, session_id: &str) -> Result<()> {
        if let Some(mut session) = self.active_sessions.remove(session_id) {
            session.kill()?;
        }
        Ok(())
    }

    /// Get default shell type
    pub fn get_default_shell_type(&self) -> ShellType {
        self.shell_manager
            .get_default_shell()
            .cloned()
            .unwrap_or(ShellType::Cmd)
    }
}
