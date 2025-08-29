use anyhow::Result;
use std::process::{Command, Stdio};
use tracing::{debug, error};

#[cfg(windows)]
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{BOOL, HWND, LPARAM},
        System::{
            Console::{AllocConsole, FreeConsole, GetConsoleWindow},
            Threading::{GetCurrentProcessId, PROCESS_CREATION_FLAGS},
        },
        UI::{
            Shell::ShellExecuteA,
            WindowsAndMessaging::{
                EnumWindows, FindWindowA, GetWindowThreadProcessId, ShowWindow, SW_HIDE,
            },
        },
    },
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Console Manager for suppressing console windows on Windows
#[derive(Debug)]
pub struct ConsoleManager {
    #[cfg(windows)]
    original_console_state: bool,
}

impl ConsoleManager {
    pub fn new() -> Self {
        Self {
            #[cfg(windows)]
            original_console_state: false,
        }
    }

    /// Initialize console suppression
    pub fn initialize(&mut self) -> Result<()> {
        #[cfg(windows)]
        {
            self.hide_all_console_windows()?;
            self.setup_console_hook()?;
        }
        Ok(())
    }

    /// Execute a command with complete console suppression
    pub async fn execute_hidden_command(
        &self,
        executable: &str,
        args: &[&str],
        working_dir: Option<&str>,
    ) -> Result<(String, String, i32)> {
        #[cfg(windows)]
        {
            self.execute_windows_hidden(executable, args, working_dir).await
        }
        #[cfg(not(windows))]
        {
            self.execute_standard(executable, args, working_dir).await
        }
    }

    #[cfg(windows)]
    async fn execute_windows_hidden(
        &self,
        executable: &str,
        args: &[&str],
        working_dir: Option<&str>,
    ) -> Result<(String, String, i32)> {
        // Method 1: Try with CREATE_NO_WINDOW and additional flags
        let result = self.try_standard_hidden(executable, args, working_dir).await;
        
        if result.is_ok() {
            return result;
        }

        // Method 2: Use ShellExecute with hidden window
        self.try_shell_execute_hidden(executable, args, working_dir).await
    }

    #[cfg(windows)]
    async fn try_standard_hidden(
        &self,
        executable: &str,
        args: &[&str],
        working_dir: Option<&str>,
    ) -> Result<(String, String, i32)> {
        use std::process::{Command, Stdio};
        use std::os::windows::process::CommandExt;
        use windows::Win32::{
            Foundation::LPARAM,
            System::Threading::GetCurrentProcessId,
            UI::WindowsAndMessaging::EnumWindows,
        };
        
        let mut cmd = Command::new(executable);
        
        for arg in args {
            cmd.arg(arg);
        }
        
        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }
        
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Use multiple Windows flags for maximum console suppression
        cmd.creation_flags(
            0x08000000 | // CREATE_NO_WINDOW
            0x00000010 | // CREATE_NEW_PROCESS_GROUP
            0x00000200   // CREATE_NEW_CONSOLE (then immediately hide it)
        );

        // Execute in a separate thread to avoid blocking with immediate console hiding
        let output = tokio::task::spawn_blocking(move || {
            // Start aggressive console hiding before and during execution
            let _guard = ConsoleHideGuard::new();
            
            // Hide any existing console windows immediately
            unsafe {
                let current_pid = GetCurrentProcessId();
                let _ = EnumWindows(
                    Some(hide_console_enum_proc),
                    LPARAM(current_pid as isize),
                );
            }
            
            let result = cmd.output();
            
            // Hide console windows again after execution
            unsafe {
                let current_pid = GetCurrentProcessId();
                let _ = EnumWindows(
                    Some(hide_console_enum_proc),
                    LPARAM(current_pid as isize),
                );
            }
            
            result
        }).await??;
        
        Ok((
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            output.status.code().unwrap_or(-1),
        ))
    }

    #[cfg(windows)]
    async fn try_shell_execute_hidden(
        &self,
        executable: &str,
        args: &[&str],
        _working_dir: Option<&str>,
    ) -> Result<(String, String, i32)> {
        // For commands that still show windows, we'll use a different approach
        // Create a batch file that redirects output and runs hidden
        let batch_content = format!(
            "@echo off\n{} {} > %TEMP%\\ghostshell_output.txt 2> %TEMP%\\ghostshell_error.txt\necho %ERRORLEVEL% > %TEMP%\\ghostshell_exitcode.txt\n",
            executable,
            args.join(" ")
        );

        let temp_dir = std::env::temp_dir();
        let batch_file = temp_dir.join("ghostshell_cmd.bat");
        let output_file = temp_dir.join("ghostshell_output.txt");
        let error_file = temp_dir.join("ghostshell_error.txt");
        let exitcode_file = temp_dir.join("ghostshell_exitcode.txt");

        // Clean up any existing files
        let _ = std::fs::remove_file(&output_file);
        let _ = std::fs::remove_file(&error_file);
        let _ = std::fs::remove_file(&exitcode_file);

        // Write batch file
        std::fs::write(&batch_file, batch_content)?;

        // Execute batch file hidden using Windows API
        unsafe {
            let result = ShellExecuteA(
                HWND(0),
                PCSTR::null(),
                PCSTR(format!("{}\0", batch_file.display()).as_ptr()),
                PCSTR::null(),
                PCSTR::null(),
                SW_HIDE,
            );

            if result.0 <= 32 {
                return Err(anyhow::anyhow!("ShellExecute failed with code: {}", result.0));
            }
        }

        // Wait for completion and read results
        let mut attempts = 0;
        while attempts < 100 && !exitcode_file.exists() {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            attempts += 1;
        }

        let stdout = std::fs::read_to_string(&output_file).unwrap_or_default();
        let stderr = std::fs::read_to_string(&error_file).unwrap_or_default();
        let exit_code = std::fs::read_to_string(&exitcode_file)
            .unwrap_or_default()
            .trim()
            .parse::<i32>()
            .unwrap_or(-1);

        // Clean up
        let _ = std::fs::remove_file(&batch_file);
        let _ = std::fs::remove_file(&output_file);
        let _ = std::fs::remove_file(&error_file);
        let _ = std::fs::remove_file(&exitcode_file);

        Ok((stdout, stderr, exit_code))
    }

    #[cfg(not(windows))]
    async fn execute_standard(
        &self,
        executable: &str,
        args: &[&str],
        working_dir: Option<&str>,
    ) -> Result<(String, String, i32)> {
        let mut cmd = Command::new(executable);
        
        for arg in args {
            cmd.arg(arg);
        }
        
        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }
        
        let output = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        
        Ok((
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            output.status.code().unwrap_or(-1),
        ))
    }

    #[cfg(windows)]
    fn hide_all_console_windows(&self) -> Result<()> {
        unsafe {
            // Hide the current console window if it exists
            let console_window = GetConsoleWindow();
            if console_window.0 != 0 {
                ShowWindow(console_window, SW_HIDE);
            }

            // Enumerate and hide any console windows belonging to this process
            let current_pid = GetCurrentProcessId();
            let _ = EnumWindows(
                Some(hide_console_enum_proc),
                LPARAM(current_pid as isize),
            );
        }
        Ok(())
    }

    #[cfg(windows)]
    fn setup_console_hook(&self) -> Result<()> {
        // Additional setup for console suppression
        debug!("Console suppression initialized");
        Ok(())
    }
}

#[cfg(windows)]
struct ConsoleHideGuard {
    _phantom: std::marker::PhantomData<()>,
}

#[cfg(windows)]
impl ConsoleHideGuard {
    fn new() -> Self {
        // Start a background task to continuously hide console windows
        tokio::spawn(async {
            for _ in 0..20 { // Monitor for 1 second
                unsafe {
                    let current_pid = GetCurrentProcessId();
                    let _ = EnumWindows(
                        Some(hide_console_enum_proc),
                        LPARAM(current_pid as isize),
                    );
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        });
        
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn hide_console_enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let target_pid = lparam.0 as u32;
    let mut window_pid = 0u32;
    
    GetWindowThreadProcessId(hwnd, Some(&mut window_pid));
    
    if window_pid == target_pid {
        // Check if it's a console window
        let class_name = "ConsoleWindowClass\0";
        let console_hwnd = FindWindowA(PCSTR(class_name.as_ptr()), PCSTR::null());
        
        if hwnd == console_hwnd || hwnd == GetConsoleWindow() {
            ShowWindow(hwnd, SW_HIDE);
        }
    }
    
    BOOL::from(true) // Continue enumeration
}

impl Default for ConsoleManager {
    fn default() -> Self {
        Self::new()
    }
}
