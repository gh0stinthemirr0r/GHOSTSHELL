// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
// use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::{Manager, Window};
use tracing::{info, warn, debug};
use std::fs;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
// use uuid::Uuid;

// Notification system imports
use ghost_notify::NotificationEngine;
use ghost_log::AuditLogger;
use ghost_pq::signatures::DilithiumSigner;

// Theme system imports
use ghost_theme::ThemeEngine;


// Browser system imports
use ghost_browse::{BrowserEngine, BrowserConfig};

// ============================================================================
// Enterprise Module Imports - Comprehensive Systems
// ============================================================================

// Core enterprise modules
mod ghost_shell;           // Comprehensive shell management system
mod ghost_ssh;             // Enterprise SSH management system

// Legacy modules (to be consolidated)
mod commands;
mod security;
mod window_effects;
mod clipboard;
mod quarantine;
mod terminal;
mod embedded_nushell;
mod vpn;

mod file_manager;
mod network_topology;
mod tools;
mod pcap_studio;
mod behavioral_analytics;
mod predictive_security;
mod reporting;
mod remediation_playbooks;
mod analysis;

// Import error handling module
use commands::error_handling;

// Deprecated modules (will be removed)
// mod console_manager;        // Replaced by ghost_shell
// mod window_controller;      // Replaced by ghost_shell
// mod pure_winapi_executor;   // Replaced by ghost_shell
// mod windows_api_shell;      // Replaced by ghost_shell
// mod windows_api_network;    // To be consolidated
// mod windows_api_browser;    // To be consolidated
// mod shell_integration;      // Replaced by ghost_shell
// mod simple_shell;           // Replaced by ghost_shell
// mod ssh;                    // Replaced by ghost_ssh

// ============================================================================
// Enterprise System Imports
// ============================================================================

// Core enterprise systems
use ghost_shell::{GhostShell, GhostShellState};
use ghost_ssh::{GhostSSH, GhostSSHState};

// Command modules
use commands::{settings, theme, theme_vault, vault};

// Security and core systems
// Policy enforcement removed for single-user mode
use clipboard::ClipboardManager;
use quarantine::QuarantineManager;
use terminal::TerminalManager;
use vpn::VpnManager;

use file_manager::FileManager;
use network_topology::NetworkTopologyManager;
use tools::ToolsManager;
use pcap_studio::PcapStudioManager;
use behavioral_analytics::BehavioralAnalyticsManager;
use predictive_security::PredictiveSecurityManager;
use reporting::ReportingManager;



// ============================================================================
// Enterprise Application State
// ============================================================================

/// Main application state with enterprise systems
#[derive(Debug)]
pub struct AppState {
    // Theme and UI state
    themes: Mutex<HashMap<String, theme::ThemeV1>>,
    current_theme: Mutex<Option<String>>,
    settings: Mutex<settings::AppSettings>,
    
    // Enterprise systems
    ghost_shell: Arc<GhostShell>,
    ghost_ssh: Arc<GhostSSH>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new().expect("Failed to create default AppState")
    }
}

impl AppState {
    pub fn new() -> Result<Self> {
        info!("Initializing enterprise application state");
        
        // Initialize enterprise systems
        let ghost_shell = Arc::new(GhostShell::new());
        let ghost_ssh = Arc::new(GhostSSH::new());
        
        info!("Enterprise systems initialized successfully");
        
        Ok(Self {
            themes: Mutex::new(HashMap::new()),
            current_theme: Mutex::new(None),
            settings: Mutex::new(settings::AppSettings::default()),
            ghost_shell,
            ghost_ssh,
        })
    }
    
    /// Get GhostShell system
    pub fn ghost_shell(&self) -> &Arc<GhostShell> {
        &self.ghost_shell
    }
    
    /// Get GhostSSH system
    pub fn ghost_ssh(&self) -> &Arc<GhostSSH> {
        &self.ghost_ssh
    }
}

fn init_logging() -> Result<()> {
    // Create logs directory if it doesn't exist
    fs::create_dir_all("logs")?;
    
    // Create file appender for detailed logging
    let file_appender = RollingFileAppender::new(
        Rotation::DAILY,
        "logs",
        "ghostshell-debug.log"
    );
    
    // Create console layer for stdout
    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_file(true);
    
    // Create file layer for detailed file logging
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_appender)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_file(true)
        .with_ansi(false);
    
    // Initialize subscriber with both console and file output
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive("debug".parse()?))
        .with(console_layer)
        .with(file_layer)
        .init();
    
    info!("Logging initialized - detailed logs will be written to logs/ghostshell-debug.log");
    Ok(())
}

fn main() -> Result<()> {
    // Initialize comprehensive logging first
    if let Err(e) = init_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        // Fallback to basic logging
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }
    
    info!("=== GHOSTSHELL STARTING ===");
    debug!("Main function entry point reached");

    info!("Starting GHOSTSHELL v0.1.0 - Post-Quantum Secure Terminal");
    debug!("About to create AppState");

    let app_state = AppState::new()?;
    debug!("AppState created successfully");
    
    // Clone the enterprise systems before moving app_state
    let ghost_shell_state = GhostShellState {
        ghost_shell: Arc::clone(&app_state.ghost_shell()),
    };
    let ghost_ssh_state = GhostSSHState {
        ghost_ssh: Arc::clone(&app_state.ghost_ssh()),
    };

    tauri::Builder::default()
        .manage(app_state)
        .manage(ghost_shell_state)
        .manage(ghost_ssh_state)
        .manage(commands::ghostdash::GhostDashState::new())
        .manage(commands::ghostreport::GhostReportState::new())
        .manage(commands::ghostscript::GhostScriptState::new())
        .setup(|app| {
            debug!("Entering Tauri setup function");
            let rt = tokio::runtime::Runtime::new().unwrap();
            debug!("Tokio runtime created");
            let window = app.get_window("main").unwrap();
            debug!("Main window obtained");
            
            // Apply window effects
            debug!("About to apply window effects");
            if let Err(e) = setup_window_effects(&window) {
                warn!("Failed to apply window effects: {}", e);
            } else {
                debug!("Window effects applied successfully");
            }

            // Load default themes
            debug!("About to load default themes");
            if let Err(e) = theme::load_default_themes(app.state()) {
                warn!("Failed to load default themes: {}", e);
            } else {
                debug!("Default themes loaded successfully");
            }

            // Initialize Phase 2 security components
            let rt = tokio::runtime::Runtime::new().unwrap();
            
            // Initialize GhostLog system
            rt.block_on(async {
                use ghost_log::{initialize_ghost_log, GhostLogConfig};
                
                let config = GhostLogConfig {
                    log_directory: std::path::PathBuf::from("logs/ghostlog"),
                    max_file_size: 50 * 1024 * 1024, // 50MB per file
                    max_file_age_hours: 24, // Daily rotation
                    max_events_per_second: 1000,
                    enable_search_indexing: true,
                    retention_days: 90,
                };
                
                match initialize_ghost_log(config).await {
                    Ok(()) => {
                        info!("GhostLog system initialized successfully");
                        
                        // Log the application startup
                        if let Some(ghost_log) = ghost_log::get_ghost_log() {
                            let _ = ghost_log.log(
                                "system",
                                ghost_log::LogSeverity::Info,
                                "app-startup",
                                "GhostShell application started"
                            );
                        }
                    }
                    Err(e) => {
                        warn!("Failed to initialize GhostLog: {}", e);
                    }
                }
            });
            
            // Policy enforcement removed for single-user mode

            // Initialize Clipboard Manager
            let clipboard_manager = ClipboardManager::new();
            app.manage(clipboard_manager);
            info!("Clipboard manager initialized");

            // Initialize Quarantine Manager
            let quarantine_dir = app.path_resolver()
                .app_data_dir()
                .unwrap_or_else(|| std::env::temp_dir())
                .join("quarantine");
            
            let quarantine_manager = rt.block_on(async {
                match QuarantineManager::new(quarantine_dir).await {
                    Ok(qm) => {
                        info!("Quarantine manager initialized");
                        Ok(qm)
                    }
                    Err(e) => {
                        warn!("Failed to initialize quarantine manager: {}", e);
                        // This is a critical error, but we'll continue without quarantine
                        Err(anyhow::anyhow!("Quarantine initialization failed: {}", e))
                    }
                }
            })?;
            app.manage(quarantine_manager);

            // Initialize Vault State (Phase 2)
            let vault_state = vault::create_vault_state();
            app.manage(vault_state);
            info!("Vault state initialized");

            // Initialize Terminal Manager (Phase 3)
            let terminal_manager = TerminalManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize terminal manager: {}", e))?;
            app.manage(terminal_manager);
            info!("Terminal manager initialized");

            // SSH Manager replaced by GhostSSH enterprise system (managed in AppState)
            info!("SSH management handled by GhostSSH enterprise system");

            // Initialize VPN Manager (Phase 3)
            let vpn_manager = Arc::new(Mutex::new(VpnManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize VPN manager: {}", e))?));
            app.manage(vpn_manager);
            info!("VPN manager initialized");



            // Initialize File Manager (Phase 3)
            let file_manager = Arc::new(Mutex::new(FileManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize file manager: {}", e))?));
            app.manage(file_manager);
            info!("File manager initialized");

            // Initialize Network Topology Manager (Phase 3)
            let network_manager = Arc::new(Mutex::new(NetworkTopologyManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize network topology manager: {}", e))?));
            app.manage(network_manager);
            info!("Network topology manager initialized");

            // Initialize Tools Manager (Phase 4)
            let tools_manager = Arc::new(tokio::sync::Mutex::new(ToolsManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize tools manager: {}", e))?));
            app.manage(tools_manager);
            info!("Tools manager initialized");

            // Initialize PCAP Studio Manager (Phase 5)
            let pcap_manager = Arc::new(tokio::sync::Mutex::new(PcapStudioManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize PCAP studio manager: {}", e))?));
            
            // PCAP manager initialization will happen on first use
            
            app.manage(pcap_manager);
            info!("PCAP studio manager initialized");



            // Initialize Behavioral Analytics Manager (Phase 7)
            let behavioral_analytics_manager = Arc::new(tokio::sync::Mutex::new(BehavioralAnalyticsManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize behavioral analytics manager: {}", e))?));
            
            // Behavioral analytics manager initialization will happen on first use
            
            app.manage(behavioral_analytics_manager);
            info!("Behavioral analytics manager initialized");

            // Initialize Predictive Security Manager (Phase 7)
            let predictive_security_manager = Arc::new(tokio::sync::Mutex::new(PredictiveSecurityManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize predictive security manager: {}", e))?));
            
            // Predictive security manager initialization will happen on first use
            
            app.manage(predictive_security_manager);
            info!("Predictive security manager initialized");



            // Initialize Reporting Manager (Phase 8)
            let reporting_manager = Arc::new(tokio::sync::Mutex::new(ReportingManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize reporting manager: {}", e))?));
            // Reporting manager initialization will happen on first use
            app.manage(reporting_manager);
            info!("Reporting manager initialized");















            // Initialize Remediation Playbooks Manager (Phase 12)
            let remediation_playbooks_manager = Arc::new(tokio::sync::Mutex::new(remediation_playbooks::RemediationPlaybookManager::new()));
            app.manage(remediation_playbooks_manager);
            info!("Remediation Playbooks manager initialized");

            // Initialize Notification Engine (Phase 10)
            debug!("About to initialize Notification Engine");
            let notification_engine = rt.block_on(async {
                use ghost_log::LoggerConfig;
                use ghost_pq::signatures::DilithiumVariant;
                
                debug!("Creating logger config for notifications");
                let _config = LoggerConfig::default();
                debug!("Creating in-memory audit logger");
                let logger = Arc::new(AuditLogger::in_memory("notifications".to_string()).await
                    .map_err(|e| anyhow::anyhow!("Failed to create notification logger: {}", e))?);
                debug!("Audit logger created successfully");
                
                debug!("Creating Dilithium signer");
                let signer = Arc::new(DilithiumSigner::new(DilithiumVariant::Dilithium3)
                    .map_err(|e| anyhow::anyhow!("Failed to create notification signer: {}", e))?);
                debug!("Dilithium signer created successfully");
                
                debug!("Creating NotificationEngine");
                let engine = Arc::new(tokio::sync::Mutex::new(
                    NotificationEngine::new(logger, signer)
                        .map_err(|e| anyhow::anyhow!("Failed to create notification engine: {}", e))?
                ));
                debug!("NotificationEngine created successfully");
                
                // Initialize the notification engine
                debug!("About to initialize notification engine");
                {
                    let engine_guard = engine.lock().await;
                    debug!("Acquired notification engine lock");
                    engine_guard.initialize().await
                        .map_err(|e| anyhow::anyhow!("Failed to initialize notification engine: {}", e))?;
                    debug!("Notification engine initialized successfully");
                }
                
                Ok::<_, anyhow::Error>(engine)
            })?;
            
            app.manage(notification_engine);
            info!("Notification engine initialized");

            // Initialize Theme Engine v2 (Phase 11)
            debug!("About to initialize Theme Engine v2");
            let theme_engine = rt.block_on(async {
                debug!("Creating ThemeEngine instance");
                let engine = Arc::new(tokio::sync::Mutex::new(ThemeEngine::new()));
                debug!("ThemeEngine instance created");
                
                // Initialize with default themes
                debug!("About to initialize theme engine with default themes");
                {
                    let engine_guard = engine.lock().await;
                    debug!("Acquired theme engine lock");
                    engine_guard.initialize().await
                        .map_err(|e| anyhow::anyhow!("Failed to initialize theme engine: {}", e))?;
                    debug!("Theme engine initialized successfully");
                }
                
                Ok::<_, anyhow::Error>(engine)
            })?;
            
            app.manage(theme_engine);
            info!("Theme engine v2 initialized");



            // Initialize Browser Engine (Phase 14)
            // Setup data directory path (shared by browser and navigation)
            let current_dir = std::env::current_dir()
                .map_err(|e| anyhow::anyhow!("Failed to get current directory: {}", e))?;
            // Go up one level from src-tauri to the project root, then into data
            let project_root = current_dir.parent()
                .ok_or_else(|| anyhow::anyhow!("Failed to get project root directory"))?;
            let data_dir = project_root.join("data");
            
            // Ensure data directory exists
            if let Err(e) = std::fs::create_dir_all(&data_dir) {
                tracing::warn!("Failed to create data directory {:?}: {}", data_dir, e);
            } else {
                debug!("Data directory created/verified: {:?}", data_dir);
            }

            debug!("About to initialize Browser Engine");
            let browser_config = BrowserConfig::default();
            let browser_engine = rt.block_on(async {
                debug!("Creating BrowserEngine instance");

                // Use shared vault, policy, logger, and signer
                use ghost_vault::Vault;

                use ghost_log::LoggerConfig;
                use ghost_pq::signatures::DilithiumVariant;

                // Create browser vault with proper database path
                let browser_db_path = data_dir.join("ghostshell_browser.db");
                
                debug!("Current directory: {:?}", current_dir);
                debug!("Data directory: {:?}", data_dir);
                debug!("Browser DB path: {:?}", browser_db_path);
                
                // Try to create the database file if it doesn't exist and determine database URL
                let database_url = if !browser_db_path.exists() {
                    if let Err(e) = std::fs::File::create(&browser_db_path) {
                        tracing::warn!("Failed to create browser database file {:?}: {}", browser_db_path, e);
                        tracing::info!("Falling back to in-memory database for browser vault");
                        ":memory:".to_string()
                    } else {
                        debug!("Browser database file created: {:?}", browser_db_path);
                        browser_db_path.to_string_lossy().to_string()
                    }
                } else {
                    debug!("Browser database file already exists: {:?}", browser_db_path);
                    browser_db_path.to_string_lossy().to_string()
                };
                
                let browser_vault_config = ghost_vault::VaultConfig {
                    database_url,
                    require_mfa: false, // Browser vault doesn't need MFA for internal operations
                    auto_lock_timeout_minutes: 60,
                    max_failed_attempts: 5,
                    enable_policy_enforcement: true,
                };
                
                let vault_manager = Arc::new(tokio::sync::Mutex::new(Vault::new(browser_vault_config).await
                    .map_err(|e| anyhow::anyhow!("Failed to create browser vault manager: {}", e))?));

                let logger = Arc::new(AuditLogger::in_memory("browser".to_string()).await
                    .map_err(|e| anyhow::anyhow!("Failed to create browser logger: {}", e))?);
                let signer = Arc::new(DilithiumSigner::new(DilithiumVariant::Dilithium3)
                    .map_err(|e| anyhow::anyhow!("Failed to create browser signer: {}", e))?);

                let engine = BrowserEngine::new(
                    browser_config,
                    vault_manager,
                    logger,
                    signer,
                ).await
                    .map_err(|e| anyhow::anyhow!("Failed to create browser engine: {}", e))?;

                debug!("About to initialize browser engine");
                let engine_arc = Arc::new(tokio::sync::Mutex::new(engine));

                // Initialize the browser engine
                {
                    let engine_guard = engine_arc.lock().await;
                    engine_guard.initialize().await
                        .map_err(|e| anyhow::anyhow!("Failed to initialize browser engine: {}", e))?;
                }

                Ok::<_, anyhow::Error>(engine_arc)
            })?;

            app.manage(browser_engine);
            debug!("Browser engine initialized successfully");
            info!("Browser Engine initialized");

                        // Initialize Navigation Manager (Phase 16) - TEMPORARILY DISABLED
            debug!("Skipping navigation manager initialization for debugging");
            info!("Navigation Manager initialization skipped");

            // Shell management handled by GhostShell enterprise system (managed in AppState)
            info!("Shell management handled by GhostShell enterprise system");

            // Window control and execution handled by GhostShell enterprise system
            info!("Window control and execution integrated with GhostShell enterprise system");

            // Initialize Embedded Nushell Manager
            debug!("Initializing embedded Nushell manager");
            let nushell_manager = embedded_nushell::EmbeddedNushellManager::new();
            app.manage(nushell_manager);
            debug!("Embedded Nushell manager initialized");
            info!("Embedded Nushell initialized");
            
            // Initialize Settings Manager
            debug!("Initializing settings manager");
            let settings_manager = commands::settings::SettingsManager::new(data_dir.clone());
            app.manage(settings_manager);
            debug!("Settings manager initialized");
            info!("Settings Manager initialized");

            info!("GHOSTSHELL interface ready - Welcome to the future!");
            info!("Interface features:");
            info!("  ✅ Tauri + SvelteKit architecture");
            info!("  ✅ Cyberpunk neon aesthetics");
            info!("  ✅ Windows Mica/Acrylic transparency");
            info!("  ✅ WebGL terminal rendering");
            info!("  ✅ Post-quantum cryptography ready");
            info!("Phase 2 Security Features:");
            info!("  ✅ Policy Enforcement Point (PEP)");
            info!("  ✅ Clipboard Security Guards");
            info!("  ✅ Download Quarantine System");
            info!("  ✅ GhostVault Secure Storage");

            debug!("Setup function completed successfully");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // ============================================================================
            // Enterprise System Commands
            // ============================================================================
            
            // GhostShell commands - comprehensive shell management
            ghost_shell::ghost_shell_get_profiles,
            ghost_shell::ghost_shell_create_session,
            ghost_shell::ghost_shell_execute_command,
            ghost_shell::ghost_shell_execute_direct,
            ghost_shell::ghost_shell_get_session,
            ghost_shell::ghost_shell_list_sessions,
            ghost_shell::ghost_shell_close_session,
            
            // GhostSSH commands - enterprise SSH management
            ghost_ssh::ghost_ssh_list_hosts,
            ghost_ssh::ghost_ssh_add_host,
            ghost_ssh::ghost_ssh_connect,
            ghost_ssh::ghost_ssh_disconnect,
            ghost_ssh::ghost_ssh_list_connections,
            ghost_ssh::ghost_ssh_generate_key,
            ghost_ssh::ghost_ssh_list_keys,
            ghost_ssh::ghost_ssh_create_local_forward,
            ghost_ssh::ghost_ssh_create_dynamic_forward,
            ghost_ssh::ghost_ssh_list_forwards,

            // GhostLog commands - system-wide logging
            commands::ghostlog::ghostlog_initialize,
            commands::ghostlog::ghostlog_log_entry,
            commands::ghostlog::ghostlog_search,
            commands::ghostlog::ghostlog_get_modules,
            commands::ghostlog::ghostlog_get_stats,
            commands::ghostlog::ghostlog_export,
            commands::ghostlog::ghostlog_get_recent,
            commands::ghostlog::ghostlog_verify_integrity,
            commands::ghostlog::ghostlog_rotation_status,
            commands::ghostlog::ghostlog_rotate_logs,
            commands::ghostlog::ghostlog_cleanup_old_files,

            // GhostDash commands - system dashboard and network analytics
            commands::ghostdash::ghostdash_initialize,
            commands::ghostdash::ghostdash_start_monitoring,
            commands::ghostdash::ghostdash_get_state,
            commands::ghostdash::ghostdash_get_system_info,
            commands::ghostdash::ghostdash_get_network_snapshot,
            commands::ghostdash::ghostdash_query_interfaces,
            commands::ghostdash::ghostdash_query_dns_servers,
            commands::ghostdash::ghostdash_query_routes,
            commands::ghostdash::ghostdash_query_connections,
            commands::ghostdash::ghostdash_get_table_stats,
            commands::ghostdash::ghostdash_get_stats,
            commands::ghostdash::ghostdash_export_data,
            commands::ghostdash::ghostdash_get_analytics,
            commands::ghostdash::ghostdash_create_snapshot,
            commands::ghostdash::ghostdash_get_theme,
            commands::ghostdash::ghostdash_update_config,
            commands::ghostdash::ghostdash_refresh_data,
            commands::ghostdash::ghostdash_get_export_formats,
            commands::ghostdash::ghostdash_get_export_data_types,
            commands::ghostdash::ghostdash_test_connectivity,

            // GhostReport commands - automated reporting engine
            commands::ghostreport::ghostreport_initialize,
            commands::ghostreport::ghostreport_get_jobs,
            commands::ghostreport::ghostreport_get_templates,
            commands::ghostreport::ghostreport_get_stats,
            commands::ghostreport::ghostreport_create_job,
            commands::ghostreport::ghostreport_run_job,
            commands::ghostreport::ghostreport_delete_job,
            commands::ghostreport::ghostreport_generate_report,
            commands::ghostreport::ghostreport_generate_preview,
            commands::ghostreport::ghostreport_schedule_report,
            commands::ghostreport::ghostreport_get_scheduled_reports,
            commands::ghostreport::ghostreport_cancel_scheduled_report,
            commands::ghostreport::ghostreport_get_stats,
            commands::ghostreport::ghostreport_search_archive,
            commands::ghostreport::ghostreport_get_archive_stats,
            commands::ghostreport::ghostreport_verify_artifact,
            
            // GhostScript commands - script management and execution engine
            commands::ghostscript::ghostscript_initialize,
            commands::ghostscript::ghostscript_select_directory,
            commands::ghostscript::ghostscript_get_repositories,
            commands::ghostscript::ghostscript_add_repository,
            commands::ghostscript::ghostscript_set_active_repository,
            commands::ghostscript::ghostscript_remove_repository,
            commands::ghostscript::ghostscript_store_script,
            commands::ghostscript::ghostscript_update_script,
            commands::ghostscript::ghostscript_get_script_metadata,
            commands::ghostscript::ghostscript_get_script_content,
            commands::ghostscript::ghostscript_search_scripts,
            commands::ghostscript::ghostscript_delete_script,
            commands::ghostscript::ghostscript_execute_script,
            commands::ghostscript::ghostscript_cancel_execution,
            commands::ghostscript::ghostscript_get_execution_record,
            commands::ghostscript::ghostscript_search_executions,
            commands::ghostscript::ghostscript_get_repository_stats,
            commands::ghostscript::ghostscript_get_execution_stats,
            commands::ghostscript::ghostscript_validate_script,
            commands::ghostscript::ghostscript_format_script,
            commands::ghostscript::ghostscript_schedule_script,
            commands::ghostscript::ghostscript_get_scheduled_scripts,
            commands::ghostscript::ghostscript_cancel_schedule,
            commands::ghostscript::ghostscript_verify_execution,
            commands::ghostreport::ghostreport_get_templates,
            commands::ghostreport::ghostreport_get_templates_by_category,
            commands::ghostreport::ghostreport_get_template,
            commands::ghostreport::ghostreport_create_security_audit,
            commands::ghostreport::ghostreport_create_network_activity,
            commands::ghostreport::ghostreport_create_system_health,

            commands::ghostreport::ghostreport_create_incident_response,
            commands::ghostreport::ghostreport_create_daily_operations,
            commands::ghostreport::ghostreport_build_custom_report,
            commands::ghostreport::ghostreport_get_formats,
            commands::ghostreport::ghostreport_get_schedule_frequencies,
            commands::ghostreport::ghostreport_delete_artifact,
            commands::ghostreport::ghostreport_cleanup_old_artifacts,
            commands::ghostreport::ghostreport_export_archive_index,
            
            // ============================================================================
            // Legacy Commands (to be migrated to enterprise systems)
            // ============================================================================
            
            // Theme commands
            theme::list_themes,
            theme::apply_theme,
            theme::save_theme,
            theme::export_theme,
            theme::import_theme,
            theme::set_acrylic_tint,
            // Theme Vault commands (Phase 2)
            theme_vault::vault_store_theme,
            theme_vault::vault_list_themes,
            theme_vault::vault_get_theme,
            theme_vault::vault_update_theme,
            theme_vault::vault_delete_theme,
            theme_vault::vault_export_theme,
            theme_vault::vault_import_theme,
            theme_vault::migrate_themes_to_vault,
            // Settings commands
            settings::get_settings,
            settings::update_settings,
            settings::set_accessibility,
            settings::set_fonts,
            // Vault commands (Phase 2)
            commands::vault::vault_initialize,
            commands::vault::vault_unlock,
            commands::vault::vault_lock,
            commands::vault::vault_is_unlocked,
            commands::vault::vault_setup_mfa,
            commands::vault::vault_verify_mfa,
            commands::vault::vault_store_secret,
            commands::vault::vault_list_secrets,
            commands::vault::vault_get_secret,
            commands::vault::vault_delete_secret,
            commands::vault::vault_get_stats,
            // Policy commands (Phase 2)
            // Policy commands removed for single-user mode
            // Clipboard commands (Phase 2)
            clipboard::clipboard_copy,
            clipboard::clipboard_paste,
            clipboard::clipboard_get_history,
            clipboard::clipboard_clear_entry,
            clipboard::clipboard_clear_all,
            // Quarantine commands (Phase 2)
            quarantine::quarantine_list_files,
            quarantine::quarantine_release_file,
            quarantine::quarantine_delete_file,
            // Terminal commands (Phase 3)
            terminal::create_terminal_session,
            terminal::send_terminal_input,
            terminal::resize_terminal,
            terminal::close_terminal_session,
            terminal::list_terminal_sessions,
            // SSH commands (Phase 3) - REPLACED by GhostSSH enterprise system
            // ssh::ssh_get_crypto_config,        // Use ghost_ssh commands instead
            // ssh::ssh_generate_pq_keypair,      // Use ghost_ssh_generate_key instead
            // ssh::ssh_connect,                  // Use ghost_ssh_connect instead
            // ssh::ssh_execute_command,          // Use ghost_ssh with shell integration
            // ssh::ssh_disconnect,               // Use ghost_ssh_disconnect instead
            // ssh::ssh_list_connections,         // Use ghost_ssh_list_connections instead
            // VPN commands (Phase 3)
            vpn::vpn_generate_pq_keypair,
            vpn::vpn_create_config,
            vpn::vpn_connect,
            vpn::vpn_disconnect,
            vpn::vpn_get_stats,
            vpn::vpn_list_connections,
            vpn::vpn_list_configs,
            vpn::vpn_test_connection,

            // File Manager commands (Phase 3)
            file_manager::fm_list_directory,
            file_manager::fm_create_directory,
            file_manager::fm_copy_file,
            file_manager::fm_move_file,
            file_manager::fm_delete_file,
            file_manager::fm_encrypt_file,
            file_manager::fm_search_files,
            file_manager::fm_get_file_stats,
            file_manager::fm_get_operation_status,
            file_manager::fm_list_operations,
            file_manager::fm_add_bookmark,
            file_manager::fm_get_bookmarks,
            file_manager::fm_get_recent_files,
            // Network Topology commands (Phase 3)
            network_topology::nt_start_discovery,
            network_topology::nt_start_monitoring,
            network_topology::nt_stop_monitoring,
            network_topology::nt_get_topology,
            network_topology::nt_get_metrics,
            network_topology::nt_get_alerts,
            network_topology::nt_acknowledge_alert,
            network_topology::nt_get_scan_status,
            network_topology::nt_list_scans,
            // Tools commands (Phase 4)
            tools::tools_run_layers,
            tools::tools_run_surveyor,
            tools::tools_get_run_status,
            tools::tools_list_runs,
            tools::tools_export_results,
            tools::tools_generate_signing_keypair,
            // PCAP Studio commands (Phase 5) - moved to commands::pcap



            // Behavioral Analytics commands (Phase 7)
            behavioral_analytics::behavioral_analytics_get_profiles,
            behavioral_analytics::behavioral_analytics_get_profile,
            behavioral_analytics::behavioral_analytics_get_anomalies,
            behavioral_analytics::behavioral_analytics_get_anomaly,
            behavioral_analytics::behavioral_analytics_get_risk_scores,
            behavioral_analytics::behavioral_analytics_get_user_risk_score,
            behavioral_analytics::behavioral_analytics_analyze_behavior,
            behavioral_analytics::behavioral_analytics_update_risk_score,
            behavioral_analytics::behavioral_analytics_get_models,
            behavioral_analytics::behavioral_analytics_get_stats,
            // Predictive Security commands (Phase 7)
            predictive_security::predictive_security_get_predictions,
            predictive_security::predictive_security_get_prediction,
            predictive_security::predictive_security_get_attack_paths,
            predictive_security::predictive_security_get_attack_path,
            predictive_security::predictive_security_get_forecasts,
            predictive_security::predictive_security_get_forecast,
            predictive_security::predictive_security_get_models,
            predictive_security::predictive_security_get_model,
            predictive_security::predictive_security_get_metrics,
            predictive_security::predictive_security_generate_prediction,
            predictive_security::predictive_security_analyze_attack_path,
            predictive_security::predictive_security_get_stats,


            // Reporting commands (Phase 8)
            reporting::reporting_get_templates,
            reporting::reporting_get_template,
            reporting::reporting_create_template,
            reporting::reporting_generate_report,
            reporting::reporting_get_reports,
            reporting::reporting_get_report,
            reporting::reporting_get_dashboards,
            reporting::reporting_get_dashboard,
            reporting::reporting_create_dashboard,
            reporting::reporting_get_data_sources,
            reporting::reporting_create_data_source,
            reporting::reporting_get_stats,








            // Remediation Playbooks commands (Phase 12)
            remediation_playbooks::playbooks_list_all,
            remediation_playbooks::playbooks_get_for_control,
            remediation_playbooks::playbooks_execute,
            remediation_playbooks::playbooks_get_execution,
            remediation_playbooks::playbooks_list_executions,
            // Notification commands (Phase 10)
            commands::notify::notify_get_alerts,
            commands::notify::notify_get_alert,
            commands::notify::notify_create_alert,
            commands::notify::notify_acknowledge_alert,
            commands::notify::notify_get_stats,
            commands::notify::notify_get_rules,
            commands::notify::notify_save_rule,
            commands::notify::notify_delete_rule,
            commands::notify::notify_cleanup_expired,
            commands::notify::notify_test_rule,
            commands::notify::notify_get_config,
            commands::notify::notify_save_config,
            commands::notify::notify_export_alerts,
            commands::notify::notify_bulk_acknowledge,
            commands::notify::notify_search_alerts,
            // Theme Engine v2 commands (Phase 11)
            commands::theme_v2::theme_v2_get_all,
            commands::theme_v2::theme_v2_get,
            commands::theme_v2::theme_v2_get_active,
            commands::theme_v2::theme_v2_set_active,
            commands::theme_v2::theme_v2_generate_css,
            commands::theme_v2::theme_v2_generate_theme_css,
            commands::theme_v2::theme_v2_create,
            commands::theme_v2::theme_v2_update,
            commands::theme_v2::theme_v2_delete,
            commands::theme_v2::theme_v2_export,
            commands::theme_v2::theme_v2_import,
            commands::theme_v2::theme_v2_generate_from_color,
            commands::theme_v2::theme_v2_generate_random,
            commands::theme_v2::theme_v2_create_variant,
            commands::theme_v2::theme_v2_create_variations,
            commands::theme_v2::theme_v2_check_accessibility,
            commands::theme_v2::theme_v2_generate_palette,
            commands::theme_v2::theme_v2_lighten_color,
            commands::theme_v2::theme_v2_darken_color,
            commands::theme_v2::theme_v2_add_alpha,
            commands::theme_v2::theme_v2_clear_cache,
            commands::theme_v2::theme_v2_preview,
            

            
            // Browser commands (Phase 14)
            commands::browse::browse_open,
            commands::browse::browse_close,
            commands::browse::browse_list_tabs,
            commands::browse::browse_get_tab,
            commands::browse::browse_navigate,
            commands::browse::browse_autofill,
            commands::browse::browse_update_posture,
            commands::browse::browse_get_active_tab,
            commands::browse::browse_set_active_tab,
            commands::browse::browse_start_download,
            commands::browse::browse_get_downloads,
            commands::browse::browse_cancel_download,
            commands::browse::browse_unseal_download,
            commands::browse::browse_get_config,
            commands::browse::browse_update_config,
            commands::browse::browse_set_mode,
            commands::browse::browse_get_window_config,
            commands::browse::browse_create_window,
            commands::browse::browse_show_window,
            commands::browse::browse_hide_window,
            commands::browse::browse_navigate_window,
            commands::browse::browse_open_external,
            commands::browse::browse_get_servo_stats,
            commands::browse::browse_get_all_servo_stats,
            commands::browse::browse_test_webview,
            commands::browse::browse_create_tab_webview,
            commands::browse::browse_close_tab_webview,
            commands::browse::browse_update_tab_webview,
            
            // VPN Status Commands - removed unused placeholder functionality
            
            // Navigation Commands (Phase 16) - TEMPORARILY DISABLED
            // commands::navigation::nav_get_layout,
            // commands::navigation::nav_preview_layout,
            // commands::navigation::nav_save_layout,
            // commands::navigation::nav_list_workspaces,
            // commands::navigation::nav_set_workspace,
            // commands::navigation::nav_export_layout,
            // commands::navigation::nav_import_layout,
            // commands::navigation::nav_create_workspace_from_preset,
            // commands::navigation::nav_get_presets,
            // commands::navigation::nav_get_module_metadata,
            // commands::navigation::nav_validate_layout,
            // commands::navigation::nav_get_workspace_suggestions,
            // commands::navigation::nav_reorder_modules,
            // commands::navigation::nav_toggle_module_visibility,
            // commands::navigation::nav_toggle_module_pin,
            // commands::navigation::nav_move_module_to_group,
            
            // Shell Integration Commands (old PTY-based system removed - commands removed to prevent console windows)
            
            // Simple Shell Commands (PTY commands removed)
            // commands::shell::simple_execute_command, // Replaced by ghost_shell::ghost_shell_execute_direct
            // Embedded Nushell Commands
            commands::nushell::nushell_create_session,
            commands::nushell::nushell_execute_command,
            commands::nushell::nushell_close_session,
            commands::nushell::nushell_list_sessions,
            commands::nushell::nushell_session_exists,
            commands::nushell::nushell_get_info,
            
            // Font Commands
            commands::fonts::get_embedded_fonts,
            commands::fonts::get_fonts_by_category,
            commands::fonts::get_font_weights,
            
            // Settings Commands
            commands::settings::get_settings,
            commands::settings::update_settings,
            commands::settings::set_fonts,
            commands::settings::set_accessibility,
            commands::settings::apply_font_settings,
            
            quarantine::quarantine_approve_file,
            
            // Window control commands
            // Window control commands replaced by enterprise system
            // commands::window_control::window_set_strategy,
            // commands::window_control::window_control_by_pattern,
            // commands::window_control::window_get_all,
            // commands::window_control::window_emergency_hide_consoles,
            // commands::window_control::window_control_by_handle,
            // Window control commands removed - functionality integrated with GhostShell
            
            // Pure WinAPI executor commands
            // Pure executor commands temporarily disabled due to compilation errors
            // commands::pure_executor::pure_test_powershell,
            // commands::pure_executor::pure_test_cmd,
            commands::pure_executor::pure_initialize,
            commands::pure_executor::pure_shutdown,
            // commands::pure_executor::pure_comprehensive_test,
            // commands::pure_executor::pure_test_problematic_commands,
            
            // Layers commands - OSI layer testing
            commands::layers::layers_run_test,
            commands::layers::layers_get_report_path,
            
            // Surveyor commands - network quality testing
            commands::surveyor::surveyor_analyze_endpoint,
            commands::surveyor::surveyor_start_test,
            commands::surveyor::surveyor_stop_test,
            commands::surveyor::surveyor_get_metrics,
            
                    // PCAP Studio commands - network traffic analysis (BruteShark-inspired)
        commands::pcap::pcap_check_dependencies,
        commands::pcap::pcap_get_interfaces,
        commands::pcap::pcap_list_captures,
        commands::pcap::pcap_start_capture,
        commands::pcap::pcap_stop_capture,
        commands::pcap::pcap_get_live_stats,
        
        // File Operations commands - CSV parsing and file dialogs
        commands::file_operations::open_file_dialog,
        commands::file_operations::open_directory_dialog,
        commands::file_operations::parse_csv_headers,
        commands::file_operations::parse_csv_file,
        
        // Enhanced CSV Operations - robust parsing with validation
        commands::file_operations::validate_csv_structure,
        commands::file_operations::parse_csv_file_robust,
        commands::file_operations::get_file_info,
        commands::file_operations::export_analysis_results,
        
        // PAN-OS Policy Analysis commands - based on original evaluator.py logic
        commands::pan_analysis::analyze_policy_rules,
        
        // PAN-OS API Integration commands - real firewall data access
        commands::pan_api::test_pan_api_connection,
        commands::pan_api::fetch_pan_security_rules,
        commands::pan_api::fetch_pan_rule_usage,
        commands::pan_api::pan_api_call,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

    debug!("Tauri application run completed");
    info!("=== GHOSTSHELL SHUTDOWN ===");
    Ok(())
}

fn setup_window_effects(window: &Window) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use window_vibrancy::{apply_mica, apply_acrylic};
        
        // Try Mica first (Windows 11), fallback to Acrylic
        if apply_mica(window, Some(true)).is_err() {
            let tint = (12, 15, 28, 180); // ~70% opacity cyberpunk tint
            apply_acrylic(window, Some(tint))?;
            info!("Applied Acrylic window effect");
        } else {
            info!("Applied Mica window effect");
        }
    }

    #[cfg(target_os = "macos")]
    {
        use window_vibrancy::apply_vibrancy;
        apply_vibrancy(window, window_vibrancy::NSVisualEffectMaterial::HudWindow, None, None)?;
        info!("Applied macOS vibrancy effect");
    }

    #[cfg(target_os = "linux")]
    {
        info!("Linux transparency handled via CSS backdrop-filter");
    }

    Ok(())
}
