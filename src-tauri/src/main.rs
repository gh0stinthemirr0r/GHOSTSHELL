// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
// use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::{Manager, Window};
use tracing::{info, warn, error, debug};
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
use ghost_ai::{AIEngine, AIConfig};

// Browser system imports
use ghost_browse::{BrowserEngine, BrowserConfig};

mod commands;
mod security;
mod window_effects;
mod clipboard;
mod quarantine;
mod terminal;
mod ssh;
mod vpn;
mod ai_assistant;
mod file_manager;
mod network_topology;
mod tools;
mod pcap_studio;
mod exploit_engine;
mod forensics_kit;
mod threat_intelligence;
mod behavioral_analytics;
mod predictive_security;
mod orchestration;
mod compliance;
mod reporting;
mod multi_tenant;
mod api_gateway;
mod autonomous_soc;

mod security_automation;
mod quantum_safe_operations;
mod global_threat_intelligence;


mod compliance_dashboard;
mod remediation_playbooks;

use commands::{settings, theme, theme_vault, vault, policy};
use security::{PepState, initialize_pep};
use clipboard::ClipboardManager;
use quarantine::QuarantineManager;
use terminal::TerminalManager;
use ssh::SshManager;
use vpn::VpnManager;
use ai_assistant::AiAssistantManager;
use file_manager::FileManager;
use network_topology::NetworkTopologyManager;
use tools::ToolsManager;
use pcap_studio::PcapStudioManager;
use exploit_engine::ExploitEngineManager;
use forensics_kit::ForensicsKitManager;
use threat_intelligence::ThreatIntelligenceManager;
use behavioral_analytics::BehavioralAnalyticsManager;
use predictive_security::PredictiveSecurityManager;
use orchestration::OrchestrationManager;
use compliance::ComplianceManager;
use reporting::ReportingManager;
use multi_tenant::MultiTenantManager;
use api_gateway::ApiGatewayManager;
use autonomous_soc::AutonomousSOCManager;

use security_automation::SecurityAutomationManager;
use quantum_safe_operations::QuantumSafeOperationsManager;
use global_threat_intelligence::GlobalThreatIntelligenceManager;



// Application state
#[derive(Debug, Default)]
pub struct AppState {
    themes: Mutex<HashMap<String, theme::ThemeV1>>,
    current_theme: Mutex<Option<String>>,
    settings: Mutex<settings::AppSettings>,
}

impl AppState {
    pub fn new() -> Result<Self> {
        Ok(Self {
            themes: Mutex::new(HashMap::new()),
            current_theme: Mutex::new(None),
            settings: Mutex::new(settings::AppSettings::default()),
        })
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

    tauri::Builder::default()
        .manage(app_state)
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
            
            // Initialize Policy Enforcement Point
            let pep_state = rt.block_on(async {
                match initialize_pep().await {
                    Ok(pep) => {
                        info!("Policy Enforcement Point initialized");
                        Ok(pep)
                    }
                    Err(e) => {
                        warn!("Failed to initialize PEP: {}", e);
                        Err(anyhow::anyhow!("PEP initialization failed: {}", e))
                    }
                }
            })?;
            app.manage(pep_state);

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

            // Initialize SSH Manager (Phase 3)
            let ssh_manager = Arc::new(Mutex::new(SshManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize SSH manager: {}", e))?));
            app.manage(ssh_manager);
            info!("SSH manager initialized");

            // Initialize VPN Manager (Phase 3)
            let vpn_manager = Arc::new(Mutex::new(VpnManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize VPN manager: {}", e))?));
            app.manage(vpn_manager);
            info!("VPN manager initialized");

            // Initialize AI Assistant Manager (Phase 3)
            let ai_manager = Arc::new(Mutex::new(AiAssistantManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize AI assistant manager: {}", e))?));
            app.manage(ai_manager);
            info!("AI assistant manager initialized");

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

            // Initialize Exploit Engine Manager (Phase 6)
            let exploit_manager = Arc::new(tokio::sync::Mutex::new(ExploitEngineManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize exploit engine manager: {}", e))?));
            
            // Exploit engine initialization will happen on first use
            
            app.manage(exploit_manager);
            info!("Exploit engine manager initialized");

            // Initialize Forensics Kit Manager (Phase 6)
            let forensics_manager = Arc::new(tokio::sync::Mutex::new(ForensicsKitManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize forensics kit manager: {}", e))?));
            
            // Forensics manager initialization will happen on first use
            
            app.manage(forensics_manager);
            info!("Forensics kit manager initialized");

            // Initialize Threat Intelligence Manager (Phase 7)
            let threat_intel_manager = Arc::new(tokio::sync::Mutex::new(ThreatIntelligenceManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize threat intelligence manager: {}", e))?));
            
            // Threat intelligence manager initialization will happen on first use
            
            app.manage(threat_intel_manager);
            info!("Threat intelligence manager initialized");

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

            // Initialize Orchestration Manager (Phase 8)
            let orchestration_manager = Arc::new(tokio::sync::Mutex::new(OrchestrationManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize orchestration manager: {}", e))?));
            // Orchestration manager initialization will happen on first use
            app.manage(orchestration_manager);
            info!("Orchestration manager initialized");

            // Initialize Compliance Manager (Phase 8)
            let compliance_manager = Arc::new(tokio::sync::Mutex::new(ComplianceManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize compliance manager: {}", e))?));
            // Compliance manager initialization will happen on first use
            app.manage(compliance_manager);
            info!("Compliance manager initialized");

            // Initialize Reporting Manager (Phase 8)
            let reporting_manager = Arc::new(tokio::sync::Mutex::new(ReportingManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize reporting manager: {}", e))?));
            // Reporting manager initialization will happen on first use
            app.manage(reporting_manager);
            info!("Reporting manager initialized");

            // Initialize API Gateway Manager (Phase 8)
            let api_gateway_manager = Arc::new(tokio::sync::Mutex::new(ApiGatewayManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize API gateway manager: {}", e))?));
            // API gateway manager initialization will happen on first use
            app.manage(api_gateway_manager);
            info!("API gateway manager initialized");

            // Initialize Autonomous SOC Manager (Phase 9)
            let autonomous_soc_manager = Arc::new(tokio::sync::Mutex::new(AutonomousSOCManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize autonomous SOC manager: {}", e))?));
            // Autonomous SOC manager initialization will happen on first use
            app.manage(autonomous_soc_manager);
            info!("Autonomous SOC manager initialized");



            // Initialize Security Automation Manager (Phase 9)
            let security_automation_manager = Arc::new(tokio::sync::Mutex::new(SecurityAutomationManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize security automation manager: {}", e))?));
            // Security Automation manager initialization will happen on first use
            app.manage(security_automation_manager);
            info!("Security Automation manager initialized");

            // Initialize Quantum-Safe Operations Manager (Phase 9)
            let quantum_safe_manager = Arc::new(tokio::sync::Mutex::new(QuantumSafeOperationsManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize quantum-safe operations manager: {}", e))?));
            // Quantum-Safe Operations manager initialization will happen on first use
            app.manage(quantum_safe_manager);
            info!("Quantum-Safe Operations manager initialized");

            // Initialize Global Threat Intelligence Manager (Phase 9)
            let global_threat_intel_manager = Arc::new(tokio::sync::Mutex::new(GlobalThreatIntelligenceManager::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize global threat intelligence manager: {}", e))?));
            // Global Threat Intelligence manager initialization will happen on first use
            app.manage(global_threat_intel_manager);
            info!("Global Threat Intelligence manager initialized");





            // Initialize Compliance Dashboard Manager (Phase 12)
            let compliance_dashboard_manager = Arc::new(tokio::sync::Mutex::new(compliance_dashboard::ComplianceDashboardManager::new()));
            app.manage(compliance_dashboard_manager);
            info!("Compliance Dashboard manager initialized");

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
                let config = LoggerConfig::default();
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

            // Initialize AI Engine (Phase 13)  
            debug!("About to initialize AI Engine");
            let ai_config = AIConfig::default();
            let ai_engine = rt.block_on(async {
                debug!("Creating AIEngine instance");
                
                // Use the same logger and signer from notification engine
                use ghost_log::LoggerConfig;
                use ghost_pq::signatures::DilithiumVariant;

                let config = LoggerConfig::default();
                let logger = Arc::new(AuditLogger::in_memory("ai".to_string()).await
                    .map_err(|e| anyhow::anyhow!("Failed to create AI logger: {}", e))?);
                let signer = Arc::new(DilithiumSigner::new(DilithiumVariant::Dilithium3)
                    .map_err(|e| anyhow::anyhow!("Failed to create AI signer: {}", e))?);
                
                let engine = AIEngine::new(ai_config, logger, signer)
                    .map_err(|e| anyhow::anyhow!("Failed to create AI engine: {}", e))?;
                
                debug!("About to initialize AI engine");
                let engine_arc = Arc::new(tokio::sync::Mutex::new(engine));
                
                // Initialize the AI engine
                {
                    let engine_guard = engine_arc.lock().await;
                    engine_guard.initialize().await
                        .map_err(|e| anyhow::anyhow!("Failed to initialize AI engine: {}", e))?;
                }
                
                Ok::<_, anyhow::Error>(engine_arc)
            })?;

            app.manage(ai_engine);
            debug!("AI engine initialized successfully");
            info!("AI Engine initialized");

            // Initialize Browser Engine (Phase 14)
            debug!("About to initialize Browser Engine");
            let browser_config = BrowserConfig::default();
            let browser_engine = rt.block_on(async {
                debug!("Creating BrowserEngine instance");

                // Use shared vault, policy, logger, and signer
                use ghost_vault::Vault;
                use ghost_policy::PolicyEvaluator;
                use ghost_log::LoggerConfig;
                use ghost_pq::signatures::DilithiumVariant;

                // Create browser vault with proper database path
                // Use absolute path to ensure we're in the right directory
                let current_dir = std::env::current_dir()
                    .map_err(|e| anyhow::anyhow!("Failed to get current directory: {}", e))?;
                // Go up one level from src-tauri to the project root, then into data
                let project_root = current_dir.parent()
                    .ok_or_else(|| anyhow::anyhow!("Failed to get project root directory"))?;
                let data_dir = project_root.join("data");
                let browser_db_path = data_dir.join("ghostshell_browser.db");
                
                debug!("Current directory: {:?}", current_dir);
                debug!("Data directory: {:?}", data_dir);
                debug!("Browser DB path: {:?}", browser_db_path);
                
                // Ensure data directory exists
                if let Err(e) = std::fs::create_dir_all(&data_dir) {
                    tracing::warn!("Failed to create data directory {:?}: {}", data_dir, e);
                } else {
                    debug!("Data directory created/verified: {:?}", data_dir);
                }
                
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
                let policy_engine = Arc::new(tokio::sync::Mutex::new(PolicyEvaluator::new(ghost_policy::Policy::new(1))));
                let logger = Arc::new(AuditLogger::in_memory("browser".to_string()).await
                    .map_err(|e| anyhow::anyhow!("Failed to create browser logger: {}", e))?);
                let signer = Arc::new(DilithiumSigner::new(DilithiumVariant::Dilithium3)
                    .map_err(|e| anyhow::anyhow!("Failed to create browser signer: {}", e))?);

                let engine = BrowserEngine::new(
                    browser_config,
                    vault_manager,
                    policy_engine,
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
            vault::vault_initialize,
            vault::vault_unlock,
            vault::vault_lock,
            vault::vault_is_unlocked,
            vault::vault_setup_mfa,
            vault::vault_verify_mfa,
            vault::vault_store_secret,
            vault::vault_list_secrets,
            vault::vault_get_secret,
            vault::vault_delete_secret,
            vault::vault_get_stats,
            // Policy commands (Phase 2)
            policy::policy_load,
            policy::policy_get_stats,
            policy::policy_dry_run,
            policy::policy_set_user,
            policy::policy_update_context,
            policy::policy_test_access,
            policy::policy_get_defaults,
            policy::policy_validate,
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
            // SSH commands (Phase 3)
            ssh::ssh_get_crypto_config,
            ssh::ssh_generate_pq_keypair,
            ssh::ssh_connect,
            ssh::ssh_execute_command,
            ssh::ssh_disconnect,
            ssh::ssh_list_connections,
            // VPN commands (Phase 3)
            vpn::vpn_generate_pq_keypair,
            vpn::vpn_create_config,
            vpn::vpn_connect,
            vpn::vpn_disconnect,
            vpn::vpn_get_stats,
            vpn::vpn_list_connections,
            vpn::vpn_list_configs,
            vpn::vpn_test_connection,
            // AI Assistant commands (Phase 3)
            ai_assistant::ai_create_assistant,
            ai_assistant::ai_query,
            ai_assistant::ai_learn_from_interaction,

            ai_assistant::ai_list_assistants,
            ai_assistant::ai_assistant_get_stats,
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
            // PCAP Studio commands (Phase 5)
            pcap_studio::pcap_get_interfaces,
            pcap_studio::pcap_start_capture,
            pcap_studio::pcap_stop_capture,
            pcap_studio::pcap_get_capture_status,
            pcap_studio::pcap_list_captures,
            pcap_studio::pcap_export_results,
            // Exploit Engine commands (Phase 6)
            exploit_engine::exploit_scan_target,
            exploit_engine::exploit_get_targets,
            exploit_engine::exploit_get_exploits,
            exploit_engine::exploit_generate_payload,
            exploit_engine::exploit_execute,
            exploit_engine::exploit_get_sessions,
            exploit_engine::exploit_get_session_status,
            exploit_engine::exploit_get_stats,
            // Forensics Kit commands (Phase 6)
            forensics_kit::forensics_get_cases,
            forensics_kit::forensics_get_case,
            forensics_kit::forensics_create_case,
            forensics_kit::forensics_start_analysis,
            forensics_kit::forensics_get_analysis_status,
            forensics_kit::forensics_generate_report,
            forensics_kit::forensics_get_stats,
            // Threat Intelligence commands (Phase 7)
            threat_intelligence::threat_intel_get_iocs,
            threat_intelligence::threat_intel_get_ioc,
            threat_intelligence::threat_intel_get_feeds,
            threat_intelligence::threat_intel_get_campaigns,
            threat_intelligence::threat_intel_get_campaign,
            threat_intelligence::threat_intel_get_actors,
            threat_intelligence::threat_intel_get_actor,
            threat_intelligence::threat_intel_get_hunting_rules,
            threat_intelligence::threat_intel_execute_hunt,
            threat_intelligence::threat_intel_get_stats,
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
            // Orchestration commands (Phase 8)
            orchestration::orchestration_get_playbooks,
            orchestration::orchestration_get_playbook,
            orchestration::orchestration_create_playbook,
            orchestration::orchestration_execute_playbook,
            orchestration::orchestration_get_cases,
            orchestration::orchestration_get_case,
            orchestration::orchestration_create_case,
            orchestration::orchestration_update_case_status,
            orchestration::orchestration_get_executions,
            orchestration::orchestration_get_execution,
            orchestration::orchestration_get_integrations,
            orchestration::orchestration_get_stats,
            // Compliance commands (Phase 8) - compliance_get_frameworks removed due to conflict with Phase 12
            compliance::compliance_get_framework,
            compliance::compliance_create_framework,
            compliance::compliance_get_requirements,
            compliance::compliance_get_controls,
            compliance::compliance_get_findings,
            compliance::compliance_get_assessments,
            compliance::compliance_create_assessment,
            compliance::compliance_generate_report,
            compliance::compliance_get_audit_trail,
            compliance::compliance_get_stats,
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
            // API Gateway commands (Phase 8)
            api_gateway::api_gateway_get_endpoints,
            api_gateway::api_gateway_get_endpoint,
            api_gateway::api_gateway_create_endpoint,
            api_gateway::api_gateway_get_routes,
            api_gateway::api_gateway_get_route,
            api_gateway::api_gateway_create_route,
            api_gateway::api_gateway_get_webhooks,
            api_gateway::api_gateway_get_webhook,
            api_gateway::api_gateway_create_webhook,
            api_gateway::api_gateway_trigger_webhook,
            api_gateway::api_gateway_get_api_keys,
            api_gateway::api_gateway_get_api_key,
            api_gateway::api_gateway_create_api_key,
            api_gateway::api_gateway_revoke_api_key,
            api_gateway::api_gateway_get_integrations,
            api_gateway::api_gateway_get_integration,
            api_gateway::api_gateway_create_integration,
            api_gateway::api_gateway_sync_integration,
            api_gateway::api_gateway_get_stats,
            // Autonomous SOC commands (Phase 9)
            autonomous_soc::autonomous_soc_get_stats,
            autonomous_soc::autonomous_soc_get_incidents,
            autonomous_soc::autonomous_soc_get_incident,
            autonomous_soc::autonomous_soc_get_agents,
            autonomous_soc::autonomous_soc_get_playbooks,
            autonomous_soc::autonomous_soc_get_hunting_sessions,
            autonomous_soc::autonomous_soc_execute_playbook,
            autonomous_soc::autonomous_soc_start_threat_hunt,

            // Security Automation commands (Phase 9)
            security_automation::security_automation_get_stats,
            security_automation::security_automation_get_workflows,
            security_automation::security_automation_get_workflow,
            security_automation::security_automation_create_workflow,
            security_automation::security_automation_get_executions,
            security_automation::security_automation_get_execution,
            security_automation::security_automation_execute_workflow,
            security_automation::security_automation_get_templates,
            security_automation::security_automation_create_from_template,
            // Quantum-Safe Operations commands (Phase 9)
            quantum_safe_operations::quantum_safe_get_stats,
            quantum_safe_operations::quantum_safe_get_pq_keys,
            quantum_safe_operations::quantum_safe_get_incidents,
            quantum_safe_operations::quantum_safe_get_protocols,
            quantum_safe_operations::quantum_safe_get_assessments,
            quantum_safe_operations::quantum_safe_generate_keypair,
            quantum_safe_operations::quantum_safe_rotate_key,
            quantum_safe_operations::quantum_safe_create_incident,
            // Global Threat Intelligence commands (Phase 9)
            global_threat_intelligence::global_threat_intel_get_stats,
            global_threat_intelligence::global_threat_intel_get_feeds,
            global_threat_intelligence::global_threat_intel_get_indicators,
            global_threat_intelligence::global_threat_intel_get_campaigns,
            global_threat_intelligence::global_threat_intel_get_nodes,
            global_threat_intelligence::global_threat_intel_get_hunting_queries,
            global_threat_intelligence::global_threat_intel_execute_hunt,
            global_threat_intelligence::global_threat_intel_share_indicator,



            // Compliance Dashboard commands (Phase 12)
            compliance_dashboard::compliance_dashboard_get_frameworks,
            compliance_dashboard::compliance_get_framework_controls,
            compliance_dashboard::compliance_create_snapshot,
            compliance_dashboard::compliance_get_current_snapshot,
            compliance_dashboard::compliance_get_control_details,
            compliance_dashboard::compliance_get_dashboard_stats,
            compliance_dashboard::compliance_create_evidence_bundle,
            compliance_dashboard::compliance_list_evidence_bundles,
            compliance_dashboard::compliance_get_posture_trends,
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
            
            // AI commands (Phase 13)
            commands::ai::ai_explain_error,
            commands::ai::ai_explain_control,
            commands::ai::ai_generate_report,
            commands::ai::ai_get_stats,
            commands::ai::ai_get_config,
            commands::ai::ai_update_config,
            
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
            
            quarantine::quarantine_approve_file,
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
