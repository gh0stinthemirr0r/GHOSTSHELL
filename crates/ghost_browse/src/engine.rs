use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, error};
use uuid::Uuid;

use crate::{BrowserTab, TabMeta, TabState, BrowserWindow, BrowserWindowConfig, BrowserMode};
use ghost_tls::{GhostTLSClient, GhostTLSConfig, PQPosture};
use ghost_autofill::AutofillBridge;
use ghost_download::DownloadManager;
use ghost_vault::Vault;

use ghost_log::AuditLogger;
use ghost_pq::signatures::DilithiumSigner;

/// Browser engine configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserConfig {
    pub tls_config: GhostTLSConfig,
    pub enable_autofill: bool,
    pub enable_downloads: bool,
    pub max_tabs: usize,
    pub user_agent: String,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            tls_config: GhostTLSConfig::default(),
            enable_autofill: true,
            enable_downloads: true,
            max_tabs: 50,
            user_agent: "GhostBrowse/1.0 (GHOSTSHELL)".to_string(),
        }
    }
}

/// Main browser engine
pub struct BrowserEngine {
    config: BrowserConfig,
    tabs: Arc<Mutex<HashMap<String, BrowserTab>>>,
    active_tab: Arc<Mutex<Option<String>>>,
    browser_windows: Arc<Mutex<HashMap<String, BrowserWindow>>>,
    tls_client: Arc<GhostTLSClient>,
    autofill_bridge: Arc<AutofillBridge>,
    download_manager: Arc<DownloadManager>,
    vault_manager: Arc<Mutex<Vault>>,
    // Policy engine removed for single-user mode
    logger: Arc<AuditLogger>,
}

impl BrowserEngine {
    /// Create a new browser engine
    pub async fn new(
        config: BrowserConfig,
        vault_manager: Arc<Mutex<Vault>>,
        // Policy engine removed for single-user mode
        logger: Arc<AuditLogger>,
        signer: Arc<DilithiumSigner>,
    ) -> Result<Self> {
        // Create TLS client
        let tls_client = Arc::new(
            GhostTLSClient::new(config.tls_config.clone(), logger.clone(), signer.clone()).await?
        );

        // Create autofill bridge
        let autofill_bridge = Arc::new(
            AutofillBridge::new(vault_manager.clone(), logger.clone()).await?
        );

        // Create download manager
        let download_manager = Arc::new(
            DownloadManager::new(vault_manager.clone(), signer.clone(), logger.clone()).await?
        );

        Ok(Self {
            config,
            tabs: Arc::new(Mutex::new(HashMap::new())),
            active_tab: Arc::new(Mutex::new(None)),
            browser_windows: Arc::new(Mutex::new(HashMap::new())),
            tls_client,
            autofill_bridge,
            download_manager,
            vault_manager,
            // Policy engine removed for single-user mode
            logger,
        })
    }

    /// Initialize the browser engine
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing GhostBrowse engine");
        
        // Initialize components
        self.autofill_bridge.initialize().await?;
        self.download_manager.initialize().await?;

        info!("GhostBrowse engine initialized successfully");
        Ok(())
    }

    /// Open a new tab
    pub async fn open_tab(&self, url: String, is_incognito: bool) -> Result<String> {
        let mut tabs = self.tabs.lock().await;
        
        // Check tab limit
        if tabs.len() >= self.config.max_tabs {
            return Err(anyhow::anyhow!("Maximum number of tabs ({}) reached", self.config.max_tabs));
        }

        // Check policy (simplified for now)
        {
            // Policy engine removed for single-user mode
            // Policy checking removed for single-user mode
            // For now, allow all requests
        }

        // Create new tab
        let tab = BrowserTab::new(url.clone(), is_incognito);
        let tab_id = tab.meta.id.clone();

        // Add to tabs
        tabs.insert(tab_id.clone(), tab);

        // Set as active tab
        *self.active_tab.lock().await = Some(tab_id.clone());

        // Log tab creation
        self.log_tab_event(&tab_id, "tab_opened", &url).await?;

        info!("Opened new tab: {} -> {}", tab_id, url);
        Ok(tab_id)
    }

    /// Close a tab
    pub async fn close_tab(&self, tab_id: &str) -> Result<()> {
        let mut tabs = self.tabs.lock().await;
        
        if let Some(mut tab) = tabs.remove(tab_id) {
            tab.meta.set_state(TabState::Closed);
            
            // If this was the active tab, clear it
            let mut active_tab = self.active_tab.lock().await;
            if active_tab.as_ref() == Some(&tab_id.to_string()) {
                *active_tab = None;
            }

            // Log tab closure
            self.log_tab_event(tab_id, "tab_closed", &tab.meta.url).await?;

            info!("Closed tab: {}", tab_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Tab {} not found", tab_id))
        }
    }

    /// List all tabs
    pub async fn list_tabs(&self) -> Result<Vec<TabMeta>> {
        let tabs = self.tabs.lock().await;
        Ok(tabs.values().map(|tab| tab.meta.clone()).collect())
    }

    /// Get tab by ID
    pub async fn get_tab(&self, tab_id: &str) -> Result<Option<TabMeta>> {
        let tabs = self.tabs.lock().await;
        Ok(tabs.get(tab_id).map(|tab| tab.meta.clone()))
    }

    /// Navigate tab to URL
    pub async fn navigate_tab(&self, tab_id: &str, url: String) -> Result<()> {
        let mut tabs = self.tabs.lock().await;
        
        if let Some(tab) = tabs.get_mut(tab_id) {
            // Check policy (simplified for now)
            {
                // Policy engine removed for single-user mode
                // Policy checking removed for single-user mode
                // For now, allow all requests
            }

            // Validate URL
            let parsed_url = url::Url::parse(&url)
                .map_err(|e| anyhow::anyhow!("Invalid URL: {}", e))?;
            
            // Check if it's a supported protocol
            if !matches!(parsed_url.scheme(), "https" | "http") {
                return Err(anyhow::anyhow!("Unsupported protocol: {}", parsed_url.scheme()));
            }

            // Navigate the tab
            tab.navigate(url.clone());
            
            // Update tab state to show it's loading
            tab.meta.set_state(TabState::Loading);
            
            // Log navigation
            self.log_tab_event(tab_id, "navigation", &url).await?;
            
            // Simulate navigation completion after a delay
            // In a real implementation, this would be handled by webview events
            let tab_id_clone = tab_id.to_string();
            let tabs_clone = self.tabs.clone();
            let url_clone = url.clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                
                let mut tabs = tabs_clone.lock().await;
                if let Some(tab) = tabs.get_mut(&tab_id_clone) {
                    tab.meta.set_state(TabState::Active);
                    
                    // Extract title from URL
                    if let Ok(parsed) = url::Url::parse(&url_clone) {
                        if let Some(host) = parsed.host_str() {
                            tab.meta.set_title(host.to_string());
                        }
                    }
                    
                    // Set a mock PQ posture
                    use ghost_tls::PQPosture;
                    tab.meta.set_posture(PQPosture::Hybrid);
                }
            });

            info!("Tab {} navigated to {}", tab_id, url);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Tab {} not found", tab_id))
        }
    }

    /// Update tab posture after TLS connection
    pub async fn update_tab_posture(&self, tab_id: &str, posture: PQPosture) -> Result<()> {
        let mut tabs = self.tabs.lock().await;
        
        if let Some(tab) = tabs.get_mut(tab_id) {
            tab.meta.set_posture(posture.clone());
            tab.update_current_page(None, Some(posture.clone()));

            // Log posture update
            let log_data = serde_json::json!({
                "tab_id": tab_id,
                "posture": posture,
                "url": tab.meta.url
            });
            let actor = ghost_log::Actor {
                actor_type: ghost_log::ActorType::System,
                id: "ghost_browse".to_string(),
                name: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            };

            let resource = ghost_log::Resource {
                resource_type: ghost_log::ResourceType::Network,
                id: Some(tab_id.to_string()),
                name: None,
                path: None,
                attributes: std::collections::HashMap::new(),
            };

            self.logger.log_event().await
                .event_type(ghost_log::EventType::SystemEvent)
                .severity(ghost_log::Severity::Info)
                .actor(actor)
                .resource(resource)
                .action(ghost_log::Action::Update)
                .outcome(ghost_log::Outcome::Success)
                .message(format!("Tab posture updated: {:?}", posture))
                .submit()
                .await?;

            debug!("Updated tab {} posture to {:?}", tab_id, posture);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Tab {} not found", tab_id))
        }
    }

    /// Perform autofill in tab
    pub async fn autofill_tab(&self, tab_id: &str, secret_id: &str) -> Result<()> {
        let mut tabs = self.tabs.lock().await;
        
        if let Some(tab) = tabs.get_mut(tab_id) {
            // Check if incognito mode allows autofill
            if tab.meta.is_incognito && !self.config.enable_autofill {
                return Err(anyhow::anyhow!("Autofill disabled in incognito mode"));
            }

            // Perform autofill
            self.autofill_bridge.inject_credentials(tab_id, secret_id).await?;
            
            // Record vault usage
            tab.meta.add_vault_usage(secret_id.to_string());

            // Log autofill
            self.log_tab_event(tab_id, "autofill", &format!("secret:{}", secret_id)).await?;

            info!("Autofilled credentials in tab {} using secret {}", tab_id, secret_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Tab {} not found", tab_id))
        }
    }

    /// Get active tab ID
    pub async fn get_active_tab(&self) -> Option<String> {
        self.active_tab.lock().await.clone()
    }

    /// Set active tab
    pub async fn set_active_tab(&self, tab_id: &str) -> Result<()> {
        let tabs = self.tabs.lock().await;
        
        if tabs.contains_key(tab_id) {
            *self.active_tab.lock().await = Some(tab_id.to_string());
            info!("Set active tab to {}", tab_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Tab {} not found", tab_id))
        }
    }

    /// Create a new browser window
    pub async fn create_browser_window(&self, config: BrowserWindowConfig) -> Result<String> {
        let window_id = Uuid::new_v4().to_string();
        let window = BrowserWindow::new(config)?;
        
        let mut windows = self.browser_windows.lock().await;
        windows.insert(window_id.clone(), window);
        
        info!("Created browser window: {}", window_id);
        Ok(window_id)
    }

    /// Show browser window
    pub async fn show_browser_window(&self, window_id: &str) -> Result<()> {
        let windows = self.browser_windows.lock().await;
        if let Some(window) = windows.get(window_id) {
            window.show().await?;
            info!("Showed browser window: {}", window_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Browser window {} not found", window_id))
        }
    }

    /// Hide browser window
    pub async fn hide_browser_window(&self, window_id: &str) -> Result<()> {
        let windows = self.browser_windows.lock().await;
        if let Some(window) = windows.get(window_id) {
            window.hide().await?;
            info!("Hid browser window: {}", window_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Browser window {} not found", window_id))
        }
    }

    /// Navigate browser window
    pub async fn navigate_browser_window(&self, window_id: &str, url: &str) -> Result<()> {
        let windows = self.browser_windows.lock().await;
        if let Some(window) = windows.get(window_id) {
            window.navigate(url).await?;
            info!("Navigated browser window {} to {}", window_id, url);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Browser window {} not found", window_id))
        }
    }

    /// Set browser window mode
    pub async fn set_browser_window_mode(&self, window_id: &str, mode: BrowserMode) -> Result<()> {
        let mut windows = self.browser_windows.lock().await;
        if let Some(window) = windows.get_mut(window_id) {
            window.set_mode(mode).await?;
            info!("Set browser window {} mode", window_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Browser window {} not found", window_id))
        }
    }

    /// Log tab event
    async fn log_tab_event(&self, tab_id: &str, event_type: &str, data: &str) -> Result<()> {
        let log_entry = serde_json::json!({
            "event_type": event_type,
            "tab_id": tab_id,
            "data": data,
            "timestamp": chrono::Utc::now(),
        });

        let actor = ghost_log::Actor {
            actor_type: ghost_log::ActorType::System,
            id: "ghost_browse".to_string(),
            name: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
        };

        let resource = ghost_log::Resource {
            resource_type: ghost_log::ResourceType::File,
            id: Some(tab_id.to_string()),
            name: None,
            path: None,
            attributes: std::collections::HashMap::new(),
        };

        self.logger.log_event().await
            .event_type(ghost_log::EventType::UserAction)
            .severity(ghost_log::Severity::Info)
            .actor(actor)
            .resource(resource)
            .action(ghost_log::Action::Create)
            .outcome(ghost_log::Outcome::Success)
            .message(format!("{}: {}", event_type, data))
            .submit()
            .await?;
        Ok(())
    }
}
