use tauri::State;
use std::sync::Arc;
use tokio::sync::Mutex;

use ghost_browse::{BrowserEngine, BrowserConfig, TabMeta, BrowserMode, BrowserWindowConfig};
use ghost_download::{DownloadMeta, ActiveDownload};
use ghost_tls::PQPosture;

/// Open a new browser tab
#[tauri::command]
pub async fn browse_open(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    url: String,
    is_incognito: Option<bool>,
) -> Result<String, String> {
    let engine = browser_engine.lock().await;
    let is_incognito = is_incognito.unwrap_or(false);
    
    engine.open_tab(url, is_incognito).await
        .map_err(|e| e.to_string())
}

/// Close a browser tab
#[tauri::command]
pub async fn browse_close(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    tab_id: String,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    engine.close_tab(&tab_id).await
        .map_err(|e| e.to_string())
}

/// List all browser tabs
#[tauri::command]
pub async fn browse_list_tabs(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
) -> Result<Vec<TabMeta>, String> {
    let engine = browser_engine.lock().await;
    
    engine.list_tabs().await
        .map_err(|e| e.to_string())
}

/// Get a specific tab by ID
#[tauri::command]
pub async fn browse_get_tab(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    tab_id: String,
) -> Result<Option<TabMeta>, String> {
    let engine = browser_engine.lock().await;
    
    engine.get_tab(&tab_id).await
        .map_err(|e| e.to_string())
}

/// Navigate a tab to a new URL
#[tauri::command]
pub async fn browse_navigate(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    tab_id: String,
    url: String,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    engine.navigate_tab(&tab_id, url).await
        .map_err(|e| e.to_string())
}

/// Perform autofill in a tab
#[tauri::command]
pub async fn browse_autofill(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    tab_id: String,
    secret_id: String,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    engine.autofill_tab(&tab_id, &secret_id).await
        .map_err(|e| e.to_string())
}

/// Update tab PQ posture
#[tauri::command]
pub async fn browse_update_posture(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    tab_id: String,
    posture: PQPosture,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    engine.update_tab_posture(&tab_id, posture).await
        .map_err(|e| e.to_string())
}

/// Get the active tab ID
#[tauri::command]
pub async fn browse_get_active_tab(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
) -> Result<Option<String>, String> {
    let engine = browser_engine.lock().await;
    Ok(engine.get_active_tab().await)
}

/// Set the active tab
#[tauri::command]
pub async fn browse_set_active_tab(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    tab_id: String,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    engine.set_active_tab(&tab_id).await
        .map_err(|e| e.to_string())
}

/// Start a download
#[tauri::command]
pub async fn browse_start_download(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    url: String,
    filename: Option<String>,
    tab_id: Option<String>,
) -> Result<String, String> {
    let engine = browser_engine.lock().await;
    
    // Access the download manager through the browser engine
    // TODO: Implement download manager access
    // For now, return a mock download ID
    Ok(uuid::Uuid::new_v4().to_string())
}

/// Get active downloads
#[tauri::command]
pub async fn browse_get_downloads(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
) -> Result<Vec<ActiveDownload>, String> {
    let _engine = browser_engine.lock().await;
    
    // TODO: Implement download manager access
    // For now, return empty list
    Ok(vec![])
}

/// Cancel a download
#[tauri::command]
pub async fn browse_cancel_download(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    download_id: String,
) -> Result<(), String> {
    let _engine = browser_engine.lock().await;
    
    // TODO: Implement download cancellation
    Ok(())
}

/// Unseal a download
#[tauri::command]
pub async fn browse_unseal_download(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    download_id: String,
    output_path: String,
) -> Result<bool, String> {
    let _engine = browser_engine.lock().await;
    
    // TODO: Implement download unsealing
    Ok(true)
}

/// Get browser configuration
#[tauri::command]
pub async fn browse_get_config(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
) -> Result<BrowserConfig, String> {
    let _engine = browser_engine.lock().await;
    
    // TODO: Implement config access
    Ok(BrowserConfig::default())
}

/// Update browser configuration
#[tauri::command]
pub async fn browse_update_config(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    config: BrowserConfig,
) -> Result<(), String> {
    let _engine = browser_engine.lock().await;
    
    // TODO: Implement config update
    Ok(())
}

/// Set browser mode (Cyberpunk/Executive)
#[tauri::command]
pub async fn browse_set_mode(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    mode: BrowserMode,
) -> Result<(), String> {
    let _engine = browser_engine.lock().await;
    
    // TODO: Implement mode switching
    Ok(())
}

/// Get browser window configuration
#[tauri::command]
pub async fn browse_get_window_config(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
) -> Result<BrowserWindowConfig, String> {
    let _engine = browser_engine.lock().await;
    
    // TODO: Implement window config access
    Ok(BrowserWindowConfig::default())
}

/// Show browser window
#[tauri::command]
pub async fn browse_show_window(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
) -> Result<(), String> {
    let _engine = browser_engine.lock().await;
    
    // TODO: Implement window showing
    Ok(())
}

/// Hide browser window
#[tauri::command]
pub async fn browse_hide_window(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
) -> Result<(), String> {
    let _engine = browser_engine.lock().await;
    
    // TODO: Implement window hiding
    Ok(())
}
