use tauri::{State, Manager};
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::Utc;

use ghost_browse::{BrowserEngine, BrowserConfig, TabMeta, BrowserMode, BrowserWindowConfig};
use ghost_download::ActiveDownload;
use ghost_tls::PQPosture;

/// Open a new browser tab with real webview
#[tauri::command]
pub async fn browse_open(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    url: String,
    is_incognito: Option<bool>,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    let engine = browser_engine.lock().await;
    let is_incognito = is_incognito.unwrap_or(false);
    
    let tab_id = engine.open_tab(url.clone(), is_incognito).await
        .map_err(|e| e.to_string())?;
    
    // Create a new Tauri webview window for this tab
    let window_label = format!("webview_{}", tab_id);
    
    match tauri::WindowBuilder::new(
        &app_handle,
        &window_label,
        tauri::WindowUrl::External(url.parse().map_err(|e| format!("Invalid URL: {}", e))?),
    )
    .title(&format!("GhostBrowse - {}", url))
    .inner_size(1200.0, 800.0)
    .min_inner_size(800.0, 600.0)
    .resizable(true)
    .center()
    .focused(true)
    .visible(true)
    .decorations(true)
    .always_on_top(false)
    .build() {
        Ok(window) => {
            tracing::info!("Created webview window for tab {}: {}", tab_id, url);
            
            // Show the window explicitly
            if let Err(e) = window.show() {
                tracing::warn!("Failed to show webview window: {}", e);
            }
            
            // Set focus to the new window
            if let Err(e) = window.set_focus() {
                tracing::warn!("Failed to focus webview window: {}", e);
            }
            
            Ok(tab_id)
        }
        Err(e) => {
            tracing::error!("Failed to create webview window: {}", e);
            // Still return the tab ID even if window creation fails
            Ok(tab_id)
        }
    }
}

/// Close a browser tab and its webview window
#[tauri::command]
pub async fn browse_close(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    tab_id: String,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    // Close the tab in the engine
    engine.close_tab(&tab_id).await
        .map_err(|e| e.to_string())?;
    
    // Close the associated webview window
    let window_label = format!("webview_{}", tab_id);
    if let Some(window) = app_handle.get_window(&window_label) {
        if let Err(e) = window.close() {
            tracing::warn!("Failed to close webview window {}: {}", window_label, e);
        } else {
            tracing::info!("Closed webview window for tab {}", tab_id);
        }
    }
    
    Ok(())
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

/// Navigate a tab to a new URL with real webview
#[tauri::command]
pub async fn browse_navigate(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    tab_id: String,
    url: String,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    // Update the tab in the engine
    engine.navigate_tab(&tab_id, url.clone()).await
        .map_err(|e| e.to_string())?;
    
    // Update the webview window if it exists
    let window_label = format!("webview_{}", tab_id);
    if let Some(window) = app_handle.get_window(&window_label) {
        // Navigate the existing window
        if let Err(e) = window.eval(&format!("window.location.href = '{}';", url)) {
            tracing::warn!("Failed to navigate webview window: {}", e);
            // Try to close and recreate the window
            let _ = window.close();
            
            // Create new window with updated URL
            match tauri::WindowBuilder::new(
                &app_handle,
                &window_label,
                tauri::WindowUrl::External(url.parse().map_err(|e| format!("Invalid URL: {}", e))?),
            )
            .title(&format!("GhostBrowse - {}", url))
            .inner_size(1200.0, 800.0)
            .resizable(true)
            .build() {
                Ok(_) => tracing::info!("Recreated webview window for tab {}", tab_id),
                Err(e) => tracing::error!("Failed to recreate webview window: {}", e),
            }
        }
    } else {
        // Create new window if it doesn't exist
        match tauri::WindowBuilder::new(
            &app_handle,
            &window_label,
            tauri::WindowUrl::External(url.parse().map_err(|e| format!("Invalid URL: {}", e))?),
        )
        .title(&format!("GhostBrowse - {}", url))
        .inner_size(1200.0, 800.0)
        .resizable(true)
        .build() {
            Ok(_) => tracing::info!("Created new webview window for tab {}", tab_id),
            Err(e) => tracing::error!("Failed to create webview window: {}", e),
        }
    }
    
    Ok(())
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

/// Create browser window
#[tauri::command]
pub async fn browse_create_window(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    config: BrowserWindowConfig,
) -> Result<String, String> {
    let engine = browser_engine.lock().await;
    
    engine.create_browser_window(config).await
        .map_err(|e| e.to_string())
}

/// Show browser window
#[tauri::command]
pub async fn browse_show_window(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    window_id: String,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    engine.show_browser_window(&window_id).await
        .map_err(|e| e.to_string())
}

/// Hide browser window
#[tauri::command]
pub async fn browse_hide_window(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    window_id: String,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    engine.hide_browser_window(&window_id).await
        .map_err(|e| e.to_string())
}

/// Navigate browser window
#[tauri::command]
pub async fn browse_navigate_window(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    window_id: String,
    url: String,
) -> Result<(), String> {
    let engine = browser_engine.lock().await;
    
    engine.navigate_browser_window(&window_id, &url).await
        .map_err(|e| e.to_string())
}

/// Open URL in external browser using Windows Shell API
#[tauri::command]
pub async fn browse_open_external(
    url: String,
) -> Result<(), String> {
    // Windows API browser launcher replaced by enterprise browser system
    // use crate::windows_api_browser::WindowsBrowserLauncher;
    
    // TODO: Implement with enterprise browser system
    // For now, use standard system browser opening
    #[cfg(windows)]
    {
        use std::process::Command;
        Command::new("cmd")
            .args(["/C", "start", &url])
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    
    #[cfg(not(windows))]
    {
        return Err("External browser opening not implemented for this platform".to_string());
    }
    
    Ok(())
}

/// Get Servo processing stats for a tab
#[tauri::command]
pub async fn browse_get_servo_stats(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    tab_id: String,
) -> Result<Option<serde_json::Value>, String> {
    let engine = browser_engine.lock().await;
    
    match engine.get_servo_stats(&tab_id).await {
        Ok(Some(stats)) => Ok(Some(serde_json::to_value(stats).map_err(|e| e.to_string())?)),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Get all Servo processing stats
#[tauri::command]
pub async fn browse_get_all_servo_stats(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
) -> Result<serde_json::Value, String> {
    let engine = browser_engine.lock().await;
    
    let stats = engine.get_all_servo_stats().await
        .map_err(|e| e.to_string())?;
    
    serde_json::to_value(stats).map_err(|e| e.to_string())
}

/// Test webview creation with a simple URL
#[tauri::command]
pub async fn browse_test_webview(
    app_handle: tauri::AppHandle,
    test_url: Option<String>,
) -> Result<String, String> {
    let url = test_url.unwrap_or_else(|| "https://example.com".to_string());
    let window_label = format!("test_webview_{}", chrono::Utc::now().timestamp());
    
    tracing::info!("Testing webview creation with URL: {}", url);
    
    match tauri::WindowBuilder::new(
        &app_handle,
        &window_label,
        tauri::WindowUrl::External(url.parse().map_err(|e| format!("Invalid URL: {}", e))?),
    )
    .title(&format!("Test Webview - {}", url))
    .inner_size(1000.0, 700.0)
    .center()
    .focused(true)
    .visible(true)
    .build() {
        Ok(window) => {
            tracing::info!("Successfully created test webview window: {}", window_label);
            
            // Show and focus the window
            let _ = window.show();
            let _ = window.set_focus();
            
            Ok(format!("Test webview created successfully: {}", window_label))
        }
        Err(e) => {
            tracing::error!("Failed to create test webview: {}", e);
            Err(format!("Failed to create test webview: {}", e))
        }
    }
}

/// Create an embedded webview for a specific tab
#[tauri::command]
pub async fn browse_create_tab_webview(
    browser_engine: State<'_, Arc<Mutex<BrowserEngine>>>,
    app_handle: tauri::AppHandle,
    tab_id: String,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
) -> Result<String, String> {
    let engine = browser_engine.lock().await;
    
    // Get the tab's URL
    let tabs = engine.list_tabs().await.map_err(|e| e.to_string())?;
    let tab = tabs.iter().find(|t| t.id == tab_id)
        .ok_or_else(|| format!("Tab {} not found", tab_id))?;
    
    let window_label = format!("tab_webview_{}", tab_id);
    
    tracing::info!("Creating embedded webview for tab {} with URL: {} at position ({}, {}) with size {}x{}", 
                   tab_id, tab.url, x, y, width, height);
    
    // Close existing webview for this tab if it exists
    if let Some(existing_window) = app_handle.get_window(&window_label) {
        let _ = existing_window.close();
    }
    
    match tauri::WindowBuilder::new(
        &app_handle,
        &window_label,
        tauri::WindowUrl::External(tab.url.parse().map_err(|e| format!("Invalid URL: {}", e))?),
    )
    .title(&format!("GhostBrowse Tab - {}", tab.title.as_deref().unwrap_or(&tab.url)))
    .inner_size(width, height)
    .position(x, y)
    .resizable(false)
    .decorations(false)  // No window decorations to look embedded
    .always_on_top(false)
    .skip_taskbar(true)  // Don't show in taskbar
    .focused(false)      // Don't steal focus from main window
    .visible(true)
    .transparent(false)
    .build() {
        Ok(window) => {
            tracing::info!("Successfully created tab webview: {}", window_label);
            
            // Show the window
            let _ = window.show();
            
            Ok(window_label)
        }
        Err(e) => {
            tracing::error!("Failed to create tab webview: {}", e);
            Err(format!("Failed to create tab webview: {}", e))
        }
    }
}

/// Close the embedded webview for a specific tab
#[tauri::command]
pub async fn browse_close_tab_webview(
    app_handle: tauri::AppHandle,
    tab_id: String,
) -> Result<(), String> {
    let window_label = format!("tab_webview_{}", tab_id);
    
    if let Some(window) = app_handle.get_window(&window_label) {
        window.close().map_err(|e| format!("Failed to close tab webview: {}", e))?;
        tracing::info!("Closed tab webview: {}", window_label);
    }
    
    Ok(())
}

/// Update the position and size of a tab's webview
#[tauri::command]
pub async fn browse_update_tab_webview(
    app_handle: tauri::AppHandle,
    tab_id: String,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
) -> Result<(), String> {
    let window_label = format!("tab_webview_{}", tab_id);
    
    if let Some(window) = app_handle.get_window(&window_label) {
        window.set_position(tauri::Position::Physical(tauri::PhysicalPosition { x: x as i32, y: y as i32 }))
            .map_err(|e| format!("Failed to set position: {}", e))?;
        
        window.set_size(tauri::Size::Physical(tauri::PhysicalSize { width: width as u32, height: height as u32 }))
            .map_err(|e| format!("Failed to set size: {}", e))?;
        
        tracing::debug!("Updated tab webview {} position to ({}, {}) and size to {}x{}", 
                       tab_id, x, y, width, height);
    }
    
    Ok(())
}