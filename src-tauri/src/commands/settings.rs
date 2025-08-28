use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tauri::State;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibilitySettings {
    pub reduce_motion: bool,
    pub high_contrast: bool,
    pub transparency: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontSettings {
    pub mono_font: String,
    pub ui_font: String,
    pub font_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSettings {
    pub cursor_style: String,
    pub cursor_blink: bool,
    pub font_ligatures: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub accessibility: AccessibilitySettings,
    pub fonts: FontSettings,
    pub terminal: TerminalSettings,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            accessibility: AccessibilitySettings {
                reduce_motion: false,
                high_contrast: false,
                transparency: 0.7,
            },
            fonts: FontSettings {
                mono_font: "JetBrains Mono".to_string(),
                ui_font: "Inter".to_string(),
                font_size: 14,
            },
            terminal: TerminalSettings {
                cursor_style: "block".to_string(),
                cursor_blink: false,
                font_ligatures: true,
            },
        }
    }
}

pub struct SettingsManager {
    settings: Mutex<AppSettings>,
    settings_path: PathBuf,
}

impl SettingsManager {
    pub fn new(data_dir: PathBuf) -> Self {
        let settings_path = data_dir.join("settings.json");
        let settings = if settings_path.exists() {
            match fs::read_to_string(&settings_path) {
                Ok(content) => {
                    match serde_json::from_str::<AppSettings>(&content) {
                        Ok(settings) => {
                            info!("Loaded settings from {:?}", settings_path);
                            settings
                        }
                        Err(e) => {
                            error!("Failed to parse settings file: {}", e);
                            AppSettings::default()
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read settings file: {}", e);
                    AppSettings::default()
                }
            }
        } else {
            info!("No settings file found, using defaults");
            AppSettings::default()
        };

        Self {
            settings: Mutex::new(settings),
            settings_path,
        }
    }

    pub async fn get_settings(&self) -> AppSettings {
        self.settings.lock().await.clone()
    }

    pub async fn update_settings(&self, new_settings: AppSettings) -> Result<()> {
        debug!("Updating settings: {:?}", new_settings);
        
        // Update in memory
        *self.settings.lock().await = new_settings.clone();
        
        // Save to disk
        self.save_settings(&new_settings).await?;
        
        info!("Settings updated successfully");
        Ok(())
    }

    pub async fn update_fonts(&self, mono_font: String, ui_font: String, font_size: u32) -> Result<()> {
        debug!("Updating font settings: mono={}, ui={}, size={}", mono_font, ui_font, font_size);
        
        let mut settings = self.settings.lock().await;
        settings.fonts.mono_font = mono_font;
        settings.fonts.ui_font = ui_font;
        settings.fonts.font_size = font_size;
        
        // Save to disk
        self.save_settings(&settings.clone()).await?;
        
        info!("Font settings updated successfully");
        Ok(())
    }

    pub async fn update_accessibility(&self, reduce_motion: bool, high_contrast: bool, transparency: f64) -> Result<()> {
        debug!("Updating accessibility settings: motion={}, contrast={}, transparency={}", reduce_motion, high_contrast, transparency);
        
        let mut settings = self.settings.lock().await;
        settings.accessibility.reduce_motion = reduce_motion;
        settings.accessibility.high_contrast = high_contrast;
        settings.accessibility.transparency = transparency;
        
        // Save to disk
        self.save_settings(&settings.clone()).await?;
        
        info!("Accessibility settings updated successfully");
        Ok(())
    }

    async fn save_settings(&self, settings: &AppSettings) -> Result<()> {
        let content = serde_json::to_string_pretty(settings)?;
        fs::write(&self.settings_path, content)?;
        debug!("Settings saved to {:?}", self.settings_path);
        Ok(())
    }
}

// Tauri Commands

#[tauri::command]
pub async fn get_settings(
    settings_manager: State<'_, SettingsManager>,
) -> Result<AppSettings, String> {
    Ok(settings_manager.get_settings().await)
}

#[tauri::command]
pub async fn update_settings(
    new_settings: AppSettings,
    settings_manager: State<'_, SettingsManager>,
) -> Result<(), String> {
    settings_manager.update_settings(new_settings).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_fonts(
    mono_font: String,
    ui_font: String,
    font_size: u32,
    settings_manager: State<'_, SettingsManager>,
) -> Result<(), String> {
    settings_manager.update_fonts(mono_font, ui_font, font_size).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_accessibility(
    reduce_motion: bool,
    high_contrast: bool,
    transparency: f64,
    settings_manager: State<'_, SettingsManager>,
) -> Result<(), String> {
    settings_manager.update_accessibility(reduce_motion, high_contrast, transparency).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn apply_font_settings(
    mono_font: String,
    ui_font: String,
    font_size: u32,
    settings_manager: State<'_, SettingsManager>,
) -> Result<AppSettings, String> {
    // Update the settings
    settings_manager.update_fonts(mono_font, ui_font, font_size).await
        .map_err(|e| e.to_string())?;
    
    // Return the updated settings so frontend can apply them
    Ok(settings_manager.get_settings().await)
}