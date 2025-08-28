use anyhow::Result;
use serde::{Deserialize, Serialize};
use tauri::State;
use tracing::info;

use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub accessibility: AccessibilitySettings,
    pub fonts: FontSettings,
    pub terminal: TerminalSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibilitySettings {
    pub reduce_motion: bool,
    pub high_contrast: bool,
    pub transparency: f32, // 0.0 to 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontSettings {
    pub mono_font: String,
    pub ui_font: String,
    pub font_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSettings {
    pub cursor_style: String, // "block", "underline", "bar"
    pub cursor_blink: bool,
    pub font_ligatures: bool,
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
                mono_font: "JetBrainsMono Nerd Font".to_string(),
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

#[tauri::command]
pub fn get_settings(state: State<AppState>) -> Result<AppSettings, String> {
    let settings = state.settings.lock().unwrap();
    Ok(settings.clone())
}

#[tauri::command]
pub fn update_settings(new_settings: AppSettings, state: State<AppState>) -> Result<(), String> {
    let mut settings = state.settings.lock().unwrap();
    *settings = new_settings;
    info!("Updated application settings");
    Ok(())
}

#[tauri::command]
pub fn set_accessibility(
    reduce_motion: bool,
    high_contrast: bool,
    transparency: f32,
    state: State<AppState>,
) -> Result<(), String> {
    let mut settings = state.settings.lock().unwrap();
    settings.accessibility.reduce_motion = reduce_motion;
    settings.accessibility.high_contrast = high_contrast;
    settings.accessibility.transparency = transparency.clamp(0.0, 1.0);
    
    info!(
        "Updated accessibility: motion={}, contrast={}, transparency={}",
        reduce_motion, high_contrast, transparency
    );
    
    Ok(())
}

#[tauri::command]
pub fn set_fonts(
    mono_font: String,
    ui_font: String,
    font_size: u32,
    state: State<AppState>,
) -> Result<(), String> {
    let mut settings = state.settings.lock().unwrap();
    settings.fonts.mono_font = mono_font.clone();
    settings.fonts.ui_font = ui_font.clone();
    settings.fonts.font_size = font_size;
    
    info!("Updated fonts: mono={}, ui={}, size={}", mono_font, ui_font, font_size);
    
    Ok(())
}
