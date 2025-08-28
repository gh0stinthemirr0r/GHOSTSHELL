use anyhow::Result;
use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
use tauri::{State, Window};
use tracing::{info, warn};

use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeV1 {
    pub name: String,
    pub version: u32,
    pub tokens: ThemeTokens,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeTokens {
    #[serde(rename = "bgTint")]
    pub bg_tint: String,
    pub fg: String,
    pub slate: String,
    #[serde(rename = "accentPink")]
    pub accent_pink: String,
    #[serde(rename = "accentCyan")]
    pub accent_cyan: String,
    #[serde(rename = "accentNeonGreen")]
    pub accent_neon_green: String,
    #[serde(rename = "glowStrength")]
    pub glow_strength: f32,
    #[serde(rename = "blurPx")]
    pub blur_px: u32,
    #[serde(rename = "noiseOpacity")]
    pub noise_opacity: f32,
    #[serde(rename = "cursorStyle")]
    pub cursor_style: String,
    #[serde(rename = "cursorColor")]
    pub cursor_color: String,
    #[serde(rename = "monoFont")]
    pub mono_font: String,
    #[serde(rename = "uiFont")]
    pub ui_font: String,
    pub radius: u32,
    pub border: String,
}

#[derive(Debug, Serialize)]
pub struct ThemeMeta {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub is_default: bool,
}

impl Default for ThemeTokens {
    fn default() -> Self {
        Self {
            bg_tint: "rgba(12,15,28,0.70)".to_string(),
            fg: "#EAEAEA".to_string(),
            slate: "#2B2B2E".to_string(),
            accent_pink: "#FF008C".to_string(),
            accent_cyan: "#00FFD1".to_string(),
            accent_neon_green: "#AFFF00".to_string(),
            glow_strength: 0.6,
            blur_px: 18,
            noise_opacity: 0.08,
            cursor_style: "block".to_string(),
            cursor_color: "#AFFF00".to_string(),
            mono_font: "JetBrains Mono".to_string(),
            ui_font: "JetBrains Mono, Space Grotesk".to_string(),
            radius: 14,
            border: "rgba(255,255,255,0.10)".to_string(),
        }
    }
}

pub fn load_default_themes(state: State<AppState>) -> Result<()> {
    let mut themes = state.themes.lock().unwrap();
    
    // Cyberpunk Neon (default)
    let cyberpunk = ThemeV1 {
        name: "Cyberpunk Neon".to_string(),
        version: 1,
        tokens: ThemeTokens::default(),
    };
    themes.insert("cyberpunk-neon".to_string(), cyberpunk);

    // Dark Academic
    let dark_academic = ThemeV1 {
        name: "Dark Academic".to_string(),
        version: 1,
        tokens: ThemeTokens {
            bg_tint: "rgba(20,16,12,0.75)".to_string(),
            fg: "#E8DCC6".to_string(),
            slate: "#3A2F26".to_string(),
            accent_pink: "#D4A574".to_string(),
            accent_cyan: "#8B9DC3".to_string(),
            accent_neon_green: "#A8B56A".to_string(),
            glow_strength: 0.3,
            ui_font: "Space Grotesk, JetBrains Mono".to_string(),
            ..ThemeTokens::default()
        },
    };
    themes.insert("dark-academic".to_string(), dark_academic);

    // Retro Green
    let retro_green = ThemeV1 {
        name: "Retro Green".to_string(),
        version: 1,
        tokens: ThemeTokens {
            bg_tint: "rgba(0,0,0,0.85)".to_string(),
            fg: "#00FF00".to_string(),
            slate: "#001100".to_string(),
            accent_pink: "#FFAA00".to_string(),
            accent_cyan: "#00FFAA".to_string(),
            accent_neon_green: "#00FF00".to_string(),
            cursor_color: "#00FF00".to_string(),
            mono_font: "Courier New".to_string(),
            ui_font: "Space Grotesk, JetBrains Mono".to_string(),
            ..ThemeTokens::default()
        },
    };
    themes.insert("retro-green".to_string(), retro_green);

    // Exec Mode
    let exec_mode = ThemeV1 {
        name: "Executive Mode".to_string(),
        version: 1,
        tokens: ThemeTokens {
            bg_tint: "rgba(244,246,250,0.96)".to_string(),
            fg: "#1C1F26".to_string(),
            slate: "#F0F2F6".to_string(),
            accent_pink: "#2B6CB0".to_string(),
            accent_cyan: "#3182CE".to_string(),
            accent_neon_green: "#2F855A".to_string(),
            glow_strength: 0.0,
            noise_opacity: 0.02,
            cursor_color: "#2B6CB0".to_string(),
            border: "rgba(0,0,0,0.08)".to_string(),
            ui_font: "Space Grotesk, JetBrains Mono".to_string(),
            ..ThemeTokens::default()
        },
    };
    themes.insert("exec-mode".to_string(), exec_mode);

    // Set default theme
    *state.current_theme.lock().unwrap() = Some("cyberpunk-neon".to_string());

    info!("Loaded {} default themes", themes.len());
    Ok(())
}

#[tauri::command]
pub fn list_themes(state: State<AppState>) -> Result<Vec<ThemeMeta>, String> {
    let themes = state.themes.lock().unwrap();
    let _current = state.current_theme.lock().unwrap();
    
    let mut theme_list: Vec<ThemeMeta> = themes
        .iter()
        .map(|(id, theme)| ThemeMeta {
            id: id.clone(),
            name: theme.name.clone(),
            version: theme.version,
            is_default: matches!(id.as_str(), "cyberpunk-neon" | "dark-academic" | "retro-green" | "exec-mode"),
        })
        .collect();
    
    theme_list.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(theme_list)
}

#[tauri::command]
pub fn apply_theme(theme_id: String, state: State<AppState>, window: Window) -> Result<ThemeV1, String> {
    let themes = state.themes.lock().unwrap();
    
    if let Some(theme) = themes.get(&theme_id) {
        // Update current theme
        *state.current_theme.lock().unwrap() = Some(theme_id.clone());
        
        // Apply acrylic tint based on theme
        if let Err(e) = apply_theme_tint(&window, &theme.tokens) {
            warn!("Failed to apply theme tint: {}", e);
        }
        
        info!("Applied theme: {}", theme.name);
        Ok(theme.clone())
    } else {
        Err(format!("Theme not found: {}", theme_id))
    }
}

#[tauri::command]
pub fn save_theme(theme: ThemeV1, state: State<AppState>) -> Result<String, String> {
    let theme_id = uuid::Uuid::new_v4().to_string();
    let mut themes = state.themes.lock().unwrap();
    
    themes.insert(theme_id.clone(), theme.clone());
    info!("Saved theme: {} ({})", theme.name, theme_id);
    
    Ok(theme_id)
}

#[tauri::command]
pub fn export_theme(theme_id: String, state: State<AppState>) -> Result<ThemeV1, String> {
    let themes = state.themes.lock().unwrap();
    
    if let Some(theme) = themes.get(&theme_id) {
        Ok(theme.clone())
    } else {
        Err(format!("Theme not found: {}", theme_id))
    }
}

#[tauri::command]
pub fn import_theme(theme: ThemeV1, state: State<AppState>) -> Result<String, String> {
    // TODO: Add signature validation in Phase 2
    let theme_id = uuid::Uuid::new_v4().to_string();
    let mut themes = state.themes.lock().unwrap();
    
    themes.insert(theme_id.clone(), theme.clone());
    info!("Imported theme: {} ({})", theme.name, theme_id);
    
    Ok(theme_id)
}

#[tauri::command]
pub fn set_acrylic_tint(r: u8, g: u8, b: u8, a: u8, window: Window) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use window_vibrancy::apply_acrylic;
        apply_acrylic(&window, Some((r, g, b, a)))
            .map_err(|e| e.to_string())?;
    }
    
    Ok(())
}

fn apply_theme_tint(window: &Window, tokens: &ThemeTokens) -> Result<()> {
    // Parse rgba color from bg_tint
    if let Some(rgba) = parse_rgba(&tokens.bg_tint) {
        let (r, g, b, a) = rgba;
        let alpha_u8 = (a * 255.0) as u8;
        
        #[cfg(target_os = "windows")]
        {
            use window_vibrancy::apply_acrylic;
            apply_acrylic(window, Some((r, g, b, alpha_u8)))?;
        }
    }
    
    Ok(())
}

fn parse_rgba(color: &str) -> Option<(u8, u8, u8, f32)> {
    // Simple rgba parser for "rgba(r,g,b,a)" format
    if color.starts_with("rgba(") && color.ends_with(')') {
        let inner = &color[5..color.len()-1];
        let parts: Vec<&str> = inner.split(',').collect();
        
        if parts.len() == 4 {
            if let (Ok(r), Ok(g), Ok(b), Ok(a)) = (
                parts[0].trim().parse::<u8>(),
                parts[1].trim().parse::<u8>(),
                parts[2].trim().parse::<u8>(),
                parts[3].trim().parse::<f32>(),
            ) {
                return Some((r, g, b, a));
            }
        }
    }
    
    None
}
