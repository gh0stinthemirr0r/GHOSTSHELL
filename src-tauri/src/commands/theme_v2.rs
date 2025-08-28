use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;
use ghost_theme::{ThemeEngine, GhostTheme, ColorScheme, ColorUtils, ThemeGenerator};
use std::collections::HashMap;

/// Get all available themes
#[tauri::command]
pub async fn theme_v2_get_all(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
) -> Result<Vec<GhostTheme>, String> {
    let engine = engine.lock().await;
    engine.get_all_themes().await.map_err(|e| e.to_string())
}

/// Get a specific theme by ID
#[tauri::command]
pub async fn theme_v2_get(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    theme_id: String,
) -> Result<Option<GhostTheme>, String> {
    let engine = engine.lock().await;
    engine.get_theme(&theme_id).await.map_err(|e| e.to_string())
}

/// Get the currently active theme
#[tauri::command]
pub async fn theme_v2_get_active(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
) -> Result<Option<GhostTheme>, String> {
    let engine = engine.lock().await;
    engine.get_active_theme().await.map_err(|e| e.to_string())
}

/// Set the active theme
#[tauri::command]
pub async fn theme_v2_set_active(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    theme_id: String,
) -> Result<(), String> {
    let engine = engine.lock().await;
    engine.set_active_theme(&theme_id).await.map_err(|e| e.to_string())
}

/// Generate CSS for the active theme
#[tauri::command]
pub async fn theme_v2_generate_css(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
) -> Result<String, String> {
    let engine = engine.lock().await;
    engine.generate_active_css().await.map_err(|e| e.to_string())
}

/// Generate CSS for a specific theme
#[tauri::command]
pub async fn theme_v2_generate_theme_css(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    theme_id: String,
) -> Result<String, String> {
    let engine = engine.lock().await;
    engine.generate_css(&theme_id).await.map_err(|e| e.to_string())
}

/// Create a new theme
#[tauri::command]
pub async fn theme_v2_create(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    theme: GhostTheme,
) -> Result<(), String> {
    let engine = engine.lock().await;
    engine.add_theme(theme).await.map_err(|e| e.to_string())
}

/// Update an existing theme
#[tauri::command]
pub async fn theme_v2_update(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    theme: GhostTheme,
) -> Result<(), String> {
    let engine = engine.lock().await;
    engine.update_theme(theme).await.map_err(|e| e.to_string())
}

/// Delete a theme
#[tauri::command]
pub async fn theme_v2_delete(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    theme_id: String,
) -> Result<(), String> {
    let engine = engine.lock().await;
    engine.delete_theme(&theme_id).await.map_err(|e| e.to_string())
}

/// Export a theme as JSON
#[tauri::command]
pub async fn theme_v2_export(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    theme_id: String,
) -> Result<String, String> {
    let engine = engine.lock().await;
    engine.export_theme(&theme_id).await.map_err(|e| e.to_string())
}

/// Import a theme from JSON
#[tauri::command]
pub async fn theme_v2_import(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    theme_json: String,
) -> Result<String, String> {
    let engine = engine.lock().await;
    engine.import_theme(&theme_json).await.map_err(|e| e.to_string())
}

/// Generate a theme from a base color
#[tauri::command]
pub async fn theme_v2_generate_from_color(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    base_color: String,
    name: String,
    scheme: String,
) -> Result<String, String> {
    let color_scheme = match scheme.as_str() {
        "monochromatic" => ColorScheme::Monochromatic,
        "analogous" => ColorScheme::Analogous,
        "complementary" => ColorScheme::Complementary,
        "triadic" => ColorScheme::Triadic,
        "tetradic" => ColorScheme::Tetradic,
        _ => ColorScheme::Custom,
    };

    let theme = ThemeGenerator::from_color(&base_color, &name, color_scheme)
        .map_err(|e| e.to_string())?;
    
    let theme_id = theme.id.clone();
    let engine = engine.lock().await;
    engine.add_theme(theme).await.map_err(|e| e.to_string())?;
    
    Ok(theme_id)
}

/// Generate a random cyberpunk theme
#[tauri::command]
pub async fn theme_v2_generate_random(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
) -> Result<String, String> {
    let theme = ThemeGenerator::random_cyberpunk()
        .map_err(|e| e.to_string())?;
    
    let theme_id = theme.id.clone();
    let engine = engine.lock().await;
    engine.add_theme(theme).await.map_err(|e| e.to_string())?;
    
    Ok(theme_id)
}

/// Create a theme variant with color modifications
#[tauri::command]
pub async fn theme_v2_create_variant(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    base_theme_id: String,
    name: String,
    color_modifications: HashMap<String, String>,
) -> Result<String, String> {
    let engine = engine.lock().await;
    engine.create_variant(&base_theme_id, &name, color_modifications)
        .await
        .map_err(|e| e.to_string())
}

/// Generate theme variations (light, high contrast, minimal)
#[tauri::command]
pub async fn theme_v2_create_variations(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
    base_theme_id: String,
) -> Result<Vec<String>, String> {
    let engine_guard = engine.lock().await;
    let base_theme = engine_guard.get_theme(&base_theme_id).await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Theme not found".to_string())?;
    
    let variations = ThemeGenerator::create_variations(&base_theme)
        .map_err(|e| e.to_string())?;
    
    let mut variation_ids = Vec::new();
    for variation in variations {
        let id = variation.id.clone();
        engine_guard.add_theme(variation).await.map_err(|e| e.to_string())?;
        variation_ids.push(id);
    }
    
    Ok(variation_ids)
}

/// Validate color accessibility
#[tauri::command]
pub async fn theme_v2_check_accessibility(
    foreground: String,
    background: String,
) -> Result<serde_json::Value, String> {
    let contrast_ratio = ColorUtils::contrast_ratio(&foreground, &background)
        .map_err(|e| e.to_string())?;
    
    let meets_aa = ColorUtils::meets_wcag_aa(&foreground, &background)
        .map_err(|e| e.to_string())?;
    
    let meets_aaa = ColorUtils::meets_wcag_aaa(&foreground, &background)
        .map_err(|e| e.to_string())?;
    
    Ok(serde_json::json!({
        "contrast_ratio": contrast_ratio,
        "meets_wcag_aa": meets_aa,
        "meets_wcag_aaa": meets_aaa,
        "rating": if meets_aaa {
            "AAA"
        } else if meets_aa {
            "AA"
        } else {
            "Fail"
        }
    }))
}

/// Generate color palette from base color
#[tauri::command]
pub async fn theme_v2_generate_palette(
    base_color: String,
    scheme: String,
) -> Result<serde_json::Value, String> {
    let color_scheme = match scheme.as_str() {
        "monochromatic" => ColorScheme::Monochromatic,
        "analogous" => ColorScheme::Analogous,
        "complementary" => ColorScheme::Complementary,
        "triadic" => ColorScheme::Triadic,
        "tetradic" => ColorScheme::Tetradic,
        _ => ColorScheme::Custom,
    };

    let palette = ColorUtils::generate_palette(&base_color, color_scheme)
        .map_err(|e| e.to_string())?;
    
    serde_json::to_value(&palette).map_err(|e| e.to_string())
}

/// Lighten a color
#[tauri::command]
pub async fn theme_v2_lighten_color(
    color: String,
    amount: f32,
) -> Result<String, String> {
    ColorUtils::lighten(&color, amount).map_err(|e| e.to_string())
}

/// Darken a color
#[tauri::command]
pub async fn theme_v2_darken_color(
    color: String,
    amount: f32,
) -> Result<String, String> {
    ColorUtils::darken(&color, amount).map_err(|e| e.to_string())
}

/// Add transparency to a color
#[tauri::command]
pub async fn theme_v2_add_alpha(
    color: String,
    alpha: f32,
) -> Result<String, String> {
    ColorUtils::with_alpha(&color, alpha).map_err(|e| e.to_string())
}

/// Clear theme cache
#[tauri::command]
pub async fn theme_v2_clear_cache(
    engine: State<'_, Arc<Mutex<ThemeEngine>>>,
) -> Result<(), String> {
    let engine = engine.lock().await;
    engine.clear_cache().await;
    Ok(())
}

/// Preview theme changes (generate CSS without saving)
#[tauri::command]
pub async fn theme_v2_preview(
    theme: GhostTheme,
) -> Result<String, String> {
    // Create a temporary theme engine just for preview
    let temp_engine = ThemeEngine::new();
    temp_engine.add_theme(theme.clone()).await.map_err(|e| e.to_string())?;
    temp_engine.generate_css(&theme.id).await.map_err(|e| e.to_string())
}
