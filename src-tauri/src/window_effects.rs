// Window effects module for acrylic/mica/vibrancy
// Handles platform-specific transparency effects

use anyhow::Result;
use tauri::Window;

#[cfg(target_os = "windows")]
pub fn apply_windows_effects(window: &Window) -> Result<()> {
    use window_vibrancy::{apply_mica, apply_acrylic};
    
    // Try Mica first (Windows 11), fallback to Acrylic
    if apply_mica(window, Some(true)).is_err() {
        let tint = (12, 15, 28, 180); // ~70% opacity cyberpunk tint
        apply_acrylic(window, Some(tint))?;
    }
    
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn apply_macos_effects(window: &Window) -> Result<()> {
    use window_vibrancy::{apply_vibrancy, NSVisualEffectMaterial};
    
    apply_vibrancy(
        window,
        NSVisualEffectMaterial::HudWindow,
        None,
        None,
    )?;
    
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply_linux_effects(_window: &Window) -> Result<()> {
    // Linux transparency is handled via CSS backdrop-filter
    // No native window effects needed
    Ok(())
}

pub fn apply_platform_effects(window: &Window) -> Result<()> {
    #[cfg(target_os = "windows")]
    return apply_windows_effects(window);
    
    #[cfg(target_os = "macos")]
    return apply_macos_effects(window);
    
    #[cfg(target_os = "linux")]
    return apply_linux_effects(window);
}
