use crate::{GhostTheme, ThemeCategory, ThemeMood, ThemeComplexity, PerformanceImpact};
use uuid::Uuid;

pub struct ThemePresets;

impl ThemePresets {
    pub fn get_all_presets() -> Vec<GhostTheme> {
        vec![
            Self::neon_blue(),
            Self::cyber_red(),
            Self::matrix_green(),
            Self::synthwave_purple(),
            Self::minimal_dark(),
            Self::high_contrast(),
        ]
    }

    pub fn neon_blue() -> GhostTheme {
        let mut theme = GhostTheme::cyberpunk_default();
        theme.id = Uuid::new_v4().to_string();
        theme.name = "Neon Blue".to_string();
        theme.description = Some("Electric blue cyberpunk theme".to_string());
        theme.tags = vec!["cyberpunk".to_string(), "blue".to_string(), "neon".to_string()];
        
        theme.colors.primary = "#00D4FF".to_string();
        theme.colors.secondary = "#0099CC".to_string();
        theme.colors.tertiary = "#66E5FF".to_string();
        theme.colors.glow_primary = "rgba(0, 212, 255, 0.5)".to_string();
        
        theme.metadata.color_preview = vec![
            "#00D4FF".to_string(),
            "#0099CC".to_string(),
            "#66E5FF".to_string(),
            "#0C0F1C".to_string(),
        ];
        
        theme
    }

    pub fn cyber_red() -> GhostTheme {
        let mut theme = GhostTheme::cyberpunk_default();
        theme.id = Uuid::new_v4().to_string();
        theme.name = "Cyber Red".to_string();
        theme.description = Some("Aggressive red cyberpunk theme".to_string());
        theme.tags = vec!["cyberpunk".to_string(), "red".to_string(), "aggressive".to_string()];
        
        theme.colors.primary = "#FF0040".to_string();
        theme.colors.secondary = "#CC0033".to_string();
        theme.colors.tertiary = "#FF6680".to_string();
        theme.colors.glow_primary = "rgba(255, 0, 64, 0.5)".to_string();
        
        theme.metadata.color_preview = vec![
            "#FF0040".to_string(),
            "#CC0033".to_string(),
            "#FF6680".to_string(),
            "#0C0F1C".to_string(),
        ];
        theme.metadata.mood = ThemeMood::Intense;
        
        theme
    }

    pub fn matrix_green() -> GhostTheme {
        let mut theme = GhostTheme::cyberpunk_default();
        theme.id = Uuid::new_v4().to_string();
        theme.name = "Matrix Green".to_string();
        theme.description = Some("Classic Matrix-inspired green theme".to_string());
        theme.tags = vec!["matrix".to_string(), "green".to_string(), "classic".to_string()];
        
        theme.colors.primary = "#00FF41".to_string();
        theme.colors.secondary = "#00CC33".to_string();
        theme.colors.tertiary = "#66FF80".to_string();
        theme.colors.glow_primary = "rgba(0, 255, 65, 0.5)".to_string();
        
        // Matrix-specific terminal styling
        theme.components.terminal.text = "#00FF41".to_string();
        theme.components.terminal.cursor = "#00FF41".to_string();
        theme.components.terminal.scan_line_color = "rgba(0, 255, 65, 0.1)".to_string();
        
        theme.metadata.color_preview = vec![
            "#00FF41".to_string(),
            "#00CC33".to_string(),
            "#66FF80".to_string(),
            "#000000".to_string(),
        ];
        theme.metadata.category = ThemeCategory::Retro;
        
        theme
    }

    pub fn synthwave_purple() -> GhostTheme {
        let mut theme = GhostTheme::cyberpunk_default();
        theme.id = Uuid::new_v4().to_string();
        theme.name = "Synthwave Purple".to_string();
        theme.description = Some("80s synthwave inspired purple theme".to_string());
        theme.tags = vec!["synthwave".to_string(), "purple".to_string(), "80s".to_string()];
        
        theme.colors.primary = "#B300FF".to_string();
        theme.colors.secondary = "#FF00B3".to_string();
        theme.colors.tertiary = "#E066FF".to_string();
        theme.colors.glow_primary = "rgba(179, 0, 255, 0.5)".to_string();
        theme.colors.glow_secondary = "rgba(255, 0, 179, 0.5)".to_string();
        
        // Enhanced glow effects for synthwave
        theme.effects.glow_intensity = 0.8;
        theme.effects.glow_radius = 25.0;
        
        theme.metadata.color_preview = vec![
            "#B300FF".to_string(),
            "#FF00B3".to_string(),
            "#E066FF".to_string(),
            "#0C0F1C".to_string(),
        ];
        theme.metadata.category = ThemeCategory::Retro;
        theme.metadata.mood = ThemeMood::Energetic;
        
        theme
    }

    pub fn minimal_dark() -> GhostTheme {
        let mut theme = GhostTheme::cyberpunk_default();
        theme.id = Uuid::new_v4().to_string();
        theme.name = "Minimal Dark".to_string();
        theme.description = Some("Clean minimal dark theme".to_string());
        theme.tags = vec!["minimal".to_string(), "dark".to_string(), "clean".to_string()];
        
        theme.colors.primary = "#FFFFFF".to_string();
        theme.colors.secondary = "#888888".to_string();
        theme.colors.tertiary = "#CCCCCC".to_string();
        theme.colors.glow_primary = "rgba(255, 255, 255, 0.2)".to_string();
        
        // Reduced effects for minimal theme
        theme.effects.glow_enabled = false;
        theme.effects.scan_lines = false;
        theme.effects.glow_intensity = 0.2;
        theme.effects.blur_radius = 10.0;
        
        theme.metadata.color_preview = vec![
            "#FFFFFF".to_string(),
            "#888888".to_string(),
            "#CCCCCC".to_string(),
            "#1A1A1A".to_string(),
        ];
        theme.metadata.category = ThemeCategory::Minimal;
        theme.metadata.mood = ThemeMood::Calm;
        theme.metadata.complexity = ThemeComplexity::Simple;
        theme.metadata.performance_impact = PerformanceImpact::Low;
        
        theme
    }

    pub fn high_contrast() -> GhostTheme {
        let mut theme = GhostTheme::cyberpunk_default();
        theme.id = Uuid::new_v4().to_string();
        theme.name = "High Contrast".to_string();
        theme.description = Some("High contrast theme for accessibility".to_string());
        theme.tags = vec!["accessibility".to_string(), "high-contrast".to_string(), "wcag".to_string()];
        
        theme.colors.primary = "#FFFF00".to_string();
        theme.colors.secondary = "#FFFFFF".to_string();
        theme.colors.tertiary = "#00FFFF".to_string();
        theme.colors.background_primary = "#000000".to_string();
        theme.colors.background_secondary = "#1A1A1A".to_string();
        theme.colors.text_primary = "#FFFFFF".to_string();
        theme.colors.border_primary = "#FFFFFF".to_string();
        
        // Accessibility optimizations
        theme.accessibility.high_contrast = true;
        theme.accessibility.focus_indicators = true;
        theme.accessibility.min_contrast_ratio = 7.0;
        theme.accessibility.focus_outline_width = 3.0;
        
        // Reduced effects for better accessibility
        theme.effects.glow_enabled = false;
        theme.effects.blur_enabled = false;
        theme.effects.transparency_enabled = false;
        theme.effects.scan_lines = false;
        
        theme.metadata.color_preview = vec![
            "#FFFF00".to_string(),
            "#FFFFFF".to_string(),
            "#00FFFF".to_string(),
            "#000000".to_string(),
        ];
        theme.metadata.category = ThemeCategory::HighContrast;
        theme.metadata.complexity = ThemeComplexity::Simple;
        theme.metadata.performance_impact = PerformanceImpact::Low;
        
        theme
    }
}
