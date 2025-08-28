use crate::{GhostTheme, ColorUtils, ColorScheme, ThemeResult};
use uuid::Uuid;
use chrono::Utc;

/// Theme generator for creating themes from various inputs
pub struct ThemeGenerator;

impl ThemeGenerator {
    /// Generate a theme from a base color
    pub fn from_color(base_color: &str, name: &str, scheme: ColorScheme) -> ThemeResult<GhostTheme> {
        let mut theme = GhostTheme::cyberpunk_default();
        
        // Update basic info
        theme.id = Uuid::new_v4().to_string();
        theme.name = name.to_string();
        theme.description = Some(format!("Generated theme based on {}", base_color));
        theme.created_at = Utc::now();
        theme.updated_at = Utc::now();
        theme.author = "Theme Generator".to_string();
        theme.tags = vec!["generated".to_string(), "custom".to_string()];
        
        // Generate color palette
        theme.colors = ColorUtils::generate_palette(base_color, scheme)?;
        
        // Update metadata
        theme.metadata.is_community = true;
        theme.metadata.color_preview = vec![
            theme.colors.primary.clone(),
            theme.colors.secondary.clone(),
            theme.colors.tertiary.clone(),
            theme.colors.background_primary.clone(),
        ];
        
        Ok(theme)
    }

    /// Generate a random cyberpunk theme
    pub fn random_cyberpunk() -> ThemeResult<GhostTheme> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Random cyberpunk colors
        let hue = rng.gen_range(0.0..360.0);
        let saturation = rng.gen_range(0.7..1.0);
        let lightness = rng.gen_range(0.5..0.8);
        
        let base_color = ColorUtils::rgb_to_hex(
            ColorUtils::hsl_to_rgb(hue, saturation, lightness).0,
            ColorUtils::hsl_to_rgb(hue, saturation, lightness).1,
            ColorUtils::hsl_to_rgb(hue, saturation, lightness).2,
        );
        
        Self::from_color(&base_color, "Random Cyberpunk", ColorScheme::Custom)
    }

    /// Generate a theme from an image (placeholder - would analyze dominant colors)
    pub fn from_image(_image_data: &[u8], name: &str) -> ThemeResult<GhostTheme> {
        // In a real implementation, this would analyze the image for dominant colors
        // For now, return a random theme
        let mut theme = Self::random_cyberpunk()?;
        theme.name = name.to_string();
        theme.description = Some("Generated from image analysis".to_string());
        Ok(theme)
    }

    /// Generate complementary theme variations
    pub fn create_variations(base_theme: &GhostTheme) -> ThemeResult<Vec<GhostTheme>> {
        let mut variations = Vec::new();
        
        // Light variation
        let mut light_theme = base_theme.clone();
        light_theme.id = Uuid::new_v4().to_string();
        light_theme.name = format!("{} Light", base_theme.name);
        light_theme.colors.background_primary = "rgba(240, 240, 245, 0.95)".to_string();
        light_theme.colors.background_secondary = "rgba(250, 250, 255, 0.9)".to_string();
        light_theme.colors.text_primary = "#1A1A1A".to_string();
        light_theme.colors.text_secondary = "#4A4A4A".to_string();
        variations.push(light_theme);
        
        // High contrast variation
        let mut contrast_theme = base_theme.clone();
        contrast_theme.id = Uuid::new_v4().to_string();
        contrast_theme.name = format!("{} High Contrast", base_theme.name);
        contrast_theme.accessibility.high_contrast = true;
        contrast_theme.colors.background_primary = "#000000".to_string();
        contrast_theme.colors.text_primary = "#FFFFFF".to_string();
        variations.push(contrast_theme);
        
        // Minimal variation
        let mut minimal_theme = base_theme.clone();
        minimal_theme.id = Uuid::new_v4().to_string();
        minimal_theme.name = format!("{} Minimal", base_theme.name);
        minimal_theme.effects.glow_enabled = false;
        minimal_theme.effects.scan_lines = false;
        minimal_theme.effects.glow_intensity = 0.1;
        variations.push(minimal_theme);
        
        Ok(variations)
    }
}
