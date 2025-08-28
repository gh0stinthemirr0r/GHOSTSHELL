use crate::{GhostTheme, ThemeResult, ThemeError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde_json;

/// Advanced theme management engine
pub struct ThemeEngine {
    themes: Arc<RwLock<HashMap<String, GhostTheme>>>,
    active_theme_id: Arc<RwLock<Option<String>>>,
    theme_cache: Arc<RwLock<HashMap<String, String>>>, // CSS cache
}

impl ThemeEngine {
    pub fn new() -> Self {
        Self {
            themes: Arc::new(RwLock::new(HashMap::new())),
            active_theme_id: Arc::new(RwLock::new(None)),
            theme_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize the theme engine with default themes
    pub async fn initialize(&self) -> ThemeResult<()> {
        tracing::debug!("ThemeEngine::initialize() - Entry");
        
        // Load default cyberpunk theme
        tracing::debug!("ThemeEngine::initialize() - Creating default cyberpunk theme");
        let default_theme = GhostTheme::cyberpunk_default();
        let theme_id = default_theme.id.clone();
        tracing::debug!("ThemeEngine::initialize() - Default theme created with ID: {}", theme_id);
        
        tracing::debug!("ThemeEngine::initialize() - Adding default theme");
        self.add_theme(default_theme).await?;
        tracing::debug!("ThemeEngine::initialize() - Default theme added");
        
        tracing::debug!("ThemeEngine::initialize() - Setting active theme");
        self.set_active_theme(&theme_id).await?;
        tracing::debug!("ThemeEngine::initialize() - Active theme set");
        
        // Load additional preset themes
        tracing::debug!("ThemeEngine::initialize() - Loading preset themes");
        self.load_preset_themes().await?;
        tracing::debug!("ThemeEngine::initialize() - Preset themes loaded");
        
        tracing::debug!("ThemeEngine::initialize() - Completed successfully");
        Ok(())
    }

    /// Add a theme to the engine
    pub async fn add_theme(&self, theme: GhostTheme) -> ThemeResult<()> {
        let theme_id = theme.id.clone();
        let mut themes = self.themes.write().await;
        themes.insert(theme_id.clone(), theme);
        
        // Clear cache for this theme
        let mut cache = self.theme_cache.write().await;
        cache.remove(&theme_id);
        
        Ok(())
    }

    /// Get a theme by ID
    pub async fn get_theme(&self, theme_id: &str) -> ThemeResult<Option<GhostTheme>> {
        let themes = self.themes.read().await;
        Ok(themes.get(theme_id).cloned())
    }

    /// Get all available themes
    pub async fn get_all_themes(&self) -> ThemeResult<Vec<GhostTheme>> {
        let themes = self.themes.read().await;
        Ok(themes.values().cloned().collect())
    }

    /// Set the active theme
    pub async fn set_active_theme(&self, theme_id: &str) -> ThemeResult<()> {
        let themes = self.themes.read().await;
        if !themes.contains_key(theme_id) {
            return Err(ThemeError::ThemeNotFound(theme_id.to_string()));
        }
        
        let mut active_id = self.active_theme_id.write().await;
        *active_id = Some(theme_id.to_string());
        
        Ok(())
    }

    /// Get the currently active theme
    pub async fn get_active_theme(&self) -> ThemeResult<Option<GhostTheme>> {
        let active_id = self.active_theme_id.read().await;
        if let Some(theme_id) = active_id.as_ref() {
            self.get_theme(theme_id).await
        } else {
            Ok(None)
        }
    }

    /// Generate CSS for a theme
    pub async fn generate_css(&self, theme_id: &str) -> ThemeResult<String> {
        // Check cache first
        {
            let cache = self.theme_cache.read().await;
            if let Some(cached_css) = cache.get(theme_id) {
                return Ok(cached_css.clone());
            }
        }

        let theme = self.get_theme(theme_id).await?
            .ok_or_else(|| ThemeError::ThemeNotFound(theme_id.to_string()))?;

        let css = self.build_css(&theme)?;
        
        // Cache the result
        {
            let mut cache = self.theme_cache.write().await;
            cache.insert(theme_id.to_string(), css.clone());
        }

        Ok(css)
    }

    /// Generate CSS for the active theme
    pub async fn generate_active_css(&self) -> ThemeResult<String> {
        let active_id = self.active_theme_id.read().await;
        if let Some(theme_id) = active_id.as_ref() {
            self.generate_css(theme_id).await
        } else {
            Err(ThemeError::ThemeNotFound("No active theme".to_string()))
        }
    }

    /// Update a theme
    pub async fn update_theme(&self, theme: GhostTheme) -> ThemeResult<()> {
        let theme_id = theme.id.clone();
        
        {
            let mut themes = self.themes.write().await;
            themes.insert(theme_id.clone(), theme);
        }
        
        // Clear cache
        {
            let mut cache = self.theme_cache.write().await;
            cache.remove(&theme_id);
        }
        
        Ok(())
    }

    /// Delete a theme
    pub async fn delete_theme(&self, theme_id: &str) -> ThemeResult<()> {
        {
            let mut themes = self.themes.write().await;
            themes.remove(theme_id);
        }
        
        // Clear cache
        {
            let mut cache = self.theme_cache.write().await;
            cache.remove(theme_id);
        }
        
        // If this was the active theme, reset to default
        {
            let active_id = self.active_theme_id.read().await;
            if active_id.as_ref() == Some(&theme_id.to_string()) {
                drop(active_id);
                let themes = self.themes.read().await;
                if let Some(first_theme) = themes.values().next() {
                    let default_id = first_theme.id.clone();
                    drop(themes);
                    self.set_active_theme(&default_id).await?;
                }
            }
        }
        
        Ok(())
    }

    /// Export a theme as JSON
    pub async fn export_theme(&self, theme_id: &str) -> ThemeResult<String> {
        let theme = self.get_theme(theme_id).await?
            .ok_or_else(|| ThemeError::ThemeNotFound(theme_id.to_string()))?;
        
        serde_json::to_string_pretty(&theme)
            .map_err(ThemeError::SerializationError)
    }

    /// Import a theme from JSON
    pub async fn import_theme(&self, json: &str) -> ThemeResult<String> {
        let theme: GhostTheme = serde_json::from_str(json)
            .map_err(ThemeError::SerializationError)?;
        
        let theme_id = theme.id.clone();
        self.add_theme(theme).await?;
        
        Ok(theme_id)
    }

    /// Create a theme variant with modified colors
    pub async fn create_variant(&self, base_theme_id: &str, name: &str, color_modifications: HashMap<String, String>) -> ThemeResult<String> {
        let mut base_theme = self.get_theme(base_theme_id).await?
            .ok_or_else(|| ThemeError::ThemeNotFound(base_theme_id.to_string()))?;
        
        // Create new theme with modified properties
        base_theme.id = uuid::Uuid::new_v4().to_string();
        base_theme.name = name.to_string();
        base_theme.created_at = chrono::Utc::now();
        base_theme.updated_at = chrono::Utc::now();
        base_theme.metadata.is_community = true;
        
        // Apply color modifications
        for (property, color) in color_modifications {
            self.apply_color_modification(&mut base_theme, &property, &color)?;
        }
        
        let theme_id = base_theme.id.clone();
        self.add_theme(base_theme).await?;
        
        Ok(theme_id)
    }

    /// Clear the CSS cache
    pub async fn clear_cache(&self) {
        let mut cache = self.theme_cache.write().await;
        cache.clear();
    }

    /// Load preset themes
    async fn load_preset_themes(&self) -> ThemeResult<()> {
        use crate::presets::ThemePresets;
        
        let presets = ThemePresets::get_all_presets();
        for preset in presets {
            self.add_theme(preset).await?;
        }
        
        Ok(())
    }

    /// Build CSS from theme configuration
    fn build_css(&self, theme: &GhostTheme) -> ThemeResult<String> {
        let mut css = String::new();
        
        // CSS Custom Properties (CSS Variables)
        css.push_str(":root {\n");
        
        // Color variables
        css.push_str(&format!("  --color-primary: {};\n", theme.colors.primary));
        css.push_str(&format!("  --color-secondary: {};\n", theme.colors.secondary));
        css.push_str(&format!("  --color-tertiary: {};\n", theme.colors.tertiary));
        
        css.push_str(&format!("  --bg-primary: {};\n", theme.colors.background_primary));
        css.push_str(&format!("  --bg-secondary: {};\n", theme.colors.background_secondary));
        css.push_str(&format!("  --bg-tertiary: {};\n", theme.colors.background_tertiary));
        
        css.push_str(&format!("  --text-primary: {};\n", theme.colors.text_primary));
        css.push_str(&format!("  --text-secondary: {};\n", theme.colors.text_secondary));
        css.push_str(&format!("  --text-muted: {};\n", theme.colors.text_muted));
        
        css.push_str(&format!("  --border-primary: {};\n", theme.colors.border_primary));
        css.push_str(&format!("  --border-secondary: {};\n", theme.colors.border_secondary));
        css.push_str(&format!("  --border-focus: {};\n", theme.colors.border_focus));
        
        // Effect variables
        css.push_str(&format!("  --glow-intensity: {};\n", theme.effects.glow_intensity));
        css.push_str(&format!("  --glow-radius: {}px;\n", theme.effects.glow_radius));
        css.push_str(&format!("  --blur-radius: {}px;\n", theme.effects.blur_radius));
        css.push_str(&format!("  --transparency: {};\n", theme.effects.transparency_level));
        
        // Typography variables
        css.push_str(&format!("  --font-family-primary: {};\n", theme.typography.font_family_primary));
        css.push_str(&format!("  --font-family-secondary: {};\n", theme.typography.font_family_secondary));
        css.push_str(&format!("  --font-family-mono: {};\n", theme.typography.font_family_mono));
        css.push_str(&format!("  --font-size-base: {}rem;\n", theme.typography.font_size_base));
        css.push_str(&format!("  --line-height-base: {};\n", theme.typography.line_height_base));
        
        // Layout variables
        css.push_str(&format!("  --spacing-unit: {}rem;\n", theme.layout.spacing_unit));
        css.push_str(&format!("  --border-radius-sm: {}px;\n", theme.layout.border_radius_small));
        css.push_str(&format!("  --border-radius-md: {}px;\n", theme.layout.border_radius_medium));
        css.push_str(&format!("  --border-radius-lg: {}px;\n", theme.layout.border_radius_large));
        
        // Animation variables
        css.push_str(&format!("  --duration-fast: {};\n", theme.animations.duration_fast));
        css.push_str(&format!("  --duration-normal: {};\n", theme.animations.duration_normal));
        css.push_str(&format!("  --duration-slow: {};\n", theme.animations.duration_slow));
        css.push_str(&format!("  --easing-standard: {};\n", theme.animations.easing_standard));
        
        css.push_str("}\n\n");
        
        // Component styles
        css.push_str(&self.build_component_css(theme)?);
        
        // Effect styles
        css.push_str(&self.build_effect_css(theme)?);
        
        // Animation styles
        css.push_str(&self.build_animation_css(theme)?);
        
        // Custom CSS
        if let Some(custom_css) = &theme.custom_css {
            css.push_str("\n/* Custom CSS */\n");
            css.push_str(custom_css);
            css.push_str("\n");
        }
        
        Ok(css)
    }

    /// Build component-specific CSS
    fn build_component_css(&self, theme: &GhostTheme) -> ThemeResult<String> {
        let mut css = String::new();
        
        // Button styles
        css.push_str("/* Button Styles */\n");
        css.push_str(".btn-primary {\n");
        css.push_str(&format!("  background: {};\n", theme.components.buttons.primary_bg));
        css.push_str(&format!("  color: {};\n", theme.components.buttons.primary_text));
        css.push_str(&format!("  border: 1px solid {};\n", theme.components.buttons.primary_border));
        css.push_str(&format!("  box-shadow: {};\n", theme.components.buttons.primary_glow));
        css.push_str(&format!("  transition: all {};\n", theme.components.buttons.transition_duration));
        css.push_str("}\n");
        
        css.push_str(".btn-primary:hover {\n");
        css.push_str(&format!("  transform: {};\n", theme.components.buttons.hover_transform));
        css.push_str("}\n");
        
        css.push_str(".btn-primary:active {\n");
        css.push_str(&format!("  transform: scale({});\n", theme.components.buttons.active_scale));
        css.push_str("}\n\n");
        
        // Input styles
        css.push_str("/* Input Styles */\n");
        css.push_str(".input-field {\n");
        css.push_str(&format!("  background: {};\n", theme.components.inputs.background));
        css.push_str(&format!("  border: 1px solid {};\n", theme.components.inputs.border));
        css.push_str(&format!("  color: {};\n", theme.components.inputs.text));
        css.push_str("}\n");
        
        css.push_str(".input-field:focus {\n");
        css.push_str(&format!("  border-color: {};\n", theme.components.inputs.border_focus));
        css.push_str(&format!("  box-shadow: {};\n", theme.components.inputs.glow_focus));
        css.push_str("}\n\n");
        
        // Card styles
        css.push_str("/* Card Styles */\n");
        css.push_str(".card {\n");
        css.push_str(&format!("  background: {};\n", theme.components.cards.background));
        css.push_str(&format!("  border: 1px solid {};\n", theme.components.cards.border));
        css.push_str(&format!("  box-shadow: {};\n", theme.components.cards.shadow));
        css.push_str(&format!("  backdrop-filter: {};\n", theme.components.cards.backdrop_filter));
        css.push_str("}\n\n");
        
        // Notification styles
        css.push_str("/* Notification Styles */\n");
        css.push_str(".notification {\n");
        css.push_str(&format!("  background: {};\n", theme.components.notifications.background));
        css.push_str(&format!("  border: 1px solid {};\n", theme.components.notifications.border));
        css.push_str(&format!("  color: {};\n", theme.components.notifications.text));
        css.push_str(&format!("  box-shadow: {};\n", theme.components.notifications.glow));
        css.push_str("}\n\n");
        
        Ok(css)
    }

    /// Build effect-specific CSS
    fn build_effect_css(&self, theme: &GhostTheme) -> ThemeResult<String> {
        let mut css = String::new();
        
        if theme.effects.glow_enabled {
            css.push_str("/* Glow Effects */\n");
            css.push_str(".glow {\n");
            css.push_str(&format!("  box-shadow: 0 0 {}px {}px var(--color-primary);\n", 
                theme.effects.glow_radius, theme.effects.glow_intensity * 2.0));
            css.push_str("}\n\n");
        }
        
        if theme.effects.scan_lines {
            css.push_str("/* Scan Lines Effect */\n");
            css.push_str(".scan-lines::before {\n");
            css.push_str("  content: '';\n");
            css.push_str("  position: absolute;\n");
            css.push_str("  top: 0;\n");
            css.push_str("  left: 0;\n");
            css.push_str("  right: 0;\n");
            css.push_str("  bottom: 0;\n");
            css.push_str("  background: repeating-linear-gradient(\n");
            css.push_str("    0deg,\n");
            css.push_str("    transparent,\n");
            css.push_str("    transparent 2px,\n");
            css.push_str(&format!("    {} 2px,\n", theme.components.terminal.scan_line_color));
            css.push_str(&format!("    {} 4px\n", theme.components.terminal.scan_line_color));
            css.push_str("  );\n");
            css.push_str(&format!("  opacity: {};\n", theme.components.terminal.scan_line_opacity));
            css.push_str("  pointer-events: none;\n");
            css.push_str("}\n\n");
        }
        
        Ok(css)
    }

    /// Build animation CSS
    fn build_animation_css(&self, theme: &GhostTheme) -> ThemeResult<String> {
        let mut css = String::new();
        
        if theme.animations.enabled {
            css.push_str("/* Animations */\n");
            
            if theme.animations.hover_animations {
                css.push_str(".hover-lift:hover {\n");
                css.push_str("  transform: translateY(-2px);\n");
                css.push_str(&format!("  transition: transform {};\n", theme.animations.duration_fast));
                css.push_str("}\n\n");
            }
            
            if theme.animations.loading_animations {
                css.push_str("@keyframes pulse {\n");
                css.push_str("  0%, 100% { opacity: 1; }\n");
                css.push_str("  50% { opacity: 0.5; }\n");
                css.push_str("}\n");
                
                css.push_str(".loading-pulse {\n");
                css.push_str(&format!("  animation: pulse {} infinite;\n", theme.animations.duration_normal));
                css.push_str("}\n\n");
            }
        }
        
        if theme.accessibility.reduce_motion {
            css.push_str("/* Reduced Motion */\n");
            css.push_str("@media (prefers-reduced-motion: reduce) {\n");
            css.push_str("  * {\n");
            css.push_str("    animation-duration: 0.01ms !important;\n");
            css.push_str("    animation-iteration-count: 1 !important;\n");
            css.push_str("    transition-duration: 0.01ms !important;\n");
            css.push_str("  }\n");
            css.push_str("}\n\n");
        }
        
        Ok(css)
    }

    /// Apply color modification to theme
    fn apply_color_modification(&self, theme: &mut GhostTheme, property: &str, color: &str) -> ThemeResult<()> {
        match property {
            "primary" => theme.colors.primary = color.to_string(),
            "secondary" => theme.colors.secondary = color.to_string(),
            "tertiary" => theme.colors.tertiary = color.to_string(),
            "background_primary" => theme.colors.background_primary = color.to_string(),
            "background_secondary" => theme.colors.background_secondary = color.to_string(),
            "text_primary" => theme.colors.text_primary = color.to_string(),
            "text_secondary" => theme.colors.text_secondary = color.to_string(),
            _ => return Err(ThemeError::ValidationError(format!("Unknown color property: {}", property))),
        }
        Ok(())
    }
}

impl Default for ThemeEngine {
    fn default() -> Self {
        Self::new()
    }
}
