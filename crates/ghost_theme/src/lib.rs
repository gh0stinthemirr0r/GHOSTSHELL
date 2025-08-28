use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub mod engine;
pub mod colors;
pub mod effects;
pub mod presets;
pub mod generator;

pub use engine::ThemeEngine;
pub use colors::{ColorScheme, ColorUtils};
pub use effects::{VisualEffect, GlowEffect, BlurEffect, AnimationEffect};
pub use presets::ThemePresets;
pub use generator::ThemeGenerator;

/// Advanced theme configuration for GHOSTSHELL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostTheme {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub version: String,
    pub author: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
    
    // Core color scheme
    pub colors: ColorPalette,
    
    // Visual effects
    pub effects: EffectSettings,
    
    // Typography
    pub typography: TypographySettings,
    
    // Layout and spacing
    pub layout: LayoutSettings,
    
    // Component-specific styling
    pub components: ComponentStyles,
    
    // Animation settings
    pub animations: AnimationSettings,
    
    // Accessibility settings
    pub accessibility: AccessibilitySettings,
    
    // Custom CSS overrides
    pub custom_css: Option<String>,
    
    // Theme metadata
    pub metadata: ThemeMetadata,
}

/// Color palette with semantic color assignments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorPalette {
    // Primary colors
    pub primary: String,           // Main brand color (#00FFD1)
    pub secondary: String,         // Secondary accent (#FF008C)
    pub tertiary: String,          // Third accent (#FFAA00)
    
    // Background colors
    pub background_primary: String,    // Main background
    pub background_secondary: String,  // Card/panel backgrounds
    pub background_tertiary: String,   // Elevated surfaces
    
    // Text colors
    pub text_primary: String,      // Main text
    pub text_secondary: String,    // Secondary text
    pub text_muted: String,        // Muted/disabled text
    pub text_inverse: String,      // Text on dark backgrounds
    
    // Border and outline colors
    pub border_primary: String,
    pub border_secondary: String,
    pub border_focus: String,
    
    // Status colors
    pub success: String,
    pub warning: String,
    pub error: String,
    pub info: String,
    
    // Interactive states
    pub hover: String,
    pub active: String,
    pub disabled: String,
    
    // Special effects
    pub glow_primary: String,
    pub glow_secondary: String,
    pub shadow: String,
}

/// Visual effects configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectSettings {
    pub glow_enabled: bool,
    pub glow_intensity: f32,        // 0.0 - 1.0
    pub glow_radius: f32,           // pixels
    
    pub blur_enabled: bool,
    pub blur_radius: f32,           // pixels
    
    pub transparency_enabled: bool,
    pub transparency_level: f32,    // 0.0 - 1.0
    
    pub animations_enabled: bool,
    pub animation_speed: f32,       // 0.5 - 2.0 (multiplier)
    
    pub particle_effects: bool,
    pub scan_lines: bool,
    pub chromatic_aberration: bool,
    pub noise_overlay: bool,
}

/// Typography settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypographySettings {
    pub font_family_primary: String,
    pub font_family_secondary: String,
    pub font_family_mono: String,
    
    pub font_size_base: f32,        // rem
    pub font_size_scale: f32,       // scaling factor
    
    pub line_height_base: f32,
    pub letter_spacing: f32,        // em
    
    pub font_weight_normal: u16,
    pub font_weight_bold: u16,
    
    pub text_shadow_enabled: bool,
    pub text_glow_enabled: bool,
}

/// Layout and spacing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutSettings {
    pub spacing_unit: f32,          // base spacing unit (rem)
    pub border_radius_small: f32,   // pixels
    pub border_radius_medium: f32,
    pub border_radius_large: f32,
    
    pub container_max_width: String, // CSS value
    pub sidebar_width: String,
    pub header_height: String,
    
    pub grid_gap: f32,              // rem
    pub section_padding: f32,       // rem
}

/// Component-specific styling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStyles {
    pub buttons: ButtonStyles,
    pub inputs: InputStyles,
    pub cards: CardStyles,
    pub modals: ModalStyles,
    pub navigation: NavigationStyles,
    pub terminal: TerminalStyles,
    pub notifications: NotificationStyles,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ButtonStyles {
    pub primary_bg: String,
    pub primary_text: String,
    pub primary_border: String,
    pub primary_glow: String,
    
    pub secondary_bg: String,
    pub secondary_text: String,
    pub secondary_border: String,
    
    pub hover_transform: String,    // CSS transform
    pub active_scale: f32,
    pub transition_duration: String, // CSS duration
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputStyles {
    pub background: String,
    pub border: String,
    pub border_focus: String,
    pub text: String,
    pub placeholder: String,
    pub glow_focus: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardStyles {
    pub background: String,
    pub border: String,
    pub shadow: String,
    pub glow: String,
    pub backdrop_filter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModalStyles {
    pub backdrop: String,
    pub background: String,
    pub border: String,
    pub shadow: String,
    pub blur_backdrop: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigationStyles {
    pub background: String,
    pub border: String,
    pub item_hover: String,
    pub item_active: String,
    pub indicator_color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalStyles {
    pub background: String,
    pub text: String,
    pub cursor: String,
    pub selection: String,
    pub scan_line_color: String,
    pub scan_line_opacity: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationStyles {
    pub background: String,
    pub border: String,
    pub text: String,
    pub glow: String,
    pub progress_bar: String,
}

/// Animation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnimationSettings {
    pub enabled: bool,
    pub duration_fast: String,      // CSS duration
    pub duration_normal: String,
    pub duration_slow: String,
    
    pub easing_standard: String,    // CSS easing function
    pub easing_enter: String,
    pub easing_exit: String,
    
    pub hover_animations: bool,
    pub focus_animations: bool,
    pub loading_animations: bool,
    pub transition_animations: bool,
}

/// Accessibility settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibilitySettings {
    pub high_contrast: bool,
    pub reduce_motion: bool,
    pub focus_indicators: bool,
    pub screen_reader_optimized: bool,
    
    pub min_contrast_ratio: f32,    // WCAG compliance
    pub font_size_multiplier: f32,  // 0.8 - 2.0
    pub focus_outline_width: f32,   // pixels
}

/// Theme metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeMetadata {
    pub category: ThemeCategory,
    pub mood: ThemeMood,
    pub complexity: ThemeComplexity,
    pub performance_impact: PerformanceImpact,
    
    pub preview_image: Option<String>, // base64 or URL
    pub color_preview: Vec<String>,    // Representative colors
    
    pub compatibility_version: String,
    pub requires_features: Vec<String>,
    
    pub download_count: u64,
    pub rating: Option<f32>,           // 0.0 - 5.0
    pub is_featured: bool,
    pub is_community: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThemeCategory {
    Cyberpunk,
    Neon,
    Dark,
    Light,
    HighContrast,
    Retro,
    Minimal,
    Gaming,
    Professional,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThemeMood {
    Energetic,
    Calm,
    Intense,
    Playful,
    Serious,
    Mysterious,
    Futuristic,
    Classic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThemeComplexity {
    Simple,
    Moderate,
    Complex,
    Extreme,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceImpact {
    Low,
    Medium,
    High,
    Extreme,
}

/// Theme operation results
pub type ThemeResult<T> = Result<T, ThemeError>;

/// Theme system errors
#[derive(Debug, thiserror::Error)]
pub enum ThemeError {
    #[error("Theme not found: {0}")]
    ThemeNotFound(String),
    #[error("Invalid theme format: {0}")]
    InvalidFormat(String),
    #[error("Color parsing error: {0}")]
    ColorError(String),
    #[error("CSS generation error: {0}")]
    CssError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

impl Default for GhostTheme {
    fn default() -> Self {
        Self::cyberpunk_default()
    }
}

impl GhostTheme {
    /// Create the default cyberpunk theme
    pub fn cyberpunk_default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: "Cyberpunk Default".to_string(),
            description: Some("The classic GHOSTSHELL cyberpunk aesthetic".to_string()),
            version: "1.0.0".to_string(),
            author: "GHOSTSHELL Team".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags: vec!["cyberpunk".to_string(), "neon".to_string(), "default".to_string()],
            
            colors: ColorPalette {
                primary: "#00FFD1".to_string(),
                secondary: "#FF008C".to_string(),
                tertiary: "#FFAA00".to_string(),
                
                background_primary: "rgba(12, 15, 28, 0.95)".to_string(),
                background_secondary: "rgba(20, 25, 40, 0.9)".to_string(),
                background_tertiary: "rgba(30, 35, 50, 0.85)".to_string(),
                
                text_primary: "#EAEAEA".to_string(),
                text_secondary: "#B0B0B0".to_string(),
                text_muted: "#707070".to_string(),
                text_inverse: "#1A1A1A".to_string(),
                
                border_primary: "rgba(0, 255, 209, 0.3)".to_string(),
                border_secondary: "rgba(255, 255, 255, 0.1)".to_string(),
                border_focus: "#00FFD1".to_string(),
                
                success: "#00FF88".to_string(),
                warning: "#FFAA00".to_string(),
                error: "#FF008C".to_string(),
                info: "#00FFD1".to_string(),
                
                hover: "rgba(0, 255, 209, 0.1)".to_string(),
                active: "rgba(0, 255, 209, 0.2)".to_string(),
                disabled: "rgba(255, 255, 255, 0.3)".to_string(),
                
                glow_primary: "rgba(0, 255, 209, 0.5)".to_string(),
                glow_secondary: "rgba(255, 0, 140, 0.5)".to_string(),
                shadow: "rgba(0, 0, 0, 0.5)".to_string(),
            },
            
            effects: EffectSettings {
                glow_enabled: true,
                glow_intensity: 0.6,
                glow_radius: 20.0,
                blur_enabled: true,
                blur_radius: 18.0,
                transparency_enabled: true,
                transparency_level: 0.9,
                animations_enabled: true,
                animation_speed: 1.0,
                particle_effects: false,
                scan_lines: true,
                chromatic_aberration: false,
                noise_overlay: false,
            },
            
            typography: TypographySettings {
                font_family_primary: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif".to_string(),
                font_family_secondary: "'JetBrains Mono', 'Fira Code', monospace".to_string(),
                font_family_mono: "'JetBrains Mono', 'Consolas', monospace".to_string(),
                font_size_base: 1.0,
                font_size_scale: 1.2,
                line_height_base: 1.5,
                letter_spacing: 0.02,
                font_weight_normal: 400,
                font_weight_bold: 600,
                text_shadow_enabled: true,
                text_glow_enabled: true,
            },
            
            layout: LayoutSettings {
                spacing_unit: 1.0,
                border_radius_small: 6.0,
                border_radius_medium: 12.0,
                border_radius_large: 20.0,
                container_max_width: "1400px".to_string(),
                sidebar_width: "280px".to_string(),
                header_height: "64px".to_string(),
                grid_gap: 1.5,
                section_padding: 2.0,
            },
            
            components: ComponentStyles {
                buttons: ButtonStyles {
                    primary_bg: "#00FFD1".to_string(),
                    primary_text: "#000000".to_string(),
                    primary_border: "#00FFD1".to_string(),
                    primary_glow: "0 0 20px rgba(0, 255, 209, 0.5)".to_string(),
                    secondary_bg: "rgba(255, 255, 255, 0.1)".to_string(),
                    secondary_text: "#EAEAEA".to_string(),
                    secondary_border: "rgba(255, 255, 255, 0.2)".to_string(),
                    hover_transform: "translateY(-2px)".to_string(),
                    active_scale: 0.98,
                    transition_duration: "0.2s".to_string(),
                },
                inputs: InputStyles {
                    background: "rgba(255, 255, 255, 0.1)".to_string(),
                    border: "rgba(255, 255, 255, 0.2)".to_string(),
                    border_focus: "#00FFD1".to_string(),
                    text: "#EAEAEA".to_string(),
                    placeholder: "rgba(255, 255, 255, 0.5)".to_string(),
                    glow_focus: "0 0 15px rgba(0, 255, 209, 0.3)".to_string(),
                },
                cards: CardStyles {
                    background: "rgba(20, 25, 40, 0.9)".to_string(),
                    border: "rgba(0, 255, 209, 0.3)".to_string(),
                    shadow: "0 8px 32px rgba(0, 0, 0, 0.3)".to_string(),
                    glow: "0 0 20px rgba(0, 255, 209, 0.1)".to_string(),
                    backdrop_filter: "blur(18px)".to_string(),
                },
                modals: ModalStyles {
                    backdrop: "rgba(0, 0, 0, 0.8)".to_string(),
                    background: "rgba(12, 15, 28, 0.95)".to_string(),
                    border: "rgba(0, 255, 209, 0.5)".to_string(),
                    shadow: "0 20px 60px rgba(0, 0, 0, 0.5)".to_string(),
                    blur_backdrop: 10.0,
                },
                navigation: NavigationStyles {
                    background: "rgba(12, 15, 28, 0.9)".to_string(),
                    border: "rgba(0, 255, 209, 0.2)".to_string(),
                    item_hover: "rgba(0, 255, 209, 0.1)".to_string(),
                    item_active: "rgba(0, 255, 209, 0.2)".to_string(),
                    indicator_color: "#00FFD1".to_string(),
                },
                terminal: TerminalStyles {
                    background: "rgba(0, 0, 0, 0.9)".to_string(),
                    text: "#00FF88".to_string(),
                    cursor: "#00FFD1".to_string(),
                    selection: "rgba(0, 255, 209, 0.3)".to_string(),
                    scan_line_color: "rgba(0, 255, 209, 0.1)".to_string(),
                    scan_line_opacity: 0.3,
                },
                notifications: NotificationStyles {
                    background: "rgba(12, 15, 28, 0.95)".to_string(),
                    border: "rgba(0, 255, 209, 0.5)".to_string(),
                    text: "#EAEAEA".to_string(),
                    glow: "0 0 20px rgba(0, 255, 209, 0.3)".to_string(),
                    progress_bar: "#00FFD1".to_string(),
                },
            },
            
            animations: AnimationSettings {
                enabled: true,
                duration_fast: "0.15s".to_string(),
                duration_normal: "0.3s".to_string(),
                duration_slow: "0.6s".to_string(),
                easing_standard: "cubic-bezier(0.4, 0, 0.2, 1)".to_string(),
                easing_enter: "cubic-bezier(0, 0, 0.2, 1)".to_string(),
                easing_exit: "cubic-bezier(0.4, 0, 1, 1)".to_string(),
                hover_animations: true,
                focus_animations: true,
                loading_animations: true,
                transition_animations: true,
            },
            
            accessibility: AccessibilitySettings {
                high_contrast: false,
                reduce_motion: false,
                focus_indicators: true,
                screen_reader_optimized: false,
                min_contrast_ratio: 4.5,
                font_size_multiplier: 1.0,
                focus_outline_width: 2.0,
            },
            
            custom_css: None,
            
            metadata: ThemeMetadata {
                category: ThemeCategory::Cyberpunk,
                mood: ThemeMood::Futuristic,
                complexity: ThemeComplexity::Moderate,
                performance_impact: PerformanceImpact::Medium,
                preview_image: None,
                color_preview: vec![
                    "#00FFD1".to_string(),
                    "#FF008C".to_string(),
                    "#FFAA00".to_string(),
                    "#0C0F1C".to_string(),
                ],
                compatibility_version: "1.0.0".to_string(),
                requires_features: vec!["css-backdrop-filter".to_string(), "css-glow".to_string()],
                download_count: 0,
                rating: None,
                is_featured: true,
                is_community: false,
            },
        }
    }
}
