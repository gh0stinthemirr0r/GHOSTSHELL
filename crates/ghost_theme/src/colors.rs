use crate::{ColorPalette, ThemeResult, ThemeError};
use serde::{Deserialize, Serialize};

/// Color scheme types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ColorScheme {
    Monochromatic,
    Analogous,
    Complementary,
    Triadic,
    Tetradic,
    Custom,
}

/// Color utilities for theme generation and manipulation
pub struct ColorUtils;

impl ColorUtils {
    /// Parse a color string to RGB values
    pub fn parse_color(color: &str) -> ThemeResult<(u8, u8, u8)> {
        if color.starts_with('#') {
            Self::parse_hex(color)
        } else if color.starts_with("rgb") {
            Self::parse_rgb(color)
        } else if color.starts_with("hsl") {
            Self::parse_hsl(color)
        } else {
            Self::parse_named_color(color)
        }
    }

    /// Convert RGB to hex
    pub fn rgb_to_hex(r: u8, g: u8, b: u8) -> String {
        format!("#{:02x}{:02x}{:02x}", r, g, b)
    }

    /// Convert hex to RGB
    pub fn hex_to_rgb(hex: &str) -> ThemeResult<(u8, u8, u8)> {
        Self::parse_hex(hex)
    }

    /// Convert RGB to HSL
    pub fn rgb_to_hsl(r: u8, g: u8, b: u8) -> (f32, f32, f32) {
        let r = r as f32 / 255.0;
        let g = g as f32 / 255.0;
        let b = b as f32 / 255.0;

        let max = r.max(g.max(b));
        let min = r.min(g.min(b));
        let delta = max - min;

        let lightness = (max + min) / 2.0;

        if delta == 0.0 {
            return (0.0, 0.0, lightness);
        }

        let saturation = if lightness < 0.5 {
            delta / (max + min)
        } else {
            delta / (2.0 - max - min)
        };

        let hue = if max == r {
            60.0 * (((g - b) / delta) % 6.0)
        } else if max == g {
            60.0 * ((b - r) / delta + 2.0)
        } else {
            60.0 * ((r - g) / delta + 4.0)
        };

        let hue = if hue < 0.0 { hue + 360.0 } else { hue };

        (hue, saturation, lightness)
    }

    /// Convert HSL to RGB
    pub fn hsl_to_rgb(h: f32, s: f32, l: f32) -> (u8, u8, u8) {
        let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
        let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
        let m = l - c / 2.0;

        let (r_prime, g_prime, b_prime) = if h < 60.0 {
            (c, x, 0.0)
        } else if h < 120.0 {
            (x, c, 0.0)
        } else if h < 180.0 {
            (0.0, c, x)
        } else if h < 240.0 {
            (0.0, x, c)
        } else if h < 300.0 {
            (x, 0.0, c)
        } else {
            (c, 0.0, x)
        };

        let r = ((r_prime + m) * 255.0) as u8;
        let g = ((g_prime + m) * 255.0) as u8;
        let b = ((b_prime + m) * 255.0) as u8;

        (r, g, b)
    }

    /// Generate a color palette from a base color
    pub fn generate_palette(base_color: &str, scheme: ColorScheme) -> ThemeResult<ColorPalette> {
        let (r, g, b) = Self::parse_color(base_color)?;
        let (h, s, l) = Self::rgb_to_hsl(r, g, b);

        match scheme {
            ColorScheme::Monochromatic => Self::generate_monochromatic(h, s, l),
            ColorScheme::Analogous => Self::generate_analogous(h, s, l),
            ColorScheme::Complementary => Self::generate_complementary(h, s, l),
            ColorScheme::Triadic => Self::generate_triadic(h, s, l),
            ColorScheme::Tetradic => Self::generate_tetradic(h, s, l),
            ColorScheme::Custom => Self::generate_cyberpunk_palette(h, s, l),
        }
    }

    /// Lighten a color by a percentage
    pub fn lighten(color: &str, amount: f32) -> ThemeResult<String> {
        let (r, g, b) = Self::parse_color(color)?;
        let (h, s, l) = Self::rgb_to_hsl(r, g, b);
        let new_l = (l + amount).min(1.0);
        let (new_r, new_g, new_b) = Self::hsl_to_rgb(h, s, new_l);
        Ok(Self::rgb_to_hex(new_r, new_g, new_b))
    }

    /// Darken a color by a percentage
    pub fn darken(color: &str, amount: f32) -> ThemeResult<String> {
        let (r, g, b) = Self::parse_color(color)?;
        let (h, s, l) = Self::rgb_to_hsl(r, g, b);
        let new_l = (l - amount).max(0.0);
        let (new_r, new_g, new_b) = Self::hsl_to_rgb(h, s, new_l);
        Ok(Self::rgb_to_hex(new_r, new_g, new_b))
    }

    /// Add transparency to a color
    pub fn with_alpha(color: &str, alpha: f32) -> ThemeResult<String> {
        let (r, g, b) = Self::parse_color(color)?;
        Ok(format!("rgba({}, {}, {}, {:.2})", r, g, b, alpha))
    }

    /// Calculate contrast ratio between two colors
    pub fn contrast_ratio(color1: &str, color2: &str) -> ThemeResult<f32> {
        let (r1, g1, b1) = Self::parse_color(color1)?;
        let (r2, g2, b2) = Self::parse_color(color2)?;

        let l1 = Self::relative_luminance(r1, g1, b1);
        let l2 = Self::relative_luminance(r2, g2, b2);

        let lighter = l1.max(l2);
        let darker = l1.min(l2);

        Ok((lighter + 0.05) / (darker + 0.05))
    }

    /// Check if color combination meets WCAG accessibility standards
    pub fn meets_wcag_aa(foreground: &str, background: &str) -> ThemeResult<bool> {
        let ratio = Self::contrast_ratio(foreground, background)?;
        Ok(ratio >= 4.5)
    }

    /// Check if color combination meets WCAG AAA standards
    pub fn meets_wcag_aaa(foreground: &str, background: &str) -> ThemeResult<bool> {
        let ratio = Self::contrast_ratio(foreground, background)?;
        Ok(ratio >= 7.0)
    }

    // Private helper methods

    fn parse_hex(hex: &str) -> ThemeResult<(u8, u8, u8)> {
        let hex = hex.trim_start_matches('#');
        if hex.len() != 6 {
            return Err(ThemeError::ColorError("Invalid hex color format".to_string()));
        }

        let r = u8::from_str_radix(&hex[0..2], 16)
            .map_err(|_| ThemeError::ColorError("Invalid hex color".to_string()))?;
        let g = u8::from_str_radix(&hex[2..4], 16)
            .map_err(|_| ThemeError::ColorError("Invalid hex color".to_string()))?;
        let b = u8::from_str_radix(&hex[4..6], 16)
            .map_err(|_| ThemeError::ColorError("Invalid hex color".to_string()))?;

        Ok((r, g, b))
    }

    fn parse_rgb(_rgb: &str) -> ThemeResult<(u8, u8, u8)> {
        // Simple RGB parsing - in a real implementation, use a proper CSS parser
        Err(ThemeError::ColorError("RGB parsing not implemented".to_string()))
    }

    fn parse_hsl(_hsl: &str) -> ThemeResult<(u8, u8, u8)> {
        // Simple HSL parsing - in a real implementation, use a proper CSS parser
        Err(ThemeError::ColorError("HSL parsing not implemented".to_string()))
    }

    fn parse_named_color(name: &str) -> ThemeResult<(u8, u8, u8)> {
        match name.to_lowercase().as_str() {
            "white" => Ok((255, 255, 255)),
            "black" => Ok((0, 0, 0)),
            "red" => Ok((255, 0, 0)),
            "green" => Ok((0, 255, 0)),
            "blue" => Ok((0, 0, 255)),
            "cyan" => Ok((0, 255, 255)),
            "magenta" => Ok((255, 0, 255)),
            "yellow" => Ok((255, 255, 0)),
            _ => Err(ThemeError::ColorError(format!("Unknown color name: {}", name))),
        }
    }

    fn relative_luminance(r: u8, g: u8, b: u8) -> f32 {
        let r = r as f32 / 255.0;
        let g = g as f32 / 255.0;
        let b = b as f32 / 255.0;

        let r = if r <= 0.03928 { r / 12.92 } else { ((r + 0.055) / 1.055).powf(2.4) };
        let g = if g <= 0.03928 { g / 12.92 } else { ((g + 0.055) / 1.055).powf(2.4) };
        let b = if b <= 0.03928 { b / 12.92 } else { ((b + 0.055) / 1.055).powf(2.4) };

        0.2126 * r + 0.7152 * g + 0.0722 * b
    }

    fn generate_monochromatic(h: f32, s: f32, l: f32) -> ThemeResult<ColorPalette> {
        let primary_rgb = Self::hsl_to_rgb(h, s, l);
        let secondary_rgb = Self::hsl_to_rgb(h, s * 0.8, l * 0.8);
        let tertiary_rgb = Self::hsl_to_rgb(h, s * 0.6, l * 0.6);
        
        let primary = Self::rgb_to_hex(primary_rgb.0, primary_rgb.1, primary_rgb.2);
        let secondary = Self::rgb_to_hex(secondary_rgb.0, secondary_rgb.1, secondary_rgb.2);
        let tertiary = Self::rgb_to_hex(tertiary_rgb.0, tertiary_rgb.1, tertiary_rgb.2);

        Ok(ColorPalette {
            primary: primary.clone(),
            secondary: secondary.clone(),
            tertiary,
            background_primary: "rgba(12, 15, 28, 0.95)".to_string(),
            background_secondary: "rgba(20, 25, 40, 0.9)".to_string(),
            background_tertiary: "rgba(30, 35, 50, 0.85)".to_string(),
            text_primary: "#EAEAEA".to_string(),
            text_secondary: "#B0B0B0".to_string(),
            text_muted: "#707070".to_string(),
            text_inverse: "#1A1A1A".to_string(),
            border_primary: Self::with_alpha(&primary, 0.3)?,
            border_secondary: "rgba(255, 255, 255, 0.1)".to_string(),
            border_focus: primary.clone(),
            success: "#00FF88".to_string(),
            warning: "#FFAA00".to_string(),
            error: "#FF008C".to_string(),
            info: primary.clone(),
            hover: Self::with_alpha(&primary, 0.1)?,
            active: Self::with_alpha(&primary, 0.2)?,
            disabled: "rgba(255, 255, 255, 0.3)".to_string(),
            glow_primary: Self::with_alpha(&primary, 0.5)?,
            glow_secondary: Self::with_alpha(&secondary, 0.5)?,
            shadow: "rgba(0, 0, 0, 0.5)".to_string(),
        })
    }

    fn generate_analogous(h: f32, s: f32, l: f32) -> ThemeResult<ColorPalette> {
        let primary = Self::rgb_to_hex(Self::hsl_to_rgb(h, s, l).0, Self::hsl_to_rgb(h, s, l).1, Self::hsl_to_rgb(h, s, l).2);
        let secondary = Self::rgb_to_hex(Self::hsl_to_rgb((h + 30.0) % 360.0, s, l).0, Self::hsl_to_rgb((h + 30.0) % 360.0, s, l).1, Self::hsl_to_rgb((h + 30.0) % 360.0, s, l).2);
        let tertiary = Self::rgb_to_hex(Self::hsl_to_rgb((h - 30.0 + 360.0) % 360.0, s, l).0, Self::hsl_to_rgb((h - 30.0 + 360.0) % 360.0, s, l).1, Self::hsl_to_rgb((h - 30.0 + 360.0) % 360.0, s, l).2);

        Self::build_palette_from_colors(primary, secondary, tertiary)
    }

    fn generate_complementary(h: f32, s: f32, l: f32) -> ThemeResult<ColorPalette> {
        let primary = Self::rgb_to_hex(Self::hsl_to_rgb(h, s, l).0, Self::hsl_to_rgb(h, s, l).1, Self::hsl_to_rgb(h, s, l).2);
        let secondary = Self::rgb_to_hex(Self::hsl_to_rgb((h + 180.0) % 360.0, s, l).0, Self::hsl_to_rgb((h + 180.0) % 360.0, s, l).1, Self::hsl_to_rgb((h + 180.0) % 360.0, s, l).2);
        let tertiary = Self::rgb_to_hex(Self::hsl_to_rgb(h, s * 0.7, l * 1.2).0, Self::hsl_to_rgb(h, s * 0.7, l * 1.2).1, Self::hsl_to_rgb(h, s * 0.7, l * 1.2).2);

        Self::build_palette_from_colors(primary, secondary, tertiary)
    }

    fn generate_triadic(h: f32, s: f32, l: f32) -> ThemeResult<ColorPalette> {
        let primary = Self::rgb_to_hex(Self::hsl_to_rgb(h, s, l).0, Self::hsl_to_rgb(h, s, l).1, Self::hsl_to_rgb(h, s, l).2);
        let secondary = Self::rgb_to_hex(Self::hsl_to_rgb((h + 120.0) % 360.0, s, l).0, Self::hsl_to_rgb((h + 120.0) % 360.0, s, l).1, Self::hsl_to_rgb((h + 120.0) % 360.0, s, l).2);
        let tertiary = Self::rgb_to_hex(Self::hsl_to_rgb((h + 240.0) % 360.0, s, l).0, Self::hsl_to_rgb((h + 240.0) % 360.0, s, l).1, Self::hsl_to_rgb((h + 240.0) % 360.0, s, l).2);

        Self::build_palette_from_colors(primary, secondary, tertiary)
    }

    fn generate_tetradic(h: f32, s: f32, l: f32) -> ThemeResult<ColorPalette> {
        let primary = Self::rgb_to_hex(Self::hsl_to_rgb(h, s, l).0, Self::hsl_to_rgb(h, s, l).1, Self::hsl_to_rgb(h, s, l).2);
        let secondary = Self::rgb_to_hex(Self::hsl_to_rgb((h + 90.0) % 360.0, s, l).0, Self::hsl_to_rgb((h + 90.0) % 360.0, s, l).1, Self::hsl_to_rgb((h + 90.0) % 360.0, s, l).2);
        let tertiary = Self::rgb_to_hex(Self::hsl_to_rgb((h + 180.0) % 360.0, s, l).0, Self::hsl_to_rgb((h + 180.0) % 360.0, s, l).1, Self::hsl_to_rgb((h + 180.0) % 360.0, s, l).2);

        Self::build_palette_from_colors(primary, secondary, tertiary)
    }

    fn generate_cyberpunk_palette(h: f32, s: f32, l: f32) -> ThemeResult<ColorPalette> {
        // Generate cyberpunk-style colors with neon accents
        let primary = Self::rgb_to_hex(Self::hsl_to_rgb(h, s.max(0.8), l.max(0.6)).0, Self::hsl_to_rgb(h, s.max(0.8), l.max(0.6)).1, Self::hsl_to_rgb(h, s.max(0.8), l.max(0.6)).2);
        let secondary = Self::rgb_to_hex(Self::hsl_to_rgb((h + 180.0) % 360.0, s.max(0.9), l.max(0.7)).0, Self::hsl_to_rgb((h + 180.0) % 360.0, s.max(0.9), l.max(0.7)).1, Self::hsl_to_rgb((h + 180.0) % 360.0, s.max(0.9), l.max(0.7)).2);
        let tertiary = Self::rgb_to_hex(Self::hsl_to_rgb((h + 60.0) % 360.0, s.max(0.8), l.max(0.6)).0, Self::hsl_to_rgb((h + 60.0) % 360.0, s.max(0.8), l.max(0.6)).1, Self::hsl_to_rgb((h + 60.0) % 360.0, s.max(0.8), l.max(0.6)).2);

        Self::build_palette_from_colors(primary, secondary, tertiary)
    }

    fn build_palette_from_colors(primary: String, secondary: String, tertiary: String) -> ThemeResult<ColorPalette> {
        Ok(ColorPalette {
            primary: primary.clone(),
            secondary: secondary.clone(),
            tertiary: tertiary.clone(),
            background_primary: "rgba(12, 15, 28, 0.95)".to_string(),
            background_secondary: "rgba(20, 25, 40, 0.9)".to_string(),
            background_tertiary: "rgba(30, 35, 50, 0.85)".to_string(),
            text_primary: "#EAEAEA".to_string(),
            text_secondary: "#B0B0B0".to_string(),
            text_muted: "#707070".to_string(),
            text_inverse: "#1A1A1A".to_string(),
            border_primary: Self::with_alpha(&primary, 0.3)?,
            border_secondary: "rgba(255, 255, 255, 0.1)".to_string(),
            border_focus: primary.clone(),
            success: "#00FF88".to_string(),
            warning: "#FFAA00".to_string(),
            error: "#FF008C".to_string(),
            info: primary.clone(),
            hover: Self::with_alpha(&primary, 0.1)?,
            active: Self::with_alpha(&primary, 0.2)?,
            disabled: "rgba(255, 255, 255, 0.3)".to_string(),
            glow_primary: Self::with_alpha(&primary, 0.5)?,
            glow_secondary: Self::with_alpha(&secondary, 0.5)?,
            shadow: "rgba(0, 0, 0, 0.5)".to_string(),
        })
    }
}
