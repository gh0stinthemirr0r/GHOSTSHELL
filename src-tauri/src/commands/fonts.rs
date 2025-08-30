use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{debug, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontInfo {
    pub name: String,
    pub family: String,
    pub file_path: String,
    pub preview: String,
    pub category: String,
    pub weight: String,
    pub style: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontFamily {
    pub name: String,
    pub display_name: String,
    pub variants: Vec<FontInfo>,
    pub category: String,
    pub preview: String,
}

/// Get all available fonts from the embedded fonts directory
#[tauri::command]
pub async fn get_embedded_fonts() -> Result<Vec<FontFamily>, String> {
    debug!("Loading embedded fonts from src-tauri/fonts");
    
    let fonts_dir = Path::new("fonts");
    
    if !fonts_dir.exists() {
        error!("Fonts directory not found: {:?}", fonts_dir);
        return Err("Fonts directory not found".to_string());
    }
    
    let mut font_families: HashMap<String, FontFamily> = HashMap::new();
    
    // Read all font files
    let entries = fs::read_dir(fonts_dir)
        .map_err(|e| format!("Failed to read fonts directory: {}", e))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        
        if let Some(extension) = path.extension() {
            if extension == "ttf" || extension == "otf" {
                if let Some(font_info) = parse_font_filename(&path) {
                    let family_key = font_info.family.clone();
                    
                    // Add to family or create new family
                    if let Some(family) = font_families.get_mut(&family_key) {
                        family.variants.push(font_info);
                    } else {
                        let display_name = create_display_name(&font_info.family);
                        let category = categorize_font(&font_info.family);
                        let preview = create_preview(&font_info.family);
                        
                        font_families.insert(family_key.clone(), FontFamily {
                            name: family_key.clone(),
                            display_name,
                            variants: vec![font_info],
                            category,
                            preview,
                        });
                    }
                }
            }
        }
    }
    
    // Convert to sorted vector
    let mut families: Vec<FontFamily> = font_families.into_values().collect();
    families.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    
    debug!("Loaded {} font families", families.len());
    Ok(families)
}

/// Parse font filename to extract font information
fn parse_font_filename(path: &Path) -> Option<FontInfo> {
    let filename = path.file_stem()?.to_str()?;
    let file_path = path.to_str()?.to_string();
    
    // Parse Nerd Font naming convention
    // Examples: JetBrainsMonoNerdFont-Bold.ttf, FiraCodeNerdFontMono-Regular.ttf
    
    let (family, weight, style) = if filename.contains("NerdFont") {
        parse_nerd_font_name(filename)
    } else {
        // Fallback for other fonts
        parse_generic_font_name(filename)
    };
    
    let preview = create_preview(&family);
    let category = categorize_font(&family);
    
    Some(FontInfo {
        name: format!("{} {}", family, if weight != "Regular" { &weight } else { "" }).trim().to_string(),
        family: family.clone(),
        file_path,
        preview,
        category,
        weight,
        style,
    })
}

/// Parse Nerd Font naming convention
fn parse_nerd_font_name(filename: &str) -> (String, String, String) {
    // Remove NerdFont suffixes and parse
    let base_name = filename
        .replace("NerdFontMono", "")
        .replace("NerdFontPropo", "")
        .replace("NerdFont", "");
    
    // Split by dash to get weight/style
    let parts: Vec<&str> = base_name.split('-').collect();
    
    let family = if let Some(first_part) = parts.first() {
        // Convert camelCase to spaced name
        convert_camel_case_to_spaced(first_part)
    } else {
        "Unknown".to_string()
    };
    
    let (weight, style) = if parts.len() > 1 {
        parse_weight_and_style(parts[1])
    } else {
        ("Regular".to_string(), "Normal".to_string())
    };
    
    (family, weight, style)
}

/// Parse generic font name
fn parse_generic_font_name(filename: &str) -> (String, String, String) {
    let parts: Vec<&str> = filename.split('-').collect();
    
    let family = if let Some(first_part) = parts.first() {
        convert_camel_case_to_spaced(first_part)
    } else {
        "Unknown".to_string()
    };
    
    let (weight, style) = if parts.len() > 1 {
        parse_weight_and_style(parts[1])
    } else {
        ("Regular".to_string(), "Normal".to_string())
    };
    
    (family, weight, style)
}

/// Convert camelCase to spaced name
fn convert_camel_case_to_spaced(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    
    while let Some(ch) = chars.next() {
        if ch.is_uppercase() && !result.is_empty() {
            // Add space before uppercase letter (except at start)
            if let Some(&next_ch) = chars.peek() {
                if next_ch.is_lowercase() {
                    result.push(' ');
                }
            }
        }
        result.push(ch);
    }
    
    result
}

/// Parse weight and style from font variant name
fn parse_weight_and_style(variant: &str) -> (String, String) {
    let variant_lower = variant.to_lowercase();
    
    let weight = if variant_lower.contains("thin") {
        "Thin"
    } else if variant_lower.contains("extralight") || variant_lower.contains("ultralight") {
        "Extra Light"
    } else if variant_lower.contains("light") {
        "Light"
    } else if variant_lower.contains("medium") {
        "Medium"
    } else if variant_lower.contains("semibold") {
        "Semi Bold"
    } else if variant_lower.contains("extrabold") || variant_lower.contains("ultrabold") {
        "Extra Bold"
    } else if variant_lower.contains("bold") {
        "Bold"
    } else if variant_lower.contains("black") {
        "Black"
    } else {
        "Regular"
    }.to_string();
    
    let style = if variant_lower.contains("italic") || variant_lower.contains("oblique") {
        "Italic"
    } else {
        "Normal"
    }.to_string();
    
    (weight, style)
}

/// Create display name for font family
fn create_display_name(family: &str) -> String {
    // Clean up the family name for display
    family.replace("NerdFont", "").trim().to_string()
}

/// Categorize font based on family name
fn categorize_font(family: &str) -> String {
    let family_lower = family.to_lowercase();
    
    if family_lower.contains("jetbrains") || family_lower.contains("fira") || family_lower.contains("hack") {
        "Popular"
    } else if family_lower.contains("dejavu") || family_lower.contains("envy") || family_lower.contains("hasklug") {
        "Professional"
    } else if family_lower.contains("meslo") {
        "Classic"
    } else if family_lower.contains("consolas") || family_lower.contains("monaco") {
        "System"
    } else {
        "Other"
    }.to_string()
}

/// Create preview text for font
fn create_preview(family: &str) -> String {
    let family_lower = family.to_lowercase();
    
    if family_lower.contains("jetbrains") {
        "  λ => console.log(\"Hello World!\"); // ⚡ 󰅲"
    } else if family_lower.contains("fira") {
        "  != === >= <= => |> <| // 󰈮 ⚡"
    } else if family_lower.contains("dejavu") {
        "  typedef struct node_t { int val; } // 󰙱"
    } else if family_lower.contains("envy") {
        "  const result = await fetch(url); // 󰘦"
    } else if family_lower.contains("hasklug") {
        "  main :: IO () // Haskell 󰲒 ⚡"
    } else if family_lower.contains("meslo") {
        "  export default class Component {} // 󰘦"
    } else {
        "  function code() { return \"awesome\"; } // 󰅲 ⚡"
    }.to_string()
}

/// Get font families grouped by category
#[tauri::command]
pub async fn get_fonts_by_category() -> Result<HashMap<String, Vec<FontFamily>>, String> {
    let fonts = get_embedded_fonts().await?;
    let mut categorized: HashMap<String, Vec<FontFamily>> = HashMap::new();
    
    for font in fonts {
        categorized
            .entry(font.category.clone())
            .or_insert_with(Vec::new)
            .push(font);
    }
    
    Ok(categorized)
}

/// Get available font weights for a specific family
#[tauri::command]
pub async fn get_font_weights(family_name: String) -> Result<Vec<String>, String> {
    let fonts = get_embedded_fonts().await?;
    
    if let Some(family) = fonts.iter().find(|f| f.name == family_name) {
        let weights: Vec<String> = family.variants.iter()
            .map(|v| v.weight.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        Ok(weights)
    } else {
        Err(format!("Font family '{}' not found", family_name))
    }
}
