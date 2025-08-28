use anyhow::Result;
use ghost_nav::{LayoutV2, WorkspaceMeta, NavPreset};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User preferences for navigation and UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    pub current_workspace: String,
    pub theme_preferences: ThemePreferences,
    pub ui_preferences: UiPreferences,
    pub accessibility_preferences: AccessibilityPreferences,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            current_workspace: "default".to_string(),
            theme_preferences: ThemePreferences::default(),
            ui_preferences: UiPreferences::default(),
            accessibility_preferences: AccessibilityPreferences::default(),
            last_updated: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemePreferences {
    pub current_theme: String,
    pub icon_set: String,
    pub exec_toning: bool,
    pub custom_colors: HashMap<String, String>,
}

impl Default for ThemePreferences {
    fn default() -> Self {
        Self {
            current_theme: "cyberpunk_neon".to_string(),
            icon_set: "neon".to_string(),
            exec_toning: false,
            custom_colors: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiPreferences {
    pub sidebar_collapsed: bool,
    pub show_tooltips: bool,
    pub animation_speed: AnimationSpeed,
    pub notification_preferences: NotificationPreferences,
}

impl Default for UiPreferences {
    fn default() -> Self {
        Self {
            sidebar_collapsed: false,
            show_tooltips: true,
            animation_speed: AnimationSpeed::Normal,
            notification_preferences: NotificationPreferences::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnimationSpeed {
    Disabled,
    Slow,
    Normal,
    Fast,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPreferences {
    pub show_toast_notifications: bool,
    pub toast_duration: u32, // milliseconds
    pub sound_enabled: bool,
    pub categories: HashMap<String, bool>, // category -> enabled
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        let mut categories = HashMap::new();
        categories.insert("system".to_string(), true);
        categories.insert("security".to_string(), true);
        categories.insert("updates".to_string(), true);
        categories.insert("warnings".to_string(), true);

        Self {
            show_toast_notifications: true,
            toast_duration: 5000,
            sound_enabled: false,
            categories,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibilityPreferences {
    pub high_contrast: bool,
    pub reduce_motion: bool,
    pub large_text: bool,
    pub keyboard_navigation: bool,
    pub screen_reader_support: bool,
}

impl Default for AccessibilityPreferences {
    fn default() -> Self {
        Self {
            high_contrast: false,
            reduce_motion: false,
            large_text: false,
            keyboard_navigation: true,
            screen_reader_support: false,
        }
    }
}

/// Workspace session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSession {
    pub workspace_id: String,
    pub active_module: String,
    pub module_states: HashMap<String, ModuleState>,
    pub window_layout: WindowLayout,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleState {
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    pub state_data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowLayout {
    pub width: u32,
    pub height: u32,
    pub x: i32,
    pub y: i32,
    pub maximized: bool,
}

impl Default for WindowLayout {
    fn default() -> Self {
        Self {
            width: 1200,
            height: 800,
            x: 100,
            y: 100,
            maximized: false,
        }
    }
}

/// Preference manager for handling user settings
pub struct PreferenceManager {
    preferences: UserPreferences,
    session: Option<WorkspaceSession>,
}

impl PreferenceManager {
    pub fn new() -> Self {
        Self {
            preferences: UserPreferences::default(),
            session: None,
        }
    }

    pub fn with_preferences(preferences: UserPreferences) -> Self {
        Self {
            preferences,
            session: None,
        }
    }

    /// Get current user preferences
    pub fn get_preferences(&self) -> &UserPreferences {
        &self.preferences
    }

    /// Update user preferences
    pub fn update_preferences<F>(&mut self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut UserPreferences),
    {
        updater(&mut self.preferences);
        self.preferences.last_updated = chrono::Utc::now();
        Ok(())
    }

    /// Start a new workspace session
    pub fn start_session(&mut self, workspace_id: String, active_module: String) {
        let now = chrono::Utc::now();
        self.session = Some(WorkspaceSession {
            workspace_id,
            active_module,
            module_states: HashMap::new(),
            window_layout: WindowLayout::default(),
            started_at: now,
            last_activity: now,
        });
    }

    /// Update session activity
    pub fn update_session_activity(&mut self, module_id: Option<String>) {
        if let Some(ref mut session) = self.session {
            session.last_activity = chrono::Utc::now();
            
            if let Some(module_id) = module_id {
                session.active_module = module_id.clone();
                session.module_states.insert(
                    module_id,
                    ModuleState {
                        last_accessed: chrono::Utc::now(),
                        state_data: serde_json::Value::Null,
                    },
                );
            }
        }
    }

    /// Get current session
    pub fn get_session(&self) -> Option<&WorkspaceSession> {
        self.session.as_ref()
    }

    /// End current session
    pub fn end_session(&mut self) -> Option<WorkspaceSession> {
        self.session.take()
    }

    /// Get workspace suggestions based on usage patterns
    pub fn get_workspace_suggestions(&self) -> Vec<String> {
        let mut suggestions = Vec::new();

        // Add current workspace first
        suggestions.push(self.preferences.current_workspace.clone());

        // Add recently used workspaces (would come from session history)
        // For now, add some defaults
        if self.preferences.current_workspace != "default" {
            suggestions.push("default".to_string());
        }

        // Add preset-based suggestions
        let presets = NavPreset::get_all_presets();
        for preset in presets {
            if !suggestions.contains(&preset.id) {
                suggestions.push(preset.id);
            }
        }

        suggestions
    }

    /// Apply theme preferences to layout
    pub fn apply_theme_to_layout(&self, mut layout: LayoutV2) -> LayoutV2 {
        layout.theme_hints.icon_set = self.preferences.theme_preferences.icon_set.clone();
        layout.theme_hints.exec_toning = self.preferences.theme_preferences.exec_toning;
        layout
    }

    /// Check if a feature is enabled based on preferences
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        match feature {
            "tooltips" => self.preferences.ui_preferences.show_tooltips,
            "animations" => !matches!(
                self.preferences.ui_preferences.animation_speed,
                AnimationSpeed::Disabled
            ),
            "toast_notifications" => {
                self.preferences.ui_preferences.notification_preferences.show_toast_notifications
            }
            "high_contrast" => self.preferences.accessibility_preferences.high_contrast,
            "reduce_motion" => self.preferences.accessibility_preferences.reduce_motion,
            _ => true, // Default to enabled for unknown features
        }
    }

    /// Get animation duration based on preferences
    pub fn get_animation_duration(&self, base_duration_ms: u32) -> u32 {
        match self.preferences.ui_preferences.animation_speed {
            AnimationSpeed::Disabled => 0,
            AnimationSpeed::Slow => base_duration_ms * 2,
            AnimationSpeed::Normal => base_duration_ms,
            AnimationSpeed::Fast => base_duration_ms / 2,
        }
    }
}
