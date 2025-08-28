use crate::{LayoutV2, NavGroup, NavModule};
use serde::{Deserialize, Serialize};

/// Built-in navigation presets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavPreset {
    pub id: String,
    pub name: String,
    pub description: String,
    pub layout: LayoutV2,
    pub signature: String,
}

impl NavPreset {
    /// Get all built-in presets
    pub fn get_all_presets() -> Vec<NavPreset> {
        vec![
            Self::analyst_preset(),
            Self::ops_preset(),
            Self::auditor_preset(),
            Self::minimal_preset(),
            Self::exec_preset(),
        ]
    }

    /// Get preset by ID
    pub fn get_by_id(id: &str) -> Option<NavPreset> {
        Self::get_all_presets().into_iter().find(|p| p.id == id)
    }

    /// Analyst preset - Full toolkit for security analysis
    pub fn analyst_preset() -> NavPreset {
        NavPreset {
            id: "analyst".to_string(),
            name: "Analyst".to_string(),
            description: "Full toolkit for security analysis and investigation".to_string(),
            layout: LayoutV2 {
                version: 2,
                workspace: "analyst".to_string(),
                groups: vec![
                    NavGroup {
                        id: "grp-pinned".to_string(),
                        name: "Pinned".to_string(),
                        collapsed: false,
                        order: 0,
                    },
                    NavGroup {
                        id: "grp-core".to_string(),
                        name: "Core".to_string(),
                        collapsed: false,
                        order: 1,
                    },
                    NavGroup {
                        id: "grp-analysis".to_string(),
                        name: "Analysis".to_string(),
                        collapsed: false,
                        order: 2,
                    },
                    NavGroup {
                        id: "grp-reporting".to_string(),
                        name: "Reporting".to_string(),
                        collapsed: true,
                        order: 3,
                    },
                ],
                modules: vec![
                    NavModule {
                        id: "terminal".to_string(),
                        visible: true,
                        pinned: true,
                        group_id: "grp-pinned".to_string(),
                        order: 0,
                        icon_variant: Some("neon".to_string()),
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "ghostssh".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-core".to_string(),
                        order: 0,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "ghostvault".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-core".to_string(),
                        order: 1,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "layers".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-analysis".to_string(),
                        order: 0,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "surveyor".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-analysis".to_string(),
                        order: 1,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "pcap".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-analysis".to_string(),
                        order: 2,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "topology".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-analysis".to_string(),
                        order: 3,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "reporting".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-reporting".to_string(),
                        order: 0,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                ],
                theme_hints: crate::ThemeHints {
                    icon_set: "neon".to_string(),
                    exec_toning: false,
                },
                signature: None,
            },
            signature: "dilithium-analyst-preset-v2".to_string(),
        }
    }

    /// Ops preset - Operational tools for system administration
    pub fn ops_preset() -> NavPreset {
        NavPreset {
            id: "ops".to_string(),
            name: "Operations".to_string(),
            description: "Essential tools for system operations and monitoring".to_string(),
            layout: LayoutV2 {
                version: 2,
                workspace: "ops".to_string(),
                groups: vec![
                    NavGroup {
                        id: "grp-pinned".to_string(),
                        name: "Pinned".to_string(),
                        collapsed: false,
                        order: 0,
                    },
                    NavGroup {
                        id: "grp-ops".to_string(),
                        name: "Operations".to_string(),
                        collapsed: false,
                        order: 1,
                    },
                    NavGroup {
                        id: "grp-monitoring".to_string(),
                        name: "Monitoring".to_string(),
                        collapsed: false,
                        order: 2,
                    },
                ],
                modules: vec![
                    NavModule {
                        id: "terminal".to_string(),
                        visible: true,
                        pinned: true,
                        group_id: "grp-pinned".to_string(),
                        order: 0,
                        icon_variant: Some("neon".to_string()),
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "ghostssh".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-ops".to_string(),
                        order: 0,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "ghostvpn".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-ops".to_string(),
                        order: 1,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "ghostvault".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-ops".to_string(),
                        order: 2,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "pcap".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-monitoring".to_string(),
                        order: 0,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "topology".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-monitoring".to_string(),
                        order: 1,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                ],
                theme_hints: crate::ThemeHints {
                    icon_set: "neon".to_string(),
                    exec_toning: false,
                },
                signature: None,
            },
            signature: "dilithium-ops-preset-v2".to_string(),
        }
    }

    /// Auditor preset - Compliance and audit tools only
    pub fn auditor_preset() -> NavPreset {
        NavPreset {
            id: "auditor".to_string(),
            name: "Auditor".to_string(),
            description: "Compliance and audit tools with restricted access".to_string(),
            layout: LayoutV2 {
                version: 2,
                workspace: "auditor".to_string(),
                groups: vec![
                    NavGroup {
                        id: "grp-compliance".to_string(),
                        name: "Compliance".to_string(),
                        collapsed: false,
                        order: 0,
                    },
                    NavGroup {
                        id: "grp-core".to_string(),
                        name: "Core".to_string(),
                        collapsed: false,
                        order: 1,
                    },
                ],
                modules: vec![
                    NavModule {
                        id: "compliance".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-compliance".to_string(),
                        order: 0,
                        icon_variant: None,
                        contextual: None,
                        locked: true,
                        lock_reason: Some("policy:auditor_required".to_string()),
                    },
                    NavModule {
                        id: "reporting".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-compliance".to_string(),
                        order: 1,
                        icon_variant: None,
                        contextual: None,
                        locked: true,
                        lock_reason: Some("policy:auditor_required".to_string()),
                    },
                    NavModule {
                        id: "ghostvault".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-core".to_string(),
                        order: 0,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                ],
                theme_hints: crate::ThemeHints {
                    icon_set: "exec".to_string(),
                    exec_toning: true,
                },
                signature: None,
            },
            signature: "dilithium-auditor-preset-v2".to_string(),
        }
    }

    /// Minimal preset - Essential tools only
    pub fn minimal_preset() -> NavPreset {
        NavPreset {
            id: "minimal".to_string(),
            name: "Minimal".to_string(),
            description: "Essential tools only for lightweight usage".to_string(),
            layout: LayoutV2 {
                version: 2,
                workspace: "minimal".to_string(),
                groups: vec![
                    NavGroup {
                        id: "grp-core".to_string(),
                        name: "Core".to_string(),
                        collapsed: false,
                        order: 0,
                    },
                ],
                modules: vec![
                    NavModule {
                        id: "terminal".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-core".to_string(),
                        order: 0,
                        icon_variant: Some("neon".to_string()),
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                    NavModule {
                        id: "ghostvault".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-core".to_string(),
                        order: 1,
                        icon_variant: None,
                        contextual: None,
                        locked: false,
                        lock_reason: None,
                    },
                ],
                theme_hints: crate::ThemeHints {
                    icon_set: "neon".to_string(),
                    exec_toning: false,
                },
                signature: None,
            },
            signature: "dilithium-minimal-preset-v2".to_string(),
        }
    }

    /// Executive preset - High-level overview tools
    pub fn exec_preset() -> NavPreset {
        NavPreset {
            id: "exec".to_string(),
            name: "Executive".to_string(),
            description: "High-level overview and reporting tools".to_string(),
            layout: LayoutV2 {
                version: 2,
                workspace: "executive".to_string(),
                groups: vec![
                    NavGroup {
                        id: "grp-overview".to_string(),
                        name: "Overview".to_string(),
                        collapsed: false,
                        order: 0,
                    },
                ],
                modules: vec![
                    NavModule {
                        id: "compliance".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-overview".to_string(),
                        order: 0,
                        icon_variant: Some("exec".to_string()),
                        contextual: None,
                        locked: true,
                        lock_reason: Some("policy:exec_required".to_string()),
                    },
                    NavModule {
                        id: "reporting".to_string(),
                        visible: true,
                        pinned: false,
                        group_id: "grp-overview".to_string(),
                        order: 1,
                        icon_variant: Some("exec".to_string()),
                        contextual: None,
                        locked: true,
                        lock_reason: Some("policy:exec_required".to_string()),
                    },
                ],
                theme_hints: crate::ThemeHints {
                    icon_set: "exec".to_string(),
                    exec_toning: true,
                },
                signature: None,
            },
            signature: "dilithium-exec-preset-v2".to_string(),
        }
    }
}
