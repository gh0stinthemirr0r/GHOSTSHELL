use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Layout Schema V2 - Main navigation layout structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutV2 {
    pub version: u32,
    pub workspace: String,
    pub groups: Vec<NavGroup>,
    pub modules: Vec<NavModule>,
    pub theme_hints: ThemeHints,
    pub signature: Option<String>,
}

impl LayoutV2 {
    pub fn default_for_workspace(workspace: &str) -> Self {
        Self {
            version: 2,
            workspace: workspace.to_string(),
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
                    id: "grp-tools".to_string(),
                    name: "Tools".to_string(),
                    collapsed: false,
                    order: 2,
                },
                NavGroup {
                    id: "grp-compliance".to_string(),
                    name: "Compliance".to_string(),
                    collapsed: true,
                    order: 3,
                },
            ],
            modules: Self::default_modules(),
            theme_hints: ThemeHints::default(),
            signature: None,
        }
    }

    fn default_modules() -> Vec<NavModule> {
        vec![
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
                id: "ghostvpn".to_string(),
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
                id: "ghostbrowse".to_string(),
                visible: true,
                pinned: false,
                group_id: "grp-core".to_string(),
                order: 2,
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
                order: 3,
                icon_variant: None,
                contextual: None,
                locked: false,
                lock_reason: None,
            },
            NavModule {
                id: "layers".to_string(),
                visible: true,
                pinned: false,
                group_id: "grp-tools".to_string(),
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
                group_id: "grp-tools".to_string(),
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
                group_id: "grp-tools".to_string(),
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
                group_id: "grp-tools".to_string(),
                order: 3,
                icon_variant: None,
                contextual: None,
                locked: false,
                lock_reason: None,
            },
            NavModule {
                id: "compliance".to_string(),
                visible: false,
                pinned: false,
                group_id: "grp-compliance".to_string(),
                order: 0,
                icon_variant: None,
                contextual: None,
                locked: false,
                lock_reason: None,
            },
            NavModule {
                id: "reporting".to_string(),
                visible: false,
                pinned: false,
                group_id: "grp-compliance".to_string(),
                order: 1,
                icon_variant: None,
                contextual: None,
                locked: false,
                lock_reason: None,
            },
        ]
    }

    /// Get modules grouped by their group_id, sorted by order
    pub fn get_grouped_modules(&self) -> HashMap<String, Vec<&NavModule>> {
        let mut grouped = HashMap::new();
        
        for module in &self.modules {
            if module.visible {
                grouped
                    .entry(module.group_id.clone())
                    .or_insert_with(Vec::new)
                    .push(module);
            }
        }

        // Sort modules within each group by order
        for modules in grouped.values_mut() {
            modules.sort_by_key(|m| m.order);
        }

        grouped
    }

    /// Get groups sorted by order
    pub fn get_sorted_groups(&self) -> Vec<&NavGroup> {
        let mut groups = self.groups.iter().collect::<Vec<_>>();
        groups.sort_by_key(|g| g.order);
        groups
    }
}

/// Navigation group (e.g., "Core", "Tools", "Compliance")
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NavGroup {
    pub id: String,
    pub name: String,
    pub collapsed: bool,
    pub order: u32,
}

/// Navigation module (e.g., "terminal", "ghostssh")
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NavModule {
    pub id: String,
    pub visible: bool,
    pub pinned: bool,
    pub group_id: String,
    pub order: u32,
    pub icon_variant: Option<String>,
    pub contextual: Option<ContextualRules>,
    pub locked: bool,
    pub lock_reason: Option<String>,
}

/// Contextual visibility rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextualRules {
    pub auto_show_on: Vec<String>,
}

/// Theme-specific hints for rendering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeHints {
    pub icon_set: String,
    pub exec_toning: bool,
}

impl Default for ThemeHints {
    fn default() -> Self {
        Self {
            icon_set: "neon".to_string(),
            exec_toning: false,
        }
    }
}

/// Module metadata for UI rendering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMeta {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub category: String,
    pub requires_policy: Option<String>,
}

impl ModuleMeta {
    pub fn get_all_modules() -> Vec<ModuleMeta> {
        vec![
            ModuleMeta {
                id: "terminal".to_string(),
                name: "Terminal".to_string(),
                description: "Post-quantum secure terminal environment".to_string(),
                icon: "terminal".to_string(),
                category: "core".to_string(),
                requires_policy: None,
            },
            ModuleMeta {
                id: "ghostssh".to_string(),
                name: "SSH Manager".to_string(),
                description: "Secure shell connection management".to_string(),
                icon: "server".to_string(),
                category: "core".to_string(),
                requires_policy: None,
            },
            ModuleMeta {
                id: "ghostvpn".to_string(),
                name: "GhostVPN".to_string(),
                description: "Post-quantum VPN client".to_string(),
                icon: "shield".to_string(),
                category: "core".to_string(),
                requires_policy: None,
            },
            ModuleMeta {
                id: "ghostbrowse".to_string(),
                name: "GhostBrowse".to_string(),
                description: "Secure web browser".to_string(),
                icon: "globe".to_string(),
                category: "core".to_string(),
                requires_policy: Some("browser_access".to_string()),
            },
            ModuleMeta {
                id: "ghostvault".to_string(),
                name: "Vault".to_string(),
                description: "Encrypted credential storage".to_string(),
                icon: "lock".to_string(),
                category: "core".to_string(),
                requires_policy: None,
            },
            ModuleMeta {
                id: "layers".to_string(),
                name: "Layers".to_string(),
                description: "Network layer analysis tool".to_string(),
                icon: "layers".to_string(),
                category: "tools".to_string(),
                requires_policy: None,
            },
            ModuleMeta {
                id: "surveyor".to_string(),
                name: "Surveyor".to_string(),
                description: "Network reconnaissance tool".to_string(),
                icon: "radar".to_string(),
                category: "tools".to_string(),
                requires_policy: Some("recon_tools".to_string()),
            },
            ModuleMeta {
                id: "pcap".to_string(),
                name: "PCAP Studio".to_string(),
                description: "Packet capture and analysis".to_string(),
                icon: "activity".to_string(),
                category: "tools".to_string(),
                requires_policy: Some("packet_analysis".to_string()),
            },
            ModuleMeta {
                id: "topology".to_string(),
                name: "Network Topology".to_string(),
                description: "Network visualization and mapping".to_string(),
                icon: "network".to_string(),
                category: "tools".to_string(),
                requires_policy: None,
            },
            ModuleMeta {
                id: "compliance".to_string(),
                name: "Compliance Dashboard".to_string(),
                description: "Security compliance monitoring".to_string(),
                icon: "shield-check".to_string(),
                category: "compliance".to_string(),
                requires_policy: Some("auditor_only".to_string()),
            },
            ModuleMeta {
                id: "reporting".to_string(),
                name: "Reporting Studio".to_string(),
                description: "Generate security reports".to_string(),
                icon: "file-text".to_string(),
                category: "compliance".to_string(),
                requires_policy: None,
            },
        ]
    }

    pub fn get_by_id(id: &str) -> Option<ModuleMeta> {
        Self::get_all_modules().into_iter().find(|m| m.id == id)
    }
}
