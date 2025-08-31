use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Core rule structure matching the Python RuleLike dataclass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleLike {
    pub name: String,
    pub position: i32,
    pub action: String,
    pub fromzone: Vec<String>,
    pub tozone: Vec<String>,
    pub source: Vec<String>,
    pub destination: Vec<String>,
    pub application: Vec<String>,
    pub service: Vec<String>,
    pub source_user: Vec<String>,
    pub url_category: Vec<String>,
    pub schedule: Option<String>,
    pub log_setting: Option<String>,
    pub log_start: Option<bool>,
    pub log_end: Option<bool>,
    pub profile_setting: Option<String>,
    pub disabled: bool,
    pub negate_source: bool,
    pub negate_destination: bool,
    pub location: Option<String>, // pre/post for Panorama
    pub hits_total: Option<i64>,
    pub last_hit: Option<String>,
    pub counter_since: Option<String>,
    pub tags: Option<String>,
    pub rule_type: Option<String>,
    pub source_device: Option<String>,
    pub destination_device: Option<String>,
    pub apps_seen: Option<String>,
    pub days_no_new_apps: Option<String>,
    pub modified: Option<String>,
    pub created: Option<String>,
}

impl RuleLike {
    /// Convert rule to a row format for export
    pub fn to_row(&self) -> HashMap<String, String> {
        let mut row = HashMap::new();
        
        row.insert("Position".to_string(), self.position.to_string());
        row.insert("Name".to_string(), self.name.clone());
        row.insert("Tags".to_string(), self.tags.clone().unwrap_or_default());
        row.insert("Type".to_string(), self.rule_type.clone().unwrap_or("universal".to_string()));
        row.insert("Source Zone".to_string(), self.fromzone.join(", "));
        row.insert("Source Address".to_string(), self.source.join(", "));
        row.insert("Source User".to_string(), self.source_user.join(", "));
        row.insert("Source Device".to_string(), self.source_device.clone().unwrap_or("any".to_string()));
        row.insert("Destination Zone".to_string(), self.tozone.join(", "));
        row.insert("Destination Address".to_string(), self.destination.join(", "));
        row.insert("Destination Device".to_string(), self.destination_device.clone().unwrap_or("any".to_string()));
        row.insert("Application".to_string(), self.application.join(", "));
        row.insert("Service".to_string(), self.service.join(", "));
        row.insert("Action".to_string(), self.action.clone());
        row.insert("Profile".to_string(), self.profile_setting.clone().unwrap_or_default());
        row.insert("Options".to_string(), self.log_setting.clone().unwrap_or_default());
        row.insert("Rule Usage Hit Count".to_string(), self.hits_total.unwrap_or(0).to_string());
        row.insert("Rule Usage Last Hit".to_string(), self.last_hit.clone().unwrap_or_default());
        row.insert("Rule Usage First Hit".to_string(), self.counter_since.clone().unwrap_or_default());
        row.insert("Rule Usage Apps Seen".to_string(), self.apps_seen.clone().unwrap_or_default());
        row.insert("Days With No New Apps".to_string(), self.days_no_new_apps.clone().unwrap_or_default());
        row.insert("Modified".to_string(), self.modified.clone().unwrap_or_default());
        row.insert("Created".to_string(), self.created.clone().unwrap_or_default());
        
        row
    }

    /// Generate a fingerprint for rule comparison (used in merge detection)
    pub fn non_broadening_fingerprint(&self) -> (String, HashMap<String, String>) {
        let mut key = HashMap::new();
        
        key.insert("action".to_string(), self.action.clone());
        key.insert("from".to_string(), {
            let mut zones = self.fromzone.clone();
            zones.sort();
            zones.join(",")
        });
        key.insert("to".to_string(), {
            let mut zones = self.tozone.clone();
            zones.sort();
            zones.join(",")
        });
        key.insert("users".to_string(), {
            let mut users = self.source_user.clone();
            users.sort();
            users.join(",")
        });
        key.insert("urlcat".to_string(), {
            let mut cats = self.url_category.clone();
            cats.sort();
            cats.join(",")
        });
        key.insert("schedule".to_string(), self.schedule.clone().unwrap_or_default());
        key.insert("profiles".to_string(), self.profile_setting.clone().unwrap_or_default());
        key.insert("log_setting".to_string(), self.log_setting.clone().unwrap_or_default());
        key.insert("log_start".to_string(), self.log_start.unwrap_or(false).to_string());
        key.insert("log_end".to_string(), self.log_end.unwrap_or(false).to_string());
        key.insert("disabled".to_string(), self.disabled.to_string());
        key.insert("neg_src".to_string(), self.negate_source.to_string());
        key.insert("neg_dst".to_string(), self.negate_destination.to_string());
        key.insert("prepost".to_string(), self.location.clone().unwrap_or_default());

        // Create a simple hash of the key
        let key_str = format!("{:?}", key);
        let fingerprint = format!("{:x}", md5::compute(key_str.as_bytes()));
        
        (fingerprint, key)
    }

    /// Check if this rule has zero hits
    pub fn is_unused(&self) -> bool {
        self.hits_total.unwrap_or(0) == 0
    }

    /// Check if two rules can potentially be merged (same non-traffic attributes)
    pub fn can_merge_with(&self, other: &RuleLike) -> bool {
        let (fp1, _) = self.non_broadening_fingerprint();
        let (fp2, _) = other.non_broadening_fingerprint();
        fp1 == fp2
    }

    /// Check if this rule shadows another rule (comes before it and is more permissive)
    pub fn shadows(&self, other: &RuleLike) -> Option<String> {
        // Only allow rules can shadow other rules
        if self.action.to_lowercase() != "allow" {
            return None;
        }

        // Must be positioned before the other rule
        if self.position >= other.position {
            return None;
        }

        // Check if this rule's criteria encompass the other rule's criteria
        if self.encompasses_zones(&other.fromzone, &other.tozone) &&
           self.encompasses_addresses(&other.source, &other.destination) &&
           self.encompasses_applications(&other.application) &&
           self.encompasses_services(&other.service) &&
           self.encompasses_users(&other.source_user) {
            Some(format!(
                "Rule '{}' (position {}) shadows rule '{}' (position {}) - broader criteria positioned earlier",
                self.name, self.position, other.name, other.position
            ))
        } else {
            None
        }
    }

    fn encompasses_zones(&self, other_from: &[String], other_to: &[String]) -> bool {
        self.encompasses_list(&self.fromzone, other_from) && 
        self.encompasses_list(&self.tozone, other_to)
    }

    fn encompasses_addresses(&self, other_src: &[String], other_dst: &[String]) -> bool {
        self.encompasses_list(&self.source, other_src) && 
        self.encompasses_list(&self.destination, other_dst)
    }

    fn encompasses_applications(&self, other_apps: &[String]) -> bool {
        self.encompasses_list(&self.application, other_apps)
    }

    fn encompasses_services(&self, other_services: &[String]) -> bool {
        self.encompasses_list(&self.service, other_services)
    }

    fn encompasses_users(&self, other_users: &[String]) -> bool {
        self.encompasses_list(&self.source_user, other_users)
    }

    fn encompasses_list(&self, my_list: &[String], other_list: &[String]) -> bool {
        // If my list contains "any", it encompasses everything
        if my_list.iter().any(|x| x.to_lowercase() == "any") {
            return true;
        }

        // If other list contains "any" but mine doesn't, I don't encompass it
        if other_list.iter().any(|x| x.to_lowercase() == "any") {
            return false;
        }

        // Check if all items in other_list are contained in my_list
        other_list.iter().all(|item| my_list.contains(item))
    }
}

/// Shadow finding structure matching Python ShadowFinding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowFinding {
    pub shadowed_rule: String,
    pub shadowed_position: i32,
    pub shadowing_rule: String,
    pub shadowing_position: i32,
    pub reason: String,
    pub recommendation: String,
}

impl ShadowFinding {
    pub fn to_row(&self) -> HashMap<String, String> {
        let mut row = HashMap::new();
        row.insert("ShadowedRule".to_string(), self.shadowed_rule.clone());
        row.insert("ShadowedPosition".to_string(), self.shadowed_position.to_string());
        row.insert("ShadowingRule".to_string(), self.shadowing_rule.clone());
        row.insert("ShadowingPosition".to_string(), self.shadowing_position.to_string());
        row.insert("Reason".to_string(), self.reason.clone());
        row.insert("Recommendation".to_string(), self.recommendation.clone());
        row
    }
}

/// Merge proposal structure matching Python Proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub proposed_name: String,
    pub source_rules: Vec<String>,
    pub positions: Vec<i32>,
    pub apps_union: Vec<String>,
    pub services_union: Vec<String>,
    pub sources_union: Vec<String>,
    pub destinations_union: Vec<String>,
    pub order_sensitive: bool,
    pub order_reason: String,
    pub confidence: String,
    pub recommendation: String,
    pub notes: String,
}

impl Proposal {
    pub fn to_row(&self) -> HashMap<String, String> {
        let mut row = HashMap::new();
        row.insert("ProposedName".to_string(), self.proposed_name.clone());
        row.insert("SourceRules".to_string(), self.source_rules.join(", "));
        row.insert("Positions".to_string(), {
            let mut positions = self.positions.clone();
            positions.sort();
            positions.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        });
        row.insert("ApplicationsUnion".to_string(), self.apps_union.join(", "));
        row.insert("ServicesUnion".to_string(), self.services_union.join(", "));
        row.insert("SourcesUnion".to_string(), self.sources_union.join(", "));
        row.insert("DestinationsUnion".to_string(), self.destinations_union.join(", "));
        row.insert("OrderSensitive".to_string(), self.order_sensitive.to_string());
        row.insert("OrderReason".to_string(), self.order_reason.clone());
        row.insert("Confidence".to_string(), self.confidence.clone());
        row.insert("Recommendation".to_string(), self.recommendation.clone());
        row.insert("Notes".to_string(), self.notes.clone());
        row
    }
}

/// Analysis results container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResults {
    pub rules: Vec<RuleLike>,
    pub unused_rules: Vec<RuleLike>,
    pub shadow_findings: Vec<ShadowFinding>,
    pub merge_proposals: Vec<Proposal>,
    pub overview_metrics: Vec<OverviewMetric>,
}

/// Overview metric structure for the overview tab
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewMetric {
    pub category: String,
    pub metric: String,
    pub value: String,
    pub description: String,
}
