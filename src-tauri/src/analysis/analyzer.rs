use super::data_structures::*;
use std::collections::{HashMap, HashSet};
use chrono::Utc;

/// Core analyzer matching Python Analyzer class functionality
pub struct Analyzer {
    rules: Vec<RuleLike>,
    hits: HashMap<String, HashMap<String, serde_json::Value>>,
}

impl Analyzer {
    pub fn new(rules: Vec<RuleLike>, hits: HashMap<String, HashMap<String, serde_json::Value>>) -> Self {
        Self { rules, hits }
    }

    /// Find unused rules (zero hits over observation window)
    pub fn unused_rules_zero_hits(&self) -> Vec<RuleLike> {
        self.rules
            .iter()
            .filter(|rule| rule.is_unused())
            .cloned()
            .collect()
    }

    /// Find shadowed rules using sophisticated algorithm from Python script
    pub fn find_shadowed_rules(&self) -> Vec<ShadowFinding> {
        let mut findings = Vec::new();
        
        // Sort rules by position to ensure proper order analysis
        let mut sorted_rules = self.rules.clone();
        sorted_rules.sort_by_key(|r| r.position);

        // Check each rule against all rules that come after it
        for (i, rule1) in sorted_rules.iter().enumerate() {
            for rule2 in sorted_rules.iter().skip(i + 1) {
                if let Some(reason) = rule1.shadows(rule2) {
                    let recommendation = format!(
                        "Shadowed by '{}' (pos {}); consider merge into top-most and remove after review.",
                        rule1.name, rule1.position
                    );

                    findings.push(ShadowFinding {
                        shadowed_rule: rule2.name.clone(),
                        shadowed_position: rule2.position,
                        shadowing_rule: rule1.name.clone(),
                        shadowing_position: rule1.position,
                        reason,
                        recommendation,
                    });
                }
            }
        }

        findings
    }

    /// Propose rule merges using sophisticated algorithm from Python script
    pub fn propose_merges(&self) -> Vec<Proposal> {
        let mut proposals = Vec::new();
        let mut processed_rules: HashSet<String> = HashSet::new();

        // Group rules by their non-broadening fingerprint
        let mut fingerprint_groups: HashMap<String, Vec<&RuleLike>> = HashMap::new();
        
        for rule in &self.rules {
            let (fingerprint, _) = rule.non_broadening_fingerprint();
            fingerprint_groups.entry(fingerprint).or_insert_with(Vec::new).push(rule);
        }

        // Analyze each group for merge potential
        for (fingerprint, group) in fingerprint_groups {
            if group.len() < 2 {
                continue; // Need at least 2 rules to merge
            }

            // Skip if any rule in group is already processed
            if group.iter().any(|r| processed_rules.contains(&r.name)) {
                continue;
            }

            // Check if rules can be safely merged
            let merge_analysis = self.analyze_merge_safety(&group);
            
            if merge_analysis.is_safe {
                let proposal = self.create_merge_proposal(&group, &merge_analysis);
                
                // Mark rules as processed
                for rule in &group {
                    processed_rules.insert(rule.name.clone());
                }
                
                proposals.push(proposal);
            }
        }

        proposals
    }

    /// Analyze if a group of rules can be safely merged
    fn analyze_merge_safety(&self, rules: &[&RuleLike]) -> MergeAnalysis {
        let mut analysis = MergeAnalysis {
            is_safe: true,
            confidence: "High".to_string(),
            order_sensitive: false,
            order_reason: String::new(),
            apps_union: HashSet::new(),
            services_union: HashSet::new(),
            sources_union: HashSet::new(),
            destinations_union: HashSet::new(),
        };

        // Collect all unique values across rules
        for rule in rules {
            analysis.apps_union.extend(rule.application.iter().cloned());
            analysis.services_union.extend(rule.service.iter().cloned());
            analysis.sources_union.extend(rule.source.iter().cloned());
            analysis.destinations_union.extend(rule.destination.iter().cloned());
        }

        // Check for order sensitivity
        let positions: Vec<i32> = rules.iter().map(|r| r.position).collect();
        let min_pos = *positions.iter().min().unwrap();
        let max_pos = *positions.iter().max().unwrap();

        // Check if there are intervening deny rules
        let intervening_denies = self.rules
            .iter()
            .filter(|r| r.position > min_pos && r.position < max_pos)
            .filter(|r| r.action.to_lowercase() == "deny" || r.action.to_lowercase() == "drop")
            .count();

        if intervening_denies > 0 {
            analysis.order_sensitive = true;
            analysis.confidence = "Medium".to_string();
            analysis.order_reason = format!(
                "{} deny/drop rules between positions {} and {} - review order carefully",
                intervening_denies, min_pos, max_pos
            );
        }

        // Check for significant traffic pattern differences
        let total_hits: i64 = rules.iter().map(|r| r.hits_total.unwrap_or(0)).sum();
        if total_hits == 0 {
            analysis.confidence = "Low".to_string();
            analysis.order_reason += " No traffic data available for validation";
        }

        analysis
    }

    /// Create a merge proposal from analyzed rules
    fn create_merge_proposal(&self, rules: &[&RuleLike], analysis: &MergeAnalysis) -> Proposal {
        let source_rules: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();
        let positions: Vec<i32> = rules.iter().map(|r| r.position).collect();
        
        // Generate proposed name
        let proposed_name = if source_rules.len() == 2 {
            format!("Merged_{}_and_{}", source_rules[0], source_rules[1])
        } else {
            format!("Merged_Group_{}_rules", source_rules.len())
        };

        let recommendation = if analysis.order_sensitive {
            format!(
                "Merge-candidate with {}; confidence={}. CAUTION: {}",
                source_rules[1..].join(", "),
                analysis.confidence,
                analysis.order_reason
            )
        } else {
            format!(
                "Merge-candidate with {}; confidence={}. Safe to merge - no order dependencies detected.",
                source_rules[1..].join(", "),
                analysis.confidence
            )
        };

        Proposal {
            proposed_name,
            source_rules,
            positions,
            apps_union: analysis.apps_union.iter().cloned().collect(),
            services_union: analysis.services_union.iter().cloned().collect(),
            sources_union: analysis.sources_union.iter().cloned().collect(),
            destinations_union: analysis.destinations_union.iter().cloned().collect(),
            order_sensitive: analysis.order_sensitive,
            order_reason: analysis.order_reason.clone(),
            confidence: analysis.confidence.clone(),
            recommendation,
            notes: String::new(),
        }
    }

    /// Generate comprehensive overview metrics matching Python script
    pub fn generate_overview_metrics(&self, source: &str) -> Vec<OverviewMetric> {
        let mut metrics = Vec::new();
        
        // System Information
        let total_rules = self.rules.len();
        let disabled_rules = self.rules.iter().filter(|r| r.disabled).count();
        let enabled_rules = total_rules - disabled_rules;

        metrics.extend(vec![
            OverviewMetric {
                category: "System".to_string(),
                metric: "Analysis Source".to_string(),
                value: source.to_string(),
                description: "Data source for this analysis".to_string(),
            },
            OverviewMetric {
                category: "System".to_string(),
                metric: "Analysis Date".to_string(),
                value: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                description: "When this analysis was performed".to_string(),
            },
            OverviewMetric {
                category: "System".to_string(),
                metric: "Total Rules".to_string(),
                value: total_rules.to_string(),
                description: "Total number of security rules".to_string(),
            },
            OverviewMetric {
                category: "System".to_string(),
                metric: "Enabled Rules".to_string(),
                value: enabled_rules.to_string(),
                description: "Number of enabled rules".to_string(),
            },
            OverviewMetric {
                category: "System".to_string(),
                metric: "Disabled Rules".to_string(),
                value: disabled_rules.to_string(),
                description: "Number of disabled rules".to_string(),
            },
        ]);

        // Rule Actions
        let allow_rules = self.rules.iter().filter(|r| r.action.to_lowercase() == "allow").count();
        let deny_rules = self.rules.iter().filter(|r| {
            let action = r.action.to_lowercase();
            action == "deny" || action == "drop"
        }).count();

        let allow_percentage = if total_rules > 0 {
            format!("{:.1}%", (allow_rules as f64 / total_rules as f64) * 100.0)
        } else {
            "0%".to_string()
        };

        metrics.extend(vec![
            OverviewMetric {
                category: "Actions".to_string(),
                metric: "Allow Rules".to_string(),
                value: allow_rules.to_string(),
                description: "Rules that allow traffic".to_string(),
            },
            OverviewMetric {
                category: "Actions".to_string(),
                metric: "Deny/Drop Rules".to_string(),
                value: deny_rules.to_string(),
                description: "Rules that deny or drop traffic".to_string(),
            },
            OverviewMetric {
                category: "Actions".to_string(),
                metric: "Allow Percentage".to_string(),
                value: allow_percentage,
                description: "Percentage of rules that allow traffic".to_string(),
            },
        ]);

        // Hit Count Analytics
        let zero_hit_rules = self.rules.iter().filter(|r| r.hits_total.unwrap_or(0) == 0).count();
        let total_hits: i64 = self.rules.iter().map(|r| r.hits_total.unwrap_or(0)).sum();
        let avg_hits = if total_rules > 0 {
            format!("{:.1}", total_hits as f64 / total_rules as f64)
        } else {
            "0".to_string()
        };

        let zero_hit_percentage = if total_rules > 0 {
            format!("{:.1}%", (zero_hit_rules as f64 / total_rules as f64) * 100.0)
        } else {
            "0%".to_string()
        };

        metrics.extend(vec![
            OverviewMetric {
                category: "Hit Counts".to_string(),
                metric: "Zero Hit Rules".to_string(),
                value: zero_hit_rules.to_string(),
                description: "Rules with no traffic hits".to_string(),
            },
            OverviewMetric {
                category: "Hit Counts".to_string(),
                metric: "Zero Hit Percentage".to_string(),
                value: zero_hit_percentage,
                description: "Percentage of rules with no hits".to_string(),
            },
            OverviewMetric {
                category: "Hit Counts".to_string(),
                metric: "Total Hits".to_string(),
                value: total_hits.to_string(),
                description: "Sum of all rule hit counts".to_string(),
            },
            OverviewMetric {
                category: "Hit Counts".to_string(),
                metric: "Average Hits".to_string(),
                value: avg_hits,
                description: "Average hits per rule".to_string(),
            },
        ]);

        // Diversity Metrics
        let mut unique_apps = HashSet::new();
        let mut unique_services = HashSet::new();
        let mut unique_sources = HashSet::new();
        let mut unique_destinations = HashSet::new();
        let mut unique_zones = HashSet::new();

        for rule in &self.rules {
            unique_apps.extend(rule.application.iter().cloned());
            unique_services.extend(rule.service.iter().cloned());
            unique_sources.extend(rule.source.iter().cloned());
            unique_destinations.extend(rule.destination.iter().cloned());
            unique_zones.extend(rule.fromzone.iter().cloned());
            unique_zones.extend(rule.tozone.iter().cloned());
        }

        // Remove 'any' from counts for meaningful metrics
        unique_apps.remove("any");
        unique_services.remove("any");
        unique_sources.remove("any");
        unique_destinations.remove("any");
        unique_zones.remove("any");

        metrics.extend(vec![
            OverviewMetric {
                category: "Diversity".to_string(),
                metric: "Unique Applications".to_string(),
                value: unique_apps.len().to_string(),
                description: "Number of unique applications referenced".to_string(),
            },
            OverviewMetric {
                category: "Diversity".to_string(),
                metric: "Unique Services".to_string(),
                value: unique_services.len().to_string(),
                description: "Number of unique services referenced".to_string(),
            },
            OverviewMetric {
                category: "Diversity".to_string(),
                metric: "Unique Sources".to_string(),
                value: unique_sources.len().to_string(),
                description: "Number of unique source addresses".to_string(),
            },
            OverviewMetric {
                category: "Diversity".to_string(),
                metric: "Unique Destinations".to_string(),
                value: unique_destinations.len().to_string(),
                description: "Number of unique destination addresses".to_string(),
            },
            OverviewMetric {
                category: "Diversity".to_string(),
                metric: "Unique Zones".to_string(),
                value: unique_zones.len().to_string(),
                description: "Number of unique zones referenced".to_string(),
            },
        ]);

        // Analysis Results
        let unused_rules = self.unused_rules_zero_hits();
        let shadow_findings = self.find_shadowed_rules();
        let merge_proposals = self.propose_merges();

        metrics.extend(vec![
            OverviewMetric {
                category: "Analysis".to_string(),
                metric: "Unused Rules".to_string(),
                value: unused_rules.len().to_string(),
                description: "Rules with zero hits - candidates for disabling".to_string(),
            },
            OverviewMetric {
                category: "Analysis".to_string(),
                metric: "Shadowed Rules".to_string(),
                value: shadow_findings.len().to_string(),
                description: "Rules that are shadowed by earlier rules".to_string(),
            },
            OverviewMetric {
                category: "Analysis".to_string(),
                metric: "Merge Groups".to_string(),
                value: merge_proposals.len().to_string(),
                description: "Groups of rules that can potentially be merged".to_string(),
            },
        ]);

        // Recommendations
        let disable_candidates = unused_rules.len();
        let consolidation_opportunities = shadow_findings.len() + merge_proposals.len();

        metrics.extend(vec![
            OverviewMetric {
                category: "Recommendations".to_string(),
                metric: "Disable Candidates".to_string(),
                value: disable_candidates.to_string(),
                description: "Rules with zero hits - consider disabling".to_string(),
            },
            OverviewMetric {
                category: "Recommendations".to_string(),
                metric: "Consolidation Opportunities".to_string(),
                value: consolidation_opportunities.to_string(),
                description: "Total opportunities for rule consolidation".to_string(),
            },
        ]);

        metrics
    }

    /// Perform complete analysis and return results
    pub fn analyze(&self, source: &str) -> AnalysisResults {
        let unused_rules = self.unused_rules_zero_hits();
        let shadow_findings = self.find_shadowed_rules();
        let merge_proposals = self.propose_merges();
        let overview_metrics = self.generate_overview_metrics(source);

        AnalysisResults {
            rules: self.rules.clone(),
            unused_rules,
            shadow_findings,
            merge_proposals,
            overview_metrics,
        }
    }
}

/// Helper structure for merge analysis
struct MergeAnalysis {
    is_safe: bool,
    confidence: String,
    order_sensitive: bool,
    order_reason: String,
    apps_union: HashSet<String>,
    services_union: HashSet<String>,
    sources_union: HashSet<String>,
    destinations_union: HashSet<String>,
}
