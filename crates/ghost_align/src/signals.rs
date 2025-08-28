use serde::{Deserialize, Serialize};
use chrono::Utc;
use std::collections::HashMap;
use crate::{SignalValue, TimeWindow, AlignResult};

/// Signal definition with collection metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalDefinition {
    pub key: String,
    pub name: String,
    pub description: String,
    pub owner: String,
    pub frequency: SignalFrequency,
    pub target_value: Option<f64>,
    pub unit: String,
    pub calculation: SignalCalculation,
    pub evidence_link: Option<String>,
}

/// How often a signal should be collected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalFrequency {
    RealTime,
    Hourly,
    Daily,
    Weekly,
    OnDemand,
}

/// Signal calculation method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalCalculation {
    Count,
    Percentage,
    Average,
    Sum,
    Ratio,
    Boolean,
    Custom(String),
}

/// Signal collector trait
#[async_trait::async_trait]
pub trait SignalCollector: Send + Sync {
    async fn collect_signals(&self, window: TimeWindow) -> AlignResult<Vec<SignalValue>>;
    fn supported_signals(&self) -> Vec<String>;
    fn collector_name(&self) -> String;
}

/// Built-in signal catalog
pub struct SignalCatalog {
    definitions: HashMap<String, SignalDefinition>,
}

impl SignalCatalog {
    pub fn new() -> Self {
        let mut catalog = Self {
            definitions: HashMap::new(),
        };
        catalog.load_builtin_signals();
        catalog
    }

    pub fn add_signal(&mut self, definition: SignalDefinition) {
        self.definitions.insert(definition.key.clone(), definition);
    }

    pub fn get_signal(&self, key: &str) -> Option<&SignalDefinition> {
        self.definitions.get(key)
    }

    pub fn list_signals(&self) -> Vec<&SignalDefinition> {
        self.definitions.values().collect()
    }

    fn load_builtin_signals(&mut self) {
        // Vault signals
        self.add_signal(SignalDefinition {
            key: "vault.rotation.rate30d".to_string(),
            name: "Vault Secret Rotation Rate (30d)".to_string(),
            description: "Percentage of secrets rotated in the last 30 days".to_string(),
            owner: "vault".to_string(),
            frequency: SignalFrequency::Daily,
            target_value: Some(0.95),
            unit: "percentage".to_string(),
            calculation: SignalCalculation::Percentage,
            evidence_link: Some("vault.rotation_logs".to_string()),
        });

        self.add_signal(SignalDefinition {
            key: "vault.mfa.enabled".to_string(),
            name: "Vault MFA Enforcement".to_string(),
            description: "Percentage of users with MFA enforced".to_string(),
            owner: "vault".to_string(),
            frequency: SignalFrequency::Hourly,
            target_value: Some(1.0),
            unit: "percentage".to_string(),
            calculation: SignalCalculation::Percentage,
            evidence_link: Some("vault.user_configs".to_string()),
        });

        // VPN signals
        self.add_signal(SignalDefinition {
            key: "vpn.pq_fraction".to_string(),
            name: "VPN Post-Quantum Usage".to_string(),
            description: "Percentage of VPN sessions using PQ/hybrid handshake".to_string(),
            owner: "vpn".to_string(),
            frequency: SignalFrequency::Hourly,
            target_value: Some(1.0),
            unit: "percentage".to_string(),
            calculation: SignalCalculation::Percentage,
            evidence_link: Some("vpn.session_logs".to_string()),
        });

        // SSH signals
        self.add_signal(SignalDefinition {
            key: "ssh.pq_required.hosts_fraction".to_string(),
            name: "SSH PQ Requirement Coverage".to_string(),
            description: "Percentage of SSH host configs with PQ required".to_string(),
            owner: "ssh".to_string(),
            frequency: SignalFrequency::Daily,
            target_value: Some(1.0),
            unit: "percentage".to_string(),
            calculation: SignalCalculation::Percentage,
            evidence_link: Some("ssh.host_configs".to_string()),
        });

        self.add_signal(SignalDefinition {
            key: "ssh.hostkey.pin_coverage".to_string(),
            name: "SSH Host Key Pinning Coverage".to_string(),
            description: "Percentage of hosts with key pinning enabled".to_string(),
            owner: "ssh".to_string(),
            frequency: SignalFrequency::Daily,
            target_value: Some(1.0),
            unit: "percentage".to_string(),
            calculation: SignalCalculation::Percentage,
            evidence_link: Some("ssh.pinning_configs".to_string()),
        });

        // PCAP signals
        self.add_signal(SignalDefinition {
            key: "pcap.tls.classical_flows".to_string(),
            name: "Classical TLS Flow Count".to_string(),
            description: "Number of classical-only TLS flows detected".to_string(),
            owner: "pcap".to_string(),
            frequency: SignalFrequency::RealTime,
            target_value: Some(0.0),
            unit: "count".to_string(),
            calculation: SignalCalculation::Count,
            evidence_link: Some("pcap.flow_analysis".to_string()),
        });

        // Topology signals
        self.add_signal(SignalDefinition {
            key: "topo.policy.violations".to_string(),
            name: "Network Policy Violations".to_string(),
            description: "Number of open policy violations in protected segments".to_string(),
            owner: "topology".to_string(),
            frequency: SignalFrequency::Hourly,
            target_value: Some(0.0),
            unit: "count".to_string(),
            calculation: SignalCalculation::Count,
            evidence_link: Some("topology.violation_logs".to_string()),
        });

        // Notification signals
        self.add_signal(SignalDefinition {
            key: "notify.critical.unacked_24h".to_string(),
            name: "Unacknowledged Critical Alerts (24h)".to_string(),
            description: "Number of unacknowledged critical alerts in 24h".to_string(),
            owner: "notifications".to_string(),
            frequency: SignalFrequency::Hourly,
            target_value: Some(0.0),
            unit: "count".to_string(),
            calculation: SignalCalculation::Count,
            evidence_link: Some("notifications.alert_logs".to_string()),
        });

        // Reports signals
        self.add_signal(SignalDefinition {
            key: "reports.last_exec.kpis".to_string(),
            name: "Last Executive Report Age".to_string(),
            description: "Hours since last executive report was generated".to_string(),
            owner: "reports".to_string(),
            frequency: SignalFrequency::Daily,
            target_value: Some(168.0), // 1 week
            unit: "hours".to_string(),
            calculation: SignalCalculation::Custom("time_since_last".to_string()),
            evidence_link: Some("reports.generation_logs".to_string()),
        });

        // Policy signals
        self.add_signal(SignalDefinition {
            key: "policy.pq_required.coverage".to_string(),
            name: "PQ Policy Coverage".to_string(),
            description: "Percentage of resources with PQ requirements enforced".to_string(),
            owner: "policy".to_string(),
            frequency: SignalFrequency::Daily,
            target_value: Some(1.0),
            unit: "percentage".to_string(),
            calculation: SignalCalculation::Percentage,
            evidence_link: Some("policy.enforcement_logs".to_string()),
        });

        self.add_signal(SignalDefinition {
            key: "policy.deny_allow_ratio".to_string(),
            name: "Policy Deny/Allow Ratio".to_string(),
            description: "Ratio of denied to allowed policy decisions".to_string(),
            owner: "policy".to_string(),
            frequency: SignalFrequency::Hourly,
            target_value: Some(0.1), // Low deny ratio indicates good compliance
            unit: "ratio".to_string(),
            calculation: SignalCalculation::Ratio,
            evidence_link: Some("policy.decision_logs".to_string()),
        });
    }
}

impl Default for SignalCatalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock signal collector for demonstration
pub struct MockSignalCollector {
    name: String,
    signals: Vec<String>,
}

impl MockSignalCollector {
    pub fn new(name: String, signals: Vec<String>) -> Self {
        Self { name, signals }
    }
}

#[async_trait::async_trait]
impl SignalCollector for MockSignalCollector {
    async fn collect_signals(&self, _window: TimeWindow) -> AlignResult<Vec<SignalValue>> {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::from_entropy();
        
        let mut values = Vec::new();
        
        for signal_key in &self.signals {
            let value = match signal_key.as_str() {
                "vault.rotation.rate30d" => 0.85 + rng.gen::<f64>() * 0.1, // 85-95%
                "vault.mfa.enabled" => 0.95 + rng.gen::<f64>() * 0.05, // 95-100%
                "vpn.pq_fraction" => 0.80 + rng.gen::<f64>() * 0.15, // 80-95%
                "ssh.pq_required.hosts_fraction" => 0.70 + rng.gen::<f64>() * 0.25, // 70-95%
                "ssh.hostkey.pin_coverage" => 0.90 + rng.gen::<f64>() * 0.1, // 90-100%
                "pcap.tls.classical_flows" => rng.gen::<f64>() * 10.0, // 0-10 flows
                "topo.policy.violations" => rng.gen::<f64>() * 5.0, // 0-5 violations
                "notify.critical.unacked_24h" => rng.gen::<f64>() * 3.0, // 0-3 alerts
                "reports.last_exec.kpis" => rng.gen::<f64>() * 200.0, // 0-200 hours
                "policy.pq_required.coverage" => 0.85 + rng.gen::<f64>() * 0.1, // 85-95%
                "policy.deny_allow_ratio" => rng.gen::<f64>() * 0.2, // 0-20%
                _ => rng.gen::<f64>(),
            };

            values.push(SignalValue {
                key: signal_key.clone(),
                value,
                target: None, // Will be filled from catalog
                timestamp: Utc::now(),
                confidence: 0.9 + rng.gen::<f64>() * 0.1, // 90-100%
                source: self.name.clone(),
                metadata: HashMap::new(),
            });
        }
        
        Ok(values)
    }

    fn supported_signals(&self) -> Vec<String> {
        self.signals.clone()
    }

    fn collector_name(&self) -> String {
        self.name.clone()
    }
}
