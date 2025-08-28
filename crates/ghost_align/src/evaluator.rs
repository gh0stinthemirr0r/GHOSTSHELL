use serde::{Deserialize, Serialize};
use chrono::Utc;
use std::collections::HashMap;
use crate::{SignalValue, ControlStatus, ControlEvaluation, AlignResult, AlignError};

/// Control evaluation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRule {
    pub control_id: String,
    pub signal_requirements: Vec<SignalRequirement>,
    pub evaluation_logic: EvaluationLogic,
    pub confidence_weights: HashMap<String, f64>,
    pub remediation_playbooks: Vec<String>,
}

/// Signal requirement for a control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalRequirement {
    pub signal_key: String,
    pub operator: ComparisonOperator,
    pub threshold: f64,
    pub weight: f64,
    pub required: bool,
}

/// Comparison operators for signal evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Equal,
    NotEqual,
}

/// Logic for combining multiple signal requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvaluationLogic {
    All, // All requirements must pass
    Any, // Any requirement must pass
    Weighted, // Weighted scoring
    Custom(String), // Custom logic expression
}

/// Control evaluator
pub struct ControlEvaluator {
    rules: HashMap<String, EvaluationRule>,
}

impl ControlEvaluator {
    pub fn new() -> Self {
        let mut evaluator = Self {
            rules: HashMap::new(),
        };
        evaluator.load_builtin_rules();
        evaluator
    }

    pub fn add_rule(&mut self, rule: EvaluationRule) {
        self.rules.insert(rule.control_id.clone(), rule);
    }

    pub fn evaluate_control(
        &self,
        control_id: &str,
        signals: &[SignalValue],
    ) -> AlignResult<ControlEvaluation> {
        let rule = self.rules.get(control_id)
            .ok_or_else(|| AlignError::Evaluation(format!("No rule found for control: {}", control_id)))?;

        let mut rationale = Vec::new();
        let mut relevant_signals = Vec::new();
        let mut requirement_results = Vec::new();

        // Evaluate each signal requirement
        for req in &rule.signal_requirements {
            if let Some(signal) = signals.iter().find(|s| s.key == req.signal_key) {
                relevant_signals.push(signal.clone());
                
                let passes = self.evaluate_signal_requirement(req, signal);
                let target_str = if let Some(target) = signal.target {
                    format!(" (target: {:.2})", target)
                } else {
                    String::new()
                };
                
                if passes {
                    rationale.push(format!(
                        "✓ {}: {:.2}{} - PASS",
                        req.signal_key, signal.value, target_str
                    ));
                } else {
                    rationale.push(format!(
                        "✗ {}: {:.2}{} - FAIL (threshold: {:.2})",
                        req.signal_key, signal.value, target_str, req.threshold
                    ));
                }
                
                requirement_results.push((req, passes, signal.confidence));
            } else if req.required {
                rationale.push(format!("✗ {}: MISSING (required)", req.signal_key));
                requirement_results.push((req, false, 0.0));
            }
        }

        // Apply evaluation logic
        let (status, confidence) = self.apply_evaluation_logic(rule, &requirement_results)?;

        // Generate remediation suggestions
        let remediation_suggestions = if status != ControlStatus::Pass {
            rule.remediation_playbooks.clone()
        } else {
            Vec::new()
        };

        Ok(ControlEvaluation {
            control_id: control_id.to_string(),
            status,
            confidence,
            rationale,
            signals: relevant_signals,
            evidence_refs: Vec::new(), // Will be populated by evidence system
            timestamp: Utc::now(),
            remediation_suggestions,
        })
    }

    fn evaluate_signal_requirement(&self, req: &SignalRequirement, signal: &SignalValue) -> bool {
        match req.operator {
            ComparisonOperator::GreaterThan => signal.value > req.threshold,
            ComparisonOperator::GreaterThanOrEqual => signal.value >= req.threshold,
            ComparisonOperator::LessThan => signal.value < req.threshold,
            ComparisonOperator::LessThanOrEqual => signal.value <= req.threshold,
            ComparisonOperator::Equal => (signal.value - req.threshold).abs() < f64::EPSILON,
            ComparisonOperator::NotEqual => (signal.value - req.threshold).abs() >= f64::EPSILON,
        }
    }

    fn apply_evaluation_logic(
        &self,
        rule: &EvaluationRule,
        results: &[(&SignalRequirement, bool, f64)],
    ) -> AlignResult<(ControlStatus, f64)> {
        if results.is_empty() {
            return Ok((ControlStatus::Unknown, 0.0));
        }

        match rule.evaluation_logic {
            EvaluationLogic::All => {
                let all_pass = results.iter().all(|(_, passes, _)| *passes);
                let confidence = results.iter().map(|(_, _, conf)| *conf).sum::<f64>() / results.len() as f64;
                
                if all_pass {
                    Ok((ControlStatus::Pass, confidence))
                } else {
                    Ok((ControlStatus::Fail, confidence))
                }
            },
            EvaluationLogic::Any => {
                let any_pass = results.iter().any(|(_, passes, _)| *passes);
                let confidence = results.iter().map(|(_, _, conf)| *conf).sum::<f64>() / results.len() as f64;
                
                if any_pass {
                    Ok((ControlStatus::Pass, confidence))
                } else {
                    Ok((ControlStatus::Fail, confidence))
                }
            },
            EvaluationLogic::Weighted => {
                let mut total_weight = 0.0;
                let mut weighted_score = 0.0;
                let mut total_confidence = 0.0;

                for (req, passes, confidence) in results {
                    total_weight += req.weight;
                    if *passes {
                        weighted_score += req.weight;
                    }
                    total_confidence += confidence * req.weight;
                }

                if total_weight == 0.0 {
                    return Ok((ControlStatus::Unknown, 0.0));
                }

                let score = weighted_score / total_weight;
                let avg_confidence = total_confidence / total_weight;

                let status = if score >= 0.9 {
                    ControlStatus::Pass
                } else if score >= 0.7 {
                    ControlStatus::Partial
                } else {
                    ControlStatus::Fail
                };

                Ok((status, avg_confidence))
            },
            EvaluationLogic::Custom(_) => {
                // For now, fall back to weighted logic
                // In a real implementation, this would parse and execute custom logic
                self.apply_evaluation_logic(
                    &EvaluationRule {
                        evaluation_logic: EvaluationLogic::Weighted,
                        ..rule.clone()
                    },
                    results,
                )
            },
        }
    }

    fn load_builtin_rules(&mut self) {
        // NIST CSF PR.AC-1: Identity and credentials are issued, managed, verified, revoked, and audited
        self.add_rule(EvaluationRule {
            control_id: "NIST-CSF-PR.AC-1".to_string(),
            signal_requirements: vec![
                SignalRequirement {
                    signal_key: "vault.mfa.enabled".to_string(),
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    threshold: 0.95,
                    weight: 0.4,
                    required: true,
                },
                SignalRequirement {
                    signal_key: "vault.rotation.rate30d".to_string(),
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    threshold: 0.90,
                    weight: 0.3,
                    required: true,
                },
                SignalRequirement {
                    signal_key: "policy.pq_required.coverage".to_string(),
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    threshold: 0.85,
                    weight: 0.3,
                    required: false,
                },
            ],
            evaluation_logic: EvaluationLogic::Weighted,
            confidence_weights: HashMap::new(),
            remediation_playbooks: vec![
                "enable-vault-mfa".to_string(),
                "rotate-expired-secrets".to_string(),
                "enforce-pq-policy".to_string(),
            ],
        });

        // NIST CSF PR.DS-1: Data-at-rest is protected
        self.add_rule(EvaluationRule {
            control_id: "NIST-CSF-PR.DS-1".to_string(),
            signal_requirements: vec![
                SignalRequirement {
                    signal_key: "vault.rotation.rate30d".to_string(),
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    threshold: 0.95,
                    weight: 0.5,
                    required: true,
                },
                SignalRequirement {
                    signal_key: "pcap.tls.classical_flows".to_string(),
                    operator: ComparisonOperator::LessThanOrEqual,
                    threshold: 5.0,
                    weight: 0.5,
                    required: true,
                },
            ],
            evaluation_logic: EvaluationLogic::Weighted,
            confidence_weights: HashMap::new(),
            remediation_playbooks: vec![
                "rotate-expired-secrets".to_string(),
                "upgrade-tls-protocols".to_string(),
            ],
        });

        // CIS Control 4.1: Establish and Maintain a Secure Configuration Process
        self.add_rule(EvaluationRule {
            control_id: "CIS-4.1".to_string(),
            signal_requirements: vec![
                SignalRequirement {
                    signal_key: "ssh.pq_required.hosts_fraction".to_string(),
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    threshold: 1.0,
                    weight: 0.4,
                    required: true,
                },
                SignalRequirement {
                    signal_key: "ssh.hostkey.pin_coverage".to_string(),
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    threshold: 0.95,
                    weight: 0.3,
                    required: true,
                },
                SignalRequirement {
                    signal_key: "topo.policy.violations".to_string(),
                    operator: ComparisonOperator::LessThanOrEqual,
                    threshold: 2.0,
                    weight: 0.3,
                    required: false,
                },
            ],
            evaluation_logic: EvaluationLogic::Weighted,
            confidence_weights: HashMap::new(),
            remediation_playbooks: vec![
                "enforce-pq-ssh".to_string(),
                "enable-hostkey-pinning".to_string(),
                "remediate-policy-violations".to_string(),
            ],
        });

        // ISO 27001 A.9.4.2: Secure log-on procedures
        self.add_rule(EvaluationRule {
            control_id: "ISO-27001-A.9.4.2".to_string(),
            signal_requirements: vec![
                SignalRequirement {
                    signal_key: "vault.mfa.enabled".to_string(),
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    threshold: 1.0,
                    weight: 0.6,
                    required: true,
                },
                SignalRequirement {
                    signal_key: "vpn.pq_fraction".to_string(),
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    threshold: 0.90,
                    weight: 0.4,
                    required: true,
                },
            ],
            evaluation_logic: EvaluationLogic::Weighted,
            confidence_weights: HashMap::new(),
            remediation_playbooks: vec![
                "enable-vault-mfa".to_string(),
                "upgrade-vpn-pq".to_string(),
            ],
        });

        // SOC 2 CC6.1: Logical and physical access controls
        self.add_rule(EvaluationRule {
            control_id: "SOC2-CC6.1".to_string(),
            signal_requirements: vec![
                SignalRequirement {
                    signal_key: "notify.critical.unacked_24h".to_string(),
                    operator: ComparisonOperator::LessThanOrEqual,
                    threshold: 1.0,
                    weight: 0.3,
                    required: true,
                },
                SignalRequirement {
                    signal_key: "policy.deny_allow_ratio".to_string(),
                    operator: ComparisonOperator::LessThanOrEqual,
                    threshold: 0.15,
                    weight: 0.4,
                    required: false,
                },
                SignalRequirement {
                    signal_key: "topo.policy.violations".to_string(),
                    operator: ComparisonOperator::LessThanOrEqual,
                    threshold: 0.0,
                    weight: 0.3,
                    required: true,
                },
            ],
            evaluation_logic: EvaluationLogic::Weighted,
            confidence_weights: HashMap::new(),
            remediation_playbooks: vec![
                "acknowledge-critical-alerts".to_string(),
                "review-policy-decisions".to_string(),
                "remediate-policy-violations".to_string(),
            ],
        });
    }
}

impl Default for ControlEvaluator {
    fn default() -> Self {
        Self::new()
    }
}
