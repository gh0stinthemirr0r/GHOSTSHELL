use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{ControlEvaluation, ControlStatus, PostureSnapshot, AlignResult};
use uuid::Uuid;
use chrono::Utc;

/// Framework domain definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkDomain {
    pub id: String,
    pub name: String,
    pub description: String,
    pub weight: f64,
    pub control_ids: Vec<String>,
}

/// Framework definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Framework {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub domains: Vec<FrameworkDomain>,
    pub total_controls: usize,
}

/// Posture scoring engine
pub struct PostureScorer {
    frameworks: HashMap<String, Framework>,
}

impl PostureScorer {
    pub fn new() -> Self {
        let mut scorer = Self {
            frameworks: HashMap::new(),
        };
        scorer.load_builtin_frameworks();
        scorer
    }

    pub fn add_framework(&mut self, framework: Framework) {
        self.frameworks.insert(framework.id.clone(), framework);
    }

    pub fn get_framework(&self, id: &str) -> Option<&Framework> {
        self.frameworks.get(id)
    }

    pub fn list_frameworks(&self) -> Vec<&Framework> {
        self.frameworks.values().collect()
    }

    pub fn calculate_posture_snapshot(
        &self,
        framework_id: &str,
        evaluations: Vec<ControlEvaluation>,
    ) -> AlignResult<PostureSnapshot> {
        let framework = self.frameworks.get(framework_id)
            .ok_or_else(|| crate::AlignError::Scoring(format!("Framework not found: {}", framework_id)))?;

        let mut domain_scores = HashMap::new();
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        // Calculate domain scores
        for domain in &framework.domains {
            let domain_evaluations: Vec<&ControlEvaluation> = evaluations
                .iter()
                .filter(|eval| domain.control_ids.contains(&eval.control_id))
                .collect();

            if !domain_evaluations.is_empty() {
                let domain_score = self.calculate_domain_score(&domain_evaluations);
                domain_scores.insert(domain.id.clone(), domain_score);
                
                total_score += domain_score * domain.weight;
                total_weight += domain.weight;
            }
        }

        // Calculate overall score
        let overall_score = if total_weight > 0.0 {
            total_score / total_weight
        } else {
            0.0
        };

        // Count control statuses
        let mut passed_controls = 0;
        let mut failed_controls = 0;
        let mut partial_controls = 0;
        let mut unknown_controls = 0;

        for eval in &evaluations {
            match eval.status {
                ControlStatus::Pass => passed_controls += 1,
                ControlStatus::Fail => failed_controls += 1,
                ControlStatus::Partial => partial_controls += 1,
                ControlStatus::Unknown => unknown_controls += 1,
            }
        }

        Ok(PostureSnapshot {
            snapshot_id: Uuid::new_v4(),
            framework_id: framework_id.to_string(),
            timestamp: Utc::now(),
            overall_score,
            domain_scores,
            control_evaluations: evaluations,
            total_controls: passed_controls + failed_controls + partial_controls + unknown_controls,
            passed_controls,
            failed_controls,
            partial_controls,
            unknown_controls,
        })
    }

    fn calculate_domain_score(&self, evaluations: &[&ControlEvaluation]) -> f64 {
        if evaluations.is_empty() {
            return 0.0;
        }

        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for eval in evaluations {
            let control_score = match eval.status {
                ControlStatus::Pass => 1.0,
                ControlStatus::Partial => 0.5,
                ControlStatus::Fail => 0.0,
                ControlStatus::Unknown => 0.0,
            };

            // Weight by confidence
            let weight = eval.confidence;
            total_score += control_score * weight;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            total_score / total_weight
        } else {
            0.0
        }
    }

    fn load_builtin_frameworks(&mut self) {
        // NIST Cybersecurity Framework
        self.add_framework(Framework {
            id: "NIST-CSF".to_string(),
            name: "NIST Cybersecurity Framework".to_string(),
            version: "1.1".to_string(),
            description: "Framework for improving critical infrastructure cybersecurity".to_string(),
            domains: vec![
                FrameworkDomain {
                    id: "identify".to_string(),
                    name: "Identify".to_string(),
                    description: "Develop organizational understanding to manage cybersecurity risk".to_string(),
                    weight: 0.2,
                    control_ids: vec!["NIST-CSF-ID.AM-1".to_string(), "NIST-CSF-ID.GV-1".to_string()],
                },
                FrameworkDomain {
                    id: "protect".to_string(),
                    name: "Protect".to_string(),
                    description: "Develop and implement appropriate safeguards".to_string(),
                    weight: 0.3,
                    control_ids: vec!["NIST-CSF-PR.AC-1".to_string(), "NIST-CSF-PR.DS-1".to_string()],
                },
                FrameworkDomain {
                    id: "detect".to_string(),
                    name: "Detect".to_string(),
                    description: "Develop and implement activities to identify cybersecurity events".to_string(),
                    weight: 0.2,
                    control_ids: vec!["NIST-CSF-DE.AE-1".to_string(), "NIST-CSF-DE.CM-1".to_string()],
                },
                FrameworkDomain {
                    id: "respond".to_string(),
                    name: "Respond".to_string(),
                    description: "Develop and implement activities to take action on detected events".to_string(),
                    weight: 0.15,
                    control_ids: vec!["NIST-CSF-RS.RP-1".to_string(), "NIST-CSF-RS.CO-1".to_string()],
                },
                FrameworkDomain {
                    id: "recover".to_string(),
                    name: "Recover".to_string(),
                    description: "Develop and implement activities to maintain resilience plans".to_string(),
                    weight: 0.15,
                    control_ids: vec!["NIST-CSF-RC.RP-1".to_string(), "NIST-CSF-RC.CO-1".to_string()],
                },
            ],
            total_controls: 108,
        });

        // CIS Controls v8
        self.add_framework(Framework {
            id: "CIS-v8".to_string(),
            name: "CIS Controls v8".to_string(),
            version: "8.0".to_string(),
            description: "Center for Internet Security Controls version 8".to_string(),
            domains: vec![
                FrameworkDomain {
                    id: "basic".to_string(),
                    name: "Basic CIS Controls".to_string(),
                    description: "Essential cyber hygiene controls".to_string(),
                    weight: 0.4,
                    control_ids: vec!["CIS-1.1".to_string(), "CIS-2.1".to_string(), "CIS-3.1".to_string()],
                },
                FrameworkDomain {
                    id: "foundational".to_string(),
                    name: "Foundational CIS Controls".to_string(),
                    description: "Foundational security controls".to_string(),
                    weight: 0.35,
                    control_ids: vec!["CIS-4.1".to_string(), "CIS-5.1".to_string(), "CIS-6.1".to_string()],
                },
                FrameworkDomain {
                    id: "organizational".to_string(),
                    name: "Organizational CIS Controls".to_string(),
                    description: "Organizational and governance controls".to_string(),
                    weight: 0.25,
                    control_ids: vec!["CIS-7.1".to_string(), "CIS-8.1".to_string()],
                },
            ],
            total_controls: 153,
        });

        // ISO 27001:2013
        self.add_framework(Framework {
            id: "ISO-27001".to_string(),
            name: "ISO/IEC 27001:2013".to_string(),
            version: "2013".to_string(),
            description: "Information security management systems requirements".to_string(),
            domains: vec![
                FrameworkDomain {
                    id: "information_security_policies".to_string(),
                    name: "Information Security Policies".to_string(),
                    description: "A.5 Information security policies".to_string(),
                    weight: 0.1,
                    control_ids: vec!["ISO-27001-A.5.1.1".to_string(), "ISO-27001-A.5.1.2".to_string()],
                },
                FrameworkDomain {
                    id: "access_control".to_string(),
                    name: "Access Control".to_string(),
                    description: "A.9 Access control".to_string(),
                    weight: 0.25,
                    control_ids: vec!["ISO-27001-A.9.4.2".to_string(), "ISO-27001-A.9.2.1".to_string()],
                },
                FrameworkDomain {
                    id: "cryptography".to_string(),
                    name: "Cryptography".to_string(),
                    description: "A.10 Cryptography".to_string(),
                    weight: 0.2,
                    control_ids: vec!["ISO-27001-A.10.1.1".to_string(), "ISO-27001-A.10.1.2".to_string()],
                },
                FrameworkDomain {
                    id: "operations_security".to_string(),
                    name: "Operations Security".to_string(),
                    description: "A.12 Operations security".to_string(),
                    weight: 0.25,
                    control_ids: vec!["ISO-27001-A.12.1.1".to_string(), "ISO-27001-A.12.6.1".to_string()],
                },
                FrameworkDomain {
                    id: "incident_management".to_string(),
                    name: "Information Security Incident Management".to_string(),
                    description: "A.16 Information security incident management".to_string(),
                    weight: 0.2,
                    control_ids: vec!["ISO-27001-A.16.1.1".to_string(), "ISO-27001-A.16.1.2".to_string()],
                },
            ],
            total_controls: 114,
        });

        // SOC 2 Type II
        self.add_framework(Framework {
            id: "SOC2".to_string(),
            name: "SOC 2 Type II".to_string(),
            version: "2017".to_string(),
            description: "Service Organization Control 2 Trust Services Criteria".to_string(),
            domains: vec![
                FrameworkDomain {
                    id: "security".to_string(),
                    name: "Security".to_string(),
                    description: "Common Criteria for Security".to_string(),
                    weight: 0.4,
                    control_ids: vec!["SOC2-CC6.1".to_string(), "SOC2-CC6.2".to_string(), "SOC2-CC6.3".to_string()],
                },
                FrameworkDomain {
                    id: "availability".to_string(),
                    name: "Availability".to_string(),
                    description: "Additional Criteria for Availability".to_string(),
                    weight: 0.2,
                    control_ids: vec!["SOC2-A1.1".to_string(), "SOC2-A1.2".to_string()],
                },
                FrameworkDomain {
                    id: "confidentiality".to_string(),
                    name: "Confidentiality".to_string(),
                    description: "Additional Criteria for Confidentiality".to_string(),
                    weight: 0.2,
                    control_ids: vec!["SOC2-C1.1".to_string(), "SOC2-C1.2".to_string()],
                },
                FrameworkDomain {
                    id: "processing_integrity".to_string(),
                    name: "Processing Integrity".to_string(),
                    description: "Additional Criteria for Processing Integrity".to_string(),
                    weight: 0.1,
                    control_ids: vec!["SOC2-PI1.1".to_string()],
                },
                FrameworkDomain {
                    id: "privacy".to_string(),
                    name: "Privacy".to_string(),
                    description: "Additional Criteria for Privacy".to_string(),
                    weight: 0.1,
                    control_ids: vec!["SOC2-P1.1".to_string()],
                },
            ],
            total_controls: 64,
        });
    }
}

impl Default for PostureScorer {
    fn default() -> Self {
        Self::new()
    }
}
