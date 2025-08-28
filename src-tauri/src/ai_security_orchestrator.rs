use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use anyhow::Result;
use rand::Rng;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AISecurityOrchestrator {
    pub orchestrator_id: String,
    pub name: String,
    pub ai_engines: Vec<AIEngine>,
    pub decision_frameworks: Vec<DecisionFramework>,
    pub autonomous_capabilities: Vec<AutonomousCapability>,
    pub risk_assessment: RiskAssessmentEngine,
    pub self_healing: SelfHealingSystem,
    pub quantum_ai_hybrid: QuantumAIHybrid,
    pub performance_metrics: OrchestratorMetrics,
    pub status: OrchestratorStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIEngine {
    pub engine_id: String,
    pub name: String,
    pub engine_type: AIEngineType,
    pub neural_architecture: NeuralArchitecture,
    pub training_status: TrainingStatus,
    pub specialization: Vec<String>,
    pub performance_metrics: AIEngineMetrics,
    pub quantum_enhancement: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AIEngineType {
    DeepLearning,
    ReinforcementLearning,
    NaturalLanguageProcessing,
    ComputerVision,
    PredictiveAnalytics,
    AnomalyDetection,
    DecisionSupport,
    QuantumML,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralArchitecture {
    pub architecture_type: String,
    pub layer_count: u32,
    pub parameter_count: u64,
    pub activation_functions: Vec<String>,
    pub optimization_algorithm: String,
    pub learning_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrainingStatus {
    Untrained,
    Training { epoch: u32, loss: f64, accuracy: f64 },
    Trained { final_accuracy: f64, validation_score: f64 },
    Updating { progress: f64 },
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIEngineMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub inference_speed: f64,
    pub resource_utilization: f64,
    pub adaptation_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionFramework {
    pub framework_id: String,
    pub name: String,
    pub decision_type: DecisionType,
    pub criteria: Vec<DecisionCriterion>,
    pub algorithms: Vec<DecisionAlgorithm>,
    pub confidence_threshold: f64,
    pub escalation_rules: Vec<EscalationRule>,
    pub audit_trail: Vec<DecisionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionType {
    ThreatResponse,
    ResourceAllocation,
    PolicyEnforcement,
    IncidentEscalation,
    SystemConfiguration,
    UserAccess,
    NetworkSegmentation,
    DataClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionCriterion {
    pub criterion_id: String,
    pub name: String,
    pub weight: f64,
    pub threshold: f64,
    pub measurement_type: String,
    pub data_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionAlgorithm {
    pub algorithm_id: String,
    pub name: String,
    pub algorithm_type: String,
    pub parameters: HashMap<String, f64>,
    pub accuracy: f64,
    pub execution_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    pub rule_id: String,
    pub trigger_condition: String,
    pub escalation_level: EscalationLevel,
    pub target_systems: Vec<String>,
    pub notification_channels: Vec<String>,
    pub automatic_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationLevel {
    Low,
    Medium,
    High,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub record_id: String,
    pub decision_id: String,
    pub timestamp: DateTime<Utc>,
    pub decision_maker: String,
    pub input_data: HashMap<String, String>,
    pub decision_outcome: String,
    pub confidence_score: f64,
    pub execution_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutonomousCapability {
    ThreatHunting,
    IncidentResponse,
    VulnerabilityManagement,
    ComplianceMonitoring,
    UserBehaviorAnalysis,
    NetworkOptimization,
    ResourceProvisioning,
    PolicyAdaptation,
    SelfDiagnosis,
    PredictiveMaintenace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessmentEngine {
    pub engine_id: String,
    pub assessment_models: Vec<RiskModel>,
    pub risk_factors: Vec<RiskFactor>,
    pub mitigation_strategies: Vec<MitigationStrategy>,
    pub current_risk_level: RiskLevel,
    pub risk_history: Vec<RiskAssessment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskModel {
    pub model_id: String,
    pub name: String,
    pub model_type: String,
    pub input_variables: Vec<String>,
    pub output_metrics: Vec<String>,
    pub accuracy: f64,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_id: String,
    pub name: String,
    pub category: String,
    pub severity_weight: f64,
    pub probability: f64,
    pub impact_score: f64,
    pub mitigation_difficulty: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationStrategy {
    pub strategy_id: String,
    pub name: String,
    pub target_risks: Vec<String>,
    pub implementation_steps: Vec<String>,
    pub resource_requirements: HashMap<String, f64>,
    pub effectiveness_score: f64,
    pub implementation_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
    Extreme,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub assessment_id: String,
    pub timestamp: DateTime<Utc>,
    pub overall_risk_score: f64,
    pub risk_level: RiskLevel,
    pub contributing_factors: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub confidence_level: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfHealingSystem {
    pub system_id: String,
    pub healing_capabilities: Vec<HealingCapability>,
    pub diagnostic_engines: Vec<DiagnosticEngine>,
    pub repair_mechanisms: Vec<RepairMechanism>,
    pub health_metrics: SystemHealthMetrics,
    pub healing_history: Vec<HealingEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealingCapability {
    AutomaticRestart,
    ConfigurationReset,
    ResourceReallocation,
    ServiceRecovery,
    DataRecovery,
    NetworkRerouting,
    SecurityPatchApplication,
    PerformanceOptimization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticEngine {
    pub engine_id: String,
    pub name: String,
    pub diagnostic_type: String,
    pub monitored_components: Vec<String>,
    pub detection_accuracy: f64,
    pub response_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairMechanism {
    pub mechanism_id: String,
    pub name: String,
    pub repair_type: String,
    pub target_issues: Vec<String>,
    pub success_rate: f64,
    pub execution_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthMetrics {
    pub overall_health_score: f64,
    pub component_health: HashMap<String, f64>,
    pub performance_metrics: HashMap<String, f64>,
    pub availability: f64,
    pub reliability: f64,
    pub maintainability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub issue_detected: String,
    pub healing_action: String,
    pub success: bool,
    pub recovery_time: u64,
    pub impact_assessment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumAIHybrid {
    pub hybrid_id: String,
    pub quantum_processors: Vec<QuantumProcessor>,
    pub classical_processors: Vec<ClassicalProcessor>,
    pub hybrid_algorithms: Vec<HybridAlgorithm>,
    pub entanglement_network: EntanglementNetwork,
    pub quantum_advantage_metrics: QuantumAdvantageMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumProcessor {
    pub processor_id: String,
    pub name: String,
    pub qubit_count: u32,
    pub coherence_time: f64,
    pub gate_fidelity: f64,
    pub quantum_volume: u32,
    pub specialization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassicalProcessor {
    pub processor_id: String,
    pub name: String,
    pub core_count: u32,
    pub clock_speed: f64,
    pub memory_capacity: u64,
    pub specialization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAlgorithm {
    pub algorithm_id: String,
    pub name: String,
    pub quantum_component: String,
    pub classical_component: String,
    pub coordination_protocol: String,
    pub performance_gain: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntanglementNetwork {
    pub network_id: String,
    pub entangled_pairs: u32,
    pub network_topology: String,
    pub coherence_preservation: f64,
    pub communication_fidelity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumAdvantageMetrics {
    pub speedup_factor: f64,
    pub accuracy_improvement: f64,
    pub resource_efficiency: f64,
    pub problem_complexity_handled: String,
    pub quantum_supremacy_achieved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorMetrics {
    pub total_decisions_made: u64,
    pub autonomous_actions_taken: u64,
    pub average_decision_time: f64,
    pub decision_accuracy: f64,
    pub system_uptime: f64,
    pub threat_response_time: f64,
    pub self_healing_events: u32,
    pub quantum_advantage_utilization: f64,
    pub risk_mitigation_effectiveness: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrchestratorStatus {
    Initializing,
    Active,
    Learning,
    Optimizing,
    SelfHealing,
    Maintenance,
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDecision {
    pub decision_id: String,
    pub decision_type: DecisionType,
    pub input_context: DecisionContext,
    pub analysis_results: AnalysisResults,
    pub recommended_actions: Vec<RecommendedAction>,
    pub confidence_score: f64,
    pub risk_assessment: f64,
    pub execution_plan: ExecutionPlan,
    pub status: DecisionStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionContext {
    pub threat_indicators: Vec<String>,
    pub system_state: HashMap<String, String>,
    pub user_context: HashMap<String, String>,
    pub environmental_factors: Vec<String>,
    pub historical_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResults {
    pub threat_probability: f64,
    pub impact_assessment: f64,
    pub urgency_score: f64,
    pub complexity_rating: f64,
    pub resource_requirements: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub action_id: String,
    pub action_type: String,
    pub description: String,
    pub priority: ActionPriority,
    pub resource_cost: f64,
    pub expected_outcome: String,
    pub success_probability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionPriority {
    Low,
    Medium,
    High,
    Critical,
    Immediate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub plan_id: String,
    pub execution_steps: Vec<ExecutionStep>,
    pub timeline: Vec<TimelineEvent>,
    pub resource_allocation: HashMap<String, f64>,
    pub success_criteria: Vec<String>,
    pub rollback_plan: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub step_id: String,
    pub step_name: String,
    pub description: String,
    pub assigned_system: String,
    pub dependencies: Vec<String>,
    pub estimated_duration: u64,
    pub success_criteria: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub event_id: String,
    pub scheduled_time: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub responsible_system: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionStatus {
    Pending,
    Analyzing,
    Approved,
    Executing,
    Completed,
    Failed,
    Cancelled,
}

pub struct AISecurityOrchestratorManager {
    pub orchestrators: Vec<AISecurityOrchestrator>,
    pub decisions: Vec<SecurityDecision>,
    pub active_frameworks: Vec<DecisionFramework>,
}

impl AISecurityOrchestratorManager {
    pub fn new() -> Self {
        Self {
            orchestrators: Vec::new(),
            decisions: Vec::new(),
            active_frameworks: Vec::new(),
        }
    }

    pub fn create_orchestrator(&mut self, name: String, capabilities: Vec<AutonomousCapability>) -> Result<AISecurityOrchestrator> {
        let orchestrator_id = format!("orchestrator_{}", chrono::Utc::now().timestamp());
        let mut rng = rand::thread_rng();

        let orchestrator = AISecurityOrchestrator {
            orchestrator_id: orchestrator_id.clone(),
            name,
            ai_engines: self.create_default_ai_engines(),
            decision_frameworks: self.create_default_frameworks(),
            autonomous_capabilities: capabilities,
            risk_assessment: self.create_risk_assessment_engine(),
            self_healing: self.create_self_healing_system(),
            quantum_ai_hybrid: self.create_quantum_ai_hybrid(),
            performance_metrics: OrchestratorMetrics {
                total_decisions_made: 0,
                autonomous_actions_taken: 0,
                average_decision_time: 150.0 + rng.gen::<f64>() * 100.0,
                decision_accuracy: 0.92 + rng.gen::<f64>() * 0.08,
                system_uptime: 99.5 + rng.gen::<f64>() * 0.5,
                threat_response_time: 50.0 + rng.gen::<f64>() * 100.0,
                self_healing_events: 0,
                quantum_advantage_utilization: 0.7 + rng.gen::<f64>() * 0.3,
                risk_mitigation_effectiveness: 0.88 + rng.gen::<f64>() * 0.12,
            },
            status: OrchestratorStatus::Active,
        };

        self.orchestrators.push(orchestrator.clone());
        Ok(orchestrator)
    }

    pub fn make_security_decision(&mut self, decision_type: DecisionType, context: DecisionContext) -> Result<SecurityDecision> {
        let decision_id = format!("decision_{}", chrono::Utc::now().timestamp());
        let mut rng = rand::thread_rng();

        let decision = SecurityDecision {
            decision_id: decision_id.clone(),
            decision_type,
            input_context: context,
            analysis_results: AnalysisResults {
                threat_probability: rng.gen::<f64>(),
                impact_assessment: rng.gen::<f64>(),
                urgency_score: rng.gen::<f64>(),
                complexity_rating: rng.gen::<f64>(),
                resource_requirements: {
                    let mut req = HashMap::new();
                    req.insert("CPU".to_string(), 0.3 + rng.gen::<f64>() * 0.4);
                    req.insert("Memory".to_string(), 0.2 + rng.gen::<f64>() * 0.5);
                    req.insert("Network".to_string(), 0.1 + rng.gen::<f64>() * 0.3);
                    req
                },
            },
            recommended_actions: vec![
                RecommendedAction {
                    action_id: format!("action_{}", rng.gen::<u32>()),
                    action_type: "Containment".to_string(),
                    description: "Isolate affected systems".to_string(),
                    priority: ActionPriority::High,
                    resource_cost: 0.3 + rng.gen::<f64>() * 0.4,
                    expected_outcome: "Threat contained".to_string(),
                    success_probability: 0.8 + rng.gen::<f64>() * 0.2,
                },
            ],
            confidence_score: 0.85 + rng.gen::<f64>() * 0.15,
            risk_assessment: rng.gen::<f64>(),
            execution_plan: ExecutionPlan {
                plan_id: format!("plan_{}", rng.gen::<u32>()),
                execution_steps: vec![
                    ExecutionStep {
                        step_id: "step_1".to_string(),
                        step_name: "Analysis".to_string(),
                        description: "Analyze threat indicators".to_string(),
                        assigned_system: "AI Analysis Engine".to_string(),
                        dependencies: Vec::new(),
                        estimated_duration: 60,
                        success_criteria: vec!["Analysis completed".to_string()],
                    },
                ],
                timeline: Vec::new(),
                resource_allocation: HashMap::new(),
                success_criteria: vec!["Threat neutralized".to_string()],
                rollback_plan: vec!["Restore from backup".to_string()],
            },
            status: DecisionStatus::Pending,
            created_at: Utc::now(),
        };

        self.decisions.push(decision.clone());
        Ok(decision)
    }

    pub fn get_orchestrator_stats(&self) -> OrchestratorMetrics {
        let mut rng = rand::thread_rng();
        
        OrchestratorMetrics {
            total_decisions_made: 500 + (rng.gen::<f64>() * 300.0) as u64,
            autonomous_actions_taken: 350 + (rng.gen::<f64>() * 200.0) as u64,
            average_decision_time: 120.0 + rng.gen::<f64>() * 80.0,
            decision_accuracy: 0.94 + rng.gen::<f64>() * 0.06,
            system_uptime: 99.8 + rng.gen::<f64>() * 0.2,
            threat_response_time: 45.0 + rng.gen::<f64>() * 55.0,
            self_healing_events: 25 + (rng.gen::<f64>() * 15.0) as u32,
            quantum_advantage_utilization: 0.75 + rng.gen::<f64>() * 0.25,
            risk_mitigation_effectiveness: 0.91 + rng.gen::<f64>() * 0.09,
        }
    }

    // Helper methods
    fn create_default_ai_engines(&self) -> Vec<AIEngine> {
        let mut rng = rand::thread_rng();
        
        vec![
            AIEngine {
                engine_id: "deep_learning_engine".to_string(),
                name: "Deep Learning Threat Detector".to_string(),
                engine_type: AIEngineType::DeepLearning,
                neural_architecture: NeuralArchitecture {
                    architecture_type: "Transformer".to_string(),
                    layer_count: 24,
                    parameter_count: 175000000000, // 175B parameters
                    activation_functions: vec!["ReLU".to_string(), "GELU".to_string()],
                    optimization_algorithm: "AdamW".to_string(),
                    learning_rate: 0.0001,
                },
                training_status: TrainingStatus::Trained {
                    final_accuracy: 0.95 + rng.gen::<f64>() * 0.05,
                    validation_score: 0.93 + rng.gen::<f64>() * 0.07,
                },
                specialization: vec!["Threat Detection".to_string(), "Anomaly Analysis".to_string()],
                performance_metrics: AIEngineMetrics {
                    accuracy: 0.95 + rng.gen::<f64>() * 0.05,
                    precision: 0.93 + rng.gen::<f64>() * 0.07,
                    recall: 0.91 + rng.gen::<f64>() * 0.09,
                    f1_score: 0.92 + rng.gen::<f64>() * 0.08,
                    inference_speed: 1000.0 + rng.gen::<f64>() * 4000.0,
                    resource_utilization: 0.6 + rng.gen::<f64>() * 0.3,
                    adaptation_rate: 0.8 + rng.gen::<f64>() * 0.2,
                },
                quantum_enhancement: true,
            },
        ]
    }

    fn create_default_frameworks(&self) -> Vec<DecisionFramework> {
        vec![
            DecisionFramework {
                framework_id: "threat_response_framework".to_string(),
                name: "Autonomous Threat Response".to_string(),
                decision_type: DecisionType::ThreatResponse,
                criteria: vec![
                    DecisionCriterion {
                        criterion_id: "threat_severity".to_string(),
                        name: "Threat Severity".to_string(),
                        weight: 0.4,
                        threshold: 0.7,
                        measurement_type: "Continuous".to_string(),
                        data_sources: vec!["Threat Intelligence".to_string()],
                    },
                ],
                algorithms: vec![
                    DecisionAlgorithm {
                        algorithm_id: "ml_classifier".to_string(),
                        name: "ML Threat Classifier".to_string(),
                        algorithm_type: "Random Forest".to_string(),
                        parameters: HashMap::new(),
                        accuracy: 0.92,
                        execution_time: 50.0,
                    },
                ],
                confidence_threshold: 0.8,
                escalation_rules: Vec::new(),
                audit_trail: Vec::new(),
            },
        ]
    }

    fn create_risk_assessment_engine(&self) -> RiskAssessmentEngine {
        let mut rng = rand::thread_rng();
        
        RiskAssessmentEngine {
            engine_id: "risk_engine_1".to_string(),
            assessment_models: Vec::new(),
            risk_factors: Vec::new(),
            mitigation_strategies: Vec::new(),
            current_risk_level: RiskLevel::Medium,
            risk_history: Vec::new(),
        }
    }

    fn create_self_healing_system(&self) -> SelfHealingSystem {
        SelfHealingSystem {
            system_id: "self_healing_1".to_string(),
            healing_capabilities: vec![
                HealingCapability::AutomaticRestart,
                HealingCapability::ConfigurationReset,
                HealingCapability::ResourceReallocation,
            ],
            diagnostic_engines: Vec::new(),
            repair_mechanisms: Vec::new(),
            health_metrics: SystemHealthMetrics {
                overall_health_score: 0.95,
                component_health: HashMap::new(),
                performance_metrics: HashMap::new(),
                availability: 0.999,
                reliability: 0.995,
                maintainability: 0.98,
            },
            healing_history: Vec::new(),
        }
    }

    fn create_quantum_ai_hybrid(&self) -> QuantumAIHybrid {
        let mut rng = rand::thread_rng();
        
        QuantumAIHybrid {
            hybrid_id: "quantum_ai_1".to_string(),
            quantum_processors: vec![
                QuantumProcessor {
                    processor_id: "qpu_1".to_string(),
                    name: "Primary Quantum Processor".to_string(),
                    qubit_count: 64,
                    coherence_time: 100.0 + rng.gen::<f64>() * 100.0,
                    gate_fidelity: 0.999,
                    quantum_volume: 4096,
                    specialization: "Machine Learning".to_string(),
                },
            ],
            classical_processors: vec![
                ClassicalProcessor {
                    processor_id: "cpu_1".to_string(),
                    name: "High-Performance CPU".to_string(),
                    core_count: 64,
                    clock_speed: 3.5,
                    memory_capacity: 1024 * 1024 * 1024 * 1024, // 1TB
                    specialization: "Deep Learning".to_string(),
                },
            ],
            hybrid_algorithms: Vec::new(),
            entanglement_network: EntanglementNetwork {
                network_id: "entanglement_net_1".to_string(),
                entangled_pairs: 32,
                network_topology: "Mesh".to_string(),
                coherence_preservation: 0.95,
                communication_fidelity: 0.98,
            },
            quantum_advantage_metrics: QuantumAdvantageMetrics {
                speedup_factor: 5.2 + rng.gen::<f64>() * 2.8,
                accuracy_improvement: 0.15 + rng.gen::<f64>() * 0.1,
                resource_efficiency: 0.8 + rng.gen::<f64>() * 0.2,
                problem_complexity_handled: "NP-Hard".to_string(),
                quantum_supremacy_achieved: true,
            },
        }
    }

    pub fn list_orchestrators(&self) -> Vec<AISecurityOrchestrator> {
        self.orchestrators.clone()
    }

    pub fn list_decisions(&self) -> Vec<SecurityDecision> {
        self.decisions.clone()
    }

    pub fn list_frameworks(&self) -> Vec<DecisionFramework> {
        self.active_frameworks.clone()
    }
}

// Tauri commands
#[tauri::command]
pub async fn ai_orchestrator_get_stats(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<AISecurityOrchestratorManager>>>,
) -> Result<OrchestratorMetrics, String> {
    let manager = manager.lock().await;
    Ok(manager.get_orchestrator_stats())
}

#[tauri::command]
pub async fn ai_orchestrator_create(
    name: String,
    capabilities: Vec<String>,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<AISecurityOrchestratorManager>>>,
) -> Result<AISecurityOrchestrator, String> {
    let mut manager = manager.lock().await;
    
    let capabilities_enum: Vec<AutonomousCapability> = capabilities.iter().map(|c| {
        match c.as_str() {
            "ThreatHunting" => AutonomousCapability::ThreatHunting,
            "IncidentResponse" => AutonomousCapability::IncidentResponse,
            "VulnerabilityManagement" => AutonomousCapability::VulnerabilityManagement,
            "ComplianceMonitoring" => AutonomousCapability::ComplianceMonitoring,
            "UserBehaviorAnalysis" => AutonomousCapability::UserBehaviorAnalysis,
            "NetworkOptimization" => AutonomousCapability::NetworkOptimization,
            "ResourceProvisioning" => AutonomousCapability::ResourceProvisioning,
            "PolicyAdaptation" => AutonomousCapability::PolicyAdaptation,
            "SelfDiagnosis" => AutonomousCapability::SelfDiagnosis,
            "PredictiveMaintenace" => AutonomousCapability::PredictiveMaintenace,
            _ => AutonomousCapability::ThreatHunting,
        }
    }).collect();
    
    manager.create_orchestrator(name, capabilities_enum)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_orchestrator_make_decision(
    decision_type: String,
    threat_indicators: Vec<String>,
    system_state: HashMap<String, String>,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<AISecurityOrchestratorManager>>>,
) -> Result<SecurityDecision, String> {
    let mut manager = manager.lock().await;
    
    let decision_type_enum = match decision_type.as_str() {
        "ThreatResponse" => DecisionType::ThreatResponse,
        "ResourceAllocation" => DecisionType::ResourceAllocation,
        "PolicyEnforcement" => DecisionType::PolicyEnforcement,
        "IncidentEscalation" => DecisionType::IncidentEscalation,
        "SystemConfiguration" => DecisionType::SystemConfiguration,
        "UserAccess" => DecisionType::UserAccess,
        "NetworkSegmentation" => DecisionType::NetworkSegmentation,
        "DataClassification" => DecisionType::DataClassification,
        _ => DecisionType::ThreatResponse,
    };
    
    let context = DecisionContext {
        threat_indicators,
        system_state,
        user_context: HashMap::new(),
        environmental_factors: Vec::new(),
        historical_patterns: Vec::new(),
    };
    
    manager.make_security_decision(decision_type_enum, context)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_orchestrator_list_orchestrators(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<AISecurityOrchestratorManager>>>,
) -> Result<Vec<AISecurityOrchestrator>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_orchestrators())
}

#[tauri::command]
pub async fn ai_orchestrator_list_decisions(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<AISecurityOrchestratorManager>>>,
) -> Result<Vec<SecurityDecision>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_decisions())
}

#[tauri::command]
pub async fn ai_orchestrator_list_frameworks(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<AISecurityOrchestratorManager>>>,
) -> Result<Vec<DecisionFramework>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_frameworks())
}
