use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use anyhow::Result;
use rand::Rng;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralDefenseAgent {
    pub agent_id: String,
    pub name: String,
    pub agent_type: AgentType,
    pub neural_network: NeuralNetworkConfig,
    pub capabilities: Vec<DefenseCapability>,
    pub current_mission: Option<DefenseMission>,
    pub performance_metrics: AgentMetrics,
    pub learning_state: LearningState,
    pub status: AgentStatus,
    pub created_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentType {
    Sentinel,      // Monitoring and detection
    Guardian,      // Active defense and response
    Hunter,        // Threat hunting and pursuit
    Analyst,       // Deep analysis and intelligence
    Coordinator,   // Swarm coordination
    Specialist,    // Domain-specific expertise
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralNetworkConfig {
    pub architecture: NetworkArchitecture,
    pub layers: Vec<NetworkLayer>,
    pub activation_functions: Vec<String>,
    pub learning_rate: f64,
    pub dropout_rate: f64,
    pub batch_size: u32,
    pub training_epochs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkArchitecture {
    CNN,           // Convolutional Neural Network
    RNN,           // Recurrent Neural Network
    LSTM,          // Long Short-Term Memory
    GRU,           // Gated Recurrent Unit
    Transformer,   // Attention-based
    GAN,           // Generative Adversarial Network
    Hybrid,        // Multiple architectures combined
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLayer {
    pub layer_id: String,
    pub layer_type: String,
    pub input_size: u32,
    pub output_size: u32,
    pub parameters: HashMap<String, f64>,
    pub weights: Vec<Vec<f64>>,
    pub biases: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DefenseCapability {
    ThreatDetection,
    AnomalyAnalysis,
    BehaviorModeling,
    NetworkMonitoring,
    IncidentResponse,
    ThreatHunting,
    ForensicAnalysis,
    PredictiveAnalysis,
    SwarmCoordination,
    AdaptiveLearning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseMission {
    pub mission_id: String,
    pub mission_type: MissionType,
    pub priority: MissionPriority,
    pub target: MissionTarget,
    pub objectives: Vec<String>,
    pub constraints: Vec<String>,
    pub assigned_agents: Vec<String>,
    pub status: MissionStatus,
    pub progress: f64,
    pub started_at: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MissionType {
    Patrol,
    Investigation,
    Response,
    Hunt,
    Analysis,
    Coordination,
    Learning,
    Adaptation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MissionPriority {
    Low,
    Medium,
    High,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionTarget {
    pub target_type: String,
    pub target_id: String,
    pub location: String,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MissionStatus {
    Pending,
    InProgress,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetrics {
    pub detection_accuracy: f64,
    pub response_time: f64,
    pub false_positive_rate: f64,
    pub learning_efficiency: f64,
    pub adaptation_speed: f64,
    pub collaboration_score: f64,
    pub missions_completed: u32,
    pub threats_neutralized: u32,
    pub uptime_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningState {
    pub knowledge_base_size: u32,
    pub training_iterations: u64,
    pub last_learning_session: DateTime<Utc>,
    pub learning_sources: Vec<LearningSource>,
    pub adaptation_history: Vec<AdaptationEvent>,
    pub expertise_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningSource {
    pub source_id: String,
    pub source_type: String,
    pub data_quality: f64,
    pub relevance_score: f64,
    pub last_accessed: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptationEvent {
    pub event_id: String,
    pub trigger: String,
    pub adaptation_type: String,
    pub effectiveness: f64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentStatus {
    Active,
    Idle,
    Learning,
    Updating,
    Maintenance,
    Offline,
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmIntelligence {
    pub swarm_id: String,
    pub name: String,
    pub swarm_type: SwarmType,
    pub agents: Vec<String>, // Agent IDs
    pub coordination_protocol: CoordinationProtocol,
    pub collective_behavior: CollectiveBehavior,
    pub swarm_metrics: SwarmMetrics,
    pub communication_network: CommunicationNetwork,
    pub decision_algorithm: DecisionAlgorithm,
    pub formation: SwarmFormation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwarmType {
    Defensive,
    Offensive,
    Reconnaissance,
    Analytical,
    Adaptive,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationProtocol {
    pub protocol_name: String,
    pub message_types: Vec<String>,
    pub consensus_algorithm: String,
    pub synchronization_method: String,
    pub fault_tolerance_level: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectiveBehavior {
    pub emergence_patterns: Vec<String>,
    pub swarm_intelligence_level: f64,
    pub collective_decision_accuracy: f64,
    pub adaptation_speed: f64,
    pub resilience_factor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmMetrics {
    pub cohesion_index: f64,
    pub efficiency_score: f64,
    pub coverage_area: f64,
    pub response_coordination: f64,
    pub collective_learning_rate: f64,
    pub fault_recovery_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationNetwork {
    pub topology: NetworkTopology,
    pub bandwidth_usage: f64,
    pub latency: f64,
    pub reliability: f64,
    pub encryption_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkTopology {
    Mesh,
    Star,
    Ring,
    Tree,
    Hybrid,
    Dynamic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionAlgorithm {
    pub algorithm_name: String,
    pub decision_speed: f64,
    pub accuracy_rate: f64,
    pub consensus_threshold: f64,
    pub voting_mechanism: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwarmFormation {
    Distributed,
    Clustered,
    Hierarchical,
    Dynamic,
    Adaptive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResponse {
    pub response_id: String,
    pub threat_id: String,
    pub response_type: ResponseType,
    pub participating_agents: Vec<String>,
    pub response_strategy: ResponseStrategy,
    pub execution_plan: ExecutionPlan,
    pub effectiveness: f64,
    pub status: ResponseStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseType {
    Containment,
    Neutralization,
    Mitigation,
    Investigation,
    Adaptation,
    Learning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseStrategy {
    pub strategy_name: String,
    pub tactics: Vec<String>,
    pub resource_allocation: HashMap<String, f64>,
    pub success_probability: f64,
    pub risk_assessment: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub phases: Vec<ExecutionPhase>,
    pub timeline: Vec<TimelineEvent>,
    pub contingencies: Vec<ContingencyPlan>,
    pub success_criteria: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPhase {
    pub phase_id: String,
    pub phase_name: String,
    pub assigned_agents: Vec<String>,
    pub actions: Vec<String>,
    pub duration_estimate: u64,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub event_id: String,
    pub event_type: String,
    pub scheduled_time: DateTime<Utc>,
    pub responsible_agent: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContingencyPlan {
    pub plan_id: String,
    pub trigger_condition: String,
    pub alternative_actions: Vec<String>,
    pub resource_requirements: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseStatus {
    Planning,
    Executing,
    Monitoring,
    Completed,
    Failed,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralDefenseStats {
    pub total_agents: u32,
    pub active_agents: u32,
    pub total_swarms: u32,
    pub active_missions: u32,
    pub threats_detected: u64,
    pub threats_neutralized: u64,
    pub average_response_time: f64,
    pub collective_intelligence_level: f64,
    pub adaptation_events: u32,
    pub learning_sessions: u32,
    pub system_uptime: f64,
    pub defense_effectiveness: f64,
}

pub struct NeuralDefenseGridManager {
    pub agents: Vec<NeuralDefenseAgent>,
    pub swarms: Vec<SwarmIntelligence>,
    pub missions: Vec<DefenseMission>,
    pub responses: Vec<ThreatResponse>,
}

impl NeuralDefenseGridManager {
    pub fn new() -> Self {
        Self {
            agents: Vec::new(),
            swarms: Vec::new(),
            missions: Vec::new(),
            responses: Vec::new(),
        }
    }

    pub fn create_agent(&mut self, name: String, agent_type: AgentType, capabilities: Vec<DefenseCapability>) -> Result<NeuralDefenseAgent> {
        let agent_id = format!("agent_{}", chrono::Utc::now().timestamp());
        let mut rng = rand::thread_rng();

        let agent = NeuralDefenseAgent {
            agent_id: agent_id.clone(),
            name,
            agent_type,
            neural_network: self.create_neural_network(),
            capabilities,
            current_mission: None,
            performance_metrics: AgentMetrics {
                detection_accuracy: 0.85 + rng.gen::<f64>() * 0.1,
                response_time: 50.0 + rng.gen::<f64>() * 100.0,
                false_positive_rate: rng.gen::<f64>() * 0.05,
                learning_efficiency: 0.8 + rng.gen::<f64>() * 0.2,
                adaptation_speed: 0.7 + rng.gen::<f64>() * 0.3,
                collaboration_score: 0.75 + rng.gen::<f64>() * 0.25,
                missions_completed: 0,
                threats_neutralized: 0,
                uptime_percentage: 95.0 + rng.gen::<f64>() * 5.0,
            },
            learning_state: LearningState {
                knowledge_base_size: 1000 + (rng.gen::<f64>() * 9000.0) as u32,
                training_iterations: (rng.gen::<f64>() * 10000.0) as u64,
                last_learning_session: Utc::now() - chrono::Duration::hours(rng.gen_range(1..24)),
                learning_sources: self.generate_learning_sources(),
                adaptation_history: Vec::new(),
                expertise_domains: vec!["Cybersecurity".to_string(), "Network Defense".to_string()],
            },
            status: AgentStatus::Active,
            created_at: Utc::now(),
            last_active: Utc::now(),
        };

        self.agents.push(agent.clone());
        Ok(agent)
    }

    pub fn create_swarm(&mut self, name: String, swarm_type: SwarmType, agent_ids: Vec<String>) -> Result<SwarmIntelligence> {
        let swarm_id = format!("swarm_{}", chrono::Utc::now().timestamp());
        let mut rng = rand::thread_rng();

        let swarm = SwarmIntelligence {
            swarm_id: swarm_id.clone(),
            name,
            swarm_type,
            agents: agent_ids,
            coordination_protocol: CoordinationProtocol {
                protocol_name: "Neural Consensus Protocol".to_string(),
                message_types: vec!["Status".to_string(), "Alert".to_string(), "Coordination".to_string()],
                consensus_algorithm: "Byzantine Fault Tolerant".to_string(),
                synchronization_method: "Vector Clock".to_string(),
                fault_tolerance_level: 0.9 + rng.gen::<f64>() * 0.1,
            },
            collective_behavior: CollectiveBehavior {
                emergence_patterns: vec!["Flocking".to_string(), "Clustering".to_string(), "Adaptation".to_string()],
                swarm_intelligence_level: 0.8 + rng.gen::<f64>() * 0.2,
                collective_decision_accuracy: 0.9 + rng.gen::<f64>() * 0.1,
                adaptation_speed: 0.75 + rng.gen::<f64>() * 0.25,
                resilience_factor: 0.85 + rng.gen::<f64>() * 0.15,
            },
            swarm_metrics: SwarmMetrics {
                cohesion_index: 0.8 + rng.gen::<f64>() * 0.2,
                efficiency_score: 0.85 + rng.gen::<f64>() * 0.15,
                coverage_area: 100.0 + rng.gen::<f64>() * 400.0,
                response_coordination: 0.9 + rng.gen::<f64>() * 0.1,
                collective_learning_rate: 0.7 + rng.gen::<f64>() * 0.3,
                fault_recovery_time: 10.0 + rng.gen::<f64>() * 20.0,
            },
            communication_network: CommunicationNetwork {
                topology: NetworkTopology::Mesh,
                bandwidth_usage: 0.3 + rng.gen::<f64>() * 0.4,
                latency: 1.0 + rng.gen::<f64>() * 9.0,
                reliability: 0.95 + rng.gen::<f64>() * 0.05,
                encryption_level: "Quantum-Safe".to_string(),
            },
            decision_algorithm: DecisionAlgorithm {
                algorithm_name: "Distributed Consensus".to_string(),
                decision_speed: 100.0 + rng.gen::<f64>() * 400.0,
                accuracy_rate: 0.92 + rng.gen::<f64>() * 0.08,
                consensus_threshold: 0.67,
                voting_mechanism: "Weighted Majority".to_string(),
            },
            formation: SwarmFormation::Dynamic,
        };

        self.swarms.push(swarm.clone());
        Ok(swarm)
    }

    pub fn assign_mission(&mut self, agent_id: String, mission_type: MissionType, priority: MissionPriority, target: MissionTarget) -> Result<DefenseMission> {
        let mission_id = format!("mission_{}", chrono::Utc::now().timestamp());
        
        let mission = DefenseMission {
            mission_id: mission_id.clone(),
            mission_type,
            priority,
            target,
            objectives: self.generate_mission_objectives(),
            constraints: vec!["Minimize collateral damage".to_string(), "Maintain stealth".to_string()],
            assigned_agents: vec![agent_id.clone()],
            status: MissionStatus::Pending,
            progress: 0.0,
            started_at: Utc::now(),
            deadline: Some(Utc::now() + chrono::Duration::hours(24)),
        };

        // Update agent with mission
        if let Some(agent) = self.agents.iter_mut().find(|a| a.agent_id == agent_id) {
            agent.current_mission = Some(mission.clone());
        }

        self.missions.push(mission.clone());
        Ok(mission)
    }

    pub fn initiate_threat_response(&mut self, threat_id: String, response_type: ResponseType, agent_ids: Vec<String>) -> Result<ThreatResponse> {
        let response_id = format!("response_{}", chrono::Utc::now().timestamp());
        let mut rng = rand::thread_rng();

        let response = ThreatResponse {
            response_id: response_id.clone(),
            threat_id,
            response_type,
            participating_agents: agent_ids,
            response_strategy: ResponseStrategy {
                strategy_name: "Adaptive Neural Response".to_string(),
                tactics: vec!["Isolation".to_string(), "Analysis".to_string(), "Neutralization".to_string()],
                resource_allocation: {
                    let mut allocation = HashMap::new();
                    allocation.insert("CPU".to_string(), 0.7 + rng.gen::<f64>() * 0.3);
                    allocation.insert("Memory".to_string(), 0.6 + rng.gen::<f64>() * 0.4);
                    allocation.insert("Network".to_string(), 0.5 + rng.gen::<f64>() * 0.5);
                    allocation
                },
                success_probability: 0.8 + rng.gen::<f64>() * 0.2,
                risk_assessment: rng.gen::<f64>() * 0.3,
            },
            execution_plan: self.create_execution_plan(),
            effectiveness: 0.0, // Will be updated during execution
            status: ResponseStatus::Planning,
            started_at: Utc::now(),
            completed_at: None,
        };

        self.responses.push(response.clone());
        Ok(response)
    }

    pub fn get_defense_stats(&self) -> NeuralDefenseStats {
        let mut rng = rand::thread_rng();
        
        NeuralDefenseStats {
            total_agents: self.agents.len() as u32,
            active_agents: self.agents.iter().filter(|a| matches!(a.status, AgentStatus::Active)).count() as u32,
            total_swarms: self.swarms.len() as u32,
            active_missions: self.missions.iter().filter(|m| matches!(m.status, MissionStatus::InProgress)).count() as u32,
            threats_detected: 500 + (rng.gen::<f64>() * 200.0) as u64,
            threats_neutralized: 450 + (rng.gen::<f64>() * 150.0) as u64,
            average_response_time: 25.0 + rng.gen::<f64>() * 50.0,
            collective_intelligence_level: 0.85 + rng.gen::<f64>() * 0.15,
            adaptation_events: 50 + (rng.gen::<f64>() * 50.0) as u32,
            learning_sessions: 100 + (rng.gen::<f64>() * 100.0) as u32,
            system_uptime: 98.5 + rng.gen::<f64>() * 1.5,
            defense_effectiveness: 0.92 + rng.gen::<f64>() * 0.08,
        }
    }

    // Helper methods
    fn create_neural_network(&self) -> NeuralNetworkConfig {
        let mut rng = rand::thread_rng();
        
        NeuralNetworkConfig {
            architecture: NetworkArchitecture::Transformer,
            layers: self.generate_network_layers(),
            activation_functions: vec!["ReLU".to_string(), "Sigmoid".to_string(), "Tanh".to_string()],
            learning_rate: 0.001 + rng.gen::<f64>() * 0.009,
            dropout_rate: 0.1 + rng.gen::<f64>() * 0.4,
            batch_size: 32 + (rng.gen::<f64>() * 96.0) as u32,
            training_epochs: 100 + (rng.gen::<f64>() * 400.0) as u32,
        }
    }

    fn generate_network_layers(&self) -> Vec<NetworkLayer> {
        let mut layers = Vec::new();
        let mut rng = rand::thread_rng();
        
        // Input layer
        layers.push(NetworkLayer {
            layer_id: "input".to_string(),
            layer_type: "Dense".to_string(),
            input_size: 128,
            output_size: 256,
            parameters: HashMap::new(),
            weights: vec![vec![rng.gen::<f64>(); 256]; 128],
            biases: (0..256).map(|_| rng.gen::<f64>()).collect(),
        });
        
        // Hidden layers
        for i in 0..3 {
            layers.push(NetworkLayer {
                layer_id: format!("hidden_{}", i),
                layer_type: "Dense".to_string(),
                input_size: 256,
                output_size: 256,
                parameters: HashMap::new(),
                weights: vec![vec![rng.gen::<f64>(); 256]; 256],
                biases: (0..256).map(|_| rng.gen::<f64>()).collect(),
            });
        }
        
        // Output layer
        layers.push(NetworkLayer {
            layer_id: "output".to_string(),
            layer_type: "Dense".to_string(),
            input_size: 256,
            output_size: 10,
            parameters: HashMap::new(),
            weights: vec![vec![rng.gen::<f64>(); 10]; 256],
            biases: (0..10).map(|_| rng.gen::<f64>()).collect(),
        });
        
        layers
    }

    fn generate_learning_sources(&self) -> Vec<LearningSource> {
        vec![
            LearningSource {
                source_id: "threat_intel".to_string(),
                source_type: "Threat Intelligence".to_string(),
                data_quality: 0.9,
                relevance_score: 0.95,
                last_accessed: Utc::now(),
            },
            LearningSource {
                source_id: "network_logs".to_string(),
                source_type: "Network Logs".to_string(),
                data_quality: 0.85,
                relevance_score: 0.8,
                last_accessed: Utc::now(),
            },
            LearningSource {
                source_id: "behavioral_patterns".to_string(),
                source_type: "Behavioral Analysis".to_string(),
                data_quality: 0.8,
                relevance_score: 0.9,
                last_accessed: Utc::now(),
            },
        ]
    }

    fn generate_mission_objectives(&self) -> Vec<String> {
        vec![
            "Identify threat source".to_string(),
            "Assess threat severity".to_string(),
            "Contain threat spread".to_string(),
            "Neutralize threat".to_string(),
            "Document findings".to_string(),
        ]
    }

    fn create_execution_plan(&self) -> ExecutionPlan {
        ExecutionPlan {
            phases: vec![
                ExecutionPhase {
                    phase_id: "phase_1".to_string(),
                    phase_name: "Assessment".to_string(),
                    assigned_agents: vec!["agent_1".to_string()],
                    actions: vec!["Analyze threat".to_string(), "Assess risk".to_string()],
                    duration_estimate: 300, // 5 minutes
                    dependencies: Vec::new(),
                },
                ExecutionPhase {
                    phase_id: "phase_2".to_string(),
                    phase_name: "Response".to_string(),
                    assigned_agents: vec!["agent_2".to_string()],
                    actions: vec!["Execute countermeasures".to_string(), "Monitor progress".to_string()],
                    duration_estimate: 600, // 10 minutes
                    dependencies: vec!["phase_1".to_string()],
                },
            ],
            timeline: Vec::new(),
            contingencies: Vec::new(),
            success_criteria: vec!["Threat neutralized".to_string(), "No collateral damage".to_string()],
        }
    }

    pub fn list_agents(&self) -> Vec<NeuralDefenseAgent> {
        self.agents.clone()
    }

    pub fn list_swarms(&self) -> Vec<SwarmIntelligence> {
        self.swarms.clone()
    }

    pub fn list_missions(&self) -> Vec<DefenseMission> {
        self.missions.clone()
    }

    pub fn list_responses(&self) -> Vec<ThreatResponse> {
        self.responses.clone()
    }
}

// Tauri commands
#[tauri::command]
pub async fn neural_defense_get_stats(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<NeuralDefenseGridManager>>>,
) -> Result<NeuralDefenseStats, String> {
    let manager = manager.lock().await;
    Ok(manager.get_defense_stats())
}

#[tauri::command]
pub async fn neural_defense_create_agent(
    name: String,
    agent_type: String,
    capabilities: Vec<String>,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<NeuralDefenseGridManager>>>,
) -> Result<NeuralDefenseAgent, String> {
    let mut manager = manager.lock().await;
    
    let agent_type_enum = match agent_type.as_str() {
        "Sentinel" => AgentType::Sentinel,
        "Guardian" => AgentType::Guardian,
        "Hunter" => AgentType::Hunter,
        "Analyst" => AgentType::Analyst,
        "Coordinator" => AgentType::Coordinator,
        "Specialist" => AgentType::Specialist,
        _ => AgentType::Sentinel,
    };
    
    let capabilities_enum: Vec<DefenseCapability> = capabilities.iter().map(|c| {
        match c.as_str() {
            "ThreatDetection" => DefenseCapability::ThreatDetection,
            "AnomalyAnalysis" => DefenseCapability::AnomalyAnalysis,
            "BehaviorModeling" => DefenseCapability::BehaviorModeling,
            "NetworkMonitoring" => DefenseCapability::NetworkMonitoring,
            "IncidentResponse" => DefenseCapability::IncidentResponse,
            "ThreatHunting" => DefenseCapability::ThreatHunting,
            "ForensicAnalysis" => DefenseCapability::ForensicAnalysis,
            "PredictiveAnalysis" => DefenseCapability::PredictiveAnalysis,
            "SwarmCoordination" => DefenseCapability::SwarmCoordination,
            "AdaptiveLearning" => DefenseCapability::AdaptiveLearning,
            _ => DefenseCapability::ThreatDetection,
        }
    }).collect();
    
    manager.create_agent(name, agent_type_enum, capabilities_enum)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn neural_defense_create_swarm(
    name: String,
    swarm_type: String,
    agent_ids: Vec<String>,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<NeuralDefenseGridManager>>>,
) -> Result<SwarmIntelligence, String> {
    let mut manager = manager.lock().await;
    
    let swarm_type_enum = match swarm_type.as_str() {
        "Defensive" => SwarmType::Defensive,
        "Offensive" => SwarmType::Offensive,
        "Reconnaissance" => SwarmType::Reconnaissance,
        "Analytical" => SwarmType::Analytical,
        "Adaptive" => SwarmType::Adaptive,
        "Hybrid" => SwarmType::Hybrid,
        _ => SwarmType::Defensive,
    };
    
    manager.create_swarm(name, swarm_type_enum, agent_ids)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn neural_defense_assign_mission(
    agent_id: String,
    mission_type: String,
    priority: String,
    target_type: String,
    target_id: String,
    location: String,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<NeuralDefenseGridManager>>>,
) -> Result<DefenseMission, String> {
    let mut manager = manager.lock().await;
    
    let mission_type_enum = match mission_type.as_str() {
        "Patrol" => MissionType::Patrol,
        "Investigation" => MissionType::Investigation,
        "Response" => MissionType::Response,
        "Hunt" => MissionType::Hunt,
        "Analysis" => MissionType::Analysis,
        "Coordination" => MissionType::Coordination,
        "Learning" => MissionType::Learning,
        "Adaptation" => MissionType::Adaptation,
        _ => MissionType::Patrol,
    };
    
    let priority_enum = match priority.as_str() {
        "Low" => MissionPriority::Low,
        "Medium" => MissionPriority::Medium,
        "High" => MissionPriority::High,
        "Critical" => MissionPriority::Critical,
        "Emergency" => MissionPriority::Emergency,
        _ => MissionPriority::Medium,
    };
    
    let target = MissionTarget {
        target_type,
        target_id,
        location,
        attributes: HashMap::new(),
    };
    
    manager.assign_mission(agent_id, mission_type_enum, priority_enum, target)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn neural_defense_initiate_response(
    threat_id: String,
    response_type: String,
    agent_ids: Vec<String>,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<NeuralDefenseGridManager>>>,
) -> Result<ThreatResponse, String> {
    let mut manager = manager.lock().await;
    
    let response_type_enum = match response_type.as_str() {
        "Containment" => ResponseType::Containment,
        "Neutralization" => ResponseType::Neutralization,
        "Mitigation" => ResponseType::Mitigation,
        "Investigation" => ResponseType::Investigation,
        "Adaptation" => ResponseType::Adaptation,
        "Learning" => ResponseType::Learning,
        _ => ResponseType::Containment,
    };
    
    manager.initiate_threat_response(threat_id, response_type_enum, agent_ids)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn neural_defense_list_agents(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<NeuralDefenseGridManager>>>,
) -> Result<Vec<NeuralDefenseAgent>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_agents())
}

#[tauri::command]
pub async fn neural_defense_list_swarms(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<NeuralDefenseGridManager>>>,
) -> Result<Vec<SwarmIntelligence>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_swarms())
}

#[tauri::command]
pub async fn neural_defense_list_missions(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<NeuralDefenseGridManager>>>,
) -> Result<Vec<DefenseMission>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_missions())
}

#[tauri::command]
pub async fn neural_defense_list_responses(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<NeuralDefenseGridManager>>>,
) -> Result<Vec<ThreatResponse>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_responses())
}
