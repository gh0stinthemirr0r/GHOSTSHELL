use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::security::PepState;
use ghost_pq::{DilithiumPrivateKey, DilithiumPublicKey, DilithiumVariant};

// Core data structures for AI Security Engine

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AISecurityEngineStats {
    pub active_models: u32,
    pub threats_detected_24h: u32,
    pub false_positive_rate: f32,
    pub model_accuracy: f32,
    pub processing_throughput: u32, // events per second
    pub training_sessions: u32,
    pub behavioral_profiles: u32,
    pub anomalies_detected: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLModel {
    pub model_id: String,
    pub name: String,
    pub description: String,
    pub model_type: ModelType,
    pub status: ModelStatus,
    pub version: String,
    pub accuracy: f32,
    pub precision: f32,
    pub recall: f32,
    pub f1_score: f32,
    pub training_data_size: u32,
    pub last_trained: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub parameters: ModelParameters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelType {
    ThreatDetection,
    BehavioralAnalysis,
    AnomalyDetection,
    MalwareClassification,
    NetworkIntrusion,
    UserBehavior,
    FileAnalysis,
    TrafficAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelStatus {
    Training,
    Active,
    Inactive,
    Updating,
    Failed,
    Deprecated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelParameters {
    pub learning_rate: f32,
    pub batch_size: u32,
    pub epochs: u32,
    pub layers: Vec<LayerConfig>,
    pub optimizer: String,
    pub loss_function: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerConfig {
    pub layer_type: String,
    pub neurons: u32,
    pub activation: String,
    pub dropout: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub detection_id: String,
    pub model_id: String,
    pub threat_type: ThreatType,
    pub confidence_score: f32,
    pub severity: ThreatSeverity,
    pub source_data: String,
    pub features: Vec<Feature>,
    pub prediction: ThreatPrediction,
    pub detected_at: DateTime<Utc>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Phishing,
    Intrusion,
    Anomaly,
    DataExfiltration,
    PrivilegeEscalation,
    LateralMovement,
    CommandAndControl,
    Persistence,
    DefenseEvasion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feature {
    pub name: String,
    pub value: f32,
    pub importance: f32,
    pub normalized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPrediction {
    pub class: String,
    pub probability: f32,
    pub alternative_classes: Vec<(String, f32)>,
    pub explanation: String,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralProfile {
    pub profile_id: String,
    pub entity_id: String,
    pub entity_type: EntityType,
    pub baseline: BehavioralBaseline,
    pub current_behavior: BehavioralMetrics,
    pub anomaly_score: f32,
    pub risk_level: RiskLevel,
    pub last_updated: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntityType {
    User,
    Device,
    Application,
    Network,
    Process,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralBaseline {
    pub login_patterns: LoginPattern,
    pub access_patterns: AccessPattern,
    pub network_patterns: NetworkPattern,
    pub file_patterns: FilePattern,
    pub time_patterns: TimePattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginPattern {
    pub avg_login_time: f32,
    pub login_frequency: f32,
    pub common_locations: Vec<String>,
    pub device_fingerprints: Vec<String>,
    pub failure_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPattern {
    pub resource_access: HashMap<String, f32>,
    pub permission_usage: HashMap<String, f32>,
    pub data_volume: f32,
    pub access_frequency: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPattern {
    pub bandwidth_usage: f32,
    pub connection_patterns: Vec<String>,
    pub protocol_distribution: HashMap<String, f32>,
    pub geographic_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePattern {
    pub file_types: HashMap<String, f32>,
    pub access_frequency: f32,
    pub modification_patterns: Vec<String>,
    pub size_patterns: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePattern {
    pub active_hours: Vec<u8>,
    pub peak_activity: Vec<u8>,
    pub weekend_activity: f32,
    pub holiday_activity: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralMetrics {
    pub current_login: LoginPattern,
    pub current_access: AccessPattern,
    pub current_network: NetworkPattern,
    pub current_file: FilePattern,
    pub current_time: TimePattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetection {
    pub anomaly_id: String,
    pub model_id: String,
    pub entity_id: String,
    pub anomaly_type: AnomalyType,
    pub severity: ThreatSeverity,
    pub confidence: f32,
    pub deviation_score: f32,
    pub baseline_value: f32,
    pub observed_value: f32,
    pub context: AnomalyContext,
    pub detected_at: DateTime<Utc>,
    pub investigated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    Statistical,
    Behavioral,
    Temporal,
    Spatial,
    Volumetric,
    Pattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyContext {
    pub feature_name: String,
    pub time_window: String,
    pub related_entities: Vec<String>,
    pub environmental_factors: HashMap<String, String>,
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingSession {
    pub session_id: String,
    pub model_id: String,
    pub dataset_id: String,
    pub status: TrainingStatus,
    pub progress: f32,
    pub current_epoch: u32,
    pub total_epochs: u32,
    pub loss: f32,
    pub validation_accuracy: f32,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub metrics: TrainingMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrainingStatus {
    Preparing,
    Training,
    Validating,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetrics {
    pub training_loss: Vec<f32>,
    pub validation_loss: Vec<f32>,
    pub training_accuracy: Vec<f32>,
    pub validation_accuracy: Vec<f32>,
    pub learning_curve: Vec<(u32, f32)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEvaluation {
    pub evaluation_id: String,
    pub model_id: String,
    pub test_dataset_id: String,
    pub accuracy: f32,
    pub precision: f32,
    pub recall: f32,
    pub f1_score: f32,
    pub auc_roc: f32,
    pub confusion_matrix: Vec<Vec<u32>>,
    pub feature_importance: Vec<(String, f32)>,
    pub evaluated_at: DateTime<Utc>,
}

// Main AI Security Engine Manager
pub struct AISecurityEngineManager {
    models: Arc<RwLock<HashMap<String, MLModel>>>,
    threat_detections: Arc<RwLock<HashMap<String, ThreatDetection>>>,
    behavioral_profiles: Arc<RwLock<HashMap<String, BehavioralProfile>>>,
    anomaly_detections: Arc<RwLock<HashMap<String, AnomalyDetection>>>,
    training_sessions: Arc<RwLock<HashMap<String, TrainingSession>>>,
    model_evaluations: Arc<RwLock<HashMap<String, ModelEvaluation>>>,
    signing_keys: Arc<RwLock<HashMap<String, (DilithiumPublicKey, DilithiumPrivateKey)>>>,
}

impl AISecurityEngineManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            models: Arc::new(RwLock::new(HashMap::new())),
            threat_detections: Arc::new(RwLock::new(HashMap::new())),
            behavioral_profiles: Arc::new(RwLock::new(HashMap::new())),
            anomaly_detections: Arc::new(RwLock::new(HashMap::new())),
            training_sessions: Arc::new(RwLock::new(HashMap::new())),
            model_evaluations: Arc::new(RwLock::new(HashMap::new())),
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn initialize(&self) -> Result<()> {
        self.create_sample_data().await?;
        Ok(())
    }

    async fn create_sample_data(&self) -> Result<()> {
        // Create sample ML models
        let mut models = self.models.write().await;
        
        let threat_detection_model = MLModel {
            model_id: "model_threat_001".to_string(),
            name: "GHOST Threat Detector v3.2".to_string(),
            description: "Deep learning model for advanced threat detection using transformer architecture".to_string(),
            model_type: ModelType::ThreatDetection,
            status: ModelStatus::Active,
            version: "3.2.1".to_string(),
            accuracy: 0.967,
            precision: 0.943,
            recall: 0.891,
            f1_score: 0.916,
            training_data_size: 2_500_000,
            last_trained: Utc::now(),
            created_at: Utc::now(),
            parameters: ModelParameters {
                learning_rate: 0.001,
                batch_size: 128,
                epochs: 50,
                layers: vec![
                    LayerConfig {
                        layer_type: "Dense".to_string(),
                        neurons: 512,
                        activation: "ReLU".to_string(),
                        dropout: Some(0.3),
                    },
                    LayerConfig {
                        layer_type: "Transformer".to_string(),
                        neurons: 256,
                        activation: "GELU".to_string(),
                        dropout: Some(0.1),
                    },
                ],
                optimizer: "AdamW".to_string(),
                loss_function: "CrossEntropy".to_string(),
            },
        };

        let behavioral_model = MLModel {
            model_id: "model_behavior_001".to_string(),
            name: "GHOST Behavioral Analyzer v2.8".to_string(),
            description: "LSTM-based model for user behavioral analysis and anomaly detection".to_string(),
            model_type: ModelType::BehavioralAnalysis,
            status: ModelStatus::Active,
            version: "2.8.3".to_string(),
            accuracy: 0.923,
            precision: 0.887,
            recall: 0.934,
            f1_score: 0.910,
            training_data_size: 1_800_000,
            last_trained: Utc::now(),
            created_at: Utc::now(),
            parameters: ModelParameters {
                learning_rate: 0.0005,
                batch_size: 64,
                epochs: 75,
                layers: vec![
                    LayerConfig {
                        layer_type: "LSTM".to_string(),
                        neurons: 128,
                        activation: "Tanh".to_string(),
                        dropout: Some(0.2),
                    },
                    LayerConfig {
                        layer_type: "Dense".to_string(),
                        neurons: 64,
                        activation: "Sigmoid".to_string(),
                        dropout: None,
                    },
                ],
                optimizer: "Adam".to_string(),
                loss_function: "BinaryCrossEntropy".to_string(),
            },
        };

        models.insert(threat_detection_model.model_id.clone(), threat_detection_model);
        models.insert(behavioral_model.model_id.clone(), behavioral_model);
        drop(models);

        // Create sample threat detections
        let mut detections = self.threat_detections.write().await;
        
        let critical_threat = ThreatDetection {
            detection_id: "threat_001".to_string(),
            model_id: "model_threat_001".to_string(),
            threat_type: ThreatType::Malware,
            confidence_score: 0.94,
            severity: ThreatSeverity::Critical,
            source_data: "Network traffic analysis".to_string(),
            features: vec![
                Feature {
                    name: "entropy".to_string(),
                    value: 7.8,
                    importance: 0.85,
                    normalized: true,
                },
                Feature {
                    name: "packet_size_variance".to_string(),
                    value: 0.67,
                    importance: 0.72,
                    normalized: true,
                },
            ],
            prediction: ThreatPrediction {
                class: "Advanced Persistent Threat".to_string(),
                probability: 0.94,
                alternative_classes: vec![
                    ("Ransomware".to_string(), 0.03),
                    ("Trojan".to_string(), 0.02),
                ],
                explanation: "High entropy patterns and unusual network behavior consistent with APT activity".to_string(),
                mitre_tactics: vec!["Initial Access".to_string(), "Persistence".to_string()],
                mitre_techniques: vec!["T1566.001".to_string(), "T1053.005".to_string()],
            },
            detected_at: Utc::now(),
            verified: Some(true),
            false_positive: Some(false),
        };

        detections.insert(critical_threat.detection_id.clone(), critical_threat);
        drop(detections);

        // Create sample behavioral profiles
        let mut profiles = self.behavioral_profiles.write().await;
        
        let user_profile = BehavioralProfile {
            profile_id: "profile_user_001".to_string(),
            entity_id: "user_john_doe".to_string(),
            entity_type: EntityType::User,
            baseline: BehavioralBaseline {
                login_patterns: LoginPattern {
                    avg_login_time: 8.5,
                    login_frequency: 1.2,
                    common_locations: vec!["Office".to_string(), "Home".to_string()],
                    device_fingerprints: vec!["laptop_001".to_string(), "mobile_001".to_string()],
                    failure_rate: 0.02,
                },
                access_patterns: AccessPattern {
                    resource_access: HashMap::from([
                        ("database".to_string(), 0.3),
                        ("file_server".to_string(), 0.7),
                    ]),
                    permission_usage: HashMap::from([
                        ("read".to_string(), 0.8),
                        ("write".to_string(), 0.2),
                    ]),
                    data_volume: 150.5,
                    access_frequency: 45.2,
                },
                network_patterns: NetworkPattern {
                    bandwidth_usage: 25.6,
                    connection_patterns: vec!["internal".to_string(), "vpn".to_string()],
                    protocol_distribution: HashMap::from([
                        ("HTTPS".to_string(), 0.8),
                        ("SSH".to_string(), 0.2),
                    ]),
                    geographic_patterns: vec!["US-East".to_string()],
                },
                file_patterns: FilePattern {
                    file_types: HashMap::from([
                        ("docx".to_string(), 0.4),
                        ("pdf".to_string(), 0.3),
                        ("xlsx".to_string(), 0.3),
                    ]),
                    access_frequency: 12.3,
                    modification_patterns: vec!["business_hours".to_string()],
                    size_patterns: vec![1024.0, 2048.0, 4096.0],
                },
                time_patterns: TimePattern {
                    active_hours: vec![9, 10, 11, 12, 13, 14, 15, 16, 17],
                    peak_activity: vec![10, 14, 16],
                    weekend_activity: 0.1,
                    holiday_activity: 0.05,
                },
            },
            current_behavior: BehavioralMetrics {
                current_login: LoginPattern {
                    avg_login_time: 8.7,
                    login_frequency: 1.1,
                    common_locations: vec!["Office".to_string()],
                    device_fingerprints: vec!["laptop_001".to_string()],
                    failure_rate: 0.01,
                },
                current_access: AccessPattern {
                    resource_access: HashMap::from([
                        ("database".to_string(), 0.4),
                        ("file_server".to_string(), 0.6),
                    ]),
                    permission_usage: HashMap::from([
                        ("read".to_string(), 0.9),
                        ("write".to_string(), 0.1),
                    ]),
                    data_volume: 145.2,
                    access_frequency: 42.8,
                },
                current_network: NetworkPattern {
                    bandwidth_usage: 23.1,
                    connection_patterns: vec!["internal".to_string()],
                    protocol_distribution: HashMap::from([
                        ("HTTPS".to_string(), 0.85),
                        ("SSH".to_string(), 0.15),
                    ]),
                    geographic_patterns: vec!["US-East".to_string()],
                },
                current_file: FilePattern {
                    file_types: HashMap::from([
                        ("docx".to_string(), 0.5),
                        ("pdf".to_string(), 0.3),
                        ("xlsx".to_string(), 0.2),
                    ]),
                    access_frequency: 11.8,
                    modification_patterns: vec!["business_hours".to_string()],
                    size_patterns: vec![1024.0, 2048.0],
                },
                current_time: TimePattern {
                    active_hours: vec![9, 10, 11, 12, 13, 14, 15, 16],
                    peak_activity: vec![10, 14],
                    weekend_activity: 0.08,
                    holiday_activity: 0.03,
                },
            },
            anomaly_score: 0.15,
            risk_level: RiskLevel::Low,
            last_updated: Utc::now(),
            created_at: Utc::now(),
        };

        profiles.insert(user_profile.profile_id.clone(), user_profile);
        drop(profiles);

        // Create sample training sessions
        let mut training = self.training_sessions.write().await;
        
        let active_training = TrainingSession {
            session_id: "training_001".to_string(),
            model_id: "model_threat_001".to_string(),
            dataset_id: "dataset_threats_2025".to_string(),
            status: TrainingStatus::Training,
            progress: 0.67,
            current_epoch: 34,
            total_epochs: 50,
            loss: 0.023,
            validation_accuracy: 0.943,
            started_at: Utc::now(),
            completed_at: None,
            metrics: TrainingMetrics {
                training_loss: vec![0.8, 0.6, 0.4, 0.3, 0.2, 0.15, 0.1, 0.08, 0.05, 0.023],
                validation_loss: vec![0.75, 0.65, 0.45, 0.35, 0.25, 0.18, 0.12, 0.09, 0.06, 0.028],
                training_accuracy: vec![0.6, 0.7, 0.8, 0.85, 0.9, 0.92, 0.94, 0.95, 0.96, 0.967],
                validation_accuracy: vec![0.58, 0.68, 0.78, 0.83, 0.88, 0.90, 0.92, 0.93, 0.94, 0.943],
                learning_curve: vec![(10, 0.8), (20, 0.9), (30, 0.94), (34, 0.943)],
            },
        };

        training.insert(active_training.session_id.clone(), active_training);

        Ok(())
    }

    pub async fn get_stats(&self) -> Result<AISecurityEngineStats> {
        let models = self.models.read().await;
        let detections = self.threat_detections.read().await;
        let profiles = self.behavioral_profiles.read().await;
        let anomalies = self.anomaly_detections.read().await;
        let training = self.training_sessions.read().await;

        let active_models = models.values()
            .filter(|m| matches!(m.status, ModelStatus::Active))
            .count() as u32;

        let threats_24h = detections.values()
            .filter(|d| (Utc::now() - d.detected_at).num_hours() <= 24)
            .count() as u32;

        let avg_accuracy = if !models.is_empty() {
            models.values().map(|m| m.accuracy).sum::<f32>() / models.len() as f32
        } else {
            0.0
        };

        let false_positive_rate = if !detections.is_empty() {
            detections.values()
                .filter(|d| d.false_positive == Some(true))
                .count() as f32 / detections.len() as f32
        } else {
            0.0
        };

        Ok(AISecurityEngineStats {
            active_models,
            threats_detected_24h: threats_24h,
            false_positive_rate,
            model_accuracy: avg_accuracy,
            processing_throughput: 1250 + (rand::random::<u32>() % 500),
            training_sessions: training.len() as u32,
            behavioral_profiles: profiles.len() as u32,
            anomalies_detected: anomalies.len() as u32,
        })
    }

    pub async fn get_models(&self) -> Result<Vec<MLModel>> {
        let models = self.models.read().await;
        Ok(models.values().cloned().collect())
    }

    pub async fn get_model(&self, model_id: &str) -> Result<Option<MLModel>> {
        let models = self.models.read().await;
        Ok(models.get(model_id).cloned())
    }

    pub async fn get_threat_detections(&self) -> Result<Vec<ThreatDetection>> {
        let detections = self.threat_detections.read().await;
        Ok(detections.values().cloned().collect())
    }

    pub async fn get_behavioral_profiles(&self) -> Result<Vec<BehavioralProfile>> {
        let profiles = self.behavioral_profiles.read().await;
        Ok(profiles.values().cloned().collect())
    }

    pub async fn get_training_sessions(&self) -> Result<Vec<TrainingSession>> {
        let training = self.training_sessions.read().await;
        Ok(training.values().cloned().collect())
    }

    pub async fn start_model_training(&self, model_id: &str, dataset_id: &str) -> Result<String> {
        let session_id = format!("training_{}", Uuid::new_v4());
        
        let training_session = TrainingSession {
            session_id: session_id.clone(),
            model_id: model_id.to_string(),
            dataset_id: dataset_id.to_string(),
            status: TrainingStatus::Preparing,
            progress: 0.0,
            current_epoch: 0,
            total_epochs: 50,
            loss: 0.0,
            validation_accuracy: 0.0,
            started_at: Utc::now(),
            completed_at: None,
            metrics: TrainingMetrics {
                training_loss: vec![],
                validation_loss: vec![],
                training_accuracy: vec![],
                validation_accuracy: vec![],
                learning_curve: vec![],
            },
        };

        let mut training = self.training_sessions.write().await;
        training.insert(session_id.clone(), training_session);

        Ok(session_id)
    }

    pub async fn run_threat_detection(&self, data: &str) -> Result<String> {
        // Simulate threat detection
        let detection_id = format!("threat_{}", Uuid::new_v4());
        
        let detection = ThreatDetection {
            detection_id: detection_id.clone(),
            model_id: "model_threat_001".to_string(),
            threat_type: ThreatType::Anomaly,
            confidence_score: 0.75 + (rand::random::<f32>() * 0.24),
            severity: ThreatSeverity::Medium,
            source_data: data.to_string(),
            features: vec![],
            prediction: ThreatPrediction {
                class: "Suspicious Activity".to_string(),
                probability: 0.78,
                alternative_classes: vec![],
                explanation: "AI detected unusual patterns in the provided data".to_string(),
                mitre_tactics: vec!["Discovery".to_string()],
                mitre_techniques: vec!["T1083".to_string()],
            },
            detected_at: Utc::now(),
            verified: None,
            false_positive: None,
        };

        let mut detections = self.threat_detections.write().await;
        detections.insert(detection_id.clone(), detection);

        Ok(detection_id)
    }
}

// Tauri command handlers
#[tauri::command]
pub async fn ai_security_engine_get_stats(
    engine_manager: tauri::State<'_, Arc<tokio::sync::Mutex<AISecurityEngineManager>>>,
) -> Result<AISecurityEngineStats, String> {
    let manager = engine_manager.lock().await;
    manager.get_stats().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_security_engine_get_models(
    engine_manager: tauri::State<'_, Arc<tokio::sync::Mutex<AISecurityEngineManager>>>,
) -> Result<Vec<MLModel>, String> {
    let manager = engine_manager.lock().await;
    manager.get_models().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_security_engine_get_model(
    model_id: String,
    engine_manager: tauri::State<'_, Arc<tokio::sync::Mutex<AISecurityEngineManager>>>,
) -> Result<Option<MLModel>, String> {
    let manager = engine_manager.lock().await;
    manager.get_model(&model_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_security_engine_get_threat_detections(
    engine_manager: tauri::State<'_, Arc<tokio::sync::Mutex<AISecurityEngineManager>>>,
) -> Result<Vec<ThreatDetection>, String> {
    let manager = engine_manager.lock().await;
    manager.get_threat_detections().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_security_engine_get_behavioral_profiles(
    engine_manager: tauri::State<'_, Arc<tokio::sync::Mutex<AISecurityEngineManager>>>,
) -> Result<Vec<BehavioralProfile>, String> {
    let manager = engine_manager.lock().await;
    manager.get_behavioral_profiles().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_security_engine_get_training_sessions(
    engine_manager: tauri::State<'_, Arc<tokio::sync::Mutex<AISecurityEngineManager>>>,
) -> Result<Vec<TrainingSession>, String> {
    let manager = engine_manager.lock().await;
    manager.get_training_sessions().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_security_engine_start_training(
    model_id: String,
    dataset_id: String,
    engine_manager: tauri::State<'_, Arc<tokio::sync::Mutex<AISecurityEngineManager>>>,
) -> Result<String, String> {
    let manager = engine_manager.lock().await;
    manager.start_model_training(&model_id, &dataset_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_security_engine_run_detection(
    data: String,
    engine_manager: tauri::State<'_, Arc<tokio::sync::Mutex<AISecurityEngineManager>>>,
) -> Result<String, String> {
    let manager = engine_manager.lock().await;
    manager.run_threat_detection(&data).await.map_err(|e| e.to_string())
}
