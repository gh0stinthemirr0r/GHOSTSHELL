use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration, Timelike};
use uuid::Uuid;
use anyhow::Result;

use ghost_pq::signatures::{DilithiumPublicKey, DilithiumPrivateKey, DilithiumVariant};
// Policy enforcement removed for single-user mode

// Core data structures for Behavioral Analytics
pub struct BehavioralAnalyticsManager {
    user_profiles: Arc<RwLock<HashMap<String, UserBehaviorProfile>>>,
    behavior_baselines: Arc<RwLock<HashMap<String, BehaviorBaseline>>>,
    anomalies: Arc<RwLock<HashMap<String, BehaviorAnomaly>>>,
    risk_scores: Arc<RwLock<HashMap<String, RiskScore>>>,
    behavior_events: Arc<RwLock<Vec<BehaviorEvent>>>,
    ml_models: Arc<RwLock<HashMap<String, MLModel>>>,
    signing_key: Arc<RwLock<Option<DilithiumPrivateKey>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBehaviorProfile {
    pub user_id: String,
    pub username: String,
    pub department: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub baseline_established: bool,
    pub behavior_patterns: Vec<BehaviorPattern>,
    pub typical_hours: WorkingHours,
    pub typical_locations: Vec<Location>,
    pub typical_devices: Vec<Device>,
    pub typical_applications: Vec<Application>,
    pub risk_factors: Vec<RiskFactor>,
    pub peer_group: String,
    pub sensitivity_level: SensitivityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPattern {
    pub pattern_id: String,
    pub pattern_type: PatternType,
    pub description: String,
    pub frequency: f32,
    pub confidence: f32,
    pub first_observed: DateTime<Utc>,
    pub last_observed: DateTime<Utc>,
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    LoginTiming,
    ApplicationUsage,
    DataAccess,
    NetworkActivity,
    FileOperations,
    EmailBehavior,
    WebBrowsing,
    SystemCommands,
    PrivilegeEscalation,
    DataTransfer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingHours {
    pub start_hour: u8,
    pub end_hour: u8,
    pub timezone: String,
    pub working_days: Vec<u8>, // 0-6, Monday-Sunday
    pub flexibility_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub location_id: String,
    pub location_type: LocationType,
    pub ip_address: Option<String>,
    pub country: String,
    pub city: String,
    pub coordinates: Option<(f64, f64)>,
    pub frequency: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LocationType {
    Office,
    Home,
    Remote,
    Mobile,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub device_type: DeviceType,
    pub os_type: String,
    pub os_version: String,
    pub browser: Option<String>,
    pub frequency: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub trusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceType {
    Desktop,
    Laptop,
    Mobile,
    Tablet,
    Server,
    IoT,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub app_id: String,
    pub app_name: String,
    pub app_category: AppCategory,
    pub usage_frequency: f32,
    pub typical_duration: u32, // minutes
    pub data_sensitivity: SensitivityLevel,
    pub first_used: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppCategory {
    Productivity,
    Communication,
    Development,
    Security,
    Finance,
    HR,
    Analytics,
    System,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SensitivityLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_id: String,
    pub factor_type: RiskFactorType,
    pub description: String,
    pub weight: f32,
    pub active: bool,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskFactorType {
    PrivilegedAccess,
    RemoteAccess,
    OffHoursActivity,
    UnusualLocation,
    NewDevice,
    DataExfiltration,
    FailedLogins,
    PolicyViolation,
    SuspiciousApplication,
    AnomalousTraffic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorBaseline {
    pub baseline_id: String,
    pub user_id: String,
    pub baseline_type: BaselineType,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub training_period_days: u32,
    pub confidence_level: f32,
    pub statistical_model: StatisticalModel,
    pub thresholds: HashMap<String, f32>,
    pub seasonal_patterns: Vec<SeasonalPattern>,
    pub peer_comparison: PeerComparison,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BaselineType {
    LoginBehavior,
    ApplicationUsage,
    DataAccess,
    NetworkActivity,
    Comprehensive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalModel {
    pub model_type: ModelType,
    pub parameters: HashMap<String, f32>,
    pub accuracy: f32,
    pub false_positive_rate: f32,
    pub last_trained: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelType {
    GaussianMixture,
    IsolationForest,
    OneClassSVM,
    LSTM,
    Autoencoder,
    EnsembleMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalPattern {
    pub pattern_id: String,
    pub pattern_name: String,
    pub cycle_type: CycleType,
    pub amplitude: f32,
    pub phase: f32,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CycleType {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Yearly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerComparison {
    pub peer_group_id: String,
    pub peer_group_size: u32,
    pub similarity_score: f32,
    pub deviation_from_peers: f32,
    pub percentile_ranking: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAnomaly {
    pub anomaly_id: String,
    pub user_id: String,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub confidence: f32,
    pub detected_at: DateTime<Utc>,
    pub description: String,
    pub affected_metrics: Vec<String>,
    pub deviation_score: f32,
    pub context: AnomalyContext,
    pub investigation_status: InvestigationStatus,
    pub false_positive: bool,
    pub analyst_notes: String,
    pub related_events: Vec<String>,
    pub mitigation_actions: Vec<MitigationAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    LoginAnomaly,
    AccessAnomaly,
    UsageAnomaly,
    LocationAnomaly,
    TimeAnomaly,
    VolumeAnomaly,
    PatternAnomaly,
    PeerDeviation,
    PolicyViolation,
    ThreatIndicator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyContext {
    pub triggering_event: BehaviorEvent,
    pub baseline_comparison: BaselineComparison,
    pub peer_comparison: PeerComparison,
    pub environmental_factors: HashMap<String, String>,
    pub threat_intelligence: Option<ThreatContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub expected_value: f32,
    pub actual_value: f32,
    pub deviation_percentage: f32,
    pub standard_deviations: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    pub threat_indicators: Vec<String>,
    pub attack_patterns: Vec<String>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvestigationStatus {
    New,
    InProgress,
    Resolved,
    FalsePositive,
    Escalated,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationAction {
    pub action_id: String,
    pub action_type: MitigationActionType,
    pub description: String,
    pub executed_at: Option<DateTime<Utc>>,
    pub executed_by: Option<String>,
    pub effectiveness: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationActionType {
    UserNotification,
    AccessRestriction,
    SessionTermination,
    AccountLock,
    MfaRequired,
    PolicyUpdate,
    MonitoringIncrease,
    ThreatHunting,
    IncidentEscalation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub user_id: String,
    pub score: f32,
    pub risk_level: RiskLevel,
    pub calculated_at: DateTime<Utc>,
    pub contributing_factors: Vec<RiskContributor>,
    pub trend: RiskTrend,
    pub peer_comparison: f32,
    pub historical_scores: Vec<HistoricalScore>,
    pub next_review: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContributor {
    pub factor: String,
    pub weight: f32,
    pub contribution: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskTrend {
    Decreasing,
    Stable,
    Increasing,
    Volatile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalScore {
    pub timestamp: DateTime<Utc>,
    pub score: f32,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEvent {
    pub event_id: String,
    pub user_id: String,
    pub event_type: EventType,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub attributes: HashMap<String, serde_json::Value>,
    pub risk_score: Option<f32>,
    pub processed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    Login,
    Logout,
    FileAccess,
    DataDownload,
    ApplicationLaunch,
    NetworkConnection,
    EmailSent,
    SystemCommand,
    PrivilegeEscalation,
    PolicyViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLModel {
    pub model_id: String,
    pub model_name: String,
    pub model_type: ModelType,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub last_trained: DateTime<Utc>,
    pub training_data_size: u64,
    pub accuracy: f32,
    pub precision: f32,
    pub recall: f32,
    pub f1_score: f32,
    pub false_positive_rate: f32,
    pub model_parameters: HashMap<String, serde_json::Value>,
    pub feature_importance: HashMap<String, f32>,
    pub deployment_status: DeploymentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentStatus {
    Training,
    Testing,
    Deployed,
    Deprecated,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalyticsStats {
    pub total_users: u64,
    pub users_with_baselines: u64,
    pub active_anomalies: u64,
    pub resolved_anomalies: u64,
    pub false_positives: u64,
    pub high_risk_users: u64,
    pub medium_risk_users: u64,
    pub low_risk_users: u64,
    pub events_processed_today: u64,
    pub models_deployed: u64,
    pub average_model_accuracy: f32,
    pub detection_rate: f32,
    pub false_positive_rate: f32,
    pub top_anomaly_types: HashMap<String, u64>,
    pub risk_distribution: HashMap<String, u64>,
}

impl BehavioralAnalyticsManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            user_profiles: Arc::new(RwLock::new(HashMap::new())),
            behavior_baselines: Arc::new(RwLock::new(HashMap::new())),
            anomalies: Arc::new(RwLock::new(HashMap::new())),
            risk_scores: Arc::new(RwLock::new(HashMap::new())),
            behavior_events: Arc::new(RwLock::new(Vec::new())),
            ml_models: Arc::new(RwLock::new(HashMap::new())),
            signing_key: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn initialize(&self) -> Result<()> {
        // Generate signing keypair for behavioral analytics verification
        let signing_key = DilithiumPrivateKey::from_bytes(vec![0u8; 32], DilithiumVariant::default())?;
        *self.signing_key.write().unwrap() = Some(signing_key);
        
        // Initialize with sample data
        self.create_sample_data().await?;
        
        Ok(())
    }

    async fn create_sample_data(&self) -> Result<()> {
        // Create sample user profiles
        let sample_profiles = vec![
            UserBehaviorProfile {
                user_id: "user_001".to_string(),
                username: "john.doe".to_string(),
                department: "Engineering".to_string(),
                role: "Senior Developer".to_string(),
                created_at: Utc::now() - Duration::days(90),
                last_updated: Utc::now(),
                baseline_established: true,
                behavior_patterns: vec![
                    BehaviorPattern {
                        pattern_id: Uuid::new_v4().to_string(),
                        pattern_type: PatternType::LoginTiming,
                        description: "Regular 9-5 login pattern".to_string(),
                        frequency: 0.95,
                        confidence: 0.87,
                        first_observed: Utc::now() - Duration::days(90),
                        last_observed: Utc::now(),
                        attributes: {
                            let mut attrs = HashMap::new();
                            attrs.insert("typical_login_hour".to_string(), serde_json::Value::Number(serde_json::Number::from(9)));
                            attrs.insert("typical_logout_hour".to_string(), serde_json::Value::Number(serde_json::Number::from(17)));
                            attrs
                        },
                    }
                ],
                typical_hours: WorkingHours {
                    start_hour: 9,
                    end_hour: 17,
                    timezone: "UTC".to_string(),
                    working_days: vec![1, 2, 3, 4, 5], // Monday-Friday
                    flexibility_minutes: 30,
                },
                typical_locations: vec![
                    Location {
                        location_id: "loc_001".to_string(),
                        location_type: LocationType::Office,
                        ip_address: Some("192.168.1.100".to_string()),
                        country: "US".to_string(),
                        city: "San Francisco".to_string(),
                        coordinates: Some((37.7749, -122.4194)),
                        frequency: 0.8,
                        first_seen: Utc::now() - Duration::days(90),
                        last_seen: Utc::now(),
                    }
                ],
                typical_devices: vec![
                    Device {
                        device_id: "dev_001".to_string(),
                        device_type: DeviceType::Laptop,
                        os_type: "Windows".to_string(),
                        os_version: "11".to_string(),
                        browser: Some("Chrome".to_string()),
                        frequency: 0.9,
                        first_seen: Utc::now() - Duration::days(90),
                        last_seen: Utc::now(),
                        trusted: true,
                    }
                ],
                typical_applications: vec![
                    Application {
                        app_id: "app_001".to_string(),
                        app_name: "Visual Studio Code".to_string(),
                        app_category: AppCategory::Development,
                        usage_frequency: 0.95,
                        typical_duration: 480, // 8 hours
                        data_sensitivity: SensitivityLevel::Internal,
                        first_used: Utc::now() - Duration::days(90),
                        last_used: Utc::now(),
                    }
                ],
                risk_factors: vec![],
                peer_group: "senior_developers".to_string(),
                sensitivity_level: SensitivityLevel::Internal,
            },
            UserBehaviorProfile {
                user_id: "user_002".to_string(),
                username: "jane.smith".to_string(),
                department: "Finance".to_string(),
                role: "Financial Analyst".to_string(),
                created_at: Utc::now() - Duration::days(60),
                last_updated: Utc::now(),
                baseline_established: true,
                behavior_patterns: vec![],
                typical_hours: WorkingHours {
                    start_hour: 8,
                    end_hour: 16,
                    timezone: "UTC".to_string(),
                    working_days: vec![1, 2, 3, 4, 5],
                    flexibility_minutes: 15,
                },
                typical_locations: vec![],
                typical_devices: vec![],
                typical_applications: vec![],
                risk_factors: vec![
                    RiskFactor {
                        factor_id: Uuid::new_v4().to_string(),
                        factor_type: RiskFactorType::PrivilegedAccess,
                        description: "Has access to financial systems".to_string(),
                        weight: 0.3,
                        active: true,
                        detected_at: Utc::now() - Duration::days(60),
                    }
                ],
                peer_group: "financial_analysts".to_string(),
                sensitivity_level: SensitivityLevel::Confidential,
            },
        ];

        // Create sample anomalies
        let sample_anomalies = vec![
            BehaviorAnomaly {
                anomaly_id: Uuid::new_v4().to_string(),
                user_id: "user_001".to_string(),
                anomaly_type: AnomalyType::TimeAnomaly,
                severity: AnomalySeverity::Medium,
                confidence: 0.78,
                detected_at: Utc::now() - Duration::hours(2),
                description: "User logged in at unusual time (2:30 AM)".to_string(),
                affected_metrics: vec!["login_time".to_string()],
                deviation_score: 2.3,
                context: AnomalyContext {
                    triggering_event: BehaviorEvent {
                        event_id: Uuid::new_v4().to_string(),
                        user_id: "user_001".to_string(),
                        event_type: EventType::Login,
                        timestamp: Utc::now() - Duration::hours(2),
                        source: "Active Directory".to_string(),
                        attributes: {
                            let mut attrs = HashMap::new();
                            attrs.insert("login_time".to_string(), serde_json::Value::String("02:30:00".to_string()));
                            attrs.insert("ip_address".to_string(), serde_json::Value::String("192.168.1.100".to_string()));
                            attrs
                        },
                        risk_score: Some(0.6),
                        processed: true,
                    },
                    baseline_comparison: BaselineComparison {
                        expected_value: 9.0,
                        actual_value: 2.5,
                        deviation_percentage: -72.2,
                        standard_deviations: 2.3,
                    },
                    peer_comparison: PeerComparison {
                        peer_group_id: "senior_developers".to_string(),
                        peer_group_size: 15,
                        similarity_score: 0.85,
                        deviation_from_peers: 2.1,
                        percentile_ranking: 5.0,
                    },
                    environmental_factors: {
                        let mut factors = HashMap::new();
                        factors.insert("day_of_week".to_string(), "Tuesday".to_string());
                        factors.insert("holiday".to_string(), "false".to_string());
                        factors
                    },
                    threat_intelligence: None,
                },
                investigation_status: InvestigationStatus::New,
                false_positive: false,
                analyst_notes: String::new(),
                related_events: vec![],
                mitigation_actions: vec![],
            }
        ];

        // Create sample risk scores
        let sample_risk_scores = vec![
            RiskScore {
                user_id: "user_001".to_string(),
                score: 0.25,
                risk_level: RiskLevel::Low,
                calculated_at: Utc::now(),
                contributing_factors: vec![
                    RiskContributor {
                        factor: "Off-hours login".to_string(),
                        weight: 0.3,
                        contribution: 0.18,
                        description: "Recent login outside normal hours".to_string(),
                    },
                    RiskContributor {
                        factor: "Baseline deviation".to_string(),
                        weight: 0.2,
                        contribution: 0.07,
                        description: "Minor deviation from established patterns".to_string(),
                    },
                ],
                trend: RiskTrend::Stable,
                peer_comparison: 0.15,
                historical_scores: vec![
                    HistoricalScore {
                        timestamp: Utc::now() - Duration::days(1),
                        score: 0.22,
                        risk_level: RiskLevel::Low,
                    }
                ],
                next_review: Utc::now() + Duration::hours(24),
            },
            RiskScore {
                user_id: "user_002".to_string(),
                score: 0.45,
                risk_level: RiskLevel::Medium,
                calculated_at: Utc::now(),
                contributing_factors: vec![
                    RiskContributor {
                        factor: "Privileged access".to_string(),
                        weight: 0.4,
                        contribution: 0.30,
                        description: "Has access to sensitive financial data".to_string(),
                    },
                    RiskContributor {
                        factor: "Data sensitivity".to_string(),
                        weight: 0.25,
                        contribution: 0.15,
                        description: "Works with confidential information".to_string(),
                    },
                ],
                trend: RiskTrend::Stable,
                peer_comparison: 0.38,
                historical_scores: vec![],
                next_review: Utc::now() + Duration::hours(12),
            },
        ];

        // Create sample ML models
        let sample_models = vec![
            MLModel {
                model_id: "model_001".to_string(),
                model_name: "Login Anomaly Detector".to_string(),
                model_type: ModelType::IsolationForest,
                version: "1.2.0".to_string(),
                created_at: Utc::now() - Duration::days(30),
                last_trained: Utc::now() - Duration::days(7),
                training_data_size: 50000,
                accuracy: 0.87,
                precision: 0.82,
                recall: 0.79,
                f1_score: 0.80,
                false_positive_rate: 0.05,
                model_parameters: {
                    let mut params = HashMap::new();
                    params.insert("contamination".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(0.1).unwrap()));
                    params.insert("n_estimators".to_string(), serde_json::Value::Number(serde_json::Number::from(100)));
                    params
                },
                feature_importance: {
                    let mut importance = HashMap::new();
                    importance.insert("login_time".to_string(), 0.35);
                    importance.insert("location".to_string(), 0.28);
                    importance.insert("device".to_string(), 0.22);
                    importance.insert("day_of_week".to_string(), 0.15);
                    importance
                },
                deployment_status: DeploymentStatus::Deployed,
            }
        ];

        // Store sample data
        for profile in sample_profiles {
            self.user_profiles.write().unwrap().insert(profile.user_id.clone(), profile);
        }

        for anomaly in sample_anomalies {
            self.anomalies.write().unwrap().insert(anomaly.anomaly_id.clone(), anomaly);
        }

        for risk_score in sample_risk_scores {
            self.risk_scores.write().unwrap().insert(risk_score.user_id.clone(), risk_score);
        }

        for model in sample_models {
            self.ml_models.write().unwrap().insert(model.model_id.clone(), model);
        }

        Ok(())
    }

    pub async fn get_user_profiles(&self) -> Result<Vec<UserBehaviorProfile>> {
        Ok(self.user_profiles.read().unwrap().values().cloned().collect())
    }

    pub async fn get_user_profile(&self, user_id: &str) -> Result<Option<UserBehaviorProfile>> {
        Ok(self.user_profiles.read().unwrap().get(user_id).cloned())
    }

    pub async fn get_anomalies(&self) -> Result<Vec<BehaviorAnomaly>> {
        Ok(self.anomalies.read().unwrap().values().cloned().collect())
    }

    pub async fn get_anomaly(&self, anomaly_id: &str) -> Result<Option<BehaviorAnomaly>> {
        Ok(self.anomalies.read().unwrap().get(anomaly_id).cloned())
    }

    pub async fn get_risk_scores(&self) -> Result<Vec<RiskScore>> {
        Ok(self.risk_scores.read().unwrap().values().cloned().collect())
    }

    pub async fn get_user_risk_score(&self, user_id: &str) -> Result<Option<RiskScore>> {
        Ok(self.risk_scores.read().unwrap().get(user_id).cloned())
    }

    pub async fn analyze_behavior(&self, user_id: String, events: Vec<BehaviorEvent>) -> Result<Vec<BehaviorAnomaly>> {
        // Simulate behavior analysis
        let mut detected_anomalies = Vec::new();

        for event in events {
            // Simple anomaly detection simulation
            if let Some(profile) = self.user_profiles.read().unwrap().get(&user_id) {
                let mut anomaly_detected = false;
                let mut anomaly_type = AnomalyType::PatternAnomaly;
                let mut severity = AnomalySeverity::Low;
                let mut description = String::new();

                // Check for time-based anomalies
                if let EventType::Login = event.event_type {
                    let hour = event.timestamp.hour();
                    if hour < profile.typical_hours.start_hour as u32 || hour > profile.typical_hours.end_hour as u32 {
                        anomaly_detected = true;
                        anomaly_type = AnomalyType::TimeAnomaly;
                        severity = AnomalySeverity::Medium;
                        description = format!("Login at unusual hour: {}:00", hour);
                    }
                }

                if anomaly_detected {
                    let anomaly = BehaviorAnomaly {
                        anomaly_id: Uuid::new_v4().to_string(),
                        user_id: user_id.clone(),
                        anomaly_type,
                        severity,
                        confidence: 0.75,
                        detected_at: Utc::now(),
                        description,
                        affected_metrics: vec!["timing".to_string()],
                        deviation_score: 2.0,
                        context: AnomalyContext {
                            triggering_event: event.clone(),
                            baseline_comparison: BaselineComparison {
                                expected_value: profile.typical_hours.start_hour as f32,
                                actual_value: event.timestamp.hour() as f32,
                                deviation_percentage: 50.0,
                                standard_deviations: 2.0,
                            },
                            peer_comparison: PeerComparison {
                                peer_group_id: profile.peer_group.clone(),
                                peer_group_size: 10,
                                similarity_score: 0.8,
                                deviation_from_peers: 1.5,
                                percentile_ranking: 10.0,
                            },
                            environmental_factors: HashMap::new(),
                            threat_intelligence: None,
                        },
                        investigation_status: InvestigationStatus::New,
                        false_positive: false,
                        analyst_notes: String::new(),
                        related_events: vec![event.event_id.clone()],
                        mitigation_actions: vec![],
                    };

                    // Store the anomaly
                    self.anomalies.write().unwrap().insert(anomaly.anomaly_id.clone(), anomaly.clone());
                    detected_anomalies.push(anomaly);
                }
            }

            // Store the event
            self.behavior_events.write().unwrap().push(event);
        }

        Ok(detected_anomalies)
    }

    pub async fn update_risk_score(&self, user_id: String) -> Result<RiskScore> {
        let mut base_score = 0.1; // Base risk score
        let mut contributing_factors = Vec::new();

        // Get user profile
        if let Some(profile) = self.user_profiles.read().unwrap().get(&user_id) {
            // Add risk based on role and access
            match profile.sensitivity_level {
                SensitivityLevel::TopSecret => {
                    base_score += 0.4;
                    contributing_factors.push(RiskContributor {
                        factor: "Top Secret Access".to_string(),
                        weight: 0.4,
                        contribution: 0.4,
                        description: "User has top secret clearance".to_string(),
                    });
                },
                SensitivityLevel::Confidential => {
                    base_score += 0.2;
                    contributing_factors.push(RiskContributor {
                        factor: "Confidential Access".to_string(),
                        weight: 0.2,
                        contribution: 0.2,
                        description: "User has confidential access".to_string(),
                    });
                },
                _ => {}
            }

            // Add risk based on recent anomalies
            let anomalies_guard = self.anomalies.read().unwrap();
            let recent_anomalies: Vec<_> = anomalies_guard
                .values()
                .filter(|a| a.user_id == user_id && a.detected_at > Utc::now() - Duration::days(7))
                .collect();

            if !recent_anomalies.is_empty() {
                let anomaly_risk = recent_anomalies.len() as f32 * 0.1;
                base_score += anomaly_risk;
                contributing_factors.push(RiskContributor {
                    factor: "Recent Anomalies".to_string(),
                    weight: 0.3,
                    contribution: anomaly_risk,
                    description: format!("{} anomalies in the last 7 days", recent_anomalies.len()),
                });
            }
        }

        // Cap the score at 1.0
        base_score = base_score.min(1.0);

        let risk_level = match base_score {
            s if s < 0.2 => RiskLevel::VeryLow,
            s if s < 0.4 => RiskLevel::Low,
            s if s < 0.6 => RiskLevel::Medium,
            s if s < 0.8 => RiskLevel::High,
            s if s < 0.95 => RiskLevel::VeryHigh,
            _ => RiskLevel::Critical,
        };

        let risk_score = RiskScore {
            user_id: user_id.clone(),
            score: base_score,
            risk_level,
            calculated_at: Utc::now(),
            contributing_factors,
            trend: RiskTrend::Stable,
            peer_comparison: 0.3,
            historical_scores: vec![],
            next_review: Utc::now() + Duration::hours(24),
        };

        // Store the updated risk score
        self.risk_scores.write().unwrap().insert(user_id, risk_score.clone());

        Ok(risk_score)
    }

    pub async fn get_ml_models(&self) -> Result<Vec<MLModel>> {
        Ok(self.ml_models.read().unwrap().values().cloned().collect())
    }

    pub async fn get_stats(&self) -> Result<BehavioralAnalyticsStats> {
        let profiles = self.user_profiles.read().unwrap();
        let anomalies = self.anomalies.read().unwrap();
        let risk_scores = self.risk_scores.read().unwrap();
        let models = self.ml_models.read().unwrap();
        let events = self.behavior_events.read().unwrap();

        let users_with_baselines = profiles.values()
            .filter(|p| p.baseline_established)
            .count() as u64;

        let active_anomalies = anomalies.values()
            .filter(|a| matches!(a.investigation_status, InvestigationStatus::New | InvestigationStatus::InProgress))
            .count() as u64;

        let resolved_anomalies = anomalies.values()
            .filter(|a| matches!(a.investigation_status, InvestigationStatus::Resolved))
            .count() as u64;

        let false_positives = anomalies.values()
            .filter(|a| a.false_positive)
            .count() as u64;

        let high_risk_users = risk_scores.values()
            .filter(|r| matches!(r.risk_level, RiskLevel::High | RiskLevel::VeryHigh | RiskLevel::Critical))
            .count() as u64;

        let medium_risk_users = risk_scores.values()
            .filter(|r| matches!(r.risk_level, RiskLevel::Medium))
            .count() as u64;

        let low_risk_users = risk_scores.values()
            .filter(|r| matches!(r.risk_level, RiskLevel::Low | RiskLevel::VeryLow))
            .count() as u64;

        let events_processed_today = events.iter()
            .filter(|e| e.timestamp > Utc::now() - Duration::days(1))
            .count() as u64;

        let models_deployed = models.values()
            .filter(|m| matches!(m.deployment_status, DeploymentStatus::Deployed))
            .count() as u64;

        let average_model_accuracy = if models_deployed > 0 {
            models.values()
                .filter(|m| matches!(m.deployment_status, DeploymentStatus::Deployed))
                .map(|m| m.accuracy)
                .sum::<f32>() / models_deployed as f32
        } else {
            0.0
        };

        let detection_rate = if events_processed_today > 0 {
            active_anomalies as f32 / events_processed_today as f32
        } else {
            0.0
        };

        let false_positive_rate = if (active_anomalies + resolved_anomalies + false_positives) > 0 {
            false_positives as f32 / (active_anomalies + resolved_anomalies + false_positives) as f32
        } else {
            0.0
        };

        let mut top_anomaly_types = HashMap::new();
        for anomaly in anomalies.values() {
            let anomaly_type = format!("{:?}", anomaly.anomaly_type);
            *top_anomaly_types.entry(anomaly_type).or_insert(0) += 1;
        }

        let mut risk_distribution = HashMap::new();
        for risk_score in risk_scores.values() {
            let risk_level = format!("{:?}", risk_score.risk_level);
            *risk_distribution.entry(risk_level).or_insert(0) += 1;
        }

        Ok(BehavioralAnalyticsStats {
            total_users: profiles.len() as u64,
            users_with_baselines,
            active_anomalies,
            resolved_anomalies,
            false_positives,
            high_risk_users,
            medium_risk_users,
            low_risk_users,
            events_processed_today,
            models_deployed,
            average_model_accuracy,
            detection_rate,
            false_positive_rate,
            top_anomaly_types,
            risk_distribution,
        })
    }

    pub async fn generate_signing_keypair(&self) -> Result<(String, String)> {
        let _private_key = DilithiumPrivateKey::from_bytes(vec![0u8; 32], DilithiumVariant::default())?;
        let _public_key = DilithiumPublicKey::from_bytes(vec![0u8; 32], DilithiumVariant::default())?;
        
        Ok((
            format!("dilithium_private_key_placeholder"),
            format!("dilithium_public_key_placeholder")
        ))
    }
}

// Tauri Commands
#[tauri::command]
pub async fn behavioral_analytics_get_profiles(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
) -> Result<Vec<UserBehaviorProfile>, String> {
    let manager = manager.lock().await;
    manager.get_user_profiles().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn behavioral_analytics_get_profile(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
    user_id: String,
) -> Result<Option<UserBehaviorProfile>, String> {
    let manager = manager.lock().await;
    manager.get_user_profile(&user_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn behavioral_analytics_get_anomalies(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
) -> Result<Vec<BehaviorAnomaly>, String> {
    let manager = manager.lock().await;
    manager.get_anomalies().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn behavioral_analytics_get_anomaly(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
    anomaly_id: String,
) -> Result<Option<BehaviorAnomaly>, String> {
    let manager = manager.lock().await;
    manager.get_anomaly(&anomaly_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn behavioral_analytics_get_risk_scores(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
) -> Result<Vec<RiskScore>, String> {
    let manager = manager.lock().await;
    manager.get_risk_scores().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn behavioral_analytics_get_user_risk_score(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
    user_id: String,
) -> Result<Option<RiskScore>, String> {
    let manager = manager.lock().await;
    manager.get_user_risk_score(&user_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn behavioral_analytics_analyze_behavior(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
    user_id: String,
    events: Vec<BehaviorEvent>,
) -> Result<Vec<BehaviorAnomaly>, String> {
    let manager = manager.lock().await;
    manager.analyze_behavior(user_id, events).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn behavioral_analytics_update_risk_score(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
    user_id: String,
) -> Result<RiskScore, String> {
    let manager = manager.lock().await;
    manager.update_risk_score(user_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn behavioral_analytics_get_models(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
) -> Result<Vec<MLModel>, String> {
    let manager = manager.lock().await;
    manager.get_ml_models().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn behavioral_analytics_get_stats(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<BehavioralAnalyticsManager>>>,
) -> Result<BehavioralAnalyticsStats, String> {
    let manager = manager.lock().await;
    manager.get_stats().await.map_err(|e| e.to_string())
}
