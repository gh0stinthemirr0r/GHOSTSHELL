use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::security::PepState;
use ghost_pq::{DilithiumPrivateKey, DilithiumPublicKey, DilithiumVariant};

// Core data structures for Security Automation Platform

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAutomationStats {
    pub active_workflows: u32,
    pub total_executions: u32,
    pub successful_executions: u32,
    pub failed_executions: u32,
    pub avg_execution_time: f32,
    pub automation_nodes: u32,
    pub scheduled_workflows: u32,
    pub trigger_events_24h: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub workflow_id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub status: WorkflowStatus,
    pub category: WorkflowCategory,
    pub nodes: Vec<WorkflowNode>,
    pub connections: Vec<NodeConnection>,
    pub triggers: Vec<WorkflowTrigger>,
    pub variables: HashMap<String, WorkflowVariable>,
    pub metadata: WorkflowMetadata,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowStatus {
    Draft,
    Active,
    Inactive,
    Testing,
    Deprecated,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowCategory {
    IncidentResponse,
    ThreatHunting,
    Compliance,
    DataCollection,
    Notification,
    Remediation,
    Analysis,
    Integration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowNode {
    pub node_id: String,
    pub node_type: NodeType,
    pub name: String,
    pub description: String,
    pub position: NodePosition,
    pub configuration: NodeConfiguration,
    pub input_ports: Vec<NodePort>,
    pub output_ports: Vec<NodePort>,
    pub execution_order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Trigger,
    Action,
    Condition,
    Loop,
    Delay,
    Notification,
    DataTransform,
    APICall,
    ScriptExecution,
    DatabaseQuery,
    FileOperation,
    NetworkScan,
    ThreatAnalysis,
    UserInput,
    Approval,
    End,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePosition {
    pub x: f32,
    pub y: f32,
    pub z: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfiguration {
    pub parameters: HashMap<String, serde_json::Value>,
    pub timeout: Option<u32>,
    pub retry_count: Option<u32>,
    pub error_handling: ErrorHandling,
    pub parallel_execution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorHandling {
    Continue,
    Stop,
    Retry,
    Escalate,
    Ignore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePort {
    pub port_id: String,
    pub port_name: String,
    pub port_type: PortType,
    pub data_type: DataType,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortType {
    Input,
    Output,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataType {
    String,
    Number,
    Boolean,
    Object,
    Array,
    File,
    Event,
    Alert,
    User,
    Asset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConnection {
    pub connection_id: String,
    pub source_node_id: String,
    pub source_port_id: String,
    pub target_node_id: String,
    pub target_port_id: String,
    pub condition: Option<String>,
    pub data_mapping: Option<DataMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMapping {
    pub source_field: String,
    pub target_field: String,
    pub transformation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTrigger {
    pub trigger_id: String,
    pub trigger_type: TriggerType,
    pub name: String,
    pub configuration: TriggerConfiguration,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerType {
    Schedule,
    Event,
    Webhook,
    FileWatch,
    Threshold,
    Manual,
    API,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerConfiguration {
    pub parameters: HashMap<String, serde_json::Value>,
    pub conditions: Vec<TriggerCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCondition {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
    pub logical_operator: Option<LogicalOperator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowVariable {
    pub variable_id: String,
    pub name: String,
    pub data_type: DataType,
    pub default_value: Option<serde_json::Value>,
    pub description: String,
    pub scope: VariableScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableScope {
    Global,
    Workflow,
    Node,
    Execution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowMetadata {
    pub tags: Vec<String>,
    pub priority: Priority,
    pub estimated_duration: Option<u32>,
    pub resource_requirements: ResourceRequirements,
    pub compliance_frameworks: Vec<String>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
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
pub struct ResourceRequirements {
    pub cpu_cores: Option<u32>,
    pub memory_mb: Option<u32>,
    pub disk_space_mb: Option<u32>,
    pub network_bandwidth: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    pub execution_id: String,
    pub workflow_id: String,
    pub workflow_version: String,
    pub status: ExecutionStatus,
    pub trigger_source: String,
    pub input_data: HashMap<String, serde_json::Value>,
    pub output_data: HashMap<String, serde_json::Value>,
    pub node_executions: Vec<NodeExecution>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u32>,
    pub error_message: Option<String>,
    pub executed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Paused,
    Waiting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeExecution {
    pub node_execution_id: String,
    pub node_id: String,
    pub status: ExecutionStatus,
    pub input_data: HashMap<String, serde_json::Value>,
    pub output_data: HashMap<String, serde_json::Value>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u32>,
    pub error_message: Option<String>,
    pub retry_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    pub template_id: String,
    pub name: String,
    pub description: String,
    pub category: WorkflowCategory,
    pub template_data: Workflow,
    pub use_count: u32,
    pub rating: f32,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub is_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub conditions: Vec<RuleCondition>,
    pub actions: Vec<RuleAction>,
    pub enabled: bool,
    pub priority: Priority,
    pub created_at: DateTime<Utc>,
    pub last_triggered: Option<DateTime<Utc>>,
    pub trigger_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub condition_id: String,
    pub condition_type: String,
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
    pub weight: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAction {
    pub action_id: String,
    pub action_type: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub delay_seconds: Option<u32>,
}

// Main Security Automation Platform Manager
pub struct SecurityAutomationManager {
    workflows: Arc<RwLock<HashMap<String, Workflow>>>,
    executions: Arc<RwLock<HashMap<String, WorkflowExecution>>>,
    templates: Arc<RwLock<HashMap<String, WorkflowTemplate>>>,
    automation_rules: Arc<RwLock<HashMap<String, AutomationRule>>>,
    signing_keys: Arc<RwLock<HashMap<String, (DilithiumPublicKey, DilithiumPrivateKey)>>>,
}

impl SecurityAutomationManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            workflows: Arc::new(RwLock::new(HashMap::new())),
            executions: Arc::new(RwLock::new(HashMap::new())),
            templates: Arc::new(RwLock::new(HashMap::new())),
            automation_rules: Arc::new(RwLock::new(HashMap::new())),
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn initialize(&self) -> Result<()> {
        self.create_sample_data().await?;
        Ok(())
    }

    async fn create_sample_data(&self) -> Result<()> {
        // Create sample workflows
        let mut workflows = self.workflows.write().await;
        
        let incident_response_workflow = Workflow {
            workflow_id: "workflow_incident_001".to_string(),
            name: "Automated Incident Response".to_string(),
            description: "Comprehensive incident response workflow with automated containment and notification".to_string(),
            version: "1.2.0".to_string(),
            status: WorkflowStatus::Active,
            category: WorkflowCategory::IncidentResponse,
            nodes: vec![
                WorkflowNode {
                    node_id: "node_trigger_001".to_string(),
                    node_type: NodeType::Trigger,
                    name: "Security Alert Trigger".to_string(),
                    description: "Triggered when a security alert is received".to_string(),
                    position: NodePosition { x: 100.0, y: 100.0, z: None },
                    configuration: NodeConfiguration {
                        parameters: HashMap::from([
                            ("alert_severity".to_string(), serde_json::Value::String("high".to_string())),
                        ]),
                        timeout: Some(30),
                        retry_count: Some(3),
                        error_handling: ErrorHandling::Stop,
                        parallel_execution: false,
                    },
                    input_ports: vec![],
                    output_ports: vec![
                        NodePort {
                            port_id: "out_alert".to_string(),
                            port_name: "Alert Data".to_string(),
                            port_type: PortType::Output,
                            data_type: DataType::Alert,
                            required: true,
                        },
                    ],
                    execution_order: 1,
                },
                WorkflowNode {
                    node_id: "node_analysis_001".to_string(),
                    node_type: NodeType::ThreatAnalysis,
                    name: "Threat Analysis".to_string(),
                    description: "Analyze the threat using AI models".to_string(),
                    position: NodePosition { x: 300.0, y: 100.0, z: None },
                    configuration: NodeConfiguration {
                        parameters: HashMap::from([
                            ("model_id".to_string(), serde_json::Value::String("model_threat_001".to_string())),
                            ("confidence_threshold".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(0.8).unwrap())),
                        ]),
                        timeout: Some(120),
                        retry_count: Some(2),
                        error_handling: ErrorHandling::Continue,
                        parallel_execution: false,
                    },
                    input_ports: vec![
                        NodePort {
                            port_id: "in_alert".to_string(),
                            port_name: "Alert Data".to_string(),
                            port_type: PortType::Input,
                            data_type: DataType::Alert,
                            required: true,
                        },
                    ],
                    output_ports: vec![
                        NodePort {
                            port_id: "out_analysis".to_string(),
                            port_name: "Analysis Result".to_string(),
                            port_type: PortType::Output,
                            data_type: DataType::Object,
                            required: true,
                        },
                    ],
                    execution_order: 2,
                },
                WorkflowNode {
                    node_id: "node_containment_001".to_string(),
                    node_type: NodeType::Action,
                    name: "Automated Containment".to_string(),
                    description: "Isolate affected systems automatically".to_string(),
                    position: NodePosition { x: 500.0, y: 100.0, z: None },
                    configuration: NodeConfiguration {
                        parameters: HashMap::from([
                            ("isolation_method".to_string(), serde_json::Value::String("network".to_string())),
                            ("approval_required".to_string(), serde_json::Value::Bool(false)),
                        ]),
                        timeout: Some(60),
                        retry_count: Some(1),
                        error_handling: ErrorHandling::Escalate,
                        parallel_execution: false,
                    },
                    input_ports: vec![
                        NodePort {
                            port_id: "in_analysis".to_string(),
                            port_name: "Analysis Result".to_string(),
                            port_type: PortType::Input,
                            data_type: DataType::Object,
                            required: true,
                        },
                    ],
                    output_ports: vec![
                        NodePort {
                            port_id: "out_containment".to_string(),
                            port_name: "Containment Status".to_string(),
                            port_type: PortType::Output,
                            data_type: DataType::Object,
                            required: true,
                        },
                    ],
                    execution_order: 3,
                },
            ],
            connections: vec![
                NodeConnection {
                    connection_id: "conn_001".to_string(),
                    source_node_id: "node_trigger_001".to_string(),
                    source_port_id: "out_alert".to_string(),
                    target_node_id: "node_analysis_001".to_string(),
                    target_port_id: "in_alert".to_string(),
                    condition: None,
                    data_mapping: None,
                },
                NodeConnection {
                    connection_id: "conn_002".to_string(),
                    source_node_id: "node_analysis_001".to_string(),
                    source_port_id: "out_analysis".to_string(),
                    target_node_id: "node_containment_001".to_string(),
                    target_port_id: "in_analysis".to_string(),
                    condition: Some("confidence > 0.8".to_string()),
                    data_mapping: None,
                },
            ],
            triggers: vec![
                WorkflowTrigger {
                    trigger_id: "trigger_001".to_string(),
                    trigger_type: TriggerType::Event,
                    name: "High Severity Alert".to_string(),
                    configuration: TriggerConfiguration {
                        parameters: HashMap::from([
                            ("event_type".to_string(), serde_json::Value::String("security_alert".to_string())),
                            ("severity".to_string(), serde_json::Value::String("high".to_string())),
                        ]),
                        conditions: vec![
                            TriggerCondition {
                                field: "severity".to_string(),
                                operator: "equals".to_string(),
                                value: serde_json::Value::String("high".to_string()),
                                logical_operator: None,
                            },
                        ],
                    },
                    enabled: true,
                },
            ],
            variables: HashMap::from([
                ("incident_id".to_string(), WorkflowVariable {
                    variable_id: "var_001".to_string(),
                    name: "incident_id".to_string(),
                    data_type: DataType::String,
                    default_value: None,
                    description: "Unique incident identifier".to_string(),
                    scope: VariableScope::Workflow,
                }),
            ]),
            metadata: WorkflowMetadata {
                tags: vec!["incident".to_string(), "response".to_string(), "automated".to_string()],
                priority: Priority::High,
                estimated_duration: Some(300),
                resource_requirements: ResourceRequirements {
                    cpu_cores: Some(2),
                    memory_mb: Some(512),
                    disk_space_mb: Some(100),
                    network_bandwidth: Some(10),
                },
                compliance_frameworks: vec!["NIST".to_string(), "ISO27001".to_string()],
                risk_level: RiskLevel::Medium,
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "system".to_string(),
        };

        workflows.insert(incident_response_workflow.workflow_id.clone(), incident_response_workflow);
        drop(workflows);

        // Create sample executions
        let mut executions = self.executions.write().await;
        
        let sample_execution = WorkflowExecution {
            execution_id: "exec_001".to_string(),
            workflow_id: "workflow_incident_001".to_string(),
            workflow_version: "1.2.0".to_string(),
            status: ExecutionStatus::Completed,
            trigger_source: "security_alert".to_string(),
            input_data: HashMap::from([
                ("alert_id".to_string(), serde_json::Value::String("alert_12345".to_string())),
                ("severity".to_string(), serde_json::Value::String("high".to_string())),
            ]),
            output_data: HashMap::from([
                ("containment_status".to_string(), serde_json::Value::String("success".to_string())),
                ("affected_systems".to_string(), serde_json::Value::Number(serde_json::Number::from(3))),
            ]),
            node_executions: vec![
                NodeExecution {
                    node_execution_id: "node_exec_001".to_string(),
                    node_id: "node_trigger_001".to_string(),
                    status: ExecutionStatus::Completed,
                    input_data: HashMap::new(),
                    output_data: HashMap::from([
                        ("alert_data".to_string(), serde_json::Value::String("alert_payload".to_string())),
                    ]),
                    started_at: Utc::now(),
                    completed_at: Some(Utc::now()),
                    duration_ms: Some(150),
                    error_message: None,
                    retry_count: 0,
                },
            ],
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            duration_ms: Some(285000),
            error_message: None,
            executed_by: "automation_engine".to_string(),
        };

        executions.insert(sample_execution.execution_id.clone(), sample_execution);
        drop(executions);

        // Create sample templates
        let mut templates = self.templates.write().await;
        
        let phishing_template = WorkflowTemplate {
            template_id: "template_phishing_001".to_string(),
            name: "Phishing Response Template".to_string(),
            description: "Standard workflow template for handling phishing incidents".to_string(),
            category: WorkflowCategory::IncidentResponse,
            template_data: Workflow {
                workflow_id: "template_workflow".to_string(),
                name: "Phishing Incident Response".to_string(),
                description: "Automated phishing incident response workflow".to_string(),
                version: "1.0.0".to_string(),
                status: WorkflowStatus::Draft,
                category: WorkflowCategory::IncidentResponse,
                nodes: vec![],
                connections: vec![],
                triggers: vec![],
                variables: HashMap::new(),
                metadata: WorkflowMetadata {
                    tags: vec!["phishing".to_string(), "email".to_string()],
                    priority: Priority::High,
                    estimated_duration: Some(180),
                    resource_requirements: ResourceRequirements {
                        cpu_cores: Some(1),
                        memory_mb: Some(256),
                        disk_space_mb: Some(50),
                        network_bandwidth: Some(5),
                    },
                    compliance_frameworks: vec!["GDPR".to_string()],
                    risk_level: RiskLevel::Medium,
                },
                created_at: Utc::now(),
                updated_at: Utc::now(),
                created_by: "template_system".to_string(),
            },
            use_count: 47,
            rating: 4.7,
            created_at: Utc::now(),
            created_by: "security_team".to_string(),
            is_public: true,
        };

        templates.insert(phishing_template.template_id.clone(), phishing_template);

        Ok(())
    }

    pub async fn get_stats(&self) -> Result<SecurityAutomationStats> {
        let workflows = self.workflows.read().await;
        let executions = self.executions.read().await;

        let active_workflows = workflows.values()
            .filter(|w| matches!(w.status, WorkflowStatus::Active))
            .count() as u32;

        let total_executions = executions.len() as u32;
        let successful_executions = executions.values()
            .filter(|e| matches!(e.status, ExecutionStatus::Completed))
            .count() as u32;
        let failed_executions = executions.values()
            .filter(|e| matches!(e.status, ExecutionStatus::Failed))
            .count() as u32;

        let avg_execution_time = if !executions.is_empty() {
            executions.values()
                .filter_map(|e| e.duration_ms)
                .map(|d| d as f32)
                .sum::<f32>() / executions.len() as f32
        } else {
            0.0
        };

        let automation_nodes = workflows.values()
            .map(|w| w.nodes.len() as u32)
            .sum();

        Ok(SecurityAutomationStats {
            active_workflows,
            total_executions,
            successful_executions,
            failed_executions,
            avg_execution_time,
            automation_nodes,
            scheduled_workflows: 5 + (rand::random::<u32>() % 10),
            trigger_events_24h: 120 + (rand::random::<u32>() % 80),
        })
    }

    pub async fn get_workflows(&self) -> Result<Vec<Workflow>> {
        let workflows = self.workflows.read().await;
        Ok(workflows.values().cloned().collect())
    }

    pub async fn get_workflow(&self, workflow_id: &str) -> Result<Option<Workflow>> {
        let workflows = self.workflows.read().await;
        Ok(workflows.get(workflow_id).cloned())
    }

    pub async fn create_workflow(&self, workflow: Workflow) -> Result<String> {
        let mut workflows = self.workflows.write().await;
        let workflow_id = workflow.workflow_id.clone();
        workflows.insert(workflow_id.clone(), workflow);
        Ok(workflow_id)
    }

    pub async fn get_executions(&self) -> Result<Vec<WorkflowExecution>> {
        let executions = self.executions.read().await;
        Ok(executions.values().cloned().collect())
    }

    pub async fn get_execution(&self, execution_id: &str) -> Result<Option<WorkflowExecution>> {
        let executions = self.executions.read().await;
        Ok(executions.get(execution_id).cloned())
    }

    pub async fn execute_workflow(&self, workflow_id: &str, input_data: HashMap<String, serde_json::Value>) -> Result<String> {
        let execution_id = format!("exec_{}", Uuid::new_v4());
        
        let execution = WorkflowExecution {
            execution_id: execution_id.clone(),
            workflow_id: workflow_id.to_string(),
            workflow_version: "1.0.0".to_string(),
            status: ExecutionStatus::Running,
            trigger_source: "manual".to_string(),
            input_data,
            output_data: HashMap::new(),
            node_executions: vec![],
            started_at: Utc::now(),
            completed_at: None,
            duration_ms: None,
            error_message: None,
            executed_by: "user".to_string(),
        };

        let mut executions = self.executions.write().await;
        executions.insert(execution_id.clone(), execution);

        Ok(execution_id)
    }

    pub async fn get_templates(&self) -> Result<Vec<WorkflowTemplate>> {
        let templates = self.templates.read().await;
        Ok(templates.values().cloned().collect())
    }

    pub async fn create_workflow_from_template(&self, template_id: &str, workflow_name: &str) -> Result<String> {
        let templates = self.templates.read().await;
        
        if let Some(template) = templates.get(template_id) {
            let mut new_workflow = template.template_data.clone();
            new_workflow.workflow_id = format!("workflow_{}", Uuid::new_v4());
            new_workflow.name = workflow_name.to_string();
            new_workflow.status = WorkflowStatus::Draft;
            new_workflow.created_at = Utc::now();
            new_workflow.updated_at = Utc::now();

            drop(templates);
            
            let workflow_id = new_workflow.workflow_id.clone();
            let mut workflows = self.workflows.write().await;
            workflows.insert(workflow_id.clone(), new_workflow);

            Ok(workflow_id)
        } else {
            Err(anyhow::anyhow!("Template not found"))
        }
    }
}

// Tauri command handlers
#[tauri::command]
pub async fn security_automation_get_stats(
    automation_manager: tauri::State<'_, Arc<tokio::sync::Mutex<SecurityAutomationManager>>>,
) -> Result<SecurityAutomationStats, String> {
    let manager = automation_manager.lock().await;
    manager.get_stats().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn security_automation_get_workflows(
    automation_manager: tauri::State<'_, Arc<tokio::sync::Mutex<SecurityAutomationManager>>>,
) -> Result<Vec<Workflow>, String> {
    let manager = automation_manager.lock().await;
    manager.get_workflows().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn security_automation_get_workflow(
    workflow_id: String,
    automation_manager: tauri::State<'_, Arc<tokio::sync::Mutex<SecurityAutomationManager>>>,
) -> Result<Option<Workflow>, String> {
    let manager = automation_manager.lock().await;
    manager.get_workflow(&workflow_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn security_automation_create_workflow(
    workflow: Workflow,
    automation_manager: tauri::State<'_, Arc<tokio::sync::Mutex<SecurityAutomationManager>>>,
) -> Result<String, String> {
    let manager = automation_manager.lock().await;
    manager.create_workflow(workflow).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn security_automation_get_executions(
    automation_manager: tauri::State<'_, Arc<tokio::sync::Mutex<SecurityAutomationManager>>>,
) -> Result<Vec<WorkflowExecution>, String> {
    let manager = automation_manager.lock().await;
    manager.get_executions().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn security_automation_get_execution(
    execution_id: String,
    automation_manager: tauri::State<'_, Arc<tokio::sync::Mutex<SecurityAutomationManager>>>,
) -> Result<Option<WorkflowExecution>, String> {
    let manager = automation_manager.lock().await;
    manager.get_execution(&execution_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn security_automation_execute_workflow(
    workflow_id: String,
    input_data: HashMap<String, serde_json::Value>,
    automation_manager: tauri::State<'_, Arc<tokio::sync::Mutex<SecurityAutomationManager>>>,
) -> Result<String, String> {
    let manager = automation_manager.lock().await;
    manager.execute_workflow(&workflow_id, input_data).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn security_automation_get_templates(
    automation_manager: tauri::State<'_, Arc<tokio::sync::Mutex<SecurityAutomationManager>>>,
) -> Result<Vec<WorkflowTemplate>, String> {
    let manager = automation_manager.lock().await;
    manager.get_templates().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn security_automation_create_from_template(
    template_id: String,
    workflow_name: String,
    automation_manager: tauri::State<'_, Arc<tokio::sync::Mutex<SecurityAutomationManager>>>,
) -> Result<String, String> {
    let manager = automation_manager.lock().await;
    manager.create_workflow_from_template(&template_id, &workflow_name).await.map_err(|e| e.to_string())
}
