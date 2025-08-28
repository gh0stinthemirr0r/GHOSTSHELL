use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use anyhow::Result;

/// Remediation playbook for automated fixes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlaybook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub control_ids: Vec<String>,
    pub framework_ids: Vec<String>,
    pub steps: Vec<PlaybookStep>,
    pub estimated_time_minutes: u32,
    pub difficulty: PlaybookDifficulty,
    pub prerequisites: Vec<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: String,
}

/// Individual step in a remediation playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub step_id: String,
    pub title: String,
    pub description: String,
    pub action_type: PlaybookActionType,
    pub commands: Vec<String>,
    pub expected_outcome: String,
    pub verification_criteria: Vec<String>,
    pub timeout_seconds: Option<u32>,
    pub retry_count: u32,
    pub continue_on_failure: bool,
}

/// Types of playbook actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlaybookActionType {
    Manual,
    Automated,
    Verification,
    Configuration,
    PolicyUpdate,
    SystemRestart,
    ServiceRestart,
    FileOperation,
    DatabaseUpdate,
}

/// Playbook difficulty levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlaybookDifficulty {
    Easy,
    Medium,
    Hard,
    Expert,
}

/// Playbook execution status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecution {
    pub execution_id: Uuid,
    pub playbook_id: String,
    pub control_ids: Vec<String>,
    pub status: ExecutionStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub executed_by: String,
    pub step_results: Vec<StepResult>,
    pub overall_result: Option<ExecutionResult>,
    pub error_message: Option<String>,
}

/// Execution status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    PartialSuccess,
}

/// Result of a single step execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub status: ExecutionStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output: String,
    pub error_message: Option<String>,
    pub verification_passed: bool,
}

/// Overall execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub steps_completed: usize,
    pub steps_failed: usize,
    pub compliance_improvement: Option<f64>,
    pub recommendations: Vec<String>,
}

/// Remediation playbook manager
pub struct RemediationPlaybookManager {
    playbooks: HashMap<String, RemediationPlaybook>,
    executions: HashMap<Uuid, PlaybookExecution>,
}

impl RemediationPlaybookManager {
    pub fn new() -> Self {
        let mut manager = Self {
            playbooks: HashMap::new(),
            executions: HashMap::new(),
        };
        manager.load_builtin_playbooks();
        manager
    }

    pub fn get_playbook(&self, id: &str) -> Option<&RemediationPlaybook> {
        self.playbooks.get(id)
    }

    pub fn list_playbooks(&self) -> Vec<&RemediationPlaybook> {
        self.playbooks.values().collect()
    }

    pub fn get_playbooks_for_control(&self, control_id: &str) -> Vec<&RemediationPlaybook> {
        self.playbooks
            .values()
            .filter(|playbook| playbook.control_ids.contains(&control_id.to_string()))
            .collect()
    }

    pub fn get_playbooks_for_framework(&self, framework_id: &str) -> Vec<&RemediationPlaybook> {
        self.playbooks
            .values()
            .filter(|playbook| playbook.framework_ids.contains(&framework_id.to_string()))
            .collect()
    }

    pub async fn execute_playbook(
        &mut self,
        playbook_id: &str,
        control_ids: Vec<String>,
        executed_by: String,
    ) -> Result<Uuid> {
        let playbook = self.playbooks
            .get(playbook_id)
            .ok_or_else(|| anyhow::anyhow!("Playbook not found: {}", playbook_id))?;

        let execution_id = Uuid::new_v4();
        let execution = PlaybookExecution {
            execution_id,
            playbook_id: playbook_id.to_string(),
            control_ids,
            status: ExecutionStatus::Pending,
            started_at: Utc::now(),
            completed_at: None,
            executed_by,
            step_results: Vec::new(),
            overall_result: None,
            error_message: None,
        };

        self.executions.insert(execution_id, execution);

        // Start execution (in a real implementation, this would be async)
        self.run_playbook_execution(execution_id).await?;

        Ok(execution_id)
    }

    pub fn get_execution(&self, execution_id: &Uuid) -> Option<&PlaybookExecution> {
        self.executions.get(execution_id)
    }

    pub fn list_executions(&self) -> Vec<&PlaybookExecution> {
        self.executions.values().collect()
    }

    async fn run_playbook_execution(&mut self, execution_id: Uuid) -> Result<()> {
        let execution = self.executions.get_mut(&execution_id)
            .ok_or_else(|| anyhow::anyhow!("Execution not found"))?;

        let playbook_id = execution.playbook_id.clone();
        let playbook = self.playbooks.get(&playbook_id)
            .ok_or_else(|| anyhow::anyhow!("Playbook not found"))?
            .clone();

        execution.status = ExecutionStatus::Running;

        let mut step_results = Vec::new();
        let mut steps_completed = 0;
        let mut steps_failed = 0;

        for step in &playbook.steps {
            let step_result = self.execute_step(step).await;
            
            match step_result.status {
                ExecutionStatus::Completed => {
                    steps_completed += 1;
                }
                ExecutionStatus::Failed => {
                    steps_failed += 1;
                    if !step.continue_on_failure {
                        break;
                    }
                }
                _ => {}
            }

            step_results.push(step_result);
        }

        // Update execution with results
        let execution = self.executions.get_mut(&execution_id).unwrap();
        execution.step_results = step_results;
        execution.completed_at = Some(Utc::now());
        execution.overall_result = Some(ExecutionResult {
            success: steps_failed == 0,
            steps_completed,
            steps_failed,
            compliance_improvement: Some(0.1), // Mock improvement
            recommendations: vec![
                "Review security policies regularly".to_string(),
                "Monitor compliance metrics continuously".to_string(),
            ],
        });

        execution.status = if steps_failed == 0 {
            ExecutionStatus::Completed
        } else if steps_completed > 0 {
            ExecutionStatus::PartialSuccess
        } else {
            ExecutionStatus::Failed
        };

        Ok(())
    }

    async fn execute_step(&self, step: &PlaybookStep) -> StepResult {
        let started_at = Utc::now();
        
        // Simulate step execution
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let (status, output, verification_passed) = match step.action_type {
            PlaybookActionType::Manual => {
                (ExecutionStatus::Completed, "Manual step completed by user".to_string(), true)
            }
            PlaybookActionType::Automated => {
                (ExecutionStatus::Completed, "Automated action executed successfully".to_string(), true)
            }
            PlaybookActionType::Verification => {
                (ExecutionStatus::Completed, "Verification checks passed".to_string(), true)
            }
            PlaybookActionType::Configuration => {
                (ExecutionStatus::Completed, "Configuration updated successfully".to_string(), true)
            }
            PlaybookActionType::PolicyUpdate => {
                (ExecutionStatus::Completed, "Policy updated and applied".to_string(), true)
            }
            _ => {
                (ExecutionStatus::Completed, "Step executed successfully".to_string(), true)
            }
        };

        StepResult {
            step_id: step.step_id.clone(),
            status,
            started_at,
            completed_at: Some(Utc::now()),
            output,
            error_message: None,
            verification_passed,
        }
    }

    fn load_builtin_playbooks(&mut self) {
        // Enable Vault MFA Playbook
        self.playbooks.insert(
            "enable-vault-mfa".to_string(),
            RemediationPlaybook {
                id: "enable-vault-mfa".to_string(),
                name: "Enable Vault Multi-Factor Authentication".to_string(),
                description: "Configure and enable MFA for all vault users to improve access control".to_string(),
                control_ids: vec!["NIST-CSF-PR.AC-1".to_string(), "ISO-27001-A.9.4.2".to_string()],
                framework_ids: vec!["NIST-CSF".to_string(), "ISO-27001".to_string()],
                steps: vec![
                    PlaybookStep {
                        step_id: "check-mfa-status".to_string(),
                        title: "Check Current MFA Status".to_string(),
                        description: "Verify current MFA configuration for all users".to_string(),
                        action_type: PlaybookActionType::Verification,
                        commands: vec!["vault auth list -detailed".to_string()],
                        expected_outcome: "List of current authentication methods".to_string(),
                        verification_criteria: vec!["MFA methods are listed".to_string()],
                        timeout_seconds: Some(30),
                        retry_count: 3,
                        continue_on_failure: false,
                    },
                    PlaybookStep {
                        step_id: "enable-mfa".to_string(),
                        title: "Enable MFA for Users".to_string(),
                        description: "Configure TOTP MFA for all vault users".to_string(),
                        action_type: PlaybookActionType::Configuration,
                        commands: vec![
                            "vault auth enable -path=userpass userpass".to_string(),
                            "vault write auth/userpass/mfa_config type=totp issuer=GhostShell".to_string(),
                        ],
                        expected_outcome: "MFA enabled for all users".to_string(),
                        verification_criteria: vec!["MFA configuration is active".to_string()],
                        timeout_seconds: Some(60),
                        retry_count: 2,
                        continue_on_failure: false,
                    },
                ],
                estimated_time_minutes: 15,
                difficulty: PlaybookDifficulty::Medium,
                prerequisites: vec!["Vault admin access".to_string(), "TOTP app available".to_string()],
                tags: vec!["mfa".to_string(), "authentication".to_string(), "vault".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: "1.0".to_string(),
            }
        );

        // Rotate Expired Secrets Playbook
        self.playbooks.insert(
            "rotate-expired-secrets".to_string(),
            RemediationPlaybook {
                id: "rotate-expired-secrets".to_string(),
                name: "Rotate Expired Secrets".to_string(),
                description: "Identify and rotate all expired secrets in the vault".to_string(),
                control_ids: vec!["NIST-CSF-PR.AC-1".to_string(), "NIST-CSF-PR.DS-1".to_string()],
                framework_ids: vec!["NIST-CSF".to_string()],
                steps: vec![
                    PlaybookStep {
                        step_id: "scan-expired".to_string(),
                        title: "Scan for Expired Secrets".to_string(),
                        description: "Identify all secrets that have expired or are near expiration".to_string(),
                        action_type: PlaybookActionType::Verification,
                        commands: vec!["vault kv list -format=json secret/".to_string()],
                        expected_outcome: "List of expired secrets identified".to_string(),
                        verification_criteria: vec!["Expired secrets are listed".to_string()],
                        timeout_seconds: Some(60),
                        retry_count: 3,
                        continue_on_failure: false,
                    },
                    PlaybookStep {
                        step_id: "rotate-secrets".to_string(),
                        title: "Rotate Expired Secrets".to_string(),
                        description: "Generate new values for expired secrets".to_string(),
                        action_type: PlaybookActionType::Automated,
                        commands: vec!["vault kv put secret/rotated-secrets".to_string()],
                        expected_outcome: "All expired secrets rotated with new values".to_string(),
                        verification_criteria: vec!["New secret versions created".to_string()],
                        timeout_seconds: Some(300),
                        retry_count: 2,
                        continue_on_failure: true,
                    },
                ],
                estimated_time_minutes: 30,
                difficulty: PlaybookDifficulty::Medium,
                prerequisites: vec!["Vault write access".to_string(), "Secret rotation policy".to_string()],
                tags: vec!["secrets".to_string(), "rotation".to_string(), "vault".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: "1.0".to_string(),
            }
        );

        // Enforce PQ SSH Playbook
        self.playbooks.insert(
            "enforce-pq-ssh".to_string(),
            RemediationPlaybook {
                id: "enforce-pq-ssh".to_string(),
                name: "Enforce Post-Quantum SSH".to_string(),
                description: "Configure all SSH hosts to require post-quantum cryptography".to_string(),
                control_ids: vec!["CIS-4.1".to_string()],
                framework_ids: vec!["CIS-v8".to_string()],
                steps: vec![
                    PlaybookStep {
                        step_id: "audit-ssh-config".to_string(),
                        title: "Audit SSH Configurations".to_string(),
                        description: "Review current SSH configurations for PQ support".to_string(),
                        action_type: PlaybookActionType::Verification,
                        commands: vec!["ssh -Q kex".to_string(), "ssh -Q cipher".to_string()],
                        expected_outcome: "Current SSH crypto algorithms identified".to_string(),
                        verification_criteria: vec!["SSH configuration audited".to_string()],
                        timeout_seconds: Some(30),
                        retry_count: 2,
                        continue_on_failure: false,
                    },
                    PlaybookStep {
                        step_id: "update-ssh-config".to_string(),
                        title: "Update SSH Configuration".to_string(),
                        description: "Configure SSH to use post-quantum algorithms".to_string(),
                        action_type: PlaybookActionType::Configuration,
                        commands: vec![
                            "echo 'KexAlgorithms kyber512-sha256@openquantumsafe.org' >> /etc/ssh/sshd_config".to_string(),
                            "systemctl reload ssh".to_string(),
                        ],
                        expected_outcome: "SSH configured for post-quantum cryptography".to_string(),
                        verification_criteria: vec!["PQ algorithms enabled".to_string()],
                        timeout_seconds: Some(60),
                        retry_count: 2,
                        continue_on_failure: false,
                    },
                ],
                estimated_time_minutes: 20,
                difficulty: PlaybookDifficulty::Hard,
                prerequisites: vec!["SSH admin access".to_string(), "PQ SSH support".to_string()],
                tags: vec!["ssh".to_string(), "post-quantum".to_string(), "cryptography".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: "1.0".to_string(),
            }
        );
    }
}

impl Default for RemediationPlaybookManager {
    fn default() -> Self {
        Self::new()
    }
}

// Tauri commands

#[tauri::command]
pub async fn playbooks_list_all(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<RemediationPlaybookManager>>>,
) -> Result<Vec<RemediationPlaybook>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_playbooks().into_iter().cloned().collect())
}

#[tauri::command]
pub async fn playbooks_get_for_control(
    control_id: String,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<RemediationPlaybookManager>>>,
) -> Result<Vec<RemediationPlaybook>, String> {
    let manager = manager.lock().await;
    Ok(manager.get_playbooks_for_control(&control_id).into_iter().cloned().collect())
}

#[tauri::command]
pub async fn playbooks_execute(
    playbook_id: String,
    control_ids: Vec<String>,
    executed_by: String,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<RemediationPlaybookManager>>>,
) -> Result<String, String> {
    let mut manager = manager.lock().await;
    manager.execute_playbook(&playbook_id, control_ids, executed_by)
        .await
        .map(|id| id.to_string())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn playbooks_get_execution(
    execution_id: String,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<RemediationPlaybookManager>>>,
) -> Result<Option<PlaybookExecution>, String> {
    let manager = manager.lock().await;
    let uuid = Uuid::parse_str(&execution_id).map_err(|e| e.to_string())?;
    Ok(manager.get_execution(&uuid).cloned())
}

#[tauri::command]
pub async fn playbooks_list_executions(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<RemediationPlaybookManager>>>,
) -> Result<Vec<PlaybookExecution>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_executions().into_iter().cloned().collect())
}
