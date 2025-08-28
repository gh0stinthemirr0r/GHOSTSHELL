use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use anyhow::Result;

// Import our Phase 12 crates
use ghost_align::{
    SignalCollector, SignalValue, TimeWindow, ControlEvaluator, PostureScorer, 
    PostureSnapshot, ControlEvaluation, ControlStatus, AlignResult
};
use ghost_controls::{ControlCatalog, FrameworkMeta, Control};
use ghost_evidence::{EvidenceBundle, BundleBuilder, EvidenceArtifact, ArtifactType};
use ghost_trends::{PostureStorage, TrendAnalyzer, PostureTrendPoint, TrendAnalysis, AggregationPeriod};

/// Compliance dashboard manager
pub struct ComplianceDashboardManager {
    signal_collectors: HashMap<String, Arc<dyn SignalCollector>>,
    control_evaluator: ControlEvaluator,
    posture_scorer: PostureScorer,
    control_catalog: ControlCatalog,
    posture_storage: Arc<RwLock<PostureStorage>>,
    current_snapshots: Arc<RwLock<HashMap<String, PostureSnapshot>>>,
    evidence_bundles: Arc<RwLock<HashMap<Uuid, EvidenceBundle>>>,
}

impl ComplianceDashboardManager {
    pub fn new() -> Self {
        let mut manager = Self {
            signal_collectors: HashMap::new(),
            control_evaluator: ControlEvaluator::new(),
            posture_scorer: PostureScorer::new(),
            control_catalog: ControlCatalog::new(),
            posture_storage: Arc::new(RwLock::new(PostureStorage::new())),
            current_snapshots: Arc::new(RwLock::new(HashMap::new())),
            evidence_bundles: Arc::new(RwLock::new(HashMap::new())),
        };

        // Register mock signal collectors for demonstration
        manager.register_mock_collectors();
        manager
    }

    pub async fn get_frameworks(&self) -> Vec<FrameworkMeta> {
        self.control_catalog.list_frameworks().into_iter().cloned().collect()
    }

    pub async fn get_framework_controls(&self, framework_id: &str) -> Vec<Control> {
        self.control_catalog
            .list_controls_for_framework(framework_id)
            .into_iter()
            .cloned()
            .collect()
    }

    pub async fn create_posture_snapshot(&self, framework_id: &str) -> Result<PostureSnapshot> {
        // Collect signals from all registered collectors
        let mut all_signals = Vec::new();
        
        for (collector_name, collector) in &self.signal_collectors {
            match collector.collect_signals(TimeWindow::Last24Hours).await {
                Ok(mut signals) => {
                    // Add collector name to signal metadata
                    for signal in &mut signals {
                        signal.metadata.insert("collector".to_string(), collector_name.clone());
                    }
                    all_signals.extend(signals);
                }
                Err(e) => {
                    tracing::warn!("Failed to collect signals from {}: {}", collector_name, e);
                }
            }
        }

        // Get framework controls
        let controls = self.control_catalog.list_controls_for_framework(framework_id);
        let mut evaluations = Vec::new();

        // Evaluate each control
        for control in controls {
            match self.control_evaluator.evaluate_control(&control.id, &all_signals) {
                Ok(evaluation) => evaluations.push(evaluation),
                Err(e) => {
                    tracing::warn!("Failed to evaluate control {}: {}", control.id, e);
                    // Create a default evaluation for failed controls
                    evaluations.push(ControlEvaluation {
                        control_id: control.id.clone(),
                        status: ControlStatus::Unknown,
                        confidence: 0.0,
                        rationale: vec![format!("Evaluation failed: {}", e)],
                        signals: Vec::new(),
                        evidence_refs: Vec::new(),
                        timestamp: Utc::now(),
                        remediation_suggestions: Vec::new(),
                    });
                }
            }
        }

        // Calculate posture snapshot
        let snapshot = self.posture_scorer.calculate_posture_snapshot(framework_id, evaluations)?;

        // Store snapshot in trends storage
        let trend_point = PostureTrendPoint::from(snapshot.clone());
        self.posture_storage.write().await.store_trend_point(framework_id, trend_point);

        // Store current snapshot
        self.current_snapshots.write().await.insert(framework_id.to_string(), snapshot.clone());

        Ok(snapshot)
    }

    pub async fn get_current_snapshot(&self, framework_id: &str) -> Option<PostureSnapshot> {
        self.current_snapshots.read().await.get(framework_id).cloned()
    }

    pub async fn get_control_details(&self, control_id: &str) -> Option<ControlDetailsResponse> {
        // Get control from catalog
        let control = self.control_catalog.get_control(control_id)?;
        
        // Get current evaluation from latest snapshot
        let current_snapshots = self.current_snapshots.read().await;
        let evaluation = current_snapshots
            .values()
            .find_map(|snapshot| {
                snapshot.control_evaluations
                    .iter()
                    .find(|eval| eval.control_id == control_id)
            })?;

        Some(ControlDetailsResponse {
            control: control.clone(),
            evaluation: evaluation.clone(),
            trend_data: Vec::new(), // TODO: Implement trend data retrieval
            evidence_artifacts: Vec::new(), // TODO: Implement evidence retrieval
        })
    }

    pub async fn get_posture_trends(
        &self,
        framework_id: &str,
        days: i64,
    ) -> Result<TrendAnalysis> {
        let end_time = Utc::now();
        let start_time = end_time - chrono::Duration::days(days);
        
        let points = self.posture_storage
            .read()
            .await
            .get_trend_points(framework_id, Some(start_time), Some(end_time))?;

        TrendAnalyzer::analyze_posture_trend(
            framework_id,
            &points,
            chrono::Duration::days(days),
        ).map_err(|e| anyhow::anyhow!("Trend analysis failed: {}", e))
    }

    pub async fn create_evidence_bundle(
        &self,
        framework_id: &str,
        control_ids: Vec<String>,
        bundle_name: String,
        created_by: String,
    ) -> Result<Uuid> {
        let mut builder = BundleBuilder::new(bundle_name, framework_id.to_string(), created_by);
        builder = builder.description(format!("Evidence bundle for {} controls", control_ids.len()));

        // Add control IDs to builder
        for control_id in &control_ids {
            builder = builder.add_control(control_id.clone());
        }

        // Create mock evidence artifacts for demonstration
        for control_id in &control_ids {
            let artifact = EvidenceArtifact {
                artifact_id: Uuid::new_v4(),
                artifact_type: ArtifactType::GhostLog,
                name: format!("Evidence for {}", control_id),
                description: format!("Compliance evidence artifact for control {}", control_id),
                file_path: None,
                content_hash: format!("sha3-256:{}", hex::encode(control_id.as_bytes())),
                signature: None,
                timestamp: Utc::now(),
                source: "compliance_dashboard".to_string(),
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("control_id".to_string(), control_id.clone());
                    meta.insert("framework_id".to_string(), framework_id.to_string());
                    meta
                },
                related_controls: vec![control_id.clone()],
            };
            
            builder = builder.add_artifact(artifact);
        }

        // Build bundle (without signing for now)
        let bundle = builder.build(None).await?;
        let bundle_id = bundle.bundle_id;

        // Store bundle
        self.evidence_bundles.write().await.insert(bundle_id, bundle);

        Ok(bundle_id)
    }

    pub async fn get_evidence_bundle(&self, bundle_id: &Uuid) -> Option<EvidenceBundle> {
        self.evidence_bundles.read().await.get(bundle_id).cloned()
    }

    pub async fn list_evidence_bundles(&self) -> Vec<EvidenceBundleSummary> {
        self.evidence_bundles
            .read()
            .await
            .values()
            .map(|bundle| EvidenceBundleSummary {
                bundle_id: bundle.bundle_id,
                name: bundle.name.clone(),
                framework_id: bundle.framework_id.clone(),
                control_count: bundle.control_ids.len(),
                artifact_count: bundle.artifacts.len(),
                created_at: bundle.created_at,
                created_by: bundle.created_by.clone(),
            })
            .collect()
    }

    pub async fn get_dashboard_stats(&self, framework_id: &str) -> ComplianceDashboardStats {
        let snapshot = self.current_snapshots.read().await.get(framework_id).cloned();
        
        if let Some(snapshot) = snapshot {
            ComplianceDashboardStats {
                framework_id: framework_id.to_string(),
                total_controls: snapshot.total_controls,
                passed_controls: snapshot.passed_controls,
                failed_controls: snapshot.failed_controls,
                partial_controls: snapshot.partial_controls,
                unknown_controls: snapshot.unknown_controls,
                overall_score: snapshot.overall_score,
                domain_scores: snapshot.domain_scores,
                last_assessment: Some(snapshot.timestamp),
                trend_direction: TrendDirection::Stable, // TODO: Calculate from trends
                evidence_bundles: self.evidence_bundles.read().await.len(),
            }
        } else {
            ComplianceDashboardStats {
                framework_id: framework_id.to_string(),
                total_controls: 0,
                passed_controls: 0,
                failed_controls: 0,
                partial_controls: 0,
                unknown_controls: 0,
                overall_score: 0.0,
                domain_scores: HashMap::new(),
                last_assessment: None,
                trend_direction: TrendDirection::Unknown,
                evidence_bundles: 0,
            }
        }
    }

    fn register_mock_collectors(&mut self) {
        use ghost_align::signals::MockSignalCollector;

        // Vault signals collector
        let vault_signals = vec![
            "vault.rotation.rate30d".to_string(),
            "vault.mfa.enabled".to_string(),
        ];
        self.signal_collectors.insert(
            "vault".to_string(),
            Arc::new(MockSignalCollector::new("vault".to_string(), vault_signals))
        );

        // VPN signals collector
        let vpn_signals = vec![
            "vpn.pq_fraction".to_string(),
        ];
        self.signal_collectors.insert(
            "vpn".to_string(),
            Arc::new(MockSignalCollector::new("vpn".to_string(), vpn_signals))
        );

        // SSH signals collector
        let ssh_signals = vec![
            "ssh.pq_required.hosts_fraction".to_string(),
            "ssh.hostkey.pin_coverage".to_string(),
        ];
        self.signal_collectors.insert(
            "ssh".to_string(),
            Arc::new(MockSignalCollector::new("ssh".to_string(), ssh_signals))
        );

        // PCAP signals collector
        let pcap_signals = vec![
            "pcap.tls.classical_flows".to_string(),
        ];
        self.signal_collectors.insert(
            "pcap".to_string(),
            Arc::new(MockSignalCollector::new("pcap".to_string(), pcap_signals))
        );

        // Topology signals collector
        let topology_signals = vec![
            "topo.policy.violations".to_string(),
        ];
        self.signal_collectors.insert(
            "topology".to_string(),
            Arc::new(MockSignalCollector::new("topology".to_string(), topology_signals))
        );

        // Notifications signals collector
        let notify_signals = vec![
            "notify.critical.unacked_24h".to_string(),
        ];
        self.signal_collectors.insert(
            "notifications".to_string(),
            Arc::new(MockSignalCollector::new("notifications".to_string(), notify_signals))
        );

        // Reports signals collector
        let reports_signals = vec![
            "reports.last_exec.kpis".to_string(),
        ];
        self.signal_collectors.insert(
            "reports".to_string(),
            Arc::new(MockSignalCollector::new("reports".to_string(), reports_signals))
        );

        // Policy signals collector
        let policy_signals = vec![
            "policy.pq_required.coverage".to_string(),
            "policy.deny_allow_ratio".to_string(),
        ];
        self.signal_collectors.insert(
            "policy".to_string(),
            Arc::new(MockSignalCollector::new("policy".to_string(), policy_signals))
        );
    }
}

// Response types for Tauri commands

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlDetailsResponse {
    pub control: Control,
    pub evaluation: ControlEvaluation,
    pub trend_data: Vec<(DateTime<Utc>, f64)>,
    pub evidence_artifacts: Vec<EvidenceArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundleSummary {
    pub bundle_id: Uuid,
    pub name: String,
    pub framework_id: String,
    pub control_count: usize,
    pub artifact_count: usize,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceDashboardStats {
    pub framework_id: String,
    pub total_controls: usize,
    pub passed_controls: usize,
    pub failed_controls: usize,
    pub partial_controls: usize,
    pub unknown_controls: usize,
    pub overall_score: f64,
    pub domain_scores: HashMap<String, f64>,
    pub last_assessment: Option<DateTime<Utc>>,
    pub trend_direction: TrendDirection,
    pub evidence_bundles: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
    Unknown,
}

// Tauri commands

#[tauri::command]
pub async fn compliance_dashboard_get_frameworks(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<ComplianceDashboardManager>>>,
) -> Result<Vec<FrameworkMeta>, String> {
    let manager = manager.lock().await;
    Ok(manager.get_frameworks().await)
}

#[tauri::command]
pub async fn compliance_get_framework_controls(
    framework_id: String,
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<ComplianceDashboardManager>>>,
) -> Result<Vec<Control>, String> {
    let manager = manager.lock().await;
    Ok(manager.get_framework_controls(&framework_id).await)
}

#[tauri::command]
pub async fn compliance_create_snapshot(
    framework_id: String,
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<ComplianceDashboardManager>>>,
) -> Result<PostureSnapshot, String> {
    let manager = manager.lock().await;
    manager.create_posture_snapshot(&framework_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn compliance_get_current_snapshot(
    framework_id: String,
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<ComplianceDashboardManager>>>,
) -> Result<Option<PostureSnapshot>, String> {
    let manager = manager.lock().await;
    Ok(manager.get_current_snapshot(&framework_id).await)
}

#[tauri::command]
pub async fn compliance_get_control_details(
    control_id: String,
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<ComplianceDashboardManager>>>,
) -> Result<Option<ControlDetailsResponse>, String> {
    let manager = manager.lock().await;
    Ok(manager.get_control_details(&control_id).await)
}

#[tauri::command]
pub async fn compliance_get_dashboard_stats(
    framework_id: String,
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<ComplianceDashboardManager>>>,
) -> Result<ComplianceDashboardStats, String> {
    let manager = manager.lock().await;
    Ok(manager.get_dashboard_stats(&framework_id).await)
}

#[tauri::command]
pub async fn compliance_create_evidence_bundle(
    framework_id: String,
    control_ids: Vec<String>,
    bundle_name: String,
    created_by: String,
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<ComplianceDashboardManager>>>,
) -> Result<String, String> {
    let manager = manager.lock().await;
    manager.create_evidence_bundle(&framework_id, control_ids, bundle_name, created_by)
        .await
        .map(|id| id.to_string())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn compliance_list_evidence_bundles(
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<ComplianceDashboardManager>>>,
) -> Result<Vec<EvidenceBundleSummary>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_evidence_bundles().await)
}

#[tauri::command]
pub async fn compliance_get_posture_trends(
    framework_id: String,
    days: i64,
    manager: tauri::State<'_, Arc<tokio::sync::Mutex<ComplianceDashboardManager>>>,
) -> Result<TrendAnalysis, String> {
    let manager = manager.lock().await;
    manager.get_posture_trends(&framework_id, days)
        .await
        .map_err(|e| e.to_string())
}
