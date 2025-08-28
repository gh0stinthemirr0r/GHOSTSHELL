use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::security::PepState;
use ghost_pq::{DilithiumPrivateKey, DilithiumPublicKey, DilithiumVariant};

// Core data structures for Global Threat Intelligence Network

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalThreatIntelStats {
    pub active_feeds: u32,
    pub total_indicators: u32,
    pub indicators_24h: u32,
    pub network_nodes: u32,
    pub threat_campaigns: u32,
    pub attribution_confidence: f32,
    pub sharing_partners: u32,
    pub global_threat_level: GlobalThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GlobalThreatLevel {
    Green,
    Yellow,
    Orange,
    Red,
    Critical,
    GlobalEmergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub feed_id: String,
    pub name: String,
    pub description: String,
    pub feed_type: FeedType,
    pub source: ThreatSource,
    pub reliability_score: f32,
    pub update_frequency: UpdateFrequency,
    pub data_format: DataFormat,
    pub access_level: AccessLevel,
    pub subscription_status: SubscriptionStatus,
    pub last_updated: DateTime<Utc>,
    pub indicators_count: u32,
    pub quality_metrics: FeedQualityMetrics,
    pub geographic_coverage: Vec<String>,
    pub threat_categories: Vec<ThreatCategory>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedType {
    IOC,
    TTP,
    Vulnerability,
    Malware,
    Attribution,
    Geopolitical,
    Behavioral,
    Network,
    Endpoint,
    Cloud,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSource {
    Commercial,
    Government,
    OpenSource,
    Community,
    Internal,
    Partner,
    Vendor,
    Research,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateFrequency {
    RealTime,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    OnDemand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataFormat {
    STIX,
    TAXII,
    JSON,
    XML,
    CSV,
    MISP,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessLevel {
    Public,
    Restricted,
    Confidential,
    Secret,
    TopSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubscriptionStatus {
    Active,
    Inactive,
    Pending,
    Expired,
    Suspended,
    Trial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedQualityMetrics {
    pub accuracy_score: f32,
    pub timeliness_score: f32,
    pub relevance_score: f32,
    pub completeness_score: f32,
    pub false_positive_rate: f32,
    pub coverage_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatCategory {
    Malware,
    Phishing,
    Ransomware,
    APT,
    Botnet,
    Cryptocurrency,
    Fraud,
    Espionage,
    Terrorism,
    Cybercrime,
    StateSponsored,
    Hacktivist,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f32,
    pub severity: ThreatSeverity,
    pub tlp_marking: TLPMarking,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expiration: Option<DateTime<Utc>>,
    pub sources: Vec<String>,
    pub tags: Vec<String>,
    pub context: IndicatorContext,
    pub attribution: Option<ThreatAttribution>,
    pub relationships: Vec<IndicatorRelationship>,
    pub kill_chain_phases: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub geographic_regions: Vec<String>,
    pub pq_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndicatorType {
    IP,
    Domain,
    URL,
    FileHash,
    Email,
    Registry,
    Mutex,
    Certificate,
    UserAgent,
    JA3,
    YARA,
    Sigma,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TLPMarking {
    White,
    Green,
    Amber,
    Red,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorContext {
    pub campaign_id: Option<String>,
    pub malware_family: Option<String>,
    pub attack_vector: Option<String>,
    pub target_sectors: Vec<String>,
    pub target_countries: Vec<String>,
    pub description: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAttribution {
    pub actor_id: String,
    pub actor_name: String,
    pub actor_type: ActorType,
    pub confidence: f32,
    pub motivation: Vec<String>,
    pub capabilities: Vec<String>,
    pub infrastructure: Vec<String>,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActorType {
    StateSponsored,
    Cybercriminal,
    Hacktivist,
    Terrorist,
    Insider,
    Script_Kiddie,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorRelationship {
    pub relationship_type: RelationshipType,
    pub target_indicator_id: String,
    pub confidence: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationshipType {
    Related,
    Derived,
    Duplicate,
    Supersedes,
    Uses,
    Indicates,
    Attributed,
    Targets,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCampaign {
    pub campaign_id: String,
    pub name: String,
    pub description: String,
    pub status: CampaignStatus,
    pub first_seen: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub attribution: Option<ThreatAttribution>,
    pub objectives: Vec<String>,
    pub target_sectors: Vec<String>,
    pub target_countries: Vec<String>,
    pub ttps: Vec<String>,
    pub indicators: Vec<String>,
    pub confidence: f32,
    pub impact_assessment: ImpactAssessment,
    pub timeline: Vec<CampaignEvent>,
    pub related_campaigns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CampaignStatus {
    Active,
    Dormant,
    Concluded,
    Suspected,
    Monitoring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    pub financial_impact: Option<f64>,
    pub affected_organizations: u32,
    pub affected_countries: u32,
    pub data_compromised: Option<u64>,
    pub systems_affected: u32,
    pub recovery_time: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub node_id: String,
    pub organization: String,
    pub node_type: NodeType,
    pub location: GeographicLocation,
    pub capabilities: Vec<String>,
    pub trust_level: f32,
    pub sharing_agreements: Vec<String>,
    pub data_quality_score: f32,
    pub last_activity: DateTime<Utc>,
    pub connection_status: ConnectionStatus,
    pub shared_indicators: u32,
    pub received_indicators: u32,
    pub reputation_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    ISAC,
    Government,
    Enterprise,
    Vendor,
    Research,
    NGO,
    Individual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicLocation {
    pub country: String,
    pub region: String,
    pub city: Option<String>,
    pub coordinates: Option<(f64, f64)>,
    pub timezone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Online,
    Offline,
    Degraded,
    Maintenance,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingAgreement {
    pub agreement_id: String,
    pub name: String,
    pub parties: Vec<String>,
    pub agreement_type: AgreementType,
    pub data_categories: Vec<String>,
    pub sharing_direction: SharingDirection,
    pub trust_level: f32,
    pub effective_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub terms_and_conditions: String,
    pub privacy_requirements: Vec<String>,
    pub attribution_requirements: AttributionRequirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgreementType {
    Bilateral,
    Multilateral,
    Community,
    Commercial,
    Government,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SharingDirection {
    Bidirectional,
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionRequirements {
    pub require_attribution: bool,
    pub anonymization_allowed: bool,
    pub aggregation_allowed: bool,
    pub redistribution_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHuntingQuery {
    pub query_id: String,
    pub name: String,
    pub description: String,
    pub query_type: QueryType,
    pub query_language: QueryLanguage,
    pub query_content: String,
    pub data_sources: Vec<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub last_executed: Option<DateTime<Utc>>,
    pub execution_count: u32,
    pub success_rate: f32,
    pub average_execution_time: f32,
    pub tags: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub sharing_level: TLPMarking,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryType {
    IOC,
    Behavioral,
    Statistical,
    Correlation,
    Anomaly,
    Timeline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryLanguage {
    KQL,
    SPL,
    SQL,
    Sigma,
    YARA,
    Custom,
}

// Main Global Threat Intelligence Network Manager
pub struct GlobalThreatIntelligenceManager {
    threat_feeds: Arc<RwLock<HashMap<String, ThreatFeed>>>,
    threat_indicators: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
    threat_campaigns: Arc<RwLock<HashMap<String, ThreatCampaign>>>,
    network_nodes: Arc<RwLock<HashMap<String, NetworkNode>>>,
    sharing_agreements: Arc<RwLock<HashMap<String, SharingAgreement>>>,
    hunting_queries: Arc<RwLock<HashMap<String, ThreatHuntingQuery>>>,
    signing_keys: Arc<RwLock<HashMap<String, (DilithiumPublicKey, DilithiumPrivateKey)>>>,
}

impl GlobalThreatIntelligenceManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            threat_feeds: Arc::new(RwLock::new(HashMap::new())),
            threat_indicators: Arc::new(RwLock::new(HashMap::new())),
            threat_campaigns: Arc::new(RwLock::new(HashMap::new())),
            network_nodes: Arc::new(RwLock::new(HashMap::new())),
            sharing_agreements: Arc::new(RwLock::new(HashMap::new())),
            hunting_queries: Arc::new(RwLock::new(HashMap::new())),
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn initialize(&self) -> Result<()> {
        self.create_sample_data().await?;
        Ok(())
    }

    async fn create_sample_data(&self) -> Result<()> {
        // Create sample threat feeds
        let mut feeds = self.threat_feeds.write().await;
        
        let commercial_feed = ThreatFeed {
            feed_id: "feed_commercial_001".to_string(),
            name: "CyberThreat Intelligence Pro".to_string(),
            description: "Premium commercial threat intelligence feed with real-time IOCs and attribution data".to_string(),
            feed_type: FeedType::IOC,
            source: ThreatSource::Commercial,
            reliability_score: 0.95,
            update_frequency: UpdateFrequency::RealTime,
            data_format: DataFormat::STIX,
            access_level: AccessLevel::Restricted,
            subscription_status: SubscriptionStatus::Active,
            last_updated: Utc::now(),
            indicators_count: 15847,
            quality_metrics: FeedQualityMetrics {
                accuracy_score: 0.96,
                timeliness_score: 0.98,
                relevance_score: 0.94,
                completeness_score: 0.92,
                false_positive_rate: 0.02,
                coverage_score: 0.89,
            },
            geographic_coverage: vec!["Global".to_string(), "North America".to_string(), "Europe".to_string()],
            threat_categories: vec![ThreatCategory::APT, ThreatCategory::Malware, ThreatCategory::Ransomware],
            created_at: Utc::now(),
        };

        let government_feed = ThreatFeed {
            feed_id: "feed_gov_001".to_string(),
            name: "National Cyber Threat Feed".to_string(),
            description: "Government-sourced threat intelligence with classified attribution data".to_string(),
            feed_type: FeedType::Attribution,
            source: ThreatSource::Government,
            reliability_score: 0.98,
            update_frequency: UpdateFrequency::Daily,
            data_format: DataFormat::TAXII,
            access_level: AccessLevel::Secret,
            subscription_status: SubscriptionStatus::Active,
            last_updated: Utc::now(),
            indicators_count: 8934,
            quality_metrics: FeedQualityMetrics {
                accuracy_score: 0.99,
                timeliness_score: 0.85,
                relevance_score: 0.97,
                completeness_score: 0.95,
                false_positive_rate: 0.01,
                coverage_score: 0.92,
            },
            geographic_coverage: vec!["Global".to_string()],
            threat_categories: vec![ThreatCategory::StateSponsored, ThreatCategory::Espionage, ThreatCategory::APT],
            created_at: Utc::now(),
        };

        feeds.insert(commercial_feed.feed_id.clone(), commercial_feed);
        feeds.insert(government_feed.feed_id.clone(), government_feed);
        drop(feeds);

        // Create sample threat indicators
        let mut indicators = self.threat_indicators.write().await;
        
        let malicious_ip = ThreatIndicator {
            indicator_id: "ioc_ip_001".to_string(),
            indicator_type: IndicatorType::IP,
            value: "192.168.100.50".to_string(),
            confidence: 0.92,
            severity: ThreatSeverity::High,
            tlp_marking: TLPMarking::Amber,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            expiration: Some(Utc::now() + chrono::Duration::days(30)),
            sources: vec!["feed_commercial_001".to_string(), "internal_analysis".to_string()],
            tags: vec!["c2".to_string(), "apt29".to_string(), "cozy_bear".to_string()],
            context: IndicatorContext {
                campaign_id: Some("campaign_apt29_001".to_string()),
                malware_family: Some("CozyDuke".to_string()),
                attack_vector: Some("Spear Phishing".to_string()),
                target_sectors: vec!["Government".to_string(), "Defense".to_string()],
                target_countries: vec!["US".to_string(), "UK".to_string(), "DE".to_string()],
                description: "Command and control server associated with APT29 operations".to_string(),
                references: vec!["https://attack.mitre.org/groups/G0016/".to_string()],
            },
            attribution: Some(ThreatAttribution {
                actor_id: "actor_apt29".to_string(),
                actor_name: "APT29 (Cozy Bear)".to_string(),
                actor_type: ActorType::StateSponsored,
                confidence: 0.89,
                motivation: vec!["Espionage".to_string(), "Intelligence Gathering".to_string()],
                capabilities: vec!["Advanced Persistent Threat".to_string(), "Zero-day Exploits".to_string()],
                infrastructure: vec!["Compromised Websites".to_string(), "Cloud Services".to_string()],
                aliases: vec!["Cozy Bear".to_string(), "The Dukes".to_string()],
            }),
            relationships: vec![
                IndicatorRelationship {
                    relationship_type: RelationshipType::Related,
                    target_indicator_id: "ioc_domain_001".to_string(),
                    confidence: 0.85,
                    description: "Resolves to malicious domain".to_string(),
                },
            ],
            kill_chain_phases: vec!["command-and-control".to_string()],
            mitre_techniques: vec!["T1071.001".to_string(), "T1090".to_string()],
            geographic_regions: vec!["Eastern Europe".to_string()],
            pq_signature: Some("dilithium_signature_placeholder".to_string()),
        };

        indicators.insert(malicious_ip.indicator_id.clone(), malicious_ip);
        drop(indicators);

        // Create sample threat campaigns
        let mut campaigns = self.threat_campaigns.write().await;
        
        let apt_campaign = ThreatCampaign {
            campaign_id: "campaign_apt29_001".to_string(),
            name: "Operation Ghost Writer".to_string(),
            description: "Sophisticated espionage campaign targeting government and defense contractors".to_string(),
            status: CampaignStatus::Active,
            first_seen: Utc::now() - chrono::Duration::days(45),
            last_activity: Utc::now(),
            attribution: Some(ThreatAttribution {
                actor_id: "actor_apt29".to_string(),
                actor_name: "APT29 (Cozy Bear)".to_string(),
                actor_type: ActorType::StateSponsored,
                confidence: 0.89,
                motivation: vec!["Espionage".to_string()],
                capabilities: vec!["Advanced Persistent Threat".to_string()],
                infrastructure: vec!["Compromised Websites".to_string()],
                aliases: vec!["Cozy Bear".to_string()],
            }),
            objectives: vec![
                "Steal classified documents".to_string(),
                "Maintain persistent access".to_string(),
                "Intelligence gathering".to_string(),
            ],
            target_sectors: vec!["Government".to_string(), "Defense".to_string(), "Technology".to_string()],
            target_countries: vec!["US".to_string(), "UK".to_string(), "DE".to_string(), "FR".to_string()],
            ttps: vec!["T1566.001".to_string(), "T1071.001".to_string(), "T1055".to_string()],
            indicators: vec!["ioc_ip_001".to_string()],
            confidence: 0.87,
            impact_assessment: ImpactAssessment {
                financial_impact: Some(50000000.0),
                affected_organizations: 23,
                affected_countries: 4,
                data_compromised: Some(2500000),
                systems_affected: 156,
                recovery_time: Some(180),
            },
            timeline: vec![
                CampaignEvent {
                    event_id: "event_001".to_string(),
                    timestamp: Utc::now() - chrono::Duration::days(45),
                    event_type: "Initial Compromise".to_string(),
                    description: "First observed spear phishing emails".to_string(),
                    indicators: vec!["ioc_email_001".to_string()],
                    confidence: 0.92,
                },
            ],
            related_campaigns: vec!["campaign_apt29_002".to_string()],
        };

        campaigns.insert(apt_campaign.campaign_id.clone(), apt_campaign);
        drop(campaigns);

        // Create sample network nodes
        let mut nodes = self.network_nodes.write().await;
        
        let isac_node = NetworkNode {
            node_id: "node_isac_001".to_string(),
            organization: "Financial Services ISAC".to_string(),
            node_type: NodeType::ISAC,
            location: GeographicLocation {
                country: "United States".to_string(),
                region: "North America".to_string(),
                city: Some("New York".to_string()),
                coordinates: Some((40.7128, -74.0060)),
                timezone: "America/New_York".to_string(),
            },
            capabilities: vec![
                "Threat Intelligence Sharing".to_string(),
                "Incident Coordination".to_string(),
                "Vulnerability Assessment".to_string(),
            ],
            trust_level: 0.95,
            sharing_agreements: vec!["agreement_001".to_string()],
            data_quality_score: 0.92,
            last_activity: Utc::now(),
            connection_status: ConnectionStatus::Online,
            shared_indicators: 2847,
            received_indicators: 5692,
            reputation_score: 0.96,
        };

        nodes.insert(isac_node.node_id.clone(), isac_node);

        Ok(())
    }

    pub async fn get_stats(&self) -> Result<GlobalThreatIntelStats> {
        let feeds = self.threat_feeds.read().await;
        let indicators = self.threat_indicators.read().await;
        let campaigns = self.threat_campaigns.read().await;
        let nodes = self.network_nodes.read().await;

        let active_feeds = feeds.values()
            .filter(|f| matches!(f.subscription_status, SubscriptionStatus::Active))
            .count() as u32;

        let total_indicators = indicators.len() as u32;

        let indicators_24h = indicators.values()
            .filter(|i| (Utc::now() - i.first_seen).num_hours() <= 24)
            .count() as u32;

        let network_nodes = nodes.len() as u32;
        let threat_campaigns = campaigns.len() as u32;

        // Calculate attribution confidence
        let attribution_confidence = campaigns.values()
            .filter_map(|c| c.attribution.as_ref())
            .map(|a| a.confidence)
            .sum::<f32>() / campaigns.len().max(1) as f32;

        let sharing_partners = nodes.values()
            .filter(|n| matches!(n.connection_status, ConnectionStatus::Online))
            .count() as u32;

        // Determine global threat level based on active campaigns and severity
        let global_threat_level = if campaigns.values().any(|c| matches!(c.status, CampaignStatus::Active) && c.confidence > 0.9) {
            GlobalThreatLevel::Red
        } else if campaigns.values().any(|c| matches!(c.status, CampaignStatus::Active)) {
            GlobalThreatLevel::Orange
        } else {
            GlobalThreatLevel::Yellow
        };

        Ok(GlobalThreatIntelStats {
            active_feeds,
            total_indicators,
            indicators_24h,
            network_nodes,
            threat_campaigns,
            attribution_confidence,
            sharing_partners,
            global_threat_level,
        })
    }

    pub async fn get_threat_feeds(&self) -> Result<Vec<ThreatFeed>> {
        let feeds = self.threat_feeds.read().await;
        Ok(feeds.values().cloned().collect())
    }

    pub async fn get_threat_indicators(&self) -> Result<Vec<ThreatIndicator>> {
        let indicators = self.threat_indicators.read().await;
        Ok(indicators.values().cloned().collect())
    }

    pub async fn get_threat_campaigns(&self) -> Result<Vec<ThreatCampaign>> {
        let campaigns = self.threat_campaigns.read().await;
        Ok(campaigns.values().cloned().collect())
    }

    pub async fn get_network_nodes(&self) -> Result<Vec<NetworkNode>> {
        let nodes = self.network_nodes.read().await;
        Ok(nodes.values().cloned().collect())
    }

    pub async fn get_hunting_queries(&self) -> Result<Vec<ThreatHuntingQuery>> {
        let queries = self.hunting_queries.read().await;
        Ok(queries.values().cloned().collect())
    }

    pub async fn create_threat_indicator(&self, indicator: ThreatIndicator) -> Result<String> {
        let mut indicators = self.threat_indicators.write().await;
        let indicator_id = indicator.indicator_id.clone();
        indicators.insert(indicator_id.clone(), indicator);
        Ok(indicator_id)
    }

    pub async fn create_hunting_query(&self, query: ThreatHuntingQuery) -> Result<String> {
        let mut queries = self.hunting_queries.write().await;
        let query_id = query.query_id.clone();
        queries.insert(query_id.clone(), query);
        Ok(query_id)
    }

    pub async fn execute_hunting_query(&self, query_id: &str) -> Result<Vec<String>> {
        let mut queries = self.hunting_queries.write().await;
        
        if let Some(query) = queries.get_mut(query_id) {
            query.last_executed = Some(Utc::now());
            query.execution_count += 1;
            
            // Simulate query execution results
            let results = vec![
                "Match found: Suspicious network connection".to_string(),
                "Match found: Anomalous process execution".to_string(),
                "Match found: Unusual file access pattern".to_string(),
            ];
            
            Ok(results)
        } else {
            Err(anyhow::anyhow!("Query not found"))
        }
    }

    pub async fn share_indicator(&self, indicator_id: &str, target_nodes: Vec<String>) -> Result<String> {
        let indicators = self.threat_indicators.read().await;
        let nodes = self.network_nodes.read().await;
        
        if let Some(_indicator) = indicators.get(indicator_id) {
            // Verify target nodes exist and are online
            let valid_targets: Vec<_> = target_nodes.iter()
                .filter(|node_id| {
                    nodes.get(*node_id)
                        .map(|n| matches!(n.connection_status, ConnectionStatus::Online))
                        .unwrap_or(false)
                })
                .collect();
            
            if valid_targets.is_empty() {
                return Err(anyhow::anyhow!("No valid target nodes available"));
            }
            
            let sharing_id = format!("share_{}", Uuid::new_v4());
            Ok(sharing_id)
        } else {
            Err(anyhow::anyhow!("Indicator not found"))
        }
    }
}

// Tauri command handlers
#[tauri::command]
pub async fn global_threat_intel_get_stats(
    threat_intel_manager: tauri::State<'_, Arc<tokio::sync::Mutex<GlobalThreatIntelligenceManager>>>,
) -> Result<GlobalThreatIntelStats, String> {
    let manager = threat_intel_manager.lock().await;
    manager.get_stats().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn global_threat_intel_get_feeds(
    threat_intel_manager: tauri::State<'_, Arc<tokio::sync::Mutex<GlobalThreatIntelligenceManager>>>,
) -> Result<Vec<ThreatFeed>, String> {
    let manager = threat_intel_manager.lock().await;
    manager.get_threat_feeds().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn global_threat_intel_get_indicators(
    threat_intel_manager: tauri::State<'_, Arc<tokio::sync::Mutex<GlobalThreatIntelligenceManager>>>,
) -> Result<Vec<ThreatIndicator>, String> {
    let manager = threat_intel_manager.lock().await;
    manager.get_threat_indicators().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn global_threat_intel_get_campaigns(
    threat_intel_manager: tauri::State<'_, Arc<tokio::sync::Mutex<GlobalThreatIntelligenceManager>>>,
) -> Result<Vec<ThreatCampaign>, String> {
    let manager = threat_intel_manager.lock().await;
    manager.get_threat_campaigns().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn global_threat_intel_get_nodes(
    threat_intel_manager: tauri::State<'_, Arc<tokio::sync::Mutex<GlobalThreatIntelligenceManager>>>,
) -> Result<Vec<NetworkNode>, String> {
    let manager = threat_intel_manager.lock().await;
    manager.get_network_nodes().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn global_threat_intel_get_hunting_queries(
    threat_intel_manager: tauri::State<'_, Arc<tokio::sync::Mutex<GlobalThreatIntelligenceManager>>>,
) -> Result<Vec<ThreatHuntingQuery>, String> {
    let manager = threat_intel_manager.lock().await;
    manager.get_hunting_queries().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn global_threat_intel_execute_hunt(
    query_id: String,
    threat_intel_manager: tauri::State<'_, Arc<tokio::sync::Mutex<GlobalThreatIntelligenceManager>>>,
) -> Result<Vec<String>, String> {
    let manager = threat_intel_manager.lock().await;
    manager.execute_hunting_query(&query_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn global_threat_intel_share_indicator(
    indicator_id: String,
    target_nodes: Vec<String>,
    threat_intel_manager: tauri::State<'_, Arc<tokio::sync::Mutex<GlobalThreatIntelligenceManager>>>,
) -> Result<String, String> {
    let manager = threat_intel_manager.lock().await;
    manager.share_indicator(&indicator_id, target_nodes).await.map_err(|e| e.to_string())
}
