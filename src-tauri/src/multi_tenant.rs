use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{State, Window};
use tokio::sync::{RwLock, Mutex};
use tracing::{info, warn, error};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// Import our post-quantum cryptography and security modules
use ghost_pq::{DilithiumPublicKey, DilithiumPrivateKey, DilithiumVariant};
// Policy enforcement removed for single-user mode

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub organization_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub organization_type: OrganizationType,
    pub parent_id: Option<String>,
    pub children: Vec<String>, // Child organization IDs
    pub domain: String,
    pub contact_email: String,
    pub contact_phone: Option<String>,
    pub address: Option<Address>,
    pub settings: OrganizationSettings,
    pub limits: ResourceLimits,
    pub billing: BillingInfo,
    pub status: OrganizationStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub metadata: HashMap<String, String>,
    pub signature: Vec<u8>, // Dilithium signature for integrity
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrganizationType {
    Enterprise,
    Department,
    Division,
    Team,
    Project,
    Subsidiary,
    Partner,
    Customer,
    Vendor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    pub street: String,
    pub city: String,
    pub state: String,
    pub postal_code: String,
    pub country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationSettings {
    pub timezone: String,
    pub locale: String,
    pub currency: String,
    pub date_format: String,
    pub time_format: String,
    pub theme: String,
    pub branding: BrandingSettings,
    pub security: SecuritySettings,
    pub features: FeatureSettings,
    pub integrations: IntegrationSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandingSettings {
    pub logo_url: Option<String>,
    pub primary_color: String,
    pub secondary_color: String,
    pub accent_color: String,
    pub custom_css: Option<String>,
    pub favicon_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub password_policy: PasswordPolicy,
    pub session_timeout: u32, // minutes
    pub max_concurrent_sessions: u32,
    pub require_mfa: bool,
    pub allowed_ip_ranges: Vec<String>,
    pub sso_enabled: bool,
    pub sso_provider: Option<String>,
    pub audit_retention_days: u32,
    pub encryption_at_rest: bool,
    pub data_residency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_symbols: bool,
    pub max_age_days: u32,
    pub history_count: u32,
    pub lockout_attempts: u32,
    pub lockout_duration: u32, // minutes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSettings {
    pub enabled_modules: Vec<String>,
    pub disabled_modules: Vec<String>,
    pub beta_features: Vec<String>,
    pub custom_features: HashMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationSettings {
    pub allowed_integrations: Vec<String>,
    pub api_rate_limits: HashMap<String, u32>,
    pub webhook_endpoints: Vec<String>,
    pub external_data_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_users: u32,
    pub max_storage_gb: u32,
    pub max_api_calls_per_hour: u32,
    pub max_concurrent_sessions: u32,
    pub max_reports_per_month: u32,
    pub max_dashboards: u32,
    pub max_data_sources: u32,
    pub max_integrations: u32,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingInfo {
    pub plan: BillingPlan,
    pub billing_cycle: BillingCycle,
    pub billing_contact: String,
    pub payment_method: PaymentMethod,
    pub billing_address: Option<Address>,
    pub tax_id: Option<String>,
    pub current_usage: UsageMetrics,
    pub next_billing_date: Option<DateTime<Utc>>,
    pub auto_renew: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BillingPlan {
    Free,
    Starter,
    Professional,
    Enterprise,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BillingCycle {
    Monthly,
    Quarterly,
    Annually,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethod {
    pub method_type: PaymentType,
    pub last_four: Option<String>,
    pub expiry_date: Option<String>,
    pub billing_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentType {
    CreditCard,
    BankTransfer,
    Invoice,
    PayPal,
    Crypto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMetrics {
    pub users_count: u32,
    pub storage_used_gb: f64,
    pub api_calls_this_month: u32,
    pub reports_generated_this_month: u32,
    pub active_sessions: u32,
    pub data_transfer_gb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrganizationStatus {
    Active,
    Suspended,
    Inactive,
    PendingActivation,
    Trial,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub organization_id: String,
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<Permission>,
    pub groups: Vec<String>,
    pub profile: UserProfile,
    pub preferences: UserPreferences,
    pub security: UserSecurity,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub login_count: u32,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub permission_id: String,
    pub resource: String,
    pub action: String,
    pub scope: PermissionScope,
    pub conditions: Vec<PermissionCondition>,
    pub granted_at: DateTime<Utc>,
    pub granted_by: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionScope {
    Global,
    Organization,
    Department,
    Team,
    Project,
    Resource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCondition {
    pub condition_type: ConditionType,
    pub field: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionType {
    TimeRange,
    IpAddress,
    Location,
    Device,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub title: Option<String>,
    pub department: Option<String>,
    pub manager: Option<String>,
    pub phone: Option<String>,
    pub location: Option<String>,
    pub timezone: String,
    pub locale: String,
    pub bio: Option<String>,
    pub skills: Vec<String>,
    pub certifications: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    pub theme: String,
    pub language: String,
    pub notifications: NotificationPreferences,
    pub dashboard_layout: String,
    pub default_views: HashMap<String, String>,
    pub shortcuts: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPreferences {
    pub email_enabled: bool,
    pub push_enabled: bool,
    pub sms_enabled: bool,
    pub notification_types: HashMap<String, bool>,
    pub quiet_hours: Option<QuietHours>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuietHours {
    pub start_time: String, // HH:MM format
    pub end_time: String,   // HH:MM format
    pub timezone: String,
    pub days: Vec<String>,  // Monday, Tuesday, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSecurity {
    pub password_last_changed: DateTime<Utc>,
    pub mfa_enabled: bool,
    pub mfa_methods: Vec<MfaMethod>,
    pub trusted_devices: Vec<TrustedDevice>,
    pub active_sessions: Vec<UserSession>,
    pub login_history: Vec<LoginRecord>,
    pub security_questions: Vec<SecurityQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaMethod {
    pub method_id: String,
    pub method_type: MfaType,
    pub is_primary: bool,
    pub is_backup: bool,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaType {
    Totp,
    Sms,
    Email,
    Hardware,
    Biometric,
    BackupCodes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub browser: String,
    pub os: String,
    pub ip_address: String,
    pub location: Option<String>,
    pub trusted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub session_id: String,
    pub device_info: String,
    pub ip_address: String,
    pub location: Option<String>,
    pub started_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRecord {
    pub login_id: String,
    pub timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub location: Option<String>,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub mfa_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityQuestion {
    pub question_id: String,
    pub question: String,
    pub answer_hash: String, // Hashed answer
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserStatus {
    Active,
    Inactive,
    Suspended,
    PendingActivation,
    Locked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub role_id: String,
    pub organization_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub role_type: RoleType,
    pub permissions: Vec<String>, // Permission IDs
    pub inherits_from: Vec<String>, // Parent role IDs
    pub is_system_role: bool,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoleType {
    System,
    Organization,
    Department,
    Project,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub group_id: String,
    pub organization_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub group_type: GroupType,
    pub parent_id: Option<String>,
    pub members: Vec<String>, // User IDs
    pub roles: Vec<String>, // Role IDs
    pub permissions: Vec<String>, // Permission IDs
    pub settings: GroupSettings,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupType {
    Department,
    Team,
    Project,
    Security,
    Functional,
    Temporary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSettings {
    pub auto_join: bool,
    pub approval_required: bool,
    pub max_members: Option<u32>,
    pub visibility: GroupVisibility,
    pub join_policy: JoinPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupVisibility {
    Public,
    Private,
    Hidden,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JoinPolicy {
    Open,
    RequestApproval,
    InviteOnly,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    pub quota_id: String,
    pub organization_id: String,
    pub resource_type: ResourceType,
    pub limit: u64,
    pub used: u64,
    pub unit: String,
    pub period: QuotaPeriod,
    pub reset_date: DateTime<Utc>,
    pub soft_limit: Option<u64>,
    pub hard_limit: u64,
    pub alert_threshold: f64, // Percentage
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    Users,
    Storage,
    ApiCalls,
    Reports,
    Dashboards,
    DataSources,
    Integrations,
    Sessions,
    DataTransfer,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuotaPeriod {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Annually,
    Unlimited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub log_id: String,
    pub organization_id: String,
    pub user_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub session_id: Option<String>,
    pub details: HashMap<String, String>,
    pub old_values: Option<HashMap<String, String>>,
    pub new_values: Option<HashMap<String, String>>,
    pub result: AuditResult,
    pub risk_score: f64,
    pub signature: Vec<u8>, // Dilithium signature for integrity
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    Partial,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantStats {
    pub total_organizations: u64,
    pub active_organizations: u64,
    pub total_users: u64,
    pub active_users: u64,
    pub total_roles: u64,
    pub total_groups: u64,
    pub total_permissions: u64,
    pub storage_used_gb: f64,
    pub total_storage_gb: f64,
    pub api_calls_today: u64,
    pub api_calls_this_month: u64,
    pub active_sessions: u64,
    pub login_attempts_today: u64,
    pub failed_logins_today: u64,
    pub mfa_adoption_rate: f64,
    pub average_session_duration: f64, // minutes
    pub top_organizations_by_usage: Vec<(String, f64)>,
    pub resource_utilization: HashMap<String, f64>,
    pub compliance_score: f64,
}

pub struct MultiTenantManager {
    organizations: Arc<RwLock<HashMap<String, Organization>>>,
    users: Arc<RwLock<HashMap<String, User>>>,
    roles: Arc<RwLock<HashMap<String, Role>>>,
    groups: Arc<RwLock<HashMap<String, Group>>>,
    quotas: Arc<RwLock<HashMap<String, ResourceQuota>>>,
    audit_logs: Arc<RwLock<Vec<AuditLog>>>,
    signing_keys: Arc<RwLock<HashMap<String, (DilithiumPublicKey, DilithiumPrivateKey)>>>,
}

impl MultiTenantManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            organizations: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
            quotas: Arc::new(RwLock::new(HashMap::new())),
            audit_logs: Arc::new(RwLock::new(Vec::new())),
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing Multi-Tenant Manager");
        
        // Create sample organizations
        self.create_sample_organizations().await?;
        
        // Create sample users
        self.create_sample_users().await?;
        
        // Create sample roles
        self.create_sample_roles().await?;
        
        // Create sample groups
        self.create_sample_groups().await?;
        
        // Create sample quotas
        self.create_sample_quotas().await?;
        
        info!("Multi-Tenant Manager initialized successfully");
        Ok(())
    }

    async fn create_sample_organizations(&self) -> Result<()> {
        let mut organizations = self.organizations.write().await;
        
        // Root Enterprise Organization
        let enterprise_org = Organization {
            organization_id: Uuid::new_v4().to_string(),
            name: "acme_corp".to_string(),
            display_name: "ACME Corporation".to_string(),
            description: "Global technology company specializing in cybersecurity solutions".to_string(),
            organization_type: OrganizationType::Enterprise,
            parent_id: None,
            children: vec![],
            domain: "acme.com".to_string(),
            contact_email: "admin@acme.com".to_string(),
            contact_phone: Some("+1-555-0123".to_string()),
            address: Some(Address {
                street: "123 Enterprise Blvd".to_string(),
                city: "San Francisco".to_string(),
                state: "CA".to_string(),
                postal_code: "94105".to_string(),
                country: "United States".to_string(),
            }),
            settings: OrganizationSettings {
                timezone: "America/Los_Angeles".to_string(),
                locale: "en-US".to_string(),
                currency: "USD".to_string(),
                date_format: "MM/DD/YYYY".to_string(),
                time_format: "12h".to_string(),
                theme: "corporate".to_string(),
                branding: BrandingSettings {
                    logo_url: Some("https://acme.com/logo.png".to_string()),
                    primary_color: "#1a365d".to_string(),
                    secondary_color: "#2d3748".to_string(),
                    accent_color: "#3182ce".to_string(),
                    custom_css: None,
                    favicon_url: Some("https://acme.com/favicon.ico".to_string()),
                },
                security: SecuritySettings {
                    password_policy: PasswordPolicy {
                        min_length: 12,
                        require_uppercase: true,
                        require_lowercase: true,
                        require_numbers: true,
                        require_symbols: true,
                        max_age_days: 90,
                        history_count: 12,
                        lockout_attempts: 5,
                        lockout_duration: 30,
                    },
                    session_timeout: 480, // 8 hours
                    max_concurrent_sessions: 3,
                    require_mfa: true,
                    allowed_ip_ranges: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
                    sso_enabled: true,
                    sso_provider: Some("Azure AD".to_string()),
                    audit_retention_days: 2555, // 7 years
                    encryption_at_rest: true,
                    data_residency: "US".to_string(),
                },
                features: FeatureSettings {
                    enabled_modules: vec![
                        "orchestration".to_string(),
                        "compliance".to_string(),
                        "reporting".to_string(),
                        "threat_intelligence".to_string(),
                    ],
                    disabled_modules: vec![],
                    beta_features: vec!["ai_assistant".to_string()],
                    custom_features: HashMap::from([
                        ("advanced_analytics".to_string(), true),
                        ("custom_integrations".to_string(), true),
                    ]),
                },
                integrations: IntegrationSettings {
                    allowed_integrations: vec![
                        "splunk".to_string(),
                        "servicenow".to_string(),
                        "slack".to_string(),
                    ],
                    api_rate_limits: HashMap::from([
                        ("default".to_string(), 1000),
                        ("reporting".to_string(), 100),
                    ]),
                    webhook_endpoints: vec!["https://acme.com/webhooks/security".to_string()],
                    external_data_sources: vec!["siem".to_string(), "edr".to_string()],
                },
            },
            limits: ResourceLimits {
                max_users: 10000,
                max_storage_gb: 10000,
                max_api_calls_per_hour: 100000,
                max_concurrent_sessions: 5000,
                max_reports_per_month: 10000,
                max_dashboards: 1000,
                max_data_sources: 100,
                max_integrations: 50,
                retention_days: 2555,
            },
            billing: BillingInfo {
                plan: BillingPlan::Enterprise,
                billing_cycle: BillingCycle::Annually,
                billing_contact: "billing@acme.com".to_string(),
                payment_method: PaymentMethod {
                    method_type: PaymentType::Invoice,
                    last_four: None,
                    expiry_date: None,
                    billing_name: "ACME Corporation".to_string(),
                },
                billing_address: Some(Address {
                    street: "123 Enterprise Blvd".to_string(),
                    city: "San Francisco".to_string(),
                    state: "CA".to_string(),
                    postal_code: "94105".to_string(),
                    country: "United States".to_string(),
                }),
                tax_id: Some("12-3456789".to_string()),
                current_usage: UsageMetrics {
                    users_count: 2500,
                    storage_used_gb: 1250.5,
                    api_calls_this_month: 2500000,
                    reports_generated_this_month: 1500,
                    active_sessions: 850,
                    data_transfer_gb: 500.2,
                },
                next_billing_date: Some(Utc::now() + chrono::Duration::days(90)),
                auto_renew: true,
            },
            status: OrganizationStatus::Active,
            created_at: Utc::now() - chrono::Duration::days(365),
            updated_at: Utc::now() - chrono::Duration::days(7),
            created_by: "system".to_string(),
            metadata: HashMap::from([
                ("industry".to_string(), "Technology".to_string()),
                ("size".to_string(), "Large".to_string()),
                ("compliance".to_string(), "SOX,GDPR,ISO27001".to_string()),
            ]),
            signature: vec![0u8; 64], // Placeholder signature
        };

        // Security Department
        let security_dept = Organization {
            organization_id: Uuid::new_v4().to_string(),
            name: "security_dept".to_string(),
            display_name: "Security Department".to_string(),
            description: "Information Security and Risk Management".to_string(),
            organization_type: OrganizationType::Department,
            parent_id: Some(enterprise_org.organization_id.clone()),
            children: vec![],
            domain: "security.acme.com".to_string(),
            contact_email: "security@acme.com".to_string(),
            contact_phone: Some("+1-555-0124".to_string()),
            address: None,
            settings: OrganizationSettings {
                timezone: "America/Los_Angeles".to_string(),
                locale: "en-US".to_string(),
                currency: "USD".to_string(),
                date_format: "MM/DD/YYYY".to_string(),
                time_format: "24h".to_string(),
                theme: "security".to_string(),
                branding: BrandingSettings {
                    logo_url: None,
                    primary_color: "#dc2626".to_string(),
                    secondary_color: "#991b1b".to_string(),
                    accent_color: "#fbbf24".to_string(),
                    custom_css: None,
                    favicon_url: None,
                },
                security: SecuritySettings {
                    password_policy: PasswordPolicy {
                        min_length: 16,
                        require_uppercase: true,
                        require_lowercase: true,
                        require_numbers: true,
                        require_symbols: true,
                        max_age_days: 60,
                        history_count: 24,
                        lockout_attempts: 3,
                        lockout_duration: 60,
                    },
                    session_timeout: 240, // 4 hours
                    max_concurrent_sessions: 2,
                    require_mfa: true,
                    allowed_ip_ranges: vec!["10.1.0.0/16".to_string()],
                    sso_enabled: true,
                    sso_provider: Some("Azure AD".to_string()),
                    audit_retention_days: 2555,
                    encryption_at_rest: true,
                    data_residency: "US".to_string(),
                },
                features: FeatureSettings {
                    enabled_modules: vec![
                        "orchestration".to_string(),
                        "compliance".to_string(),
                        "threat_intelligence".to_string(),
                        "forensics".to_string(),
                    ],
                    disabled_modules: vec![],
                    beta_features: vec!["behavioral_analytics".to_string()],
                    custom_features: HashMap::from([
                        ("threat_hunting".to_string(), true),
                        ("incident_response".to_string(), true),
                    ]),
                },
                integrations: IntegrationSettings {
                    allowed_integrations: vec![
                        "splunk".to_string(),
                        "crowdstrike".to_string(),
                        "pagerduty".to_string(),
                    ],
                    api_rate_limits: HashMap::from([
                        ("default".to_string(), 5000),
                        ("threat_intel".to_string(), 1000),
                    ]),
                    webhook_endpoints: vec!["https://security.acme.com/webhooks/alerts".to_string()],
                    external_data_sources: vec!["siem".to_string(), "edr".to_string(), "ndr".to_string()],
                },
            },
            limits: ResourceLimits {
                max_users: 100,
                max_storage_gb: 1000,
                max_api_calls_per_hour: 10000,
                max_concurrent_sessions: 200,
                max_reports_per_month: 1000,
                max_dashboards: 50,
                max_data_sources: 20,
                max_integrations: 10,
                retention_days: 2555,
            },
            billing: BillingInfo {
                plan: BillingPlan::Professional,
                billing_cycle: BillingCycle::Monthly,
                billing_contact: "security-admin@acme.com".to_string(),
                payment_method: PaymentMethod {
                    method_type: PaymentType::CreditCard,
                    last_four: Some("4567".to_string()),
                    expiry_date: Some("12/25".to_string()),
                    billing_name: "Security Department".to_string(),
                },
                billing_address: None,
                tax_id: None,
                current_usage: UsageMetrics {
                    users_count: 45,
                    storage_used_gb: 125.8,
                    api_calls_this_month: 85000,
                    reports_generated_this_month: 250,
                    active_sessions: 32,
                    data_transfer_gb: 45.2,
                },
                next_billing_date: Some(Utc::now() + chrono::Duration::days(15)),
                auto_renew: true,
            },
            status: OrganizationStatus::Active,
            created_at: Utc::now() - chrono::Duration::days(300),
            updated_at: Utc::now() - chrono::Duration::days(2),
            created_by: "admin@acme.com".to_string(),
            metadata: HashMap::from([
                ("department_code".to_string(), "SEC".to_string()),
                ("budget_center".to_string(), "IT-SEC-001".to_string()),
            ]),
            signature: vec![0u8; 64], // Placeholder signature
        };

        organizations.insert(enterprise_org.organization_id.clone(), enterprise_org);
        organizations.insert(security_dept.organization_id.clone(), security_dept);

        info!("Created {} sample organizations", organizations.len());
        Ok(())
    }

    async fn create_sample_users(&self) -> Result<()> {
        let mut users = self.users.write().await;
        let organizations = self.organizations.read().await;
        
        if let Some(org) = organizations.values().next() {
            let admin_user = User {
                user_id: Uuid::new_v4().to_string(),
                organization_id: org.organization_id.clone(),
                username: "admin".to_string(),
                email: "admin@acme.com".to_string(),
                first_name: "System".to_string(),
                last_name: "Administrator".to_string(),
                display_name: "System Administrator".to_string(),
                avatar_url: Some("https://acme.com/avatars/admin.jpg".to_string()),
                roles: vec!["super_admin".to_string(), "security_admin".to_string()],
                permissions: vec![],
                groups: vec!["administrators".to_string()],
                profile: UserProfile {
                    title: Some("Chief Information Security Officer".to_string()),
                    department: Some("Security".to_string()),
                    manager: None,
                    phone: Some("+1-555-0100".to_string()),
                    location: Some("San Francisco, CA".to_string()),
                    timezone: "America/Los_Angeles".to_string(),
                    locale: "en-US".to_string(),
                    bio: Some("Experienced cybersecurity professional with 15+ years in enterprise security".to_string()),
                    skills: vec![
                        "Incident Response".to_string(),
                        "Risk Management".to_string(),
                        "Compliance".to_string(),
                    ],
                    certifications: vec![
                        "CISSP".to_string(),
                        "CISM".to_string(),
                        "CISSP".to_string(),
                    ],
                },
                preferences: UserPreferences {
                    theme: "dark".to_string(),
                    language: "en".to_string(),
                    notifications: NotificationPreferences {
                        email_enabled: true,
                        push_enabled: true,
                        sms_enabled: true,
                        notification_types: HashMap::from([
                            ("security_alerts".to_string(), true),
                            ("system_updates".to_string(), true),
                            ("reports".to_string(), false),
                        ]),
                        quiet_hours: Some(QuietHours {
                            start_time: "22:00".to_string(),
                            end_time: "06:00".to_string(),
                            timezone: "America/Los_Angeles".to_string(),
                            days: vec!["Saturday".to_string(), "Sunday".to_string()],
                        }),
                    },
                    dashboard_layout: "executive".to_string(),
                    default_views: HashMap::from([
                        ("dashboard".to_string(), "security_overview".to_string()),
                        ("reports".to_string(), "executive_summary".to_string()),
                    ]),
                    shortcuts: HashMap::from([
                        ("ctrl+shift+i".to_string(), "incident_response".to_string()),
                        ("ctrl+shift+r".to_string(), "reports".to_string()),
                    ]),
                },
                security: UserSecurity {
                    password_last_changed: Utc::now() - chrono::Duration::days(30),
                    mfa_enabled: true,
                    mfa_methods: vec![
                        MfaMethod {
                            method_id: Uuid::new_v4().to_string(),
                            method_type: MfaType::Totp,
                            is_primary: true,
                            is_backup: false,
                            created_at: Utc::now() - chrono::Duration::days(90),
                            last_used: Some(Utc::now() - chrono::Duration::hours(2)),
                        },
                        MfaMethod {
                            method_id: Uuid::new_v4().to_string(),
                            method_type: MfaType::BackupCodes,
                            is_primary: false,
                            is_backup: true,
                            created_at: Utc::now() - chrono::Duration::days(90),
                            last_used: None,
                        },
                    ],
                    trusted_devices: vec![
                        TrustedDevice {
                            device_id: Uuid::new_v4().to_string(),
                            device_name: "MacBook Pro".to_string(),
                            device_type: "laptop".to_string(),
                            browser: "Chrome".to_string(),
                            os: "macOS".to_string(),
                            ip_address: "10.1.1.100".to_string(),
                            location: Some("San Francisco, CA".to_string()),
                            trusted_at: Utc::now() - chrono::Duration::days(30),
                            expires_at: Utc::now() + chrono::Duration::days(60),
                            last_used: Utc::now() - chrono::Duration::hours(1),
                        }
                    ],
                    active_sessions: vec![
                        UserSession {
                            session_id: Uuid::new_v4().to_string(),
                            device_info: "Chrome on macOS".to_string(),
                            ip_address: "10.1.1.100".to_string(),
                            location: Some("San Francisco, CA".to_string()),
                            started_at: Utc::now() - chrono::Duration::hours(2),
                            last_activity: Utc::now() - chrono::Duration::minutes(5),
                            expires_at: Utc::now() + chrono::Duration::hours(6),
                            is_current: true,
                        }
                    ],
                    login_history: vec![
                        LoginRecord {
                            login_id: Uuid::new_v4().to_string(),
                            timestamp: Utc::now() - chrono::Duration::hours(2),
                            ip_address: "10.1.1.100".to_string(),
                            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string(),
                            location: Some("San Francisco, CA".to_string()),
                            success: true,
                            failure_reason: None,
                            mfa_used: true,
                        }
                    ],
                    security_questions: vec![],
                },
                status: UserStatus::Active,
                created_at: Utc::now() - chrono::Duration::days(365),
                updated_at: Utc::now() - chrono::Duration::hours(2),
                last_login: Some(Utc::now() - chrono::Duration::hours(2)),
                login_count: 1247,
                metadata: HashMap::from([
                    ("employee_id".to_string(), "EMP001".to_string()),
                    ("clearance_level".to_string(), "TOP_SECRET".to_string()),
                ]),
            };

            users.insert(admin_user.user_id.clone(), admin_user);
        }

        info!("Created {} sample users", users.len());
        Ok(())
    }

    async fn create_sample_roles(&self) -> Result<()> {
        let mut roles = self.roles.write().await;
        let organizations = self.organizations.read().await;
        
        if let Some(org) = organizations.values().next() {
            let super_admin_role = Role {
                role_id: Uuid::new_v4().to_string(),
                organization_id: org.organization_id.clone(),
                name: "super_admin".to_string(),
                display_name: "Super Administrator".to_string(),
                description: "Full system access with all permissions".to_string(),
                role_type: RoleType::System,
                permissions: vec!["*".to_string()], // All permissions
                inherits_from: vec![],
                is_system_role: true,
                is_default: false,
                created_at: Utc::now() - chrono::Duration::days(365),
                updated_at: Utc::now() - chrono::Duration::days(365),
                created_by: "system".to_string(),
            };

            let security_admin_role = Role {
                role_id: Uuid::new_v4().to_string(),
                organization_id: org.organization_id.clone(),
                name: "security_admin".to_string(),
                display_name: "Security Administrator".to_string(),
                description: "Security operations and incident response management".to_string(),
                role_type: RoleType::Organization,
                permissions: vec![
                    "security:*".to_string(),
                    "incidents:*".to_string(),
                    "compliance:read".to_string(),
                    "reports:create".to_string(),
                ],
                inherits_from: vec![],
                is_system_role: false,
                is_default: false,
                created_at: Utc::now() - chrono::Duration::days(300),
                updated_at: Utc::now() - chrono::Duration::days(30),
                created_by: "admin".to_string(),
            };

            let analyst_role = Role {
                role_id: Uuid::new_v4().to_string(),
                organization_id: org.organization_id.clone(),
                name: "security_analyst".to_string(),
                display_name: "Security Analyst".to_string(),
                description: "Security monitoring and analysis".to_string(),
                role_type: RoleType::Organization,
                permissions: vec![
                    "security:read".to_string(),
                    "incidents:read".to_string(),
                    "incidents:update".to_string(),
                    "dashboards:read".to_string(),
                ],
                inherits_from: vec![],
                is_system_role: false,
                is_default: true,
                created_at: Utc::now() - chrono::Duration::days(300),
                updated_at: Utc::now() - chrono::Duration::days(30),
                created_by: "admin".to_string(),
            };

            roles.insert(super_admin_role.role_id.clone(), super_admin_role);
            roles.insert(security_admin_role.role_id.clone(), security_admin_role);
            roles.insert(analyst_role.role_id.clone(), analyst_role);
        }

        info!("Created {} sample roles", roles.len());
        Ok(())
    }

    async fn create_sample_groups(&self) -> Result<()> {
        let mut groups = self.groups.write().await;
        let organizations = self.organizations.read().await;
        
        if let Some(org) = organizations.values().next() {
            let admin_group = Group {
                group_id: Uuid::new_v4().to_string(),
                organization_id: org.organization_id.clone(),
                name: "administrators".to_string(),
                display_name: "System Administrators".to_string(),
                description: "System administrators with elevated privileges".to_string(),
                group_type: GroupType::Security,
                parent_id: None,
                members: vec![], // Would contain user IDs
                roles: vec!["super_admin".to_string()],
                permissions: vec![],
                settings: GroupSettings {
                    auto_join: false,
                    approval_required: true,
                    max_members: Some(10),
                    visibility: GroupVisibility::Private,
                    join_policy: JoinPolicy::InviteOnly,
                },
                created_at: Utc::now() - chrono::Duration::days(365),
                updated_at: Utc::now() - chrono::Duration::days(30),
                created_by: "system".to_string(),
            };

            let security_team = Group {
                group_id: Uuid::new_v4().to_string(),
                organization_id: org.organization_id.clone(),
                name: "security_team".to_string(),
                display_name: "Security Team".to_string(),
                description: "Information security professionals".to_string(),
                group_type: GroupType::Department,
                parent_id: None,
                members: vec![],
                roles: vec!["security_admin".to_string(), "security_analyst".to_string()],
                permissions: vec![],
                settings: GroupSettings {
                    auto_join: false,
                    approval_required: true,
                    max_members: Some(50),
                    visibility: GroupVisibility::Public,
                    join_policy: JoinPolicy::RequestApproval,
                },
                created_at: Utc::now() - chrono::Duration::days(300),
                updated_at: Utc::now() - chrono::Duration::days(7),
                created_by: "admin".to_string(),
            };

            groups.insert(admin_group.group_id.clone(), admin_group);
            groups.insert(security_team.group_id.clone(), security_team);
        }

        info!("Created {} sample groups", groups.len());
        Ok(())
    }

    async fn create_sample_quotas(&self) -> Result<()> {
        let mut quotas = self.quotas.write().await;
        let organizations = self.organizations.read().await;
        
        if let Some(org) = organizations.values().next() {
            let storage_quota = ResourceQuota {
                quota_id: Uuid::new_v4().to_string(),
                organization_id: org.organization_id.clone(),
                resource_type: ResourceType::Storage,
                limit: 10000, // 10TB
                used: 1250,   // 1.25TB
                unit: "GB".to_string(),
                period: QuotaPeriod::Monthly,
                reset_date: Utc::now() + chrono::Duration::days(15),
                soft_limit: Some(8000), // 8TB
                hard_limit: 10000,
                alert_threshold: 0.80, // 80%
                created_at: Utc::now() - chrono::Duration::days(365),
                updated_at: Utc::now(),
            };

            let api_quota = ResourceQuota {
                quota_id: Uuid::new_v4().to_string(),
                organization_id: org.organization_id.clone(),
                resource_type: ResourceType::ApiCalls,
                limit: 100000, // 100k calls per hour
                used: 15000,   // 15k used
                unit: "calls".to_string(),
                period: QuotaPeriod::Hourly,
                reset_date: Utc::now() + chrono::Duration::minutes(45),
                soft_limit: Some(80000), // 80k
                hard_limit: 100000,
                alert_threshold: 0.90, // 90%
                created_at: Utc::now() - chrono::Duration::days(365),
                updated_at: Utc::now(),
            };

            quotas.insert(storage_quota.quota_id.clone(), storage_quota);
            quotas.insert(api_quota.quota_id.clone(), api_quota);
        }

        info!("Created {} sample quotas", quotas.len());
        Ok(())
    }

    pub async fn get_organizations(&self) -> Result<Vec<Organization>> {
        let organizations = self.organizations.read().await;
        Ok(organizations.values().cloned().collect())
    }

    pub async fn get_organization(&self, org_id: &str) -> Result<Option<Organization>> {
        let organizations = self.organizations.read().await;
        Ok(organizations.get(org_id).cloned())
    }

    pub async fn create_organization(&self, mut organization: Organization) -> Result<String> {
        organization.organization_id = Uuid::new_v4().to_string();
        organization.created_at = Utc::now();
        organization.updated_at = Utc::now();
        
        let org_id = organization.organization_id.clone();
        let mut organizations = self.organizations.write().await;
        organizations.insert(org_id.clone(), organization);
        
        info!("Created new organization: {}", org_id);
        Ok(org_id)
    }

    pub async fn get_users(&self, org_id: Option<String>) -> Result<Vec<User>> {
        let users = self.users.read().await;
        let filtered: Vec<User> = if let Some(oid) = org_id {
            users.values()
                .filter(|u| u.organization_id == oid)
                .cloned()
                .collect()
        } else {
            users.values().cloned().collect()
        };
        Ok(filtered)
    }

    pub async fn get_user(&self, user_id: &str) -> Result<Option<User>> {
        let users = self.users.read().await;
        Ok(users.get(user_id).cloned())
    }

    pub async fn create_user(&self, mut user: User) -> Result<String> {
        user.user_id = Uuid::new_v4().to_string();
        user.created_at = Utc::now();
        user.updated_at = Utc::now();
        
        let user_id = user.user_id.clone();
        let mut users = self.users.write().await;
        users.insert(user_id.clone(), user);
        
        info!("Created new user: {}", user_id);
        Ok(user_id)
    }

    pub async fn get_roles(&self, org_id: Option<String>) -> Result<Vec<Role>> {
        let roles = self.roles.read().await;
        let filtered: Vec<Role> = if let Some(oid) = org_id {
            roles.values()
                .filter(|r| r.organization_id == oid)
                .cloned()
                .collect()
        } else {
            roles.values().cloned().collect()
        };
        Ok(filtered)
    }

    pub async fn get_groups(&self, org_id: Option<String>) -> Result<Vec<Group>> {
        let groups = self.groups.read().await;
        let filtered: Vec<Group> = if let Some(oid) = org_id {
            groups.values()
                .filter(|g| g.organization_id == oid)
                .cloned()
                .collect()
        } else {
            groups.values().cloned().collect()
        };
        Ok(filtered)
    }

    pub async fn get_quotas(&self, org_id: &str) -> Result<Vec<ResourceQuota>> {
        let quotas = self.quotas.read().await;
        let filtered: Vec<ResourceQuota> = quotas.values()
            .filter(|q| q.organization_id == org_id)
            .cloned()
            .collect();
        Ok(filtered)
    }

    pub async fn get_audit_logs(&self, org_id: Option<String>, limit: Option<usize>) -> Result<Vec<AuditLog>> {
        let audit_logs = self.audit_logs.read().await;
        let mut filtered: Vec<AuditLog> = if let Some(oid) = org_id {
            audit_logs.iter()
                .filter(|log| log.organization_id == oid)
                .cloned()
                .collect()
        } else {
            audit_logs.clone()
        };
        
        // Sort by timestamp (newest first)
        filtered.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        if let Some(limit) = limit {
            filtered.truncate(limit);
        }
        
        Ok(filtered)
    }

    pub async fn get_stats(&self) -> Result<MultiTenantStats> {
        let organizations = self.organizations.read().await;
        let users = self.users.read().await;
        let roles = self.roles.read().await;
        let groups = self.groups.read().await;
        let quotas = self.quotas.read().await;
        let audit_logs = self.audit_logs.read().await;

        let total_organizations = organizations.len() as u64;
        let active_organizations = organizations.values()
            .filter(|org| matches!(org.status, OrganizationStatus::Active))
            .count() as u64;

        let total_users = users.len() as u64;
        let active_users = users.values()
            .filter(|user| matches!(user.status, UserStatus::Active))
            .count() as u64;

        let total_storage_gb = quotas.values()
            .filter(|q| matches!(q.resource_type, ResourceType::Storage))
            .map(|q| q.limit as f64)
            .sum::<f64>();

        let storage_used_gb = quotas.values()
            .filter(|q| matches!(q.resource_type, ResourceType::Storage))
            .map(|q| q.used as f64)
            .sum::<f64>();

        let mfa_enabled_users = users.values()
            .filter(|user| user.security.mfa_enabled)
            .count() as u64;
        let mfa_adoption_rate = if total_users > 0 {
            mfa_enabled_users as f64 / total_users as f64
        } else {
            0.0
        };

        let today = Utc::now().date_naive();
        let api_calls_today = audit_logs.iter()
            .filter(|log| log.timestamp.date_naive() == today && log.action.contains("api"))
            .count() as u64;

        let failed_logins_today = audit_logs.iter()
            .filter(|log| {
                log.timestamp.date_naive() == today && 
                log.action == "login" && 
                matches!(log.result, AuditResult::Failure)
            })
            .count() as u64;

        let login_attempts_today = audit_logs.iter()
            .filter(|log| log.timestamp.date_naive() == today && log.action == "login")
            .count() as u64;

        let active_sessions = users.values()
            .map(|user| user.security.active_sessions.len() as u64)
            .sum::<u64>();

        Ok(MultiTenantStats {
            total_organizations,
            active_organizations,
            total_users,
            active_users,
            total_roles: roles.len() as u64,
            total_groups: groups.len() as u64,
            total_permissions: 0, // Would be calculated from permissions
            storage_used_gb,
            total_storage_gb,
            api_calls_today,
            api_calls_this_month: api_calls_today * 30, // Rough estimate
            active_sessions,
            login_attempts_today,
            failed_logins_today,
            mfa_adoption_rate,
            average_session_duration: 240.0, // 4 hours average
            top_organizations_by_usage: vec![
                ("ACME Corporation".to_string(), 1250.5),
                ("Security Department".to_string(), 125.8),
            ],
            resource_utilization: HashMap::from([
                ("storage".to_string(), storage_used_gb / total_storage_gb),
                ("users".to_string(), active_users as f64 / total_users as f64),
            ]),
            compliance_score: 0.92,
        })
    }
}

// Tauri Commands
#[tauri::command]
pub async fn multitenant_get_organizations(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
) -> Result<Vec<Organization>, String> {
    let manager = multitenant_manager.lock().await;
    manager.get_organizations()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_get_organization(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
    org_id: String,
) -> Result<Option<Organization>, String> {
    let manager = multitenant_manager.lock().await;
    manager.get_organization(&org_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_create_organization(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
    organization: Organization,
) -> Result<String, String> {
    let manager = multitenant_manager.lock().await;
    manager.create_organization(organization)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_get_users(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
    org_id: Option<String>,
) -> Result<Vec<User>, String> {
    let manager = multitenant_manager.lock().await;
    manager.get_users(org_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_get_user(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
    user_id: String,
) -> Result<Option<User>, String> {
    let manager = multitenant_manager.lock().await;
    manager.get_user(&user_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_create_user(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
    user: User,
) -> Result<String, String> {
    let manager = multitenant_manager.lock().await;
    manager.create_user(user)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_get_roles(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
    org_id: Option<String>,
) -> Result<Vec<Role>, String> {
    let manager = multitenant_manager.lock().await;
    manager.get_roles(org_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_get_groups(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
    org_id: Option<String>,
) -> Result<Vec<Group>, String> {
    let manager = multitenant_manager.lock().await;
    manager.get_groups(org_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_get_quotas(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
    org_id: String,
) -> Result<Vec<ResourceQuota>, String> {
    let manager = multitenant_manager.lock().await;
    manager.get_quotas(&org_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_get_audit_logs(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
    org_id: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<AuditLog>, String> {
    let manager = multitenant_manager.lock().await;
    manager.get_audit_logs(org_id, limit)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn multitenant_get_stats(
    multitenant_manager: State<'_, Arc<tokio::sync::Mutex<MultiTenantManager>>>,
) -> Result<MultiTenantStats, String> {
    let manager = multitenant_manager.lock().await;
    manager.get_stats()
        .await
        .map_err(|e| e.to_string())
}
