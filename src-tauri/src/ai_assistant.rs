use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{State, Window};
use tokio::sync::{RwLock, Mutex};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAssistant {
    pub id: String,
    pub name: String,
    pub model: AiModel,
    pub capabilities: Vec<AiCapability>,
    pub status: AiStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_interaction: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AiModel {
    LocalLLM,
    CloudLLM,
    HybridLLM,
    CommandSuggester,
    SecurityAnalyzer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AiCapability {
    CommandSuggestion,
    CodeCompletion,
    SecurityAnalysis,
    SystemDiagnostics,
    DocumentationHelp,
    TroubleshootingGuide,
    PolicyRecommendation,
    ThreatDetection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AiStatus {
    Ready,
    Processing,
    Learning,
    Offline,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiQuery {
    pub id: String,
    pub user_input: String,
    pub context: AiContext,
    pub query_type: AiQueryType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiContext {
    pub current_directory: Option<String>,
    pub active_connections: Vec<String>,
    pub recent_commands: Vec<String>,
    pub system_info: Option<SystemInfo>,
    pub security_context: Option<SecurityContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os: String,
    pub shell: String,
    pub user: String,
    pub hostname: String,
    pub uptime: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub threat_level: ThreatLevel,
    pub active_policies: Vec<String>,
    pub recent_alerts: Vec<String>,
    pub quarantine_status: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AiQueryType {
    CommandSuggestion,
    Help,
    Explanation,
    Troubleshooting,
    SecurityAdvice,
    BestPractices,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiResponse {
    pub id: String,
    pub query_id: String,
    pub response_type: AiResponseType,
    pub content: String,
    pub suggestions: Vec<CommandSuggestion>,
    pub confidence: f32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub metadata: ResponseMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AiResponseType {
    CommandSuggestion,
    Explanation,
    Warning,
    Information,
    Error,
    Tutorial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSuggestion {
    pub command: String,
    pub description: String,
    pub category: CommandCategory,
    pub confidence: f32,
    pub safety_level: SafetyLevel,
    pub estimated_time: Option<u32>, // seconds
    pub prerequisites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandCategory {
    FileSystem,
    Network,
    Security,
    System,
    Development,
    Database,
    Docker,
    Git,
    SSH,
    VPN,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafetyLevel {
    Safe,
    Caution,
    Dangerous,
    RequiresConfirmation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub processing_time_ms: u64,
    pub model_used: String,
    pub tokens_used: Option<u32>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningData {
    pub command_patterns: HashMap<String, u32>,
    pub user_preferences: HashMap<String, String>,
    pub success_rates: HashMap<String, f32>,
    pub error_patterns: HashMap<String, u32>,
}

pub struct AiAssistantManager {
    assistants: Arc<RwLock<HashMap<String, AiAssistant>>>,
    query_history: Arc<RwLock<Vec<AiQuery>>>,
    response_history: Arc<RwLock<Vec<AiResponse>>>,
    learning_data: Arc<RwLock<LearningData>>,
    command_database: Arc<RwLock<HashMap<String, Vec<CommandSuggestion>>>>,
}

impl AiAssistantManager {
    pub fn new() -> Result<Self> {
        let mut command_db = HashMap::new();
        
        // Initialize command database with common commands
        Self::populate_command_database(&mut command_db);
        
        Ok(Self {
            assistants: Arc::new(RwLock::new(HashMap::new())),
            query_history: Arc::new(RwLock::new(Vec::new())),
            response_history: Arc::new(RwLock::new(Vec::new())),
            learning_data: Arc::new(RwLock::new(LearningData {
                command_patterns: HashMap::new(),
                user_preferences: HashMap::new(),
                success_rates: HashMap::new(),
                error_patterns: HashMap::new(),
            })),
            command_database: Arc::new(RwLock::new(command_db)),
        })
    }

    fn populate_command_database(db: &mut HashMap<String, Vec<CommandSuggestion>>) {
        // File System Commands
        db.insert("file".to_string(), vec![
            CommandSuggestion {
                command: "ls -la".to_string(),
                description: "List all files with detailed information".to_string(),
                category: CommandCategory::FileSystem,
                confidence: 0.9,
                safety_level: SafetyLevel::Safe,
                estimated_time: Some(1),
                prerequisites: vec![],
            },
            CommandSuggestion {
                command: "find . -name \"*.txt\"".to_string(),
                description: "Find all .txt files in current directory".to_string(),
                category: CommandCategory::FileSystem,
                confidence: 0.8,
                safety_level: SafetyLevel::Safe,
                estimated_time: Some(5),
                prerequisites: vec![],
            },
        ]);

        // Network Commands
        db.insert("network".to_string(), vec![
            CommandSuggestion {
                command: "ping google.com".to_string(),
                description: "Test network connectivity to Google".to_string(),
                category: CommandCategory::Network,
                confidence: 0.9,
                safety_level: SafetyLevel::Safe,
                estimated_time: Some(10),
                prerequisites: vec![],
            },
            CommandSuggestion {
                command: "netstat -tuln".to_string(),
                description: "Show listening ports and connections".to_string(),
                category: CommandCategory::Network,
                confidence: 0.8,
                safety_level: SafetyLevel::Safe,
                estimated_time: Some(2),
                prerequisites: vec![],
            },
        ]);

        // Security Commands
        db.insert("security".to_string(), vec![
            CommandSuggestion {
                command: "sudo ufw status".to_string(),
                description: "Check firewall status".to_string(),
                category: CommandCategory::Security,
                confidence: 0.9,
                safety_level: SafetyLevel::Safe,
                estimated_time: Some(1),
                prerequisites: vec!["sudo access".to_string()],
            },
            CommandSuggestion {
                command: "chmod 600 ~/.ssh/id_rsa".to_string(),
                description: "Secure SSH private key permissions".to_string(),
                category: CommandCategory::Security,
                confidence: 0.8,
                safety_level: SafetyLevel::Caution,
                estimated_time: Some(1),
                prerequisites: vec!["SSH key exists".to_string()],
            },
        ]);

        // System Commands
        db.insert("system".to_string(), vec![
            CommandSuggestion {
                command: "htop".to_string(),
                description: "Interactive process viewer".to_string(),
                category: CommandCategory::System,
                confidence: 0.9,
                safety_level: SafetyLevel::Safe,
                estimated_time: None,
                prerequisites: vec!["htop installed".to_string()],
            },
            CommandSuggestion {
                command: "df -h".to_string(),
                description: "Show disk space usage in human-readable format".to_string(),
                category: CommandCategory::System,
                confidence: 0.9,
                safety_level: SafetyLevel::Safe,
                estimated_time: Some(2),
                prerequisites: vec![],
            },
        ]);
    }

    pub async fn create_assistant(&self, name: String, model: AiModel, capabilities: Vec<AiCapability>) -> Result<String> {
        let assistant_id = Uuid::new_v4().to_string();
        
        let assistant = AiAssistant {
            id: assistant_id.clone(),
            name,
            model,
            capabilities,
            status: AiStatus::Ready,
            created_at: chrono::Utc::now(),
            last_interaction: None,
        };

        self.assistants.write().await.insert(assistant_id.clone(), assistant);
        
        info!("Created AI assistant: {}", assistant_id);
        Ok(assistant_id)
    }

    pub async fn query_assistant(
        &self,
        assistant_id: &str,
        user_input: String,
        context: AiContext,
        query_type: AiQueryType,
    ) -> Result<AiResponse> {
        let query_id = Uuid::new_v4().to_string();
        let start_time = std::time::Instant::now();

        // Create query record
        let query = AiQuery {
            id: query_id.clone(),
            user_input: user_input.clone(),
            context: context.clone(),
            query_type: query_type.clone(),
            timestamp: chrono::Utc::now(),
        };

        self.query_history.write().await.push(query);

        // Update assistant last interaction
        if let Some(assistant) = self.assistants.write().await.get_mut(assistant_id) {
            assistant.last_interaction = Some(chrono::Utc::now());
            assistant.status = AiStatus::Processing;
        }

        // Process the query based on type
        let response = match query_type {
            AiQueryType::CommandSuggestion => {
                self.generate_command_suggestions(&user_input, &context).await?
            },
            AiQueryType::Help => {
                self.generate_help_response(&user_input, &context).await?
            },
            AiQueryType::Explanation => {
                self.generate_explanation(&user_input, &context).await?
            },
            AiQueryType::Troubleshooting => {
                self.generate_troubleshooting_guide(&user_input, &context).await?
            },
            AiQueryType::SecurityAdvice => {
                self.generate_security_advice(&user_input, &context).await?
            },
            AiQueryType::BestPractices => {
                self.generate_best_practices(&user_input, &context).await?
            },
        };

        let processing_time = start_time.elapsed().as_millis() as u64;

        let ai_response = AiResponse {
            id: Uuid::new_v4().to_string(),
            query_id,
            response_type: response.0,
            content: response.1,
            suggestions: response.2,
            confidence: response.3,
            timestamp: chrono::Utc::now(),
            metadata: ResponseMetadata {
                processing_time_ms: processing_time,
                model_used: "GHOSTSHELL-AI-v1".to_string(),
                tokens_used: Some(user_input.len() as u32),
                sources: vec!["Local Knowledge Base".to_string()],
            },
        };

        // Update assistant status
        if let Some(assistant) = self.assistants.write().await.get_mut(assistant_id) {
            assistant.status = AiStatus::Ready;
        }

        self.response_history.write().await.push(ai_response.clone());

        info!("AI query processed in {}ms", processing_time);
        Ok(ai_response)
    }

    async fn generate_command_suggestions(
        &self,
        user_input: &str,
        context: &AiContext,
    ) -> Result<(AiResponseType, String, Vec<CommandSuggestion>, f32)> {
        let input_lower = user_input.to_lowercase();
        let mut suggestions = Vec::new();
        let mut content = String::new();

        // Analyze input for keywords
        let keywords = vec!["file", "network", "security", "system"];
        
        for keyword in keywords {
            if input_lower.contains(keyword) {
                if let Some(commands) = self.command_database.read().await.get(keyword) {
                    suggestions.extend(commands.clone());
                }
            }
        }

        // Context-aware suggestions
        if let Some(current_dir) = &context.current_directory {
            if current_dir.contains(".git") {
                suggestions.push(CommandSuggestion {
                    command: "git status".to_string(),
                    description: "Check Git repository status".to_string(),
                    category: CommandCategory::Git,
                    confidence: 0.8,
                    safety_level: SafetyLevel::Safe,
                    estimated_time: Some(1),
                    prerequisites: vec!["Git repository".to_string()],
                });
            }
        }

        // Generate response content
        if suggestions.is_empty() {
            content = format!("I couldn't find specific command suggestions for '{}'. Try being more specific about what you want to accomplish.", user_input);
        } else {
            content = format!("Here are {} command suggestions based on your input:", suggestions.len());
        }

        let confidence = if suggestions.is_empty() { 0.3 } else { 0.8 };

        Ok((AiResponseType::CommandSuggestion, content, suggestions, confidence))
    }

    async fn generate_help_response(
        &self,
        user_input: &str,
        _context: &AiContext,
    ) -> Result<(AiResponseType, String, Vec<CommandSuggestion>, f32)> {
        let help_content = match user_input.to_lowercase().as_str() {
            s if s.contains("ssh") => {
                "SSH (Secure Shell) allows you to securely connect to remote servers. Basic usage:\n\
                 • ssh user@hostname - Connect to remote server\n\
                 • ssh-keygen - Generate SSH key pair\n\
                 • scp file user@host:/path - Copy files securely\n\
                 GHOSTSHELL supports post-quantum SSH with Dilithium signatures."
            },
            s if s.contains("vpn") => {
                "VPN (Virtual Private Network) creates secure tunnels for network traffic. GHOSTSHELL VPN features:\n\
                 • Post-quantum encryption with Kyber + Dilithium\n\
                 • Multiple protocols: OpenVPN, WireGuard, IKEv2\n\
                 • Real-time connection monitoring\n\
                 • Custom routing and DNS configuration"
            },
            s if s.contains("terminal") => {
                "GHOSTSHELL Terminal features:\n\
                 • Multiple shell sessions (Shell 1, Shell 2, etc.)\n\
                 • Real process spawning with PTY support\n\
                 • Cross-platform shell detection\n\
                 • Integrated with security policies"
            },
            _ => {
                "GHOSTSHELL is a post-quantum secure terminal environment. Available features:\n\
                 • Terminal: Multi-session shell with PTY support\n\
                 • SSH: Quantum-safe remote connections\n\
                 • VPN: Post-quantum encrypted tunnels\n\
                 • Vault: Secure secret storage\n\
                 • AI Assistant: Command suggestions and help\n\
                 Type 'help <feature>' for specific information."
            }
        };

        Ok((AiResponseType::Information, help_content.to_string(), vec![], 0.9))
    }

    async fn generate_explanation(
        &self,
        user_input: &str,
        _context: &AiContext,
    ) -> Result<(AiResponseType, String, Vec<CommandSuggestion>, f32)> {
                let explanation = if user_input.contains("post-quantum") || user_input.contains("quantum") {
            "Post-Quantum Cryptography (PQC) protects against attacks from quantum computers:\n\n\
             • Dilithium: Digital signature algorithm resistant to quantum attacks\n\
             • Kyber: Key encapsulation mechanism for secure key exchange\n\
             • GHOSTSHELL uses these algorithms in SSH, VPN, and vault operations\n\n\
             Traditional RSA and ECDSA will be vulnerable to quantum computers, \
             but Dilithium and Kyber are designed to remain secure.".to_string()
        } else if user_input.contains("dilithium") {
            "Dilithium is a post-quantum digital signature scheme:\n\n\
             • Based on lattice cryptography\n\
             • Provides authentication and non-repudiation\n\
             • Used in GHOSTSHELL for SSH authentication and VPN handshakes\n\
             • Standardized by NIST as part of the post-quantum cryptography standards".to_string()
        } else if user_input.contains("kyber") {
            "Kyber is a post-quantum key encapsulation mechanism (KEM):\n\n\
             • Based on Module Learning With Errors (M-LWE)\n\
             • Used for secure key exchange\n\
             • Enables forward secrecy in communications\n\
             • Used in GHOSTSHELL VPN for session key establishment".to_string()
        } else {
            format!("I can explain various concepts. Try asking about:\n\
                     • Post-quantum cryptography\n\
                     • Dilithium signatures\n\
                     • Kyber key exchange\n\
                     • SSH security\n\
                     • VPN protocols\n\n\
                     Your query: '{}'", user_input)
        };

        Ok((AiResponseType::Explanation, explanation.to_string(), vec![], 0.8))
    }

    async fn generate_troubleshooting_guide(
        &self,
        user_input: &str,
        context: &AiContext,
    ) -> Result<(AiResponseType, String, Vec<CommandSuggestion>, f32)> {
        let mut suggestions = Vec::new();
        
        let guide = if user_input.to_lowercase().contains("connection") {
            suggestions.push(CommandSuggestion {
                command: "ping 8.8.8.8".to_string(),
                description: "Test basic internet connectivity".to_string(),
                category: CommandCategory::Network,
                confidence: 0.9,
                safety_level: SafetyLevel::Safe,
                estimated_time: Some(5),
                prerequisites: vec![],
            });
            
            "Connection troubleshooting steps:\n\
             1. Check basic connectivity with ping\n\
             2. Verify DNS resolution\n\
             3. Check firewall settings\n\
             4. Review network interface status\n\
             5. Test with different protocols"
        } else if user_input.to_lowercase().contains("slow") {
            suggestions.push(CommandSuggestion {
                command: "htop".to_string(),
                description: "Check system resource usage".to_string(),
                category: CommandCategory::System,
                confidence: 0.8,
                safety_level: SafetyLevel::Safe,
                estimated_time: None,
                prerequisites: vec!["htop installed".to_string()],
            });
            
            "Performance troubleshooting:\n\
             1. Check CPU and memory usage\n\
             2. Monitor disk I/O\n\
             3. Review network bandwidth\n\
             4. Check for background processes\n\
             5. Analyze system logs"
        } else {
            "General troubleshooting approach:\n\
             1. Identify the specific problem\n\
             2. Gather relevant information\n\
             3. Check logs and error messages\n\
             4. Test with minimal configuration\n\
             5. Apply fixes incrementally"
        };

        Ok((AiResponseType::Tutorial, guide.to_string(), suggestions, 0.7))
    }

    async fn generate_security_advice(
        &self,
        user_input: &str,
        context: &AiContext,
    ) -> Result<(AiResponseType, String, Vec<CommandSuggestion>, f32)> {
        let mut suggestions = Vec::new();
        let mut response_type = AiResponseType::Information;

        let advice = if let Some(security_ctx) = &context.security_context {
            match security_ctx.threat_level {
                ThreatLevel::High | ThreatLevel::Critical => {
                    response_type = AiResponseType::Warning;
                    suggestions.push(CommandSuggestion {
                        command: "sudo ufw enable".to_string(),
                        description: "Enable firewall protection".to_string(),
                        category: CommandCategory::Security,
                        confidence: 0.9,
                        safety_level: SafetyLevel::RequiresConfirmation,
                        estimated_time: Some(1),
                        prerequisites: vec!["sudo access".to_string()],
                    });
                    
                    "⚠️  HIGH THREAT LEVEL DETECTED ⚠️\n\n\
                     Immediate security recommendations:\n\
                     • Enable firewall if not already active\n\
                     • Review active network connections\n\
                     • Check for unauthorized access attempts\n\
                     • Ensure all software is up to date\n\
                     • Consider isolating the system"
                },
                _ => {
                    "Security best practices:\n\
                     • Use strong, unique passwords\n\
                     • Enable two-factor authentication\n\
                     • Keep software updated\n\
                     • Use post-quantum cryptography when available\n\
                     • Regular security audits"
                }
            }
        } else {
            "General security recommendations:\n\
             • GHOSTSHELL provides post-quantum security features\n\
             • Use SSH with Dilithium signatures\n\
             • Enable VPN with Kyber key exchange\n\
             • Store secrets in the quantum-safe vault\n\
             • Regular security policy reviews"
        };

        Ok((response_type, advice.to_string(), suggestions, 0.8))
    }

    async fn generate_best_practices(
        &self,
        user_input: &str,
        _context: &AiContext,
    ) -> Result<(AiResponseType, String, Vec<CommandSuggestion>, f32)> {
        let practices = if user_input.to_lowercase().contains("ssh") {
            "SSH Best Practices:\n\
             • Use key-based authentication instead of passwords\n\
             • Disable root login\n\
             • Use non-standard ports\n\
             • Enable fail2ban for brute force protection\n\
             • Use GHOSTSHELL's post-quantum SSH for future security"
        } else if user_input.to_lowercase().contains("password") {
            "Password Best Practices:\n\
             • Use long, complex passwords (12+ characters)\n\
             • Use unique passwords for each account\n\
             • Use a password manager\n\
             • Enable two-factor authentication\n\
             • Store passwords in GHOSTSHELL's quantum-safe vault"
        } else {
            "General Security Best Practices:\n\
             • Principle of least privilege\n\
             • Defense in depth\n\
             • Regular security updates\n\
             • Backup and recovery planning\n\
             • Security awareness training\n\
             • Use post-quantum cryptography for future-proofing"
        };

        Ok((AiResponseType::Information, practices.to_string(), vec![], 0.8))
    }

    pub async fn learn_from_interaction(&self, query_id: &str, success: bool, user_feedback: Option<String>) -> Result<()> {
        let mut learning_data = self.learning_data.write().await;
        
        // Find the query
        let query_history = self.query_history.read().await;
        if let Some(query) = query_history.iter().find(|q| q.id == query_id) {
            // Update success rates
            let query_type_id = match &query.query_type {
                AiQueryType::CommandSuggestion => 0,
                AiQueryType::Help => 1,
                AiQueryType::Explanation => 2,
                AiQueryType::Troubleshooting => 3,
                AiQueryType::SecurityAdvice => 4,
                AiQueryType::BestPractices => 5,
            };
            let key = format!("{}:{}", query_type_id, query.user_input.len());
            let current_rate = learning_data.success_rates.get(&key).unwrap_or(&0.5);
            let new_rate = if success {
                (current_rate + 0.1).min(1.0)
            } else {
                (current_rate - 0.1).max(0.0)
            };
            learning_data.success_rates.insert(key, new_rate);

            // Update command patterns
            let words: Vec<&str> = query.user_input.split_whitespace().collect();
            for word in words {
                *learning_data.command_patterns.entry(word.to_lowercase()).or_insert(0) += 1;
            }

            // Store user feedback
            if let Some(feedback) = user_feedback {
                learning_data.user_preferences.insert(query_id.to_string(), feedback);
            }
        }

        info!("Learning data updated for query: {}", query_id);
        Ok(())
    }

    pub async fn get_assistant_stats(&self, assistant_id: &str) -> Result<HashMap<String, serde_json::Value>> {
        let mut stats = HashMap::new();
        
        if let Some(assistant) = self.assistants.read().await.get(assistant_id) {
            stats.insert("name".to_string(), serde_json::Value::String(assistant.name.clone()));
            stats.insert("status".to_string(), serde_json::json!(assistant.status));
            stats.insert("capabilities".to_string(), serde_json::json!(assistant.capabilities));
            
            let query_count = self.query_history.read().await.len();
            stats.insert("total_queries".to_string(), serde_json::Value::Number(query_count.into()));
            
            let response_count = self.response_history.read().await.len();
            stats.insert("total_responses".to_string(), serde_json::Value::Number(response_count.into()));
            
            if let Some(last_interaction) = assistant.last_interaction {
                stats.insert("last_interaction".to_string(), serde_json::Value::String(last_interaction.to_rfc3339()));
            }
        }

        Ok(stats)
    }

    pub async fn list_assistants(&self) -> Result<Vec<AiAssistant>> {
        let assistants = self.assistants.read().await;
        Ok(assistants.values().cloned().collect())
    }
}

// Tauri Commands
#[tauri::command]
pub async fn ai_create_assistant(
    ai_manager: State<'_, Arc<Mutex<AiAssistantManager>>>,
    name: String,
    model: AiModel,
    capabilities: Vec<AiCapability>,
) -> Result<String, String> {
    let manager = ai_manager.lock().await;
    manager.create_assistant(name, model, capabilities).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_query(
    ai_manager: State<'_, Arc<Mutex<AiAssistantManager>>>,
    assistant_id: String,
    user_input: String,
    context: AiContext,
    query_type: AiQueryType,
) -> Result<AiResponse, String> {
    let manager = ai_manager.lock().await;
    manager.query_assistant(&assistant_id, user_input, context, query_type).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_learn_from_interaction(
    ai_manager: State<'_, Arc<Mutex<AiAssistantManager>>>,
    query_id: String,
    success: bool,
    user_feedback: Option<String>,
) -> Result<(), String> {
    let manager = ai_manager.lock().await;
    manager.learn_from_interaction(&query_id, success, user_feedback).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_get_stats(
    ai_manager: State<'_, Arc<Mutex<AiAssistantManager>>>,
    assistant_id: String,
) -> Result<HashMap<String, serde_json::Value>, String> {
    let manager = ai_manager.lock().await;
    manager.get_assistant_stats(&assistant_id).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ai_list_assistants(
    ai_manager: State<'_, Arc<Mutex<AiAssistantManager>>>,
) -> Result<Vec<AiAssistant>, String> {
    let manager = ai_manager.lock().await;
    manager.list_assistants().await
        .map_err(|e| e.to_string())
}
