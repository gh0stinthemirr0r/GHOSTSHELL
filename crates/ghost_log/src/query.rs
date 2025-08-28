use chrono::{DateTime, Utc, Duration, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{
    LogStorage, CompactLogEntry, LogSearchFilter,
    EventType, Severity, ResourceType, Action, Outcome,
    LogError, Result,
};

/// Advanced query interface for audit logs
pub struct LogQuery {
    storage: LogStorage,
}

/// Query builder for complex log searches
#[derive(Debug, Clone, Default)]
pub struct QueryBuilder {
    filters: LogSearchFilter,
    aggregations: Vec<Aggregation>,
    sort_by: Option<SortField>,
    sort_order: SortOrder,
}

/// Aggregation types for log analysis
#[derive(Debug, Clone)]
pub enum Aggregation {
    CountBySeverity,
    CountByEventType,
    CountByActor,
    CountByResource,
    CountByOutcome,
    CountByTimeRange { interval: TimeInterval },
    AverageResponseTime,
    TotalBytesTransferred,
}

/// Time intervals for aggregation
#[derive(Debug, Clone)]
pub enum TimeInterval {
    Hour,
    Day,
    Week,
    Month,
}

/// Sort fields
#[derive(Debug, Clone)]
pub enum SortField {
    Timestamp,
    Severity,
    SequenceNumber,
    Actor,
    EventType,
}

/// Sort order
#[derive(Debug, Clone)]
pub enum SortOrder {
    Ascending,
    Descending,
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::Descending
    }
}

/// Query result with entries and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub entries: Vec<CompactLogEntry>,
    pub total_count: u64,
    pub aggregations: HashMap<String, serde_json::Value>,
    pub query_time_ms: u64,
    pub has_more: bool,
}

/// Aggregation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationResult {
    pub name: String,
    pub data: serde_json::Value,
}

/// Security analytics result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalytics {
    pub failed_logins: u64,
    pub policy_violations: u64,
    pub critical_events: u64,
    pub unique_actors: u64,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
}

/// Suspicious pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    pub pattern_type: PatternType,
    pub description: String,
    pub severity: Severity,
    pub count: u64,
    pub actors: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Types of suspicious patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    BruteForce,
    UnusualAccess,
    PrivilegeEscalation,
    DataExfiltration,
    SystemAnomaly,
    PolicyBypass,
}

impl LogQuery {
    /// Create new query interface
    pub async fn new(database_url: &str) -> Result<Self> {
        let storage = LogStorage::new(database_url).await?;
        Ok(Self { storage })
    }

    /// Create in-memory query interface for testing
    pub async fn in_memory() -> Result<Self> {
        let storage = LogStorage::in_memory().await?;
        Ok(Self { storage })
    }

    /// Start building a query
    pub fn query(&self) -> QueryBuilder {
        QueryBuilder::default()
    }

    /// Execute a query
    pub async fn execute(&self, query: QueryBuilder) -> Result<QueryResult> {
        let start_time = std::time::Instant::now();

        // Execute main search
        let entries = self.storage.search_entries(&query.filters).await?;
        let total_count = entries.len() as u64;

        // Apply sorting if specified
        let sorted_entries = self.apply_sorting(entries, &query.sort_by, &query.sort_order);

        // Execute aggregations
        let mut aggregations = HashMap::new();
        for agg in &query.aggregations {
            let result = self.execute_aggregation(agg, &query.filters).await?;
            aggregations.insert(result.name, result.data);
        }

        let query_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(QueryResult {
            entries: sorted_entries,
            total_count,
            aggregations,
            query_time_ms,
            has_more: false, // TODO: Implement pagination
        })
    }

    /// Get recent critical events
    pub async fn get_critical_events(&self, hours: u32) -> Result<Vec<CompactLogEntry>> {
        let start_time = Utc::now() - Duration::hours(hours as i64);
        
        let filter = LogSearchFilter {
            severity: Some(Severity::Critical),
            start_time: Some(start_time),
            ..Default::default()
        };

        self.storage.search_entries(&filter).await
    }

    /// Get failed authentication attempts
    pub async fn get_failed_auth(&self, hours: u32) -> Result<Vec<CompactLogEntry>> {
        let start_time = Utc::now() - Duration::hours(hours as i64);
        
        let filter = LogSearchFilter {
            event_type: Some(EventType::Authentication),
            outcome: Some(Outcome::Failure),
            start_time: Some(start_time),
            ..Default::default()
        };

        self.storage.search_entries(&filter).await
    }

    /// Get policy violations
    pub async fn get_policy_violations(&self, hours: u32) -> Result<Vec<CompactLogEntry>> {
        let start_time = Utc::now() - Duration::hours(hours as i64);
        
        let filter = LogSearchFilter {
            event_type: Some(EventType::PolicyViolation),
            start_time: Some(start_time),
            ..Default::default()
        };

        self.storage.search_entries(&filter).await
    }

    /// Get activity for a specific actor
    pub async fn get_actor_activity(&self, actor_id: &str, hours: u32) -> Result<Vec<CompactLogEntry>> {
        let start_time = Utc::now() - Duration::hours(hours as i64);
        
        let filter = LogSearchFilter {
            actor_id: Some(actor_id.to_string()),
            start_time: Some(start_time),
            ..Default::default()
        };

        self.storage.search_entries(&filter).await
    }

    /// Generate security analytics report
    pub async fn security_analytics(&self, hours: u32) -> Result<SecurityAnalytics> {
        let end_time = Utc::now();
        let start_time = end_time - Duration::hours(hours as i64);

        // Get failed logins
        let failed_logins = self.get_failed_auth(hours).await?.len() as u64;

        // Get policy violations
        let policy_violations = self.get_policy_violations(hours).await?.len() as u64;

        // Get critical events
        let critical_events = self.get_critical_events(hours).await?.len() as u64;

        // Get unique actors
        let all_entries = self.storage.search_entries(&LogSearchFilter {
            start_time: Some(start_time),
            end_time: Some(end_time),
            ..Default::default()
        }).await?;

        let unique_actors = all_entries.iter()
            .map(|e| &e.actor_id)
            .collect::<std::collections::HashSet<_>>()
            .len() as u64;

        // Detect suspicious patterns
        let suspicious_patterns = self.detect_suspicious_patterns(&all_entries).await?;

        Ok(SecurityAnalytics {
            failed_logins,
            policy_violations,
            critical_events,
            unique_actors,
            suspicious_patterns,
            time_range: (start_time, end_time),
        })
    }

    /// Detect suspicious patterns in log entries
    async fn detect_suspicious_patterns(&self, entries: &[CompactLogEntry]) -> Result<Vec<SuspiciousPattern>> {
        let mut patterns = Vec::new();

        // Detect brute force attempts
        let brute_force = self.detect_brute_force(entries);
        if let Some(pattern) = brute_force {
            patterns.push(pattern);
        }

        // Detect unusual access patterns
        let unusual_access = self.detect_unusual_access(entries);
        patterns.extend(unusual_access);

        // Detect privilege escalation attempts
        let privilege_escalation = self.detect_privilege_escalation(entries);
        if let Some(pattern) = privilege_escalation {
            patterns.push(pattern);
        }

        Ok(patterns)
    }

    /// Detect brute force login attempts
    fn detect_brute_force(&self, entries: &[CompactLogEntry]) -> Option<SuspiciousPattern> {
        let mut failed_attempts: HashMap<String, Vec<&CompactLogEntry>> = HashMap::new();

        // Group failed authentication attempts by actor
        for entry in entries {
            if entry.event_type == EventType::Authentication && entry.outcome == Outcome::Failure {
                failed_attempts.entry(entry.actor_id.clone()).or_default().push(entry);
            }
        }

        // Find actors with excessive failed attempts
        let mut suspicious_actors = Vec::new();
        let mut total_attempts = 0;
        let mut first_seen = None;
        let mut last_seen = None;

        for (actor_id, attempts) in failed_attempts {
            if attempts.len() >= 5 { // Threshold for suspicious activity
                suspicious_actors.push(actor_id);
                total_attempts += attempts.len();
                
                let actor_first = attempts.iter().map(|e| e.timestamp).min();
                let actor_last = attempts.iter().map(|e| e.timestamp).max();
                
                if first_seen.is_none() || actor_first < first_seen {
                    first_seen = actor_first;
                }
                if last_seen.is_none() || actor_last > last_seen {
                    last_seen = actor_last;
                }
            }
        }

        if !suspicious_actors.is_empty() {
            Some(SuspiciousPattern {
                pattern_type: PatternType::BruteForce,
                description: format!("Multiple failed login attempts detected from {} actors", suspicious_actors.len()),
                severity: Severity::Critical,
                count: total_attempts as u64,
                actors: suspicious_actors,
                first_seen: first_seen.unwrap_or_else(Utc::now),
                last_seen: last_seen.unwrap_or_else(Utc::now),
            })
        } else {
            None
        }
    }

    /// Detect unusual access patterns
    fn detect_unusual_access(&self, entries: &[CompactLogEntry]) -> Vec<SuspiciousPattern> {
        let mut patterns = Vec::new();

        // Detect access outside normal hours (example: 10 PM to 6 AM)
        let unusual_hours: Vec<&CompactLogEntry> = entries.iter()
            .filter(|e| {
                let hour = e.timestamp.hour();
                hour >= 22 || hour <= 6
            })
            .collect();

        if unusual_hours.len() >= 10 { // Threshold for unusual activity
            let actors: Vec<String> = unusual_hours.iter()
                .map(|e| e.actor_id.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            patterns.push(SuspiciousPattern {
                pattern_type: PatternType::UnusualAccess,
                description: "Unusual access patterns detected outside normal hours".to_string(),
                severity: Severity::Warning,
                count: unusual_hours.len() as u64,
                actors,
                first_seen: unusual_hours.iter().map(|e| e.timestamp).min().unwrap_or_else(Utc::now),
                last_seen: unusual_hours.iter().map(|e| e.timestamp).max().unwrap_or_else(Utc::now),
            });
        }

        patterns
    }

    /// Detect privilege escalation attempts
    fn detect_privilege_escalation(&self, entries: &[CompactLogEntry]) -> Option<SuspiciousPattern> {
        // Look for rapid succession of different resource access attempts
        let mut actor_resources: HashMap<String, std::collections::HashSet<ResourceType>> = HashMap::new();

        for entry in entries {
            actor_resources.entry(entry.actor_id.clone()).or_default().insert(entry.resource_type.clone());
        }

        let suspicious_actors: Vec<String> = actor_resources.into_iter()
            .filter(|(_, resources)| resources.len() >= 5) // Accessing many different resource types
            .map(|(actor, _)| actor)
            .collect();

        if !suspicious_actors.is_empty() {
            Some(SuspiciousPattern {
                pattern_type: PatternType::PrivilegeEscalation,
                description: "Potential privilege escalation detected - actors accessing multiple resource types".to_string(),
                severity: Severity::Error,
                count: suspicious_actors.len() as u64,
                actors: suspicious_actors,
                first_seen: entries.iter().map(|e| e.timestamp).min().unwrap_or_else(Utc::now),
                last_seen: entries.iter().map(|e| e.timestamp).max().unwrap_or_else(Utc::now),
            })
        } else {
            None
        }
    }

    /// Apply sorting to entries
    fn apply_sorting(
        &self,
        mut entries: Vec<CompactLogEntry>,
        sort_by: &Option<SortField>,
        sort_order: &SortOrder,
    ) -> Vec<CompactLogEntry> {
        if let Some(field) = sort_by {
            entries.sort_by(|a, b| {
                let cmp = match field {
                    SortField::Timestamp => a.timestamp.cmp(&b.timestamp),
                    SortField::Severity => a.severity.cmp(&b.severity),
                    SortField::SequenceNumber => a.sequence_number.cmp(&b.sequence_number),
                    SortField::Actor => a.actor_id.cmp(&b.actor_id),
                    SortField::EventType => format!("{:?}", a.event_type).cmp(&format!("{:?}", b.event_type)),
                };

                match sort_order {
                    SortOrder::Ascending => cmp,
                    SortOrder::Descending => cmp.reverse(),
                }
            });
        }

        entries
    }

    /// Execute aggregation
    async fn execute_aggregation(&self, agg: &Aggregation, filter: &LogSearchFilter) -> Result<AggregationResult> {
        match agg {
            Aggregation::CountBySeverity => {
                let entries = self.storage.search_entries(filter).await?;
                let mut counts = HashMap::new();
                
                for entry in entries {
                    *counts.entry(format!("{:?}", entry.severity)).or_insert(0u64) += 1;
                }

                Ok(AggregationResult {
                    name: "count_by_severity".to_string(),
                    data: serde_json::to_value(counts)?,
                })
            }
            Aggregation::CountByEventType => {
                let entries = self.storage.search_entries(filter).await?;
                let mut counts = HashMap::new();
                
                for entry in entries {
                    *counts.entry(format!("{:?}", entry.event_type)).or_insert(0u64) += 1;
                }

                Ok(AggregationResult {
                    name: "count_by_event_type".to_string(),
                    data: serde_json::to_value(counts)?,
                })
            }
            Aggregation::CountByActor => {
                let entries = self.storage.search_entries(filter).await?;
                let mut counts = HashMap::new();
                
                for entry in entries {
                    *counts.entry(entry.actor_id.clone()).or_insert(0u64) += 1;
                }

                Ok(AggregationResult {
                    name: "count_by_actor".to_string(),
                    data: serde_json::to_value(counts)?,
                })
            }
            _ => {
                // TODO: Implement other aggregation types
                Ok(AggregationResult {
                    name: "not_implemented".to_string(),
                    data: serde_json::Value::Null,
                })
            }
        }
    }
}

impl QueryBuilder {
    /// Filter by event type
    pub fn event_type(mut self, event_type: EventType) -> Self {
        self.filters.event_type = Some(event_type);
        self
    }

    /// Filter by severity
    pub fn severity(mut self, severity: Severity) -> Self {
        self.filters.severity = Some(severity);
        self
    }

    /// Filter by actor ID
    pub fn actor(mut self, actor_id: String) -> Self {
        self.filters.actor_id = Some(actor_id);
        self
    }

    /// Filter by resource type
    pub fn resource_type(mut self, resource_type: ResourceType) -> Self {
        self.filters.resource_type = Some(resource_type);
        self
    }

    /// Filter by action
    pub fn action(mut self, action: Action) -> Self {
        self.filters.action = Some(action);
        self
    }

    /// Filter by outcome
    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.filters.outcome = Some(outcome);
        self
    }

    /// Filter by time range
    pub fn time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.filters.start_time = Some(start);
        self.filters.end_time = Some(end);
        self
    }

    /// Filter by message pattern
    pub fn message_contains(mut self, pattern: String) -> Self {
        self.filters.message_pattern = Some(pattern);
        self
    }

    /// Set limit
    pub fn limit(mut self, limit: usize) -> Self {
        self.filters.limit = Some(limit);
        self
    }

    /// Set offset
    pub fn offset(mut self, offset: usize) -> Self {
        self.filters.offset = Some(offset);
        self
    }

    /// Add aggregation
    pub fn aggregate(mut self, aggregation: Aggregation) -> Self {
        self.aggregations.push(aggregation);
        self
    }

    /// Sort by field
    pub fn sort_by(mut self, field: SortField, order: SortOrder) -> Self {
        self.sort_by = Some(field);
        self.sort_order = order;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LogStorage, Actor, ActorType, Resource, LogEntry};

    async fn create_test_query() -> LogQuery {
        LogQuery::in_memory().await.unwrap()
    }

    async fn populate_test_data(storage: &LogStorage) {
        use std::collections::HashMap;

        for i in 0..10 {
            let actor = Actor {
                actor_type: ActorType::User,
                id: format!("user{}", i % 3), // 3 different users
                name: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            };

            let resource = Resource {
                resource_type: if i % 2 == 0 { ResourceType::Vault } else { ResourceType::Secret },
                id: Some(format!("resource{}", i)),
                name: None,
                path: None,
                attributes: HashMap::new(),
            };

            let mut entry = LogEntry::new(
                i as u64 + 1,
                if i < 5 { EventType::DataAccess } else { EventType::Authentication },
                if i % 4 == 0 { Severity::Critical } else { Severity::Info },
                actor,
                resource,
                Action::Read,
                if i % 3 == 0 { Outcome::Failure } else { Outcome::Success },
                format!("Test entry {}", i),
            );

            let hash = entry.calculate_hash().unwrap();
            entry.set_hash(hash);
            storage.store_entry(&entry).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_query_builder() {
        let query_engine = create_test_query().await;
        populate_test_data(&query_engine.storage).await;

        let query = query_engine.query()
            .event_type(EventType::DataAccess)
            .severity(Severity::Info)
            .limit(5);

        let result = query_engine.execute(query).await.unwrap();
        
        assert!(result.entries.len() <= 5);
        assert!(result.entries.iter().all(|e| e.event_type == EventType::DataAccess));
    }

    #[tokio::test]
    async fn test_aggregations() {
        let query_engine = create_test_query().await;
        populate_test_data(&query_engine.storage).await;

        let query = query_engine.query()
            .aggregate(Aggregation::CountBySeverity)
            .aggregate(Aggregation::CountByEventType);

        let result = query_engine.execute(query).await.unwrap();
        
        assert!(result.aggregations.contains_key("count_by_severity"));
        assert!(result.aggregations.contains_key("count_by_event_type"));
    }

    #[tokio::test]
    async fn test_security_analytics() {
        let query_engine = create_test_query().await;
        populate_test_data(&query_engine.storage).await;

        let analytics = query_engine.security_analytics(24).await.unwrap();
        
        assert_eq!(analytics.unique_actors, 3); // 3 different users
        assert!(analytics.failed_logins > 0); // Some failures in test data
    }

    #[tokio::test]
    async fn test_suspicious_pattern_detection() {
        let query_engine = create_test_query().await;
        
        // Create entries that should trigger brute force detection
        for i in 0..6 {
            let actor = Actor {
                actor_type: ActorType::User,
                id: "attacker".to_string(),
                name: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            };

            let resource = Resource {
                resource_type: ResourceType::Vault,
                id: None,
                name: None,
                path: None,
                attributes: std::collections::HashMap::new(),
            };

            let mut entry = LogEntry::new(
                i as u64 + 1,
                EventType::Authentication,
                Severity::Warning,
                actor,
                resource,
                Action::Login,
                Outcome::Failure,
                "Failed login attempt".to_string(),
            );

            let hash = entry.calculate_hash().unwrap();
            entry.set_hash(hash);
            query_engine.storage.store_entry(&entry).await.unwrap();
        }

        let analytics = query_engine.security_analytics(24).await.unwrap();
        
        assert!(!analytics.suspicious_patterns.is_empty());
        assert!(analytics.suspicious_patterns.iter().any(|p| matches!(p.pattern_type, PatternType::BruteForce)));
    }
}
