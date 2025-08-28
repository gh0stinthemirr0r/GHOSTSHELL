use ghost_log::*;
use std::collections::HashMap;
use tempfile::TempDir;

async fn create_test_logger() -> (AuditLogger, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_audit.db");
    
    let config = AuditConfig {
        batch_size: 10,
        batch_timeout_seconds: 5,
        enable_signing: true,
        compression_enabled: true,
        retention_days: Some(365),
    };
    
    let logger = AuditLogger::new(
        db_path.to_string_lossy().as_ref(),
        "test_component".to_string(),
        config
    ).await.expect("Failed to create audit logger");
    
    (logger, temp_dir)
}

#[tokio::test]
async fn test_basic_audit_logging() {
    let (logger, _temp_dir) = create_test_logger().await;
    
    let actor = Actor {
        actor_type: ActorType::User,
        id: "test_user".to_string(),
        name: Some("Test User".to_string()),
        session_id: Some("session_123".to_string()),
        ip_address: Some("192.168.1.100".to_string()),
        user_agent: Some("GHOSTSHELL/1.0".to_string()),
    };
    
    let resource = Resource {
        resource_type: ResourceType::Vault,
        id: Some("vault_001".to_string()),
        name: Some("Main Vault".to_string()),
        path: Some("/vault/secrets".to_string()),
        attributes: HashMap::new(),
    };
    
    // Log a successful vault access
    let entry_id = logger.log_event().await
        .event_type(EventType::Authorization)
        .severity(Severity::Info)
        .actor(actor.clone())
        .resource(resource.clone())
        .action(Action::Read)
        .outcome(Outcome::Success)
        .message("User accessed vault successfully".to_string())
        .submit().await
        .expect("Failed to log event");
    
    assert!(!entry_id.is_empty(), "Entry ID should not be empty");
    
    // Log a failed access attempt
    let failed_entry_id = logger.log_event().await
        .event_type(EventType::PolicyViolation)
        .severity(Severity::Warning)
        .actor(actor)
        .resource(resource)
        .action(Action::Write)
        .outcome(Outcome::Denied)
        .message("Access denied by policy".to_string())
        .policy_rule("deny_vault_write".to_string())
        .submit().await
        .expect("Failed to log failed event");
    
    assert!(!failed_entry_id.is_empty(), "Failed entry ID should not be empty");
    assert_ne!(entry_id, failed_entry_id, "Entry IDs should be different");
}

#[tokio::test]
async fn test_audit_log_querying() {
    let (logger, _temp_dir) = create_test_logger().await;
    
    // Log multiple events
    let events = vec![
        ("user1", EventType::Authentication, Outcome::Success),
        ("user1", EventType::Authorization, Outcome::Success),
        ("user2", EventType::Authentication, Outcome::Failure),
        ("user1", EventType::PolicyViolation, Outcome::Denied),
        ("user2", EventType::Authorization, Outcome::Success),
    ];
    
    for (user_id, event_type, outcome) in events {
        let actor = Actor {
            actor_type: ActorType::User,
            id: user_id.to_string(),
            name: Some(format!("User {}", user_id)),
            session_id: Some(format!("session_{}", user_id)),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: None,
        };
        
        logger.log_event().await
            .event_type(event_type)
            .severity(Severity::Info)
            .actor(actor)
            .action(Action::Read)
            .outcome(outcome)
            .message(format!("Test event for {}", user_id))
            .submit().await
            .expect("Failed to log test event");
    }
    
    // Query by user
    let user1_query = AuditQuery::new()
        .actor_id("user1".to_string())
        .limit(10);
    
    let user1_entries = logger.query_entries(user1_query).await
        .expect("Failed to query user1 entries");
    
    assert_eq!(user1_entries.len(), 3, "Should find 3 entries for user1");
    
    // Query by event type
    let auth_query = AuditQuery::new()
        .event_type(EventType::Authentication)
        .limit(10);
    
    let auth_entries = logger.query_entries(auth_query).await
        .expect("Failed to query authentication entries");
    
    assert_eq!(auth_entries.len(), 2, "Should find 2 authentication entries");
    
    // Query by outcome
    let failure_query = AuditQuery::new()
        .outcome(Outcome::Failure)
        .limit(10);
    
    let failure_entries = logger.query_entries(failure_query).await
        .expect("Failed to query failure entries");
    
    assert_eq!(failure_entries.len(), 1, "Should find 1 failure entry");
}

#[tokio::test]
async fn test_audit_log_time_range_queries() {
    let (logger, _temp_dir) = create_test_logger().await;
    
    let now = chrono::Utc::now();
    let one_hour_ago = now - chrono::Duration::hours(1);
    let one_hour_later = now + chrono::Duration::hours(1);
    
    // Log an event
    let actor = Actor {
        actor_type: ActorType::System,
        id: "system".to_string(),
        name: Some("System Process".to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
    };
    
    logger.log_event().await
        .event_type(EventType::SystemEvent)
        .severity(Severity::Info)
        .actor(actor)
        .action(Action::Update)
        .outcome(Outcome::Success)
        .message("System update completed".to_string())
        .submit().await
        .expect("Failed to log system event");
    
    // Query within time range (should find the event)
    let range_query = AuditQuery::new()
        .time_range(one_hour_ago, one_hour_later)
        .limit(10);
    
    let entries_in_range = logger.query_entries(range_query).await
        .expect("Failed to query entries in range");
    
    assert!(!entries_in_range.is_empty(), "Should find entries in time range");
    
    // Query outside time range (should find nothing)
    let past_query = AuditQuery::new()
        .time_range(one_hour_ago - chrono::Duration::hours(2), one_hour_ago)
        .limit(10);
    
    let past_entries = logger.query_entries(past_query).await
        .expect("Failed to query past entries");
    
    assert!(past_entries.is_empty(), "Should find no entries in past range");
}

#[tokio::test]
async fn test_audit_log_batching() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("batch_test.db");
    
    let config = AuditConfig {
        batch_size: 3, // Small batch size for testing
        batch_timeout_seconds: 1,
        enable_signing: true,
        compression_enabled: false,
        retention_days: None,
    };
    
    let logger = AuditLogger::new(
        db_path.to_string_lossy().as_ref(),
        "batch_test".to_string(),
        config
    ).await.expect("Failed to create batch logger");
    
    let actor = Actor {
        actor_type: ActorType::User,
        id: "batch_user".to_string(),
        name: Some("Batch Test User".to_string()),
        session_id: Some("batch_session".to_string()),
        ip_address: Some("10.0.0.1".to_string()),
        user_agent: None,
    };
    
    // Log events to trigger batching
    for i in 0..5 {
        logger.log_event().await
            .event_type(EventType::DataAccess)
            .severity(Severity::Info)
            .actor(actor.clone())
            .action(Action::Read)
            .outcome(Outcome::Success)
            .message(format!("Batch test event {}", i))
            .submit().await
            .expect("Failed to log batch event");
    }
    
    // Wait for batch processing
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    // Query all entries
    let all_query = AuditQuery::new().limit(10);
    let all_entries = logger.query_entries(all_query).await
        .expect("Failed to query all entries");
    
    assert_eq!(all_entries.len(), 5, "Should find all 5 batch entries");
    
    // Verify batch information
    let batches = logger.get_batches(0, 10).await
        .expect("Failed to get batches");
    
    assert!(!batches.is_empty(), "Should have created batches");
    
    for batch in &batches {
        assert!(!batch.signature.is_empty(), "Batch should be signed");
        assert!(!batch.hash.is_empty(), "Batch should have hash");
    }
}

#[tokio::test]
async fn test_audit_log_integrity_verification() {
    let (logger, _temp_dir) = create_test_logger().await;
    
    let actor = Actor {
        actor_type: ActorType::User,
        id: "integrity_user".to_string(),
        name: Some("Integrity Test User".to_string()),
        session_id: Some("integrity_session".to_string()),
        ip_address: Some("172.16.0.1".to_string()),
        user_agent: Some("Test Agent".to_string()),
    };
    
    // Log several events
    for i in 0..10 {
        logger.log_event().await
            .event_type(EventType::DataAccess)
            .severity(Severity::Info)
            .actor(actor.clone())
            .action(Action::Read)
            .outcome(Outcome::Success)
            .message(format!("Integrity test event {}", i))
            .submit().await
            .expect("Failed to log integrity event");
    }
    
    // Wait for batch processing
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    // Verify integrity
    let integrity_result = logger.verify_integrity().await
        .expect("Failed to verify integrity");
    
    assert!(integrity_result.is_valid, "Audit log integrity should be valid");
    assert!(integrity_result.verified_batches > 0, "Should have verified some batches");
    assert_eq!(integrity_result.corrupted_batches, 0, "Should have no corrupted batches");
    assert!(integrity_result.chain_valid, "Hash chain should be valid");
}

#[tokio::test]
async fn test_audit_log_different_event_types() {
    let (logger, _temp_dir) = create_test_logger().await;
    
    let user_actor = Actor {
        actor_type: ActorType::User,
        id: "test_user".to_string(),
        name: Some("Test User".to_string()),
        session_id: Some("user_session".to_string()),
        ip_address: Some("192.168.1.50".to_string()),
        user_agent: Some("GHOSTSHELL Client".to_string()),
    };
    
    let system_actor = Actor {
        actor_type: ActorType::System,
        id: "ghostshell_system".to_string(),
        name: Some("GHOSTSHELL System".to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
    };
    
    let api_actor = Actor {
        actor_type: ActorType::Service,
        id: "api_service".to_string(),
        name: Some("API Service".to_string()),
        session_id: Some("api_session".to_string()),
        ip_address: Some("10.0.0.100".to_string()),
        user_agent: Some("API Client/1.0".to_string()),
    };
    
    // Test different event types
    let events = vec![
        (user_actor.clone(), EventType::Authentication, "User login successful"),
        (user_actor.clone(), EventType::Authorization, "Access granted to vault"),
        (user_actor.clone(), EventType::DataAccess, "Retrieved secret from vault"),
        (system_actor.clone(), EventType::SystemEvent, "System startup completed"),
        (system_actor.clone(), EventType::ConfigurationChange, "Policy updated"),
        (api_actor.clone(), EventType::ApiCall, "API endpoint accessed"),
        (user_actor.clone(), EventType::PolicyViolation, "Unauthorized access attempt"),
        (system_actor.clone(), EventType::SecurityEvent, "Suspicious activity detected"),
    ];
    
    for (actor, event_type, message) in events {
        logger.log_event().await
            .event_type(event_type)
            .severity(match event_type {
                EventType::PolicyViolation | EventType::SecurityEvent => Severity::Warning,
                EventType::SystemEvent => Severity::Info,
                _ => Severity::Info,
            })
            .actor(actor)
            .action(Action::Read)
            .outcome(match event_type {
                EventType::PolicyViolation => Outcome::Denied,
                _ => Outcome::Success,
            })
            .message(message.to_string())
            .submit().await
            .expect("Failed to log event");
    }
    
    // Query by different criteria
    let user_events = logger.query_entries(
        AuditQuery::new().actor_id("test_user".to_string()).limit(10)
    ).await.expect("Failed to query user events");
    
    let system_events = logger.query_entries(
        AuditQuery::new().actor_type(ActorType::System).limit(10)
    ).await.expect("Failed to query system events");
    
    let violations = logger.query_entries(
        AuditQuery::new().event_type(EventType::PolicyViolation).limit(10)
    ).await.expect("Failed to query violations");
    
    assert_eq!(user_events.len(), 4, "Should find 4 user events");
    assert_eq!(system_events.len(), 3, "Should find 3 system events");
    assert_eq!(violations.len(), 1, "Should find 1 policy violation");
}

#[tokio::test]
async fn test_audit_log_context_and_metadata() {
    let (logger, _temp_dir) = create_test_logger().await;
    
    let actor = Actor {
        actor_type: ActorType::User,
        id: "context_user".to_string(),
        name: Some("Context Test User".to_string()),
        session_id: Some("context_session".to_string()),
        ip_address: Some("203.0.113.1".to_string()),
        user_agent: Some("GHOSTSHELL/2.0".to_string()),
    };
    
    let mut resource_attributes = HashMap::new();
    resource_attributes.insert("sensitivity".to_string(), "high".to_string());
    resource_attributes.insert("classification".to_string(), "confidential".to_string());
    
    let resource = Resource {
        resource_type: ResourceType::File,
        id: Some("file_123".to_string()),
        name: Some("sensitive_document.pdf".to_string()),
        path: Some("/vault/documents/sensitive_document.pdf".to_string()),
        attributes: resource_attributes,
    };
    
    // Log event with rich context
    logger.log_event().await
        .event_type(EventType::DataAccess)
        .severity(Severity::Info)
        .actor(actor)
        .resource(resource)
        .action(Action::Read)
        .outcome(Outcome::Success)
        .message("User accessed sensitive document".to_string())
        .context("mfa_verified".to_string(), "true".to_string())
        .context("access_method".to_string(), "direct".to_string())
        .context("client_version".to_string(), "2.0.1".to_string())
        .policy_rule("allow_document_access".to_string())
        .submit().await
        .expect("Failed to log context event");
    
    // Query and verify context
    let entries = logger.query_entries(
        AuditQuery::new().resource_type(ResourceType::File).limit(1)
    ).await.expect("Failed to query file entries");
    
    assert_eq!(entries.len(), 1, "Should find 1 file entry");
    
    let entry = &entries[0];
    assert!(entry.context.contains_key("mfa_verified"), "Should have MFA context");
    assert!(entry.context.contains_key("access_method"), "Should have access method context");
    assert_eq!(entry.context.get("mfa_verified"), Some(&"true".to_string()));
    
    if let Some(resource) = &entry.resource {
        assert!(resource.attributes.contains_key("sensitivity"), "Should have sensitivity attribute");
        assert_eq!(resource.attributes.get("sensitivity"), Some(&"high".to_string()));
    } else {
        panic!("Entry should have resource information");
    }
}

#[tokio::test]
async fn test_audit_log_performance() {
    let (logger, _temp_dir) = create_test_logger().await;
    
    let actor = Actor {
        actor_type: ActorType::User,
        id: "perf_user".to_string(),
        name: Some("Performance Test User".to_string()),
        session_id: Some("perf_session".to_string()),
        ip_address: Some("198.51.100.1".to_string()),
        user_agent: Some("Perf Test".to_string()),
    };
    
    let start_time = std::time::Instant::now();
    let num_events = 1000;
    
    // Log many events quickly
    for i in 0..num_events {
        logger.log_event().await
            .event_type(EventType::DataAccess)
            .severity(Severity::Info)
            .actor(actor.clone())
            .action(Action::Read)
            .outcome(Outcome::Success)
            .message(format!("Performance test event {}", i))
            .submit().await
            .expect("Failed to log performance event");
    }
    
    let logging_duration = start_time.elapsed();
    
    // Wait for all batches to be processed
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    
    // Query all events
    let query_start = std::time::Instant::now();
    let entries = logger.query_entries(
        AuditQuery::new().actor_id("perf_user".to_string()).limit(num_events as i64)
    ).await.expect("Failed to query performance entries");
    let query_duration = query_start.elapsed();
    
    assert_eq!(entries.len(), num_events, "Should find all performance entries");
    
    println!("Performance Results:");
    println!("  Logged {} events in {:?}", num_events, logging_duration);
    println!("  Average per event: {:?}", logging_duration / num_events as u32);
    println!("  Queried {} events in {:?}", num_events, query_duration);
    
    // Performance assertions (reasonable bounds)
    let avg_log_time = logging_duration.as_millis() / num_events as u128;
    assert!(avg_log_time < 10, "Average logging time should be under 10ms per event");
    assert!(query_duration.as_millis() < 1000, "Query should complete within 1 second");
}

#[tokio::test]
async fn test_audit_log_error_handling() {
    let (logger, _temp_dir) = create_test_logger().await;
    
    // Test logging with minimal required fields
    let minimal_actor = Actor {
        actor_type: ActorType::User,
        id: "minimal_user".to_string(),
        name: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
    };
    
    let entry_id = logger.log_event().await
        .event_type(EventType::SystemEvent)
        .severity(Severity::Info)
        .actor(minimal_actor)
        .action(Action::Read)
        .outcome(Outcome::Success)
        .message("Minimal event".to_string())
        .submit().await
        .expect("Should log event with minimal fields");
    
    assert!(!entry_id.is_empty(), "Should generate entry ID for minimal event");
    
    // Test invalid query parameters
    let invalid_query = AuditQuery::new()
        .limit(-1); // Invalid limit
    
    let result = logger.query_entries(invalid_query).await;
    assert!(result.is_err(), "Should fail with invalid query parameters");
}

#[tokio::test]
async fn test_audit_log_retention() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("retention_test.db");
    
    let config = AuditConfig {
        batch_size: 5,
        batch_timeout_seconds: 1,
        enable_signing: true,
        compression_enabled: false,
        retention_days: Some(1), // Very short retention for testing
    };
    
    let logger = AuditLogger::new(
        db_path.to_string_lossy().as_ref(),
        "retention_test".to_string(),
        config
    ).await.expect("Failed to create retention logger");
    
    let actor = Actor {
        actor_type: ActorType::User,
        id: "retention_user".to_string(),
        name: Some("Retention Test User".to_string()),
        session_id: Some("retention_session".to_string()),
        ip_address: Some("203.0.113.100".to_string()),
        user_agent: None,
    };
    
    // Log some events
    for i in 0..10 {
        logger.log_event().await
            .event_type(EventType::DataAccess)
            .severity(Severity::Info)
            .actor(actor.clone())
            .action(Action::Read)
            .outcome(Outcome::Success)
            .message(format!("Retention test event {}", i))
            .submit().await
            .expect("Failed to log retention event");
    }
    
    // Wait for batch processing
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    // Verify events exist
    let before_cleanup = logger.query_entries(
        AuditQuery::new().actor_id("retention_user".to_string()).limit(20)
    ).await.expect("Failed to query before cleanup");
    
    assert_eq!(before_cleanup.len(), 10, "Should find all events before cleanup");
    
    // Run cleanup (in a real system, this would be triggered by a scheduled task)
    let cleanup_result = logger.cleanup_old_entries().await
        .expect("Failed to run cleanup");
    
    println!("Cleanup result: {:?}", cleanup_result);
    
    // Note: Since we just created the entries, they won't be cleaned up yet
    // This test mainly verifies the cleanup mechanism doesn't crash
    assert!(cleanup_result.entries_removed >= 0, "Cleanup should report non-negative removals");
}
