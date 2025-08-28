use ghost_policy::*;
use std::collections::HashMap;

#[tokio::test]
async fn test_policy_parsing_toml() {
    let policy_toml = r#"
        version = 1
        name = "Test Policy"
        description = "Policy for testing"
        
        [defaults]
        effect = "Deny"
        require_justification = true
        audit_all = true
        auto_clear_clipboard_ms = 30000
        
        [[rules]]
        id = "allow-terminal-read"
        resource = "Terminal"
        action = "Read"
        effect = "Allow"
        
        [rules.conditions]
        user_role = "user"
        
        [[rules]]
        id = "deny-sensitive-ops"
        resource = ["Vault", "Ssh"]
        action = ["Write", "Delete"]
        effect = "Deny"
        warning_message = "Sensitive operations require approval"
    "#;
    
    let policy = Policy::from_string(policy_toml).expect("Failed to parse TOML policy");
    
    assert_eq!(policy.version, 1);
    assert_eq!(policy.name, Some("Test Policy".to_string()));
    assert_eq!(policy.rules.len(), 2);
    
    // Test validation
    policy.validate().expect("Policy should be valid");
}

#[tokio::test]
async fn test_policy_parsing_json() {
    let policy_json = r#"
    {
        "version": 1,
        "name": "JSON Test Policy",
        "rules": [
            {
                "id": "allow-settings",
                "resource": "Settings",
                "action": "Read",
                "effect": "Allow"
            }
        ],
        "defaults": {
            "effect": "Deny",
            "audit_all": false
        }
    }
    "#;
    
    let policy = Policy::from_string(policy_json).expect("Failed to parse JSON policy");
    
    assert_eq!(policy.version, 1);
    assert_eq!(policy.name, Some("JSON Test Policy".to_string()));
    assert_eq!(policy.rules.len(), 1);
}

#[tokio::test]
async fn test_policy_evaluation_basic() {
    let policy = Policy::development_default();
    
    let mut subject = Subject::new();
    subject.insert("user_id".to_string(), "test_user".to_string());
    subject.insert("role".to_string(), "user".to_string());
    
    let mut context = Context::new();
    context.insert("time_of_day".to_string(), "business_hours".to_string());
    
    // Test terminal read (should be allowed in development policy)
    let decision = evaluate_policy(
        &policy,
        &subject,
        &Resource::Terminal,
        &Action::Read,
        &context
    );
    
    assert!(decision.allowed, "Terminal read should be allowed in development policy");
    assert!(!decision.requires_justification, "Should not require justification");
}

#[tokio::test]
async fn test_policy_evaluation_restrictive() {
    let policy = Policy::restrictive_default();
    
    let mut subject = Subject::new();
    subject.insert("user_id".to_string(), "test_user".to_string());
    subject.insert("role".to_string(), "user".to_string());
    
    let context = Context::new();
    
    // Test vault write (should be denied in restrictive policy)
    let decision = evaluate_policy(
        &policy,
        &subject,
        &Resource::Vault,
        &Action::Write,
        &context
    );
    
    assert!(!decision.allowed, "Vault write should be denied in restrictive policy");
    assert!(decision.requires_justification, "Should require justification");
    assert!(decision.audit_required, "Should require audit");
}

#[tokio::test]
async fn test_policy_conditions() {
    let policy_toml = r#"
        version = 1
        
        [[rules]]
        id = "mfa-required-vault"
        resource = "Vault"
        action = "*"
        effect = "Allow"
        
        [rules.conditions]
        mfa_verified = "true"
        
        [[rules]]
        id = "business-hours-only"
        resource = "Ssh"
        action = "Connect"
        effect = "Allow"
        
        [rules.conditions]
        time_of_day = "business_hours"
        
        [defaults]
        effect = "Deny"
    "#;
    
    let policy = Policy::from_string(policy_toml).expect("Failed to parse policy");
    
    let mut subject = Subject::new();
    subject.insert("user_id".to_string(), "test_user".to_string());
    
    // Test vault access without MFA
    let mut context = Context::new();
    context.insert("mfa_verified".to_string(), "false".to_string());
    
    let decision = evaluate_policy(&policy, &subject, &Resource::Vault, &Action::Read, &context);
    assert!(!decision.allowed, "Vault access should be denied without MFA");
    
    // Test vault access with MFA
    context.insert("mfa_verified".to_string(), "true".to_string());
    let decision = evaluate_policy(&policy, &subject, &Resource::Vault, &Action::Read, &context);
    assert!(decision.allowed, "Vault access should be allowed with MFA");
    
    // Test SSH during business hours
    context.insert("time_of_day".to_string(), "business_hours".to_string());
    let decision = evaluate_policy(&policy, &subject, &Resource::Ssh, &Action::Connect, &context);
    assert!(decision.allowed, "SSH should be allowed during business hours");
    
    // Test SSH outside business hours
    context.insert("time_of_day".to_string(), "after_hours".to_string());
    let decision = evaluate_policy(&policy, &subject, &Resource::Ssh, &Action::Connect, &context);
    assert!(!decision.allowed, "SSH should be denied outside business hours");
}

#[tokio::test]
async fn test_policy_constraints() {
    let policy_toml = r#"
        version = 1
        
        [[rules]]
        id = "clipboard-with-limits"
        resource = "Clipboard"
        action = "*"
        effect = "Allow"
        auto_clear_clipboard_ms = 60000
        mask_preview = true
        
        [[rules]]
        id = "file-size-limits"
        resource = "Files"
        action = "Download"
        effect = "Allow"
        size_limit_mb = 100
        quarantine_file = true
        
        [defaults]
        effect = "Deny"
    "#;
    
    let policy = Policy::from_string(policy_toml).expect("Failed to parse policy");
    
    let subject = Subject::new();
    let context = Context::new();
    
    // Test clipboard constraints
    let decision = evaluate_policy(&policy, &subject, &Resource::Clipboard, &Action::Copy, &context);
    assert!(decision.allowed, "Clipboard copy should be allowed");
    assert_eq!(decision.auto_clear_clipboard_ms, Some(60000), "Should have auto-clear timer");
    assert!(decision.mask_preview, "Should mask preview");
    
    // Test file download constraints
    let decision = evaluate_policy(&policy, &subject, &Resource::Files, &Action::Download, &context);
    assert!(decision.allowed, "File download should be allowed");
    assert_eq!(decision.size_limit_mb, Some(100), "Should have size limit");
    assert!(decision.quarantine_file, "Should quarantine file");
}

#[tokio::test]
async fn test_policy_validation_errors() {
    // Test invalid version
    let invalid_policy = r#"
        version = 999
        [[rules]]
        id = "test"
        resource = "Terminal"
        action = "Read"
        effect = "Allow"
    "#;
    
    let result = Policy::from_string(invalid_policy);
    assert!(result.is_err(), "Should fail with invalid version");
    
    // Test missing required fields
    let incomplete_policy = r#"
        version = 1
        [[rules]]
        resource = "Terminal"
        action = "Read"
        effect = "Allow"
    "#;
    
    let result = Policy::from_string(incomplete_policy);
    assert!(result.is_err(), "Should fail with missing rule ID");
    
    // Test invalid resource
    let invalid_resource = r#"
        version = 1
        [[rules]]
        id = "test"
        resource = "InvalidResource"
        action = "Read"
        effect = "Allow"
    "#;
    
    let result = Policy::from_string(invalid_resource);
    assert!(result.is_err(), "Should fail with invalid resource");
}

#[tokio::test]
async fn test_policy_rule_precedence() {
    let policy_toml = r#"
        version = 1
        
        [[rules]]
        id = "deny-all-vault"
        resource = "Vault"
        action = "*"
        effect = "Deny"
        priority = 100
        
        [[rules]]
        id = "allow-vault-read"
        resource = "Vault"
        action = "Read"
        effect = "Allow"
        priority = 200
        
        [defaults]
        effect = "Deny"
    "#;
    
    let policy = Policy::from_string(policy_toml).expect("Failed to parse policy");
    
    let subject = Subject::new();
    let context = Context::new();
    
    // Higher priority rule should win
    let decision = evaluate_policy(&policy, &subject, &Resource::Vault, &Action::Read, &context);
    assert!(decision.allowed, "Higher priority allow rule should override deny rule");
    
    // Test other action still denied
    let decision = evaluate_policy(&policy, &subject, &Resource::Vault, &Action::Write, &context);
    assert!(!decision.allowed, "Vault write should still be denied");
}

#[tokio::test]
async fn test_policy_wildcard_matching() {
    let policy_toml = r#"
        version = 1
        
        [[rules]]
        id = "allow-all-terminal"
        resource = "Terminal"
        action = "*"
        effect = "Allow"
        
        [[rules]]
        id = "allow-read-all"
        resource = "*"
        action = "Read"
        effect = "Allow"
        
        [defaults]
        effect = "Deny"
    "#;
    
    let policy = Policy::from_string(policy_toml).expect("Failed to parse policy");
    
    let subject = Subject::new();
    let context = Context::new();
    
    // Test terminal wildcard
    let decision = evaluate_policy(&policy, &subject, &Resource::Terminal, &Action::Exec, &context);
    assert!(decision.allowed, "Terminal exec should be allowed by wildcard");
    
    // Test resource wildcard
    let decision = evaluate_policy(&policy, &subject, &Resource::Settings, &Action::Read, &context);
    assert!(decision.allowed, "Settings read should be allowed by wildcard");
    
    // Test non-matching action
    let decision = evaluate_policy(&policy, &subject, &Resource::Settings, &Action::Write, &context);
    assert!(!decision.allowed, "Settings write should be denied");
}

#[tokio::test]
async fn test_policy_context_evaluation() {
    let policy_toml = r#"
        version = 1
        
        [[rules]]
        id = "admin-override"
        resource = "*"
        action = "*"
        effect = "Allow"
        
        [rules.conditions]
        role = "admin"
        
        [[rules]]
        id = "user-limited"
        resource = ["Terminal", "Settings"]
        action = "Read"
        effect = "Allow"
        
        [rules.conditions]
        role = "user"
        
        [defaults]
        effect = "Deny"
    "#;
    
    let policy = Policy::from_string(policy_toml).expect("Failed to parse policy");
    
    let mut admin_subject = Subject::new();
    admin_subject.insert("role".to_string(), "admin".to_string());
    
    let mut user_subject = Subject::new();
    user_subject.insert("role".to_string(), "user".to_string());
    
    let context = Context::new();
    
    // Test admin access
    let decision = evaluate_policy(&policy, &admin_subject, &Resource::Vault, &Action::Delete, &context);
    assert!(decision.allowed, "Admin should have full access");
    
    // Test user limited access
    let decision = evaluate_policy(&policy, &user_subject, &Resource::Terminal, &Action::Read, &context);
    assert!(decision.allowed, "User should have terminal read access");
    
    let decision = evaluate_policy(&policy, &user_subject, &Resource::Vault, &Action::Read, &context);
    assert!(!decision.allowed, "User should not have vault access");
}

#[tokio::test]
async fn test_policy_export_import() {
    let original_policy = Policy::development_default();
    
    // Test TOML export/import
    let toml_string = original_policy.to_toml().expect("Failed to export to TOML");
    let imported_policy = Policy::from_string(&toml_string).expect("Failed to import from TOML");
    
    assert_eq!(original_policy.version, imported_policy.version);
    assert_eq!(original_policy.rules.len(), imported_policy.rules.len());
    
    // Test JSON export/import
    let json_string = original_policy.to_json().expect("Failed to export to JSON");
    let imported_json_policy = Policy::from_string(&json_string).expect("Failed to import from JSON");
    
    assert_eq!(original_policy.version, imported_json_policy.version);
    assert_eq!(original_policy.rules.len(), imported_json_policy.rules.len());
}
