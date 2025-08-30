//! Report builder for creating report configurations
//! 
//! Provides a fluent API for building report jobs

use crate::{
    ReportJob, ReportSource, ReportFilters, ReportFormat, ReportSchedule, 
    ScheduleFrequency, ReportError, ReportResult
};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

/// Fluent builder for creating report jobs
pub struct ReportBuilder {
    job: ReportJob,
}

impl ReportBuilder {
    /// Create a new report builder
    pub fn new(name: String, created_by: String) -> Self {
        Self {
            job: ReportJob::new(name, created_by),
        }
    }
    
    /// Add GhostLog data source with specific modules
    pub fn add_ghostlog_source(mut self, modules: Vec<String>) -> Self {
        self.job.sources.push(ReportSource::GhostLog { modules });
        self
    }
    
    /// Add GhostDash system analytics source
    pub fn add_ghostdash_system_source(mut self) -> Self {
        self.job.sources.push(ReportSource::GhostDashSystem);
        self
    }
    
    /// Add GhostDash network analytics source
    pub fn add_ghostdash_network_source(mut self) -> Self {
        self.job.sources.push(ReportSource::GhostDashNetwork);
        self
    }
    
    /// Add GhostDash interfaces table source
    pub fn add_ghostdash_interfaces_source(mut self) -> Self {
        self.job.sources.push(ReportSource::GhostDashInterfaces);
        self
    }
    
    /// Add GhostDash DNS servers source
    pub fn add_ghostdash_dns_source(mut self) -> Self {
        self.job.sources.push(ReportSource::GhostDashDns);
        self
    }
    
    /// Add GhostDash routes source
    pub fn add_ghostdash_routes_source(mut self) -> Self {
        self.job.sources.push(ReportSource::GhostDashRoutes);
        self
    }
    
    /// Add GhostDash connections source
    pub fn add_ghostdash_connections_source(mut self) -> Self {
        self.job.sources.push(ReportSource::GhostDashConnections);
        self
    }
    
    /// Set time range filter
    pub fn with_time_range(mut self, start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> Self {
        self.job.filters.time_start = start;
        self.job.filters.time_end = end;
        self
    }
    
    /// Set time range for last N days
    pub fn with_last_days(mut self, days: i64) -> Self {
        let end = Utc::now();
        let start = end - Duration::days(days);
        self.job.filters.time_start = Some(start);
        self.job.filters.time_end = Some(end);
        self
    }
    
    /// Set time range for last N hours
    pub fn with_last_hours(mut self, hours: i64) -> Self {
        let end = Utc::now();
        let start = end - Duration::hours(hours);
        self.job.filters.time_start = Some(start);
        self.job.filters.time_end = Some(end);
        self
    }
    
    /// Filter by log severity levels
    pub fn with_severity_filter(mut self, severities: Vec<String>) -> Self {
        self.job.filters.severity = Some(severities);
        self
    }
    
    /// Filter by modules
    pub fn with_module_filter(mut self, modules: Vec<String>) -> Self {
        self.job.filters.modules = Some(modules);
        self
    }
    
    /// Filter by network interfaces
    pub fn with_interface_filter(mut self, interfaces: Vec<String>) -> Self {
        self.job.filters.interfaces = Some(interfaces);
        self
    }
    
    /// Filter by connection states
    pub fn with_connection_state_filter(mut self, states: Vec<String>) -> Self {
        self.job.filters.connection_states = Some(states);
        self
    }
    
    /// Add custom filter
    pub fn with_custom_filter(mut self, key: String, value: String) -> Self {
        if self.job.filters.custom.is_none() {
            self.job.filters.custom = Some(HashMap::new());
        }
        self.job.filters.custom.as_mut().unwrap().insert(key, value);
        self
    }
    
    /// Set output formats
    pub fn with_formats(mut self, formats: Vec<ReportFormat>) -> Self {
        self.job.formats = formats;
        self
    }
    
    /// Add CSV format
    pub fn with_csv(mut self) -> Self {
        if !self.job.formats.contains(&ReportFormat::Csv) {
            self.job.formats.push(ReportFormat::Csv);
        }
        self
    }
    
    /// Add XLSX format
    pub fn with_xlsx(mut self) -> Self {
        if !self.job.formats.contains(&ReportFormat::Xlsx) {
            self.job.formats.push(ReportFormat::Xlsx);
        }
        self
    }
    
    /// Add PDF format
    pub fn with_pdf(mut self) -> Self {
        if !self.job.formats.contains(&ReportFormat::Pdf) {
            self.job.formats.push(ReportFormat::Pdf);
        }
        self
    }
    
    /// Set daily schedule
    pub fn with_daily_schedule(mut self, timezone: Option<String>) -> Self {
        let next_run = Utc::now() + Duration::days(1);
        self.job.schedule = Some(ReportSchedule {
            frequency: ScheduleFrequency::Daily,
            next_run,
            enabled: true,
            timezone,
        });
        self
    }
    
    /// Set weekly schedule
    pub fn with_weekly_schedule(mut self, timezone: Option<String>) -> Self {
        let next_run = Utc::now() + Duration::weeks(1);
        self.job.schedule = Some(ReportSchedule {
            frequency: ScheduleFrequency::Weekly,
            next_run,
            enabled: true,
            timezone,
        });
        self
    }
    
    /// Set monthly schedule
    pub fn with_monthly_schedule(mut self, timezone: Option<String>) -> Self {
        let next_run = Utc::now() + Duration::days(30);
        self.job.schedule = Some(ReportSchedule {
            frequency: ScheduleFrequency::Monthly,
            next_run,
            enabled: true,
            timezone,
        });
        self
    }
    
    /// Set custom cron schedule
    pub fn with_cron_schedule(mut self, cron_expr: String, timezone: Option<String>) -> ReportResult<Self> {
        // Basic cron validation (simplified)
        if cron_expr.split_whitespace().count() != 5 {
            return Err(ReportError::InvalidConfig(
                "Cron expression must have 5 fields".to_string()
            ));
        }
        
        let next_run = Utc::now() + Duration::hours(1); // Simplified - would calculate from cron
        self.job.schedule = Some(ReportSchedule {
            frequency: ScheduleFrequency::Cron(cron_expr),
            next_run,
            enabled: true,
            timezone,
        });
        Ok(self)
    }
    
    /// Set template to use
    pub fn with_template(mut self, template_name: String) -> Self {
        self.job.template = Some(template_name);
        self
    }
    
    /// Set filters directly
    pub fn with_filters(mut self, filters: ReportFilters) -> Self {
        self.job.filters = filters;
        self
    }
    
    /// Set schedule directly
    pub fn with_schedule(mut self, schedule: ReportSchedule) -> Self {
        self.job.schedule = Some(schedule);
        self
    }
    
    /// Validate the report configuration
    pub fn validate(&self) -> ReportResult<()> {
        if self.job.name.is_empty() {
            return Err(ReportError::InvalidConfig("Report name cannot be empty".to_string()));
        }
        
        if self.job.created_by.is_empty() {
            return Err(ReportError::InvalidConfig("Created by cannot be empty".to_string()));
        }
        
        if self.job.sources.is_empty() {
            return Err(ReportError::InvalidConfig("At least one data source must be specified".to_string()));
        }
        
        if self.job.formats.is_empty() {
            return Err(ReportError::InvalidConfig("At least one output format must be specified".to_string()));
        }
        
        // Validate time range
        if let (Some(start), Some(end)) = (self.job.filters.time_start, self.job.filters.time_end) {
            if start >= end {
                return Err(ReportError::InvalidConfig("Start time must be before end time".to_string()));
            }
        }
        
        Ok(())
    }
    
    /// Build the report job
    pub fn build(self) -> ReportResult<ReportJob> {
        self.validate()?;
        Ok(self.job)
    }
}

/// Predefined report templates
pub struct ReportTemplates;

impl ReportTemplates {
    /// Create a comprehensive security audit report
    pub fn security_audit(created_by: String) -> ReportBuilder {
        ReportBuilder::new("Security Audit Report".to_string(), created_by)
            .add_ghostlog_source(vec![
                "ssh".to_string(),
                "vault".to_string(),
                "policy".to_string(),
                "terminal".to_string(),
            ])
            .add_ghostdash_system_source()
            .add_ghostdash_network_source()
            .add_ghostdash_connections_source()
            .with_last_days(7)
            .with_severity_filter(vec![
                "Warning".to_string(),
                "Error".to_string(),
                "Critical".to_string(),
            ])
            .with_pdf()
            .with_xlsx()
    }
    
    /// Create a network activity report
    pub fn network_activity(created_by: String) -> ReportBuilder {
        ReportBuilder::new("Network Activity Report".to_string(), created_by)
            .add_ghostdash_network_source()
            .add_ghostdash_interfaces_source()
            .add_ghostdash_dns_source()
            .add_ghostdash_routes_source()
            .add_ghostdash_connections_source()
            .with_last_hours(24)
            .with_csv()
            .with_xlsx()
    }
    
    /// Create a system health report
    pub fn system_health(created_by: String) -> ReportBuilder {
        ReportBuilder::new("System Health Report".to_string(), created_by)
            .add_ghostdash_system_source()
            .add_ghostlog_source(vec!["system".to_string()])
            .with_last_hours(6)
            .with_pdf()
    }
    
    /// Create a compliance report
    pub fn compliance_report(created_by: String, framework: String) -> ReportBuilder {
        ReportBuilder::new(format!("{} Compliance Report", framework), created_by)
            .add_ghostlog_source(vec![
                "policy".to_string(),
                "vault".to_string(),
                "ssh".to_string(),
                "compliance".to_string(),
            ])
            .add_ghostdash_system_source()
            .with_last_days(30)
            .with_custom_filter("compliance_framework".to_string(), framework)
            .with_pdf()
            .with_xlsx()
    }
    
    /// Create an incident response report
    pub fn incident_response(created_by: String, incident_id: String) -> ReportBuilder {
        ReportBuilder::new(format!("Incident Report - {}", incident_id), created_by)
            .add_ghostlog_source(vec![
                "security".to_string(),
                "alert".to_string(),
                "forensics".to_string(),
            ])
            .add_ghostdash_network_source()
            .add_ghostdash_connections_source()
            .with_last_hours(48)
            .with_severity_filter(vec![
                "Error".to_string(),
                "Critical".to_string(),
            ])
            .with_custom_filter("incident_id".to_string(), incident_id)
            .with_pdf()
            .with_csv()
    }
    
    /// Create a daily operations report
    pub fn daily_operations(created_by: String) -> ReportBuilder {
        ReportBuilder::new("Daily Operations Report".to_string(), created_by)
            .add_ghostlog_source(vec![
                "terminal".to_string(),
                "ssh".to_string(),
                "system".to_string(),
            ])
            .add_ghostdash_system_source()
            .with_last_hours(24)
            .with_daily_schedule(None)
            .with_pdf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_report_builder_basic() {
        let job = ReportBuilder::new("Test Report".to_string(), "analyst".to_string())
            .add_ghostlog_source(vec!["ssh".to_string()])
            .with_csv()
            .build()
            .unwrap();
        
        assert_eq!(job.name, "Test Report");
        assert_eq!(job.created_by, "analyst");
        assert_eq!(job.sources.len(), 1);
        assert_eq!(job.formats.len(), 1);
        assert_eq!(job.formats[0], ReportFormat::Csv);
    }
    
    #[test]
    fn test_report_builder_validation() {
        let result = ReportBuilder::new("".to_string(), "analyst".to_string())
            .build();
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("name cannot be empty"));
    }
    
    #[test]
    fn test_security_audit_template() {
        let job = ReportTemplates::security_audit("auditor".to_string())
            .build()
            .unwrap();
        
        assert_eq!(job.name, "Security Audit Report");
        assert!(job.sources.len() > 1);
        assert!(job.formats.contains(&ReportFormat::Pdf));
        assert!(job.filters.time_start.is_some());
    }
}
