//! Report scheduling system
//! 
//! Handles scheduled report generation and management

use crate::{ReportJob, ReportError, ReportResult, ScheduleFrequency};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Report scheduler for managing scheduled report jobs
pub struct ReportScheduler {
    /// Scheduled jobs
    jobs: Arc<RwLock<HashMap<String, ScheduledJob>>>,
    /// Whether the scheduler is running
    running: Arc<RwLock<bool>>,
}

/// A scheduled report job with execution tracking
#[derive(Debug, Clone)]
struct ScheduledJob {
    /// The report job configuration
    job: ReportJob,
    /// Last execution time
    last_run: Option<DateTime<Utc>>,
    /// Next scheduled execution
    next_run: DateTime<Utc>,
    /// Number of successful executions
    success_count: u64,
    /// Number of failed executions
    failure_count: u64,
    /// Whether the job is enabled
    enabled: bool,
}

impl ReportScheduler {
    /// Create a new report scheduler
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Initialize the scheduler
    pub async fn initialize(&self) -> ReportResult<()> {
        info!("Initializing report scheduler");
        
        // Start the scheduler loop
        self.start_scheduler_loop().await;
        
        Ok(())
    }
    
    /// Schedule a new report job
    pub async fn schedule_job(&self, job: ReportJob) -> ReportResult<String> {
        let schedule = job.schedule.clone()
            .ok_or_else(|| ReportError::Scheduling("No schedule configuration".to_string()))?;
        
        let job_id = job.id.clone();
        let scheduled_job = ScheduledJob {
            next_run: schedule.next_run,
            job,
            last_run: None,
            success_count: 0,
            failure_count: 0,
            enabled: schedule.enabled,
        };
        
        let mut jobs = self.jobs.write().await;
        jobs.insert(job_id.clone(), scheduled_job);
        
        info!("Scheduled report job: {} (next run: {})", job_id, schedule.next_run);
        Ok(job_id)
    }
    
    /// Get all scheduled jobs
    pub async fn get_scheduled_jobs(&self) -> ReportResult<Vec<ReportJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.values().map(|sj| sj.job.clone()).collect())
    }
    
    /// Get a specific scheduled job
    pub async fn get_scheduled_job(&self, job_id: &str) -> ReportResult<Option<ReportJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.get(job_id).map(|sj| sj.job.clone()))
    }
    
    /// Cancel a scheduled job
    pub async fn cancel_job(&self, job_id: &str) -> ReportResult<()> {
        let mut jobs = self.jobs.write().await;
        
        if jobs.remove(job_id).is_some() {
            info!("Cancelled scheduled job: {}", job_id);
            Ok(())
        } else {
            Err(ReportError::Scheduling(format!("Job not found: {}", job_id)))
        }
    }
    
    /// Enable/disable a scheduled job
    pub async fn set_job_enabled(&self, job_id: &str, enabled: bool) -> ReportResult<()> {
        let mut jobs = self.jobs.write().await;
        
        if let Some(scheduled_job) = jobs.get_mut(job_id) {
            scheduled_job.enabled = enabled;
            info!("Set job {} enabled: {}", job_id, enabled);
            Ok(())
        } else {
            Err(ReportError::Scheduling(format!("Job not found: {}", job_id)))
        }
    }
    
    /// Update the next run time for a job
    pub async fn update_next_run(&self, job_id: &str, next_run: DateTime<Utc>) -> ReportResult<()> {
        let mut jobs = self.jobs.write().await;
        
        if let Some(scheduled_job) = jobs.get_mut(job_id) {
            scheduled_job.next_run = next_run;
            debug!("Updated next run for job {}: {}", job_id, next_run);
            Ok(())
        } else {
            Err(ReportError::Scheduling(format!("Job not found: {}", job_id)))
        }
    }
    
    /// Get scheduler statistics
    pub async fn get_stats(&self) -> SchedulerStats {
        let jobs = self.jobs.read().await;
        let running = *self.running.read().await;
        
        let total_jobs = jobs.len();
        let enabled_jobs = jobs.values().filter(|j| j.enabled).count();
        let disabled_jobs = total_jobs - enabled_jobs;
        
        let total_successes = jobs.values().map(|j| j.success_count).sum();
        let total_failures = jobs.values().map(|j| j.failure_count).sum();
        
        let next_execution = jobs.values()
            .filter(|j| j.enabled)
            .map(|j| j.next_run)
            .min();
        
        SchedulerStats {
            running,
            total_jobs,
            enabled_jobs,
            disabled_jobs,
            total_successes,
            total_failures,
            next_execution,
        }
    }
    
    /// Start the scheduler background loop
    async fn start_scheduler_loop(&self) {
        let jobs = Arc::clone(&self.jobs);
        let running = Arc::clone(&self.running);
        
        tokio::spawn(async move {
            {
                let mut running_guard = running.write().await;
                *running_guard = true;
            }
            
            info!("Report scheduler loop started");
            
            loop {
                // Check if we should continue running
                if !*running.read().await {
                    break;
                }
                
                // Check for jobs that need to run
                let jobs_to_run = {
                    let jobs_guard = jobs.read().await;
                    let now = Utc::now();
                    
                    jobs_guard.iter()
                        .filter(|(_, sj)| sj.enabled && sj.next_run <= now)
                        .map(|(id, sj)| (id.clone(), sj.job.clone()))
                        .collect::<Vec<_>>()
                };
                
                // Execute jobs that are due
                for (job_id, job) in jobs_to_run {
                    info!("Executing scheduled report: {}", job_id);
                    
                    // In a real implementation, this would call the report engine
                    // For now, we'll just simulate execution
                    let success = Self::simulate_job_execution(&job).await;
                    
                    // Update job statistics and next run time
                    let mut jobs_guard = jobs.write().await;
                    if let Some(scheduled_job) = jobs_guard.get_mut(&job_id) {
                        scheduled_job.last_run = Some(Utc::now());
                        
                        if success {
                            scheduled_job.success_count += 1;
                            info!("Scheduled report completed successfully: {}", job_id);
                        } else {
                            scheduled_job.failure_count += 1;
                            error!("Scheduled report failed: {}", job_id);
                        }
                        
                        // Calculate next run time
                        if let Some(ref schedule) = scheduled_job.job.schedule {
                            scheduled_job.next_run = Self::calculate_next_run(&schedule.frequency, Utc::now());
                        }
                    }
                }
                
                // Sleep for a minute before checking again
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            }
            
            info!("Report scheduler loop stopped");
        });
    }
    
    /// Simulate job execution (placeholder)
    async fn simulate_job_execution(job: &ReportJob) -> bool {
        debug!("Simulating execution of job: {}", job.name);
        
        // Simulate some processing time
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Simulate 95% success rate
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        job.id.hash(&mut hasher);
        let hash = hasher.finish();
        
        (hash % 100) < 95
    }
    
    /// Calculate the next run time based on frequency
    fn calculate_next_run(frequency: &ScheduleFrequency, from: DateTime<Utc>) -> DateTime<Utc> {
        match frequency {
            ScheduleFrequency::Once => from + Duration::days(365 * 10), // Far future for one-time jobs
            ScheduleFrequency::Daily => from + Duration::days(1),
            ScheduleFrequency::Weekly => from + Duration::weeks(1),
            ScheduleFrequency::Monthly => from + Duration::days(30),
            ScheduleFrequency::Cron(cron_expr) => {
                // Simplified cron parsing - in production would use a proper cron library
                debug!("Calculating next run from cron: {}", cron_expr);
                from + Duration::hours(1) // Placeholder
            }
        }
    }
    
    /// Stop the scheduler
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
        info!("Report scheduler stopped");
    }
}

impl Default for ReportScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduler statistics
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    /// Whether the scheduler is running
    pub running: bool,
    /// Total number of scheduled jobs
    pub total_jobs: usize,
    /// Number of enabled jobs
    pub enabled_jobs: usize,
    /// Number of disabled jobs
    pub disabled_jobs: usize,
    /// Total successful executions
    pub total_successes: u64,
    /// Total failed executions
    pub total_failures: u64,
    /// Next scheduled execution time
    pub next_execution: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReportSchedule, ScheduleFrequency, ReportFormat};
    
    #[tokio::test]
    async fn test_scheduler_basic() {
        let scheduler = ReportScheduler::new();
        scheduler.initialize().await.unwrap();
        
        let mut job = ReportJob::new("Test Job".to_string(), "test".to_string());
        job.schedule = Some(ReportSchedule {
            frequency: ScheduleFrequency::Daily,
            next_run: Utc::now() + Duration::hours(1),
            enabled: true,
            timezone: None,
        });
        job.formats = vec![ReportFormat::Csv];
        
        let job_id = scheduler.schedule_job(job).await.unwrap();
        
        let jobs = scheduler.get_scheduled_jobs().await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, job_id);
        
        scheduler.cancel_job(&job_id).await.unwrap();
        
        let jobs = scheduler.get_scheduled_jobs().await.unwrap();
        assert_eq!(jobs.len(), 0);
    }
    
    #[test]
    fn test_next_run_calculation() {
        let now = Utc::now();
        
        let daily_next = ReportScheduler::calculate_next_run(&ScheduleFrequency::Daily, now);
        assert!(daily_next > now);
        assert!(daily_next <= now + Duration::days(1) + Duration::seconds(1));
        
        let weekly_next = ReportScheduler::calculate_next_run(&ScheduleFrequency::Weekly, now);
        assert!(weekly_next > now);
        assert!(weekly_next <= now + Duration::weeks(1) + Duration::seconds(1));
    }
}
