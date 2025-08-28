use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;
use ghost_align::{PostureSnapshot, ControlStatus};

pub mod storage;
pub mod analysis;
pub mod rollup;

pub use storage::*;
pub use analysis::*;
pub use rollup::*;

/// Time-series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
    pub metadata: HashMap<String, String>,
}

/// Trend direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
    Unknown,
}

/// Trend analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub metric_name: String,
    pub time_period: Duration,
    pub direction: TrendDirection,
    pub change_rate: f64,
    pub confidence: f64,
    pub data_points: Vec<DataPoint>,
    pub analysis_timestamp: DateTime<Utc>,
}

/// Posture trend over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureTrend {
    pub framework_id: String,
    pub domain: Option<String>,
    pub control_id: Option<String>,
    pub trend_data: Vec<PostureTrendPoint>,
    pub overall_direction: TrendDirection,
    pub analysis: TrendAnalysis,
}

/// Individual posture trend point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureTrendPoint {
    pub timestamp: DateTime<Utc>,
    pub snapshot_id: Uuid,
    pub overall_score: f64,
    pub domain_scores: HashMap<String, f64>,
    pub control_status_counts: ControlStatusCounts,
    pub total_controls: usize,
}

/// Control status counts for trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStatusCounts {
    pub passed: usize,
    pub failed: usize,
    pub partial: usize,
    pub unknown: usize,
}

/// Aggregation period for rollups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationPeriod {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Yearly,
}

/// Aggregated posture data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedPosture {
    pub period: AggregationPeriod,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub framework_id: String,
    pub avg_score: f64,
    pub min_score: f64,
    pub max_score: f64,
    pub score_variance: f64,
    pub snapshot_count: usize,
    pub domain_averages: HashMap<String, f64>,
    pub control_pass_rates: HashMap<String, f64>,
}

/// Error types for ghost_trends
#[derive(Debug, thiserror::Error)]
pub enum TrendsError {
    #[error("Data not found: {0}")]
    DataNotFound(String),
    
    #[error("Invalid time range: {0}")]
    InvalidTimeRange(String),
    
    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type TrendsResult<T> = Result<T, TrendsError>;

impl From<PostureSnapshot> for PostureTrendPoint {
    fn from(snapshot: PostureSnapshot) -> Self {
        let control_status_counts = ControlStatusCounts {
            passed: snapshot.passed_controls,
            failed: snapshot.failed_controls,
            partial: snapshot.partial_controls,
            unknown: snapshot.unknown_controls,
        };

        Self {
            timestamp: snapshot.timestamp,
            snapshot_id: snapshot.snapshot_id,
            overall_score: snapshot.overall_score,
            domain_scores: snapshot.domain_scores,
            control_status_counts,
            total_controls: snapshot.total_controls,
        }
    }
}
