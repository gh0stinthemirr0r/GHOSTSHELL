use crate::{PostureTrendPoint, AggregatedPosture, TrendsResult, TrendsError};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use uuid::Uuid;

/// In-memory time-series storage for posture data
pub struct PostureStorage {
    trend_points: HashMap<String, Vec<PostureTrendPoint>>,
    aggregated_data: HashMap<String, Vec<AggregatedPosture>>,
    retention_period: Duration,
}

impl PostureStorage {
    pub fn new() -> Self {
        Self {
            trend_points: HashMap::new(),
            aggregated_data: HashMap::new(),
            retention_period: Duration::days(365), // 1 year default retention
        }
    }

    pub fn with_retention_period(retention_period: Duration) -> Self {
        Self {
            trend_points: HashMap::new(),
            aggregated_data: HashMap::new(),
            retention_period,
        }
    }

    pub fn store_trend_point(&mut self, framework_id: &str, point: PostureTrendPoint) {
        let key = framework_id.to_string();
        let points = self.trend_points.entry(key).or_insert_with(Vec::new);
        
        // Insert in chronological order
        let insert_pos = points
            .binary_search_by(|p| p.timestamp.cmp(&point.timestamp))
            .unwrap_or_else(|pos| pos);
        
        points.insert(insert_pos, point);
        
        // Clean up old data
        self.cleanup_old_data(framework_id);
    }

    pub fn get_trend_points(
        &self,
        framework_id: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> TrendsResult<Vec<PostureTrendPoint>> {
        let points = self.trend_points
            .get(framework_id)
            .ok_or_else(|| TrendsError::DataNotFound(format!("No data for framework: {}", framework_id)))?;

        let filtered_points: Vec<PostureTrendPoint> = points
            .iter()
            .filter(|point| {
                if let Some(start) = start_time {
                    if point.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = end_time {
                    if point.timestamp > end {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        Ok(filtered_points)
    }

    pub fn get_latest_trend_point(&self, framework_id: &str) -> TrendsResult<PostureTrendPoint> {
        let points = self.trend_points
            .get(framework_id)
            .ok_or_else(|| TrendsError::DataNotFound(format!("No data for framework: {}", framework_id)))?;

        points
            .last()
            .cloned()
            .ok_or_else(|| TrendsError::DataNotFound("No trend points available".to_string()))
    }

    pub fn store_aggregated_data(&mut self, framework_id: &str, aggregated: AggregatedPosture) {
        let key = format!("{}:{:?}", framework_id, aggregated.period);
        let data = self.aggregated_data.entry(key).or_insert_with(Vec::new);
        
        // Insert in chronological order
        let insert_pos = data
            .binary_search_by(|a| a.start_time.cmp(&aggregated.start_time))
            .unwrap_or_else(|pos| pos);
        
        data.insert(insert_pos, aggregated);
    }

    pub fn get_aggregated_data(
        &self,
        framework_id: &str,
        period: &crate::AggregationPeriod,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> TrendsResult<Vec<AggregatedPosture>> {
        let key = format!("{}:{:?}", framework_id, period);
        let data = self.aggregated_data
            .get(&key)
            .ok_or_else(|| TrendsError::DataNotFound(format!("No aggregated data for: {}", key)))?;

        let filtered_data: Vec<AggregatedPosture> = data
            .iter()
            .filter(|agg| {
                if let Some(start) = start_time {
                    if agg.end_time < start {
                        return false;
                    }
                }
                if let Some(end) = end_time {
                    if agg.start_time > end {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        Ok(filtered_data)
    }

    pub fn get_control_trend(
        &self,
        framework_id: &str,
        control_id: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> TrendsResult<Vec<(DateTime<Utc>, bool)>> {
        let points = self.get_trend_points(framework_id, start_time, end_time)?;
        
        let control_trend: Vec<(DateTime<Utc>, bool)> = points
            .iter()
            .filter_map(|point| {
                // This is simplified - in a real implementation, we'd need to store
                // individual control statuses in the trend points
                // For now, we'll estimate based on overall scores
                let passed = point.overall_score > 0.7; // Simplified threshold
                Some((point.timestamp, passed))
            })
            .collect();

        Ok(control_trend)
    }

    pub fn get_domain_trend(
        &self,
        framework_id: &str,
        domain: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> TrendsResult<Vec<(DateTime<Utc>, f64)>> {
        let points = self.get_trend_points(framework_id, start_time, end_time)?;
        
        let domain_trend: Vec<(DateTime<Utc>, f64)> = points
            .iter()
            .filter_map(|point| {
                point.domain_scores
                    .get(domain)
                    .map(|score| (point.timestamp, *score))
            })
            .collect();

        Ok(domain_trend)
    }

    pub fn calculate_statistics(&self, framework_id: &str) -> TrendsResult<StorageStatistics> {
        let points = self.trend_points
            .get(framework_id)
            .ok_or_else(|| TrendsError::DataNotFound(format!("No data for framework: {}", framework_id)))?;

        if points.is_empty() {
            return Ok(StorageStatistics {
                total_snapshots: 0,
                date_range: None,
                avg_score: 0.0,
                score_variance: 0.0,
                domains_tracked: 0,
                data_size_bytes: 0,
            });
        }

        let total_snapshots = points.len();
        let first_timestamp = points.first().unwrap().timestamp;
        let last_timestamp = points.last().unwrap().timestamp;
        
        let scores: Vec<f64> = points.iter().map(|p| p.overall_score).collect();
        let avg_score = scores.iter().sum::<f64>() / scores.len() as f64;
        
        let variance = scores
            .iter()
            .map(|score| (score - avg_score).powi(2))
            .sum::<f64>() / scores.len() as f64;

        let domains_tracked = points
            .first()
            .map(|p| p.domain_scores.len())
            .unwrap_or(0);

        // Rough estimate of data size
        let data_size_bytes = std::mem::size_of::<PostureTrendPoint>() * total_snapshots;

        Ok(StorageStatistics {
            total_snapshots,
            date_range: Some((first_timestamp, last_timestamp)),
            avg_score,
            score_variance: variance,
            domains_tracked,
            data_size_bytes,
        })
    }

    pub fn list_frameworks(&self) -> Vec<String> {
        self.trend_points.keys().cloned().collect()
    }

    fn cleanup_old_data(&mut self, framework_id: &str) {
        let cutoff_time = Utc::now() - self.retention_period;
        
        if let Some(points) = self.trend_points.get_mut(framework_id) {
            points.retain(|point| point.timestamp > cutoff_time);
        }

        // Clean up aggregated data as well
        for (key, data) in self.aggregated_data.iter_mut() {
            if key.starts_with(framework_id) {
                data.retain(|agg| agg.end_time > cutoff_time);
            }
        }
    }

    pub fn set_retention_period(&mut self, period: Duration) {
        self.retention_period = period;
        
        // Clean up existing data based on new retention period
        let frameworks: Vec<String> = self.trend_points.keys().cloned().collect();
        for framework_id in frameworks {
            self.cleanup_old_data(&framework_id);
        }
    }

    pub fn clear_framework_data(&mut self, framework_id: &str) {
        self.trend_points.remove(framework_id);
        
        // Remove aggregated data
        let keys_to_remove: Vec<String> = self.aggregated_data
            .keys()
            .filter(|key| key.starts_with(framework_id))
            .cloned()
            .collect();
        
        for key in keys_to_remove {
            self.aggregated_data.remove(&key);
        }
    }

    pub fn get_memory_usage(&self) -> usize {
        let trend_points_size = self.trend_points
            .values()
            .map(|points| points.len() * std::mem::size_of::<PostureTrendPoint>())
            .sum::<usize>();
        
        let aggregated_size = self.aggregated_data
            .values()
            .map(|data| data.len() * std::mem::size_of::<AggregatedPosture>())
            .sum::<usize>();
        
        trend_points_size + aggregated_size
    }
}

impl Default for PostureStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStatistics {
    pub total_snapshots: usize,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub avg_score: f64,
    pub score_variance: f64,
    pub domains_tracked: usize,
    pub data_size_bytes: usize,
}
