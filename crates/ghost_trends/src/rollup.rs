use crate::{PostureTrendPoint, AggregatedPosture, AggregationPeriod, TrendsResult};
use chrono::{DateTime, Utc, Datelike, Timelike, Duration};
use std::collections::HashMap;

/// Data rollup engine for aggregating posture data
pub struct RollupEngine;

impl RollupEngine {
    pub fn aggregate_by_period(
        framework_id: &str,
        points: &[PostureTrendPoint],
        period: AggregationPeriod,
    ) -> TrendsResult<Vec<AggregatedPosture>> {
        if points.is_empty() {
            return Ok(Vec::new());
        }

        let mut aggregated_data = Vec::new();
        let grouped_points = Self::group_by_period(points, &period);

        for (period_key, period_points) in grouped_points {
            if period_points.is_empty() {
                continue;
            }

            let (start_time, end_time) = Self::calculate_period_bounds(&period_key, &period);
            let aggregated = Self::aggregate_points(
                framework_id,
                &period_points,
                period.clone(),
                start_time,
                end_time,
            );

            aggregated_data.push(aggregated);
        }

        // Sort by start time
        aggregated_data.sort_by(|a, b| a.start_time.cmp(&b.start_time));

        Ok(aggregated_data)
    }

    pub fn create_daily_rollup(
        framework_id: &str,
        points: &[PostureTrendPoint],
    ) -> TrendsResult<Vec<AggregatedPosture>> {
        Self::aggregate_by_period(framework_id, points, AggregationPeriod::Daily)
    }

    pub fn create_weekly_rollup(
        framework_id: &str,
        points: &[PostureTrendPoint],
    ) -> TrendsResult<Vec<AggregatedPosture>> {
        Self::aggregate_by_period(framework_id, points, AggregationPeriod::Weekly)
    }

    pub fn create_monthly_rollup(
        framework_id: &str,
        points: &[PostureTrendPoint],
    ) -> TrendsResult<Vec<AggregatedPosture>> {
        Self::aggregate_by_period(framework_id, points, AggregationPeriod::Monthly)
    }

    pub fn downsample_data(
        points: &[PostureTrendPoint],
        target_count: usize,
    ) -> Vec<PostureTrendPoint> {
        if points.len() <= target_count {
            return points.to_vec();
        }

        let step = points.len() / target_count;
        let mut downsampled = Vec::new();

        for i in (0..points.len()).step_by(step) {
            if downsampled.len() >= target_count {
                break;
            }
            downsampled.push(points[i].clone());
        }

        // Always include the last point
        if let Some(last_point) = points.last() {
            if downsampled.last().map(|p| p.timestamp) != Some(last_point.timestamp) {
                downsampled.push(last_point.clone());
            }
        }

        downsampled
    }

    pub fn calculate_percentiles(
        points: &[PostureTrendPoint],
        percentiles: &[f64],
    ) -> HashMap<String, f64> {
        if points.is_empty() {
            return HashMap::new();
        }

        let mut scores: Vec<f64> = points.iter().map(|p| p.overall_score).collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let mut result = HashMap::new();

        for &percentile in percentiles {
            let index = ((percentile / 100.0) * (scores.len() - 1) as f64).round() as usize;
            let index = index.min(scores.len() - 1);
            result.insert(format!("p{}", percentile as u8), scores[index]);
        }

        result
    }

    fn group_by_period(
        points: &[PostureTrendPoint],
        period: &AggregationPeriod,
    ) -> HashMap<String, Vec<PostureTrendPoint>> {
        let mut grouped = HashMap::new();

        for point in points {
            let key = Self::get_period_key(&point.timestamp, period);
            grouped.entry(key).or_insert_with(Vec::new).push(point.clone());
        }

        grouped
    }

    fn get_period_key(timestamp: &DateTime<Utc>, period: &AggregationPeriod) -> String {
        match period {
            AggregationPeriod::Hourly => {
                format!("{}-{:02}-{:02}T{:02}", 
                    timestamp.year(), 
                    timestamp.month(), 
                    timestamp.day(), 
                    timestamp.hour()
                )
            }
            AggregationPeriod::Daily => {
                format!("{}-{:02}-{:02}", 
                    timestamp.year(), 
                    timestamp.month(), 
                    timestamp.day()
                )
            }
            AggregationPeriod::Weekly => {
                let week_start = timestamp.date_naive() - Duration::days(timestamp.weekday().num_days_from_monday() as i64);
                format!("{}-W{:02}", week_start.year(), week_start.iso_week().week())
            }
            AggregationPeriod::Monthly => {
                format!("{}-{:02}", timestamp.year(), timestamp.month())
            }
            AggregationPeriod::Quarterly => {
                let quarter = (timestamp.month() - 1) / 3 + 1;
                format!("{}-Q{}", timestamp.year(), quarter)
            }
            AggregationPeriod::Yearly => {
                format!("{}", timestamp.year())
            }
        }
    }

    fn calculate_period_bounds(
        period_key: &str,
        period: &AggregationPeriod,
    ) -> (DateTime<Utc>, DateTime<Utc>) {
        // This is a simplified implementation
        // In a real system, you'd parse the period_key and calculate exact bounds
        let now = Utc::now();
        let start_time = match period {
            AggregationPeriod::Hourly => now - Duration::hours(1),
            AggregationPeriod::Daily => now - Duration::days(1),
            AggregationPeriod::Weekly => now - Duration::weeks(1),
            AggregationPeriod::Monthly => now - Duration::days(30),
            AggregationPeriod::Quarterly => now - Duration::days(90),
            AggregationPeriod::Yearly => now - Duration::days(365),
        };

        (start_time, now)
    }

    fn aggregate_points(
        framework_id: &str,
        points: &[PostureTrendPoint],
        period: AggregationPeriod,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> AggregatedPosture {
        let scores: Vec<f64> = points.iter().map(|p| p.overall_score).collect();
        
        let avg_score = scores.iter().sum::<f64>() / scores.len() as f64;
        let min_score = scores.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_score = scores.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        
        // Calculate variance
        let mean = avg_score;
        let variance = scores
            .iter()
            .map(|score| (score - mean).powi(2))
            .sum::<f64>() / scores.len() as f64;

        // Aggregate domain scores
        let mut domain_totals: HashMap<String, f64> = HashMap::new();
        let mut domain_counts: HashMap<String, usize> = HashMap::new();

        for point in points {
            for (domain, score) in &point.domain_scores {
                *domain_totals.entry(domain.clone()).or_insert(0.0) += score;
                *domain_counts.entry(domain.clone()).or_insert(0) += 1;
            }
        }

        let domain_averages: HashMap<String, f64> = domain_totals
            .into_iter()
            .map(|(domain, total)| {
                let count = domain_counts.get(&domain).unwrap_or(&1);
                (domain, total / *count as f64)
            })
            .collect();

        // Calculate control pass rates (simplified)
        let mut control_pass_rates = HashMap::new();
        let total_snapshots = points.len() as f64;
        
        // This is simplified - in a real implementation, you'd track individual controls
        let avg_pass_rate = points
            .iter()
            .map(|p| {
                if p.total_controls > 0 {
                    p.control_status_counts.passed as f64 / p.total_controls as f64
                } else {
                    0.0
                }
            })
            .sum::<f64>() / total_snapshots;

        control_pass_rates.insert("overall".to_string(), avg_pass_rate);

        AggregatedPosture {
            period,
            start_time,
            end_time,
            framework_id: framework_id.to_string(),
            avg_score,
            min_score,
            max_score,
            score_variance: variance,
            snapshot_count: points.len(),
            domain_averages,
            control_pass_rates,
        }
    }

    pub fn create_summary_statistics(
        aggregated_data: &[AggregatedPosture],
    ) -> RollupSummary {
        if aggregated_data.is_empty() {
            return RollupSummary {
                total_periods: 0,
                date_range: None,
                overall_avg_score: 0.0,
                overall_min_score: 0.0,
                overall_max_score: 0.0,
                score_trend: crate::TrendDirection::Unknown,
                volatility: 0.0,
                best_period: None,
                worst_period: None,
            };
        }

        let total_periods = aggregated_data.len();
        let first_period = &aggregated_data[0];
        let last_period = &aggregated_data[aggregated_data.len() - 1];
        
        let date_range = Some((first_period.start_time, last_period.end_time));
        
        let scores: Vec<f64> = aggregated_data.iter().map(|a| a.avg_score).collect();
        let overall_avg_score = scores.iter().sum::<f64>() / scores.len() as f64;
        let overall_min_score = scores.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let overall_max_score = scores.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        
        // Calculate volatility
        let mean = overall_avg_score;
        let volatility = (scores
            .iter()
            .map(|score| (score - mean).powi(2))
            .sum::<f64>() / scores.len() as f64)
            .sqrt();

        // Determine trend
        let score_trend = if scores.len() >= 2 {
            let first_score = scores[0];
            let last_score = scores[scores.len() - 1];
            let change = last_score - first_score;
            
            if change > 0.05 {
                crate::TrendDirection::Improving
            } else if change < -0.05 {
                crate::TrendDirection::Degrading
            } else {
                crate::TrendDirection::Stable
            }
        } else {
            crate::TrendDirection::Unknown
        };

        // Find best and worst periods
        let best_period = aggregated_data
            .iter()
            .max_by(|a, b| a.avg_score.partial_cmp(&b.avg_score).unwrap())
            .map(|a| (a.start_time, a.avg_score));

        let worst_period = aggregated_data
            .iter()
            .min_by(|a, b| a.avg_score.partial_cmp(&b.avg_score).unwrap())
            .map(|a| (a.start_time, a.avg_score));

        RollupSummary {
            total_periods,
            date_range,
            overall_avg_score,
            overall_min_score,
            overall_max_score,
            score_trend,
            volatility,
            best_period,
            worst_period,
        }
    }
}

/// Summary statistics for rollup data
#[derive(Debug, Clone)]
pub struct RollupSummary {
    pub total_periods: usize,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub overall_avg_score: f64,
    pub overall_min_score: f64,
    pub overall_max_score: f64,
    pub score_trend: crate::TrendDirection,
    pub volatility: f64,
    pub best_period: Option<(DateTime<Utc>, f64)>,
    pub worst_period: Option<(DateTime<Utc>, f64)>,
}
