use crate::{PostureTrendPoint, TrendDirection, TrendAnalysis, DataPoint, TrendsResult, TrendsError};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

/// Trend analyzer for posture data
pub struct TrendAnalyzer;

impl TrendAnalyzer {
    pub fn analyze_posture_trend(
        framework_id: &str,
        points: &[PostureTrendPoint],
        time_period: Duration,
    ) -> TrendsResult<TrendAnalysis> {
        if points.len() < 2 {
            return Err(TrendsError::AnalysisFailed("Need at least 2 data points for trend analysis".to_string()));
        }

        let data_points: Vec<DataPoint> = points
            .iter()
            .map(|point| DataPoint {
                timestamp: point.timestamp,
                value: point.overall_score,
                metadata: HashMap::new(),
            })
            .collect();

        let (direction, change_rate, confidence) = Self::calculate_trend(&data_points)?;

        Ok(TrendAnalysis {
            metric_name: format!("{}_overall_score", framework_id),
            time_period,
            direction,
            change_rate,
            confidence,
            data_points,
            analysis_timestamp: Utc::now(),
        })
    }

    pub fn analyze_domain_trend(
        framework_id: &str,
        domain: &str,
        points: &[PostureTrendPoint],
        time_period: Duration,
    ) -> TrendsResult<TrendAnalysis> {
        if points.len() < 2 {
            return Err(TrendsError::AnalysisFailed("Need at least 2 data points for trend analysis".to_string()));
        }

        let data_points: Vec<DataPoint> = points
            .iter()
            .filter_map(|point| {
                point.domain_scores.get(domain).map(|score| DataPoint {
                    timestamp: point.timestamp,
                    value: *score,
                    metadata: HashMap::new(),
                })
            })
            .collect();

        if data_points.len() < 2 {
            return Err(TrendsError::AnalysisFailed(format!("Insufficient data for domain: {}", domain)));
        }

        let (direction, change_rate, confidence) = Self::calculate_trend(&data_points)?;

        Ok(TrendAnalysis {
            metric_name: format!("{}_{}_score", framework_id, domain),
            time_period,
            direction,
            change_rate,
            confidence,
            data_points,
            analysis_timestamp: Utc::now(),
        })
    }

    pub fn analyze_control_pass_rate_trend(
        framework_id: &str,
        points: &[PostureTrendPoint],
        time_period: Duration,
    ) -> TrendsResult<TrendAnalysis> {
        if points.len() < 2 {
            return Err(TrendsError::AnalysisFailed("Need at least 2 data points for trend analysis".to_string()));
        }

        let data_points: Vec<DataPoint> = points
            .iter()
            .map(|point| {
                let pass_rate = if point.total_controls > 0 {
                    point.control_status_counts.passed as f64 / point.total_controls as f64
                } else {
                    0.0
                };
                
                DataPoint {
                    timestamp: point.timestamp,
                    value: pass_rate,
                    metadata: HashMap::new(),
                }
            })
            .collect();

        let (direction, change_rate, confidence) = Self::calculate_trend(&data_points)?;

        Ok(TrendAnalysis {
            metric_name: format!("{}_control_pass_rate", framework_id),
            time_period,
            direction,
            change_rate,
            confidence,
            data_points,
            analysis_timestamp: Utc::now(),
        })
    }

    pub fn detect_anomalies(
        points: &[PostureTrendPoint],
        sensitivity: f64,
    ) -> TrendsResult<Vec<PostureAnomaly>> {
        if points.len() < 10 {
            return Ok(Vec::new()); // Need sufficient data for anomaly detection
        }

        let scores: Vec<f64> = points.iter().map(|p| p.overall_score).collect();
        let mean = scores.iter().sum::<f64>() / scores.len() as f64;
        let variance = scores
            .iter()
            .map(|score| (score - mean).powi(2))
            .sum::<f64>() / scores.len() as f64;
        let std_dev = variance.sqrt();

        let threshold = std_dev * sensitivity;
        let mut anomalies = Vec::new();

        for (i, point) in points.iter().enumerate() {
            let deviation = (point.overall_score - mean).abs();
            
            if deviation > threshold {
                let anomaly_type = if point.overall_score > mean {
                    AnomalyType::PositiveSpike
                } else {
                    AnomalyType::NegativeSpike
                };

                anomalies.push(PostureAnomaly {
                    timestamp: point.timestamp,
                    snapshot_id: point.snapshot_id,
                    anomaly_type,
                    severity: Self::calculate_anomaly_severity(deviation, threshold),
                    expected_value: mean,
                    actual_value: point.overall_score,
                    deviation,
                    context: Self::generate_anomaly_context(point, i, points),
                });
            }
        }

        Ok(anomalies)
    }

    pub fn calculate_moving_average(
        points: &[PostureTrendPoint],
        window_size: usize,
    ) -> TrendsResult<Vec<DataPoint>> {
        if points.len() < window_size {
            return Err(TrendsError::AnalysisFailed("Not enough data points for moving average".to_string()));
        }

        let mut moving_averages = Vec::new();

        for i in (window_size - 1)..points.len() {
            let window_start = i + 1 - window_size;
            let window_sum: f64 = points[window_start..=i]
                .iter()
                .map(|p| p.overall_score)
                .sum();
            
            let average = window_sum / window_size as f64;
            
            moving_averages.push(DataPoint {
                timestamp: points[i].timestamp,
                value: average,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("window_size".to_string(), window_size.to_string());
                    meta.insert("window_start".to_string(), window_start.to_string());
                    meta
                },
            });
        }

        Ok(moving_averages)
    }

    pub fn calculate_volatility(points: &[PostureTrendPoint]) -> TrendsResult<f64> {
        if points.len() < 2 {
            return Err(TrendsError::AnalysisFailed("Need at least 2 points for volatility calculation".to_string()));
        }

        let scores: Vec<f64> = points.iter().map(|p| p.overall_score).collect();
        let mean = scores.iter().sum::<f64>() / scores.len() as f64;
        
        let variance = scores
            .iter()
            .map(|score| (score - mean).powi(2))
            .sum::<f64>() / (scores.len() - 1) as f64;

        Ok(variance.sqrt())
    }

    pub fn forecast_trend(
        points: &[PostureTrendPoint],
        forecast_periods: usize,
    ) -> TrendsResult<Vec<DataPoint>> {
        if points.len() < 3 {
            return Err(TrendsError::AnalysisFailed("Need at least 3 points for forecasting".to_string()));
        }

        // Simple linear regression for forecasting
        let n = points.len() as f64;
        let x_values: Vec<f64> = (0..points.len()).map(|i| i as f64).collect();
        let y_values: Vec<f64> = points.iter().map(|p| p.overall_score).collect();

        let sum_x: f64 = x_values.iter().sum();
        let sum_y: f64 = y_values.iter().sum();
        let sum_xy: f64 = x_values.iter().zip(&y_values).map(|(x, y)| x * y).sum();
        let sum_x_squared: f64 = x_values.iter().map(|x| x * x).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x_squared - sum_x * sum_x);
        let intercept = (sum_y - slope * sum_x) / n;

        let mut forecasts = Vec::new();
        let last_timestamp = points.last().unwrap().timestamp;
        let time_interval = if points.len() > 1 {
            points[1].timestamp - points[0].timestamp
        } else {
            Duration::hours(1) // Default interval
        };

        for i in 1..=forecast_periods {
            let x = points.len() as f64 + i as f64 - 1.0;
            let predicted_value = slope * x + intercept;
            let forecast_timestamp = last_timestamp + time_interval * i as i32;

            forecasts.push(DataPoint {
                timestamp: forecast_timestamp,
                value: predicted_value.max(0.0).min(1.0), // Clamp to valid score range
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("forecast".to_string(), "true".to_string());
                    meta.insert("confidence".to_string(), Self::calculate_forecast_confidence(points, i).to_string());
                    meta
                },
            });
        }

        Ok(forecasts)
    }

    fn calculate_trend(data_points: &[DataPoint]) -> TrendsResult<(TrendDirection, f64, f64)> {
        if data_points.len() < 2 {
            return Ok((TrendDirection::Unknown, 0.0, 0.0));
        }

        // Simple linear regression
        let n = data_points.len() as f64;
        let x_values: Vec<f64> = (0..data_points.len()).map(|i| i as f64).collect();
        let y_values: Vec<f64> = data_points.iter().map(|p| p.value).collect();

        let sum_x: f64 = x_values.iter().sum();
        let sum_y: f64 = y_values.iter().sum();
        let sum_xy: f64 = x_values.iter().zip(&y_values).map(|(x, y)| x * y).sum();
        let sum_x_squared: f64 = x_values.iter().map(|x| x * x).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x_squared - sum_x * sum_x);
        
        // Calculate R-squared for confidence
        let mean_y = sum_y / n;
        let ss_tot: f64 = y_values.iter().map(|y| (y - mean_y).powi(2)).sum();
        let ss_res: f64 = x_values
            .iter()
            .zip(&y_values)
            .map(|(x, y)| {
                let predicted = slope * x + (sum_y - slope * sum_x) / n;
                (y - predicted).powi(2)
            })
            .sum();
        
        let r_squared = if ss_tot != 0.0 { 1.0 - (ss_res / ss_tot) } else { 0.0 };
        
        let direction = if slope > 0.01 {
            TrendDirection::Improving
        } else if slope < -0.01 {
            TrendDirection::Degrading
        } else {
            TrendDirection::Stable
        };

        Ok((direction, slope, r_squared.max(0.0).min(1.0)))
    }

    fn calculate_anomaly_severity(deviation: f64, threshold: f64) -> AnomalySeverity {
        let severity_ratio = deviation / threshold;
        
        if severity_ratio > 3.0 {
            AnomalySeverity::Critical
        } else if severity_ratio > 2.0 {
            AnomalySeverity::High
        } else if severity_ratio > 1.5 {
            AnomalySeverity::Medium
        } else {
            AnomalySeverity::Low
        }
    }

    fn generate_anomaly_context(
        point: &PostureTrendPoint,
        index: usize,
        all_points: &[PostureTrendPoint],
    ) -> HashMap<String, String> {
        let mut context = HashMap::new();
        
        context.insert("index".to_string(), index.to_string());
        context.insert("total_controls".to_string(), point.total_controls.to_string());
        context.insert("passed_controls".to_string(), point.control_status_counts.passed.to_string());
        context.insert("failed_controls".to_string(), point.control_status_counts.failed.to_string());
        
        // Add context about surrounding points
        if index > 0 {
            let prev_score = all_points[index - 1].overall_score;
            context.insert("prev_score".to_string(), prev_score.to_string());
            context.insert("score_change".to_string(), (point.overall_score - prev_score).to_string());
        }
        
        if index < all_points.len() - 1 {
            let next_score = all_points[index + 1].overall_score;
            context.insert("next_score".to_string(), next_score.to_string());
        }
        
        context
    }

    fn calculate_forecast_confidence(points: &[PostureTrendPoint], periods_ahead: usize) -> f64 {
        // Simple confidence calculation - decreases with distance
        let base_confidence = 0.8;
        let decay_rate = 0.1;
        
        (base_confidence - (periods_ahead as f64 * decay_rate)).max(0.1)
    }
}

/// Posture anomaly detection result
#[derive(Debug, Clone)]
pub struct PostureAnomaly {
    pub timestamp: DateTime<Utc>,
    pub snapshot_id: uuid::Uuid,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub expected_value: f64,
    pub actual_value: f64,
    pub deviation: f64,
    pub context: HashMap<String, String>,
}

/// Types of anomalies
#[derive(Debug, Clone)]
pub enum AnomalyType {
    PositiveSpike,  // Unexpectedly high score
    NegativeSpike,  // Unexpectedly low score
    Drift,          // Gradual change from baseline
    Volatility,     // High variance
}

/// Anomaly severity levels
#[derive(Debug, Clone)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}
