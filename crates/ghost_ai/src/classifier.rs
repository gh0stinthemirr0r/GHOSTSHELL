use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Error categories for AI classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    Authentication,
    Authorization, 
    Network,
    Cryptography,
    Policy,
    Configuration,
    Resource,
    Timeout,
    Unknown,
}

/// Error classifier for AI suggestions
pub struct ErrorClassifier {
    patterns: HashMap<ErrorCategory, Vec<String>>,
}

impl ErrorClassifier {
    pub fn new() -> Self {
        let mut classifier = Self {
            patterns: HashMap::new(),
        };
        classifier.load_patterns();
        classifier
    }

    fn load_patterns(&mut self) {
        // Authentication patterns
        self.patterns.insert(ErrorCategory::Authentication, vec![
            "permission denied".to_string(),
            "authentication failed".to_string(),
            "invalid credentials".to_string(),
            "login failed".to_string(),
            "unauthorized".to_string(),
        ]);

        // Network patterns
        self.patterns.insert(ErrorCategory::Network, vec![
            "connection refused".to_string(),
            "network unreachable".to_string(),
            "timeout".to_string(),
            "connection reset".to_string(),
            "host not found".to_string(),
        ]);

        // Cryptography patterns
        self.patterns.insert(ErrorCategory::Cryptography, vec![
            "certificate".to_string(),
            "key exchange".to_string(),
            "cipher".to_string(),
            "signature verification".to_string(),
            "encryption".to_string(),
        ]);

        // Policy patterns
        self.patterns.insert(ErrorCategory::Policy, vec![
            "policy violation".to_string(),
            "not allowed".to_string(),
            "restricted".to_string(),
            "compliance".to_string(),
            "blocked".to_string(),
        ]);
    }

    pub fn classify(&self, error_text: &str) -> (ErrorCategory, f64) {
        let error_lower = error_text.to_lowercase();
        let mut best_category = ErrorCategory::Unknown;
        let mut best_score = 0.0;

        for (category, patterns) in &self.patterns {
            let mut score = 0.0;
            let mut matches = 0;

            for pattern in patterns {
                if error_lower.contains(pattern) {
                    matches += 1;
                    score += 1.0 / patterns.len() as f64;
                }
            }

            // Boost score based on number of matches
            if matches > 0 {
                score *= (matches as f64).sqrt();
            }

            if score > best_score {
                best_score = score;
                best_category = category.clone();
            }
        }

        // Normalize score to 0-1 range
        best_score = best_score.min(1.0);

        (best_category, best_score)
    }
}

impl Default for ErrorClassifier {
    fn default() -> Self {
        Self::new()
    }
}
