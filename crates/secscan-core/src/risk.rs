use crate::models::{Finding, Severity};

pub struct RiskEngine;

impl RiskEngine {
    pub fn calculate_score(findings: &[Finding]) -> u32 {
        let mut score: i32 = 100;

        for finding in findings {
            let penalty = match finding.severity {
                Severity::Critical => 25,
                Severity::High => 15,
                Severity::Medium => 7,
                Severity::Low => 3,
                Severity::Info => 0,
            };
            score -= penalty;
        }

        if score < 0 {
            0
        } else {
            score as u32
        }
    }
}
