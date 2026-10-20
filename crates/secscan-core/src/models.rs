use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowStep {
    pub step_index: usize,
    pub label: String,
    pub variable: String,
    pub line: usize,
    pub column: usize,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub confidence: f64,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub source: Option<DataFlowStep>,
    pub propagation: Vec<DataFlowStep>,
    pub sink: Option<DataFlowStep>,
    pub code_snippet: String,
    pub recommended_fix: String,
    pub target_framework: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub repository_path: String,
    pub timestamp: String,
    pub scan_duration_ms: u128,
    pub files_scanned: usize,
    pub lines_analyzed: usize,
    pub findings: Vec<Finding>,
    pub security_score: u32,
    pub severity_breakdown: HashMap<String, usize>,
}
