use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub finding_id: String,
    pub patch_applied: bool,
    pub syntax_valid: bool,
    pub tests_passed: bool,
    pub test_output: String,
    pub original_vulnerability_cleared: bool,
    pub new_vulnerabilities_introduced: usize,
    pub original_score: u32,
    pub new_score: u32,
    pub status: ValidationStatus,
    pub decision_rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ValidationStatus {
    Validated,
    FailedTests,
    VulnerabilityRemains,
    RejectedUnsafe,
    Error,
}
