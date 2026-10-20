use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebiusTelemetry {
    pub provider: String,
    pub model: String,
    pub latency_ms: u128,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub is_mock: bool,
}

impl Default for NebiusTelemetry {
    fn default() -> Self {
        Self {
            provider: "Nebius Token Factory".to_string(),
            model: "nvidia/llama-3.1-nemotron-70b-instruct".to_string(),
            latency_ms: 0,
            input_tokens: 0,
            output_tokens: 0,
            is_mock: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiExplanation {
    pub finding_id: String,
    pub summary: String,
    pub root_cause: String,
    pub attack_vector: String,
    pub business_impact: String,
    pub recommended_action: String,
    pub telemetry: NebiusTelemetry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPatch {
    pub finding_id: String,
    pub file_path: String,
    pub original_code: String,
    pub remediated_code: String,
    pub unified_diff: String,
    pub explanation: String,
    pub safety_check_passed: bool,
    pub telemetry: NebiusTelemetry,
}
