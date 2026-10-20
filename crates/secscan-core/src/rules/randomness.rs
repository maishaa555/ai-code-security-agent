use crate::models::{Finding, Severity};
use regex::Regex;
use uuid::Uuid;

pub struct RandomnessScanner;

impl RandomnessScanner {
    pub fn scan(source_code: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Pattern for random module used in token / secret generation context
        let random_re = Regex::new(r"random\.(randint|random|choice|randrange)\(").unwrap();

        for (idx, line) in source_code.lines().enumerate() {
            let line_num = idx + 1;
            if random_re.is_match(line) {
                // Check if in security context (token, key, salt, auth, nonce)
                let lower = source_code.to_lowercase();
                let is_sec_ctx = line.contains("token")
                    || line.contains("key")
                    || line.contains("reset")
                    || line.contains("auth")
                    || line.contains("password")
                    || lower.contains("reset_token")
                    || lower.contains("generate_token");

                if is_sec_ctx {
                    findings.push(Finding {
                        id: format!("SEC-006-{}", Uuid::new_v4().to_string()[..8].to_uppercase()),
                        rule_id: "SEC-006".to_string(),
                        rule_name: "Insecure Randomness in Security Context".to_string(),
                        severity: Severity::Medium,
                        confidence: 0.90,
                        file_path: file_path.to_string(),
                        line: line_num,
                        column: 1,
                        source: None,
                        propagation: vec![],
                        sink: None,
                        code_snippet: line.trim().to_string(),
                        recommended_fix: "Use the cryptographically secure 'secrets' module (e.g. secrets.token_hex(16)) instead of standard 'random'.".to_string(),
                        target_framework: "Python secrets / random".to_string(),
                    });
                }
            }
        }

        findings
    }
}
