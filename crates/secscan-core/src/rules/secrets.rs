use crate::models::{Finding, Severity};
use regex::Regex;
use std::collections::HashSet;
use uuid::Uuid;

pub struct SecretScanner;

impl SecretScanner {
    pub fn scan(source_code: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Pattern for common secret assignments
        let secret_assign_re = Regex::new(
            r#"(?i)(api[_-]?key|secret[_-]?key|jwt[_-]?secret|auth[_-]?token|password|private[_-]?key)\s*=\s*["']([^"']{12,})["']"#
        ).unwrap();

        for (idx, line) in source_code.lines().enumerate() {
            let line_num = idx + 1;
            if let Some(caps) = secret_assign_re.captures(line) {
                let var_name = caps.get(1).map_or("", |m| m.as_str());
                let secret_val = caps.get(2).map_or("", |m| m.as_str());

                // Calculate Shannon entropy
                let entropy = calculate_entropy(secret_val);

                // High entropy or known secret prefixes (sk-, ghp_, etc.)
                if entropy > 3.0 || secret_val.starts_with("sk-") || secret_val.starts_with("ghp_") {
                    findings.push(Finding {
                        id: format!("SEC-004-{}", Uuid::new_v4().to_string()[..8].to_uppercase()),
                        rule_id: "SEC-004".to_string(),
                        rule_name: "Hard-coded Secret / Credential".to_string(),
                        severity: Severity::High,
                        confidence: 0.98,
                        file_path: file_path.to_string(),
                        line: line_num,
                        column: 1,
                        source: None,
                        propagation: vec![],
                        sink: None,
                        code_snippet: format!("{}: <REDACTED_SECRET>", var_name),
                        recommended_fix: "Extract credentials to environment variables or an enterprise secret manager (e.g. AWS Secrets Manager, HashiCorp Vault).".to_string(),
                        target_framework: "Generic Python".to_string(),
                    });
                }
            }
        }

        findings
    }
}

fn calculate_entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}
