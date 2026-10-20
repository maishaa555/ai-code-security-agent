use crate::models::{Finding, Severity};
use regex::Regex;
use uuid::Uuid;

pub struct CryptoScanner;

impl CryptoScanner {
    pub fn scan(source_code: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let md5_re = Regex::new(r"hashlib\.(md5|sha1)\(").unwrap();

        for (idx, line) in source_code.lines().enumerate() {
            let line_num = idx + 1;
            if let Some(caps) = md5_re.captures(line) {
                let algo = caps.get(1).map_or("md5", |m| m.as_str());
                findings.push(Finding {
                    id: format!("SEC-005-{}", Uuid::new_v4().to_string()[..8].to_uppercase()),
                    rule_id: "SEC-005".to_string(),
                    rule_name: "Weak Cryptographic Hash".to_string(),
                    severity: Severity::Medium,
                    confidence: 0.95,
                    file_path: file_path.to_string(),
                    line: line_num,
                    column: 1,
                    source: None,
                    propagation: vec![],
                    sink: None,
                    code_snippet: line.trim().to_string(),
                    recommended_fix: format!(
                        "Replace deprecated '{}' hash with SHA-256 (hashlib.sha256) or bcrypt/argon2 for password hashing.",
                        algo
                    ),
                    target_framework: "Python hashlib".to_string(),
                });
            }
        }

        findings
    }
}
