use crate::models::{Finding, Severity};
use regex::Regex;
use uuid::Uuid;

pub struct DependencyScanner;

impl DependencyScanner {
    pub fn scan_requirements_txt(content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Curated high-impact known advisory table
        let known_vulnerabilities = vec![
            ("requests", "2.25.1", "CVE-2023-32681", "High", "Unintended leak of Proxy-Authorization headers to destination servers.", "Upgrade requests to >=2.31.0"),
            ("urllib3", "1.26.4", "CVE-2021-33503", "High", "Catastrophic ReDoS in authority regular expression parsing.", "Upgrade urllib3 to >=1.26.5"),
            ("jinja2", "2.11.2", "CVE-2020-28493", "Medium", "ReDoS vulnerability in Jinja2 compiler urlize filter.", "Upgrade jinja2 to >=2.11.3"),
            ("django", "3.1.0", "CVE-2021-3281", "Critical", "Directory traversal in archive.extract()", "Upgrade django to >=3.1.6"),
        ];

        let req_line_re = Regex::new(r"^\s*([a-zA-Z0-9_\-]+)\s*==\s*([0-9\.]+)\s*$").unwrap();

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            if let Some(caps) = req_line_re.captures(line.trim()) {
                let pkg_name = caps.get(1).map_or("", |m| m.as_str()).to_lowercase();
                let pkg_ver = caps.get(2).map_or("", |m| m.as_str());

                for (vuln_pkg, vuln_ver, cve, severity_str, desc, fix) in &known_vulnerabilities {
                    if pkg_name == *vuln_pkg && pkg_ver == *vuln_ver {
                        let severity = match *severity_str {
                            "Critical" => Severity::Critical,
                            "High" => Severity::High,
                            "Medium" => Severity::Medium,
                            _ => Severity::Low,
                        };

                        findings.push(Finding {
                            id: format!("SEC-008-{}", Uuid::new_v4().to_string()[..8].to_uppercase()),
                            rule_id: "SEC-008".to_string(),
                            rule_name: format!("Vulnerable Dependency: {} ({})", pkg_name, cve),
                            severity,
                            confidence: 0.99,
                            file_path: file_path.to_string(),
                            line: line_num,
                            column: 1,
                            source: None,
                            propagation: vec![],
                            sink: None,
                            code_snippet: line.trim().to_string(),
                            recommended_fix: format!("{}. {}", desc, fix),
                            target_framework: "Python PyPI".to_string(),
                        });
                    }
                }
            }
        }

        findings
    }
}
