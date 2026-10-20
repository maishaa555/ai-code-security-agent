pub mod models;
pub mod parser;
pub mod risk;
pub mod rules;
pub mod sarif;
pub mod taint;

use models::{Finding, ScanReport, Severity};
use parser::PythonParser;
use risk::RiskEngine;
use rules::{
    crypto::CryptoScanner, dependencies::DependencyScanner, randomness::RandomnessScanner,
    secrets::SecretScanner,
};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Instant;
use taint::TaintAnalyzer;
use walkdir::WalkDir;

pub struct Scanner {
    python_parser: PythonParser,
}

impl Scanner {
    pub fn new() -> Result<Self, String> {
        let python_parser = PythonParser::new()?;
        Ok(Self { python_parser })
    }

    pub fn scan_directory<P: AsRef<Path>>(&mut self, root_path: P) -> Result<ScanReport, String> {
        let start_time = Instant::now();
        let root = root_path.as_ref();

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut files_scanned = 0;
        let mut lines_analyzed = 0;

        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| !is_ignored(e.path()))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            // Scan Python source files
            if ext == "py" {
                if let Ok(content) = fs::read_to_string(path) {
                    files_scanned += 1;
                    lines_analyzed += content.lines().count();

                    let relative_path = path
                        .strip_prefix(root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .to_string();

                    // 1. AST Taint Analysis
                    if let Some(tree) = self.python_parser.parse(&content) {
                        let taint_analyzer = TaintAnalyzer::new(&content, &relative_path);
                        let mut taint_findings = taint_analyzer.analyze(&tree);
                        all_findings.append(&mut taint_findings);
                    }

                    // 2. Secret Scan
                    let mut secret_findings = SecretScanner::scan(&content, &relative_path);
                    all_findings.append(&mut secret_findings);

                    // 3. Weak Crypto Scan
                    let mut crypto_findings = CryptoScanner::scan(&content, &relative_path);
                    all_findings.append(&mut crypto_findings);

                    // 4. Insecure Randomness Scan
                    let mut random_findings = RandomnessScanner::scan(&content, &relative_path);
                    all_findings.append(&mut random_findings);
                }
            } else if file_name == "requirements.txt" {
                if let Ok(content) = fs::read_to_string(path) {
                    files_scanned += 1;
                    lines_analyzed += content.lines().count();

                    let relative_path = path
                        .strip_prefix(root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .to_string();

                    let mut dep_findings =
                        DependencyScanner::scan_requirements_txt(&content, &relative_path);
                    all_findings.append(&mut dep_findings);
                }
            }
        }

        let duration = start_time.elapsed().as_millis();
        let security_score = RiskEngine::calculate_score(&all_findings);

        let mut severity_breakdown = HashMap::new();
        severity_breakdown.insert("CRITICAL".to_string(), 0);
        severity_breakdown.insert("HIGH".to_string(), 0);
        severity_breakdown.insert("MEDIUM".to_string(), 0);
        severity_breakdown.insert("LOW".to_string(), 0);

        for finding in &all_findings {
            let key = match finding.severity {
                Severity::Critical => "CRITICAL",
                Severity::High => "HIGH",
                Severity::Medium => "MEDIUM",
                Severity::Low => "LOW",
                Severity::Info => "LOW",
            };
            *severity_breakdown.entry(key.to_string()).or_insert(0) += 1;
        }

        Ok(ScanReport {
            repository_path: root.to_string_lossy().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            scan_duration_ms: duration,
            files_scanned,
            lines_analyzed,
            findings: all_findings,
            security_score,
            severity_breakdown,
        })
    }
}

fn is_ignored(path: &Path) -> bool {
    let p = path.to_string_lossy();
    p.contains(".git")
        || p.contains("node_modules")
        || p.contains("__pycache__")
        || p.contains(".venv")
        || p.contains("target")
        || p.contains(".pytest_cache")
}
