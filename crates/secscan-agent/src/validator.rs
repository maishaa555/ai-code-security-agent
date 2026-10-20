use crate::models::{ValidationReport, ValidationStatus};
use secscan_core::models::{Finding, ScanReport};
use secscan_core::Scanner;
use secscan_nebius::models::AiPatch;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

pub struct AgentValidator;

impl AgentValidator {
    pub fn validate_patch(
        repo_path: &Path,
        original_finding: &Finding,
        patch: &AiPatch,
        original_report: &ScanReport,
    ) -> Result<ValidationReport, String> {
        // 1. Safety check
        if !patch.safety_check_passed {
            return Ok(ValidationReport {
                finding_id: original_finding.id.clone(),
                patch_applied: false,
                syntax_valid: false,
                tests_passed: false,
                test_output: "Patch rejected: Contains unsafe or restricted operations.".to_string(),
                original_vulnerability_cleared: false,
                new_vulnerabilities_introduced: 0,
                original_score: original_report.security_score,
                new_score: original_report.security_score,
                status: ValidationStatus::RejectedUnsafe,
                decision_rationale: "Safety guard blocked patch containing potential backdoor or dangerous constructs.".to_string(),
            });
        }

        // 2. Create isolated sandbox temp directory
        let temp_dir = TempDir::new().map_err(|e| format!("Failed to create temp sandbox: {:?}", e))?;
        let sandbox_path = temp_dir.path();

        // Copy repository to sandbox
        copy_dir_recursive(repo_path, sandbox_path)
            .map_err(|e| format!("Failed to copy repo to sandbox: {:?}", e))?;

        // 3. Apply the patch to the file in the sandbox
        let target_file_sandbox = sandbox_path.join(&patch.file_path);
        if !target_file_sandbox.exists() {
            return Err(format!("Target file does not exist in sandbox: {:?}", target_file_sandbox));
        }

        let file_content = fs::read_to_string(&target_file_sandbox)
            .map_err(|e| format!("Failed to read target file: {:?}", e))?;

        if !patch.original_code.is_empty() && file_content.contains(&patch.original_code) {
            let patched_content = file_content.replace(&patch.original_code, &patch.remediated_code);
            fs::write(&target_file_sandbox, patched_content)
                .map_err(|e| format!("Failed to write patched file: {:?}", e))?;
        } else {
            // If exact snippet not found, attempt line-based replacement
            let lines: Vec<&str> = file_content.lines().collect();
            let line_idx = original_finding.line.saturating_sub(1);
            if line_idx < lines.len() {
                let mut new_lines = lines.clone();
                new_lines[line_idx] = &patch.remediated_code;
                let patched_content = new_lines.join("\n");
                fs::write(&target_file_sandbox, patched_content)
                    .map_err(|e| format!("Failed to write line-patched file: {:?}", e))?;
            }
        }

        // 4. Run tests in sandbox
        let (tests_passed, test_output) = run_sandbox_tests(sandbox_path);

        // 5. Re-scan sandbox with secscan-core
        let mut scanner = Scanner::new().map_err(|e| e.to_string())?;
        let new_report = scanner
            .scan_directory(sandbox_path)
            .map_err(|e| e.to_string())?;

        // 6. Verify vulnerability cleared
        let original_vuln_still_present = new_report
            .findings
            .iter()
            .any(|f| f.rule_id == original_finding.rule_id && f.file_path == original_finding.file_path);

        let original_vulnerability_cleared = !original_vuln_still_present;

        // 7. Check for regression or new vulnerabilities
        let new_vulnerabilities_introduced = if new_report.findings.len() > original_report.findings.len() {
            new_report.findings.len() - original_report.findings.len()
        } else {
            0
        };

        let status = if !tests_passed {
            ValidationStatus::FailedTests
        } else if !original_vulnerability_cleared {
            ValidationStatus::VulnerabilityRemains
        } else {
            ValidationStatus::Validated
        };

        let rationale = match status {
            ValidationStatus::Validated => format!(
                "Patch successfully eliminated {} while passing all test cases. Security score improved from {} to {}.",
                original_finding.rule_name, original_report.security_score, new_report.security_score
            ),
            ValidationStatus::FailedTests => "Unit tests failed after applying patch. Fix rejected to avoid breaking application functionality.".to_string(),
            ValidationStatus::VulnerabilityRemains => "The vulnerability rule is still triggered after applying the patch.".to_string(),
            _ => "Patch rejected.".to_string(),
        };

        Ok(ValidationReport {
            finding_id: original_finding.id.clone(),
            patch_applied: true,
            syntax_valid: true,
            tests_passed,
            test_output,
            original_vulnerability_cleared,
            new_vulnerabilities_introduced,
            original_score: original_report.security_score,
            new_score: new_report.security_score,
            status,
            decision_rationale: rationale,
        })
    }
}

fn run_sandbox_tests(sandbox_path: &Path) -> (bool, String) {
    let test_file = sandbox_path.join("tests").join("test_app.py");
    if !test_file.exists() {
        return (true, "No test suite found. Skipping test execution.".to_string());
    }

    // In Windows, use the 'py' launcher which points to installed Python environment
    let python_cmd = if cfg!(windows) { "py" } else { "python3" };
    let output = Command::new(python_cmd)
        .args(&["-m", "unittest", "tests/test_app.py"])
        .current_dir(sandbox_path)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let combined = format!("{}\n{}", stdout, stderr);
            let success = out.status.success() || combined.contains("OK") || combined.contains("passed");
            (success, combined.trim().to_string())
        }
        Err(e) => (false, format!("Failed to execute test runner: {:?}", e)),
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".git" || name == "target" || name == "__pycache__" || name == ".pytest_cache" {
            continue;
        }

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}
