use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use secscan_agent::AgentValidator;
use secscan_core::sarif::SarifExporter;
use secscan_core::Scanner;
use secscan_nebius::NebiusClient;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "secscan")]
#[command(about = "AI-Powered Code Security Agent - Static Core + NVIDIA Nemotron on Nebius")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory or repository for security vulnerabilities
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,

        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// Explain a finding using NVIDIA Nemotron on Nebius Token Factory
    Explain {
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Rule ID or Finding ID (e.g. SEC-001)
        #[arg(short, long, default_value = "SEC-001")]
        rule: String,
    },

    /// Generate an AI security patch for a finding
    Fix {
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Rule ID or Finding ID to remediate (e.g. SEC-001)
        #[arg(short, long, default_value = "SEC-001")]
        rule: String,
    },

    /// Full agent loop: Generate patch, apply in sandbox, run tests, and verify fix
    Verify {
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Rule ID to fix and verify (e.g. SEC-001)
        #[arg(short, long, default_value = "SEC-001")]
        rule: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let nebius = NebiusClient::new();

    match cli.command {
        Commands::Scan { path, format } => {
            let mut scanner = Scanner::new().map_err(|e| anyhow::anyhow!(e))?;
            let report = scanner
                .scan_directory(&path)
                .map_err(|e| anyhow::anyhow!(e))?;

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                OutputFormat::Sarif => {
                    let sarif = SarifExporter::to_sarif(&report);
                    println!("{}", serde_json::to_string_pretty(&sarif)?);
                }
                OutputFormat::Text => {
                    print_report_banner(&report);
                }
            }
        }

        Commands::Explain { path, rule } => {
            let mut scanner = Scanner::new().map_err(|e| anyhow::anyhow!(e))?;
            let report = scanner
                .scan_directory(&path)
                .map_err(|e| anyhow::anyhow!(e))?;

            let finding = report
                .findings
                .iter()
                .find(|f| f.rule_id == rule || f.id == rule)
                .ok_or_else(|| anyhow::anyhow!("Finding with rule ID '{}' not found in scan", rule))?;

            let file_full = path.join(&finding.file_path);
            let file_context = fs::read_to_string(&file_full).unwrap_or_default();

            println!("\n{}", "=========================================================".cyan());
            println!(" {}", "NVIDIA NEMOTRON REASONING (NEBIUS TOKEN FACTORY)".bold().cyan());
            println!("{}\n", "=========================================================".cyan());

            println!("Target Finding: {} ({})", finding.rule_name.bold(), finding.rule_id.yellow());
            println!("File Location:  {}:{}\n", finding.file_path.cyan(), finding.line);

            let explanation = nebius.explain_finding(finding, &file_context).await
                .map_err(|e| anyhow::anyhow!(e))?;

            println!("Summary:        {}", explanation.summary.bold());
            println!("\nRoot Cause:     {}", explanation.root_cause);
            println!("\nAttack Vector:  {}", explanation.attack_vector.red());
            println!("\nImpact:         {}", explanation.business_impact.yellow());
            println!("\nAction:         {}", explanation.recommended_action.green());

            println!("\n{}", "---------------------------------------------------------".cyan());
            println!(" Inference Telemetry:");
            println!("   Provider:    {}", explanation.telemetry.provider.cyan());
            println!("   Model:       {}", explanation.telemetry.model.cyan());
            println!("   Latency:     {} ms", explanation.telemetry.latency_ms);
            println!("   Tokens:      {} in / {} out", explanation.telemetry.input_tokens, explanation.telemetry.output_tokens);
            println!("   Status:      {}", if explanation.telemetry.is_mock { "Offline Engine (No API key set)".yellow() } else { "Live Token Factory API".green().bold() });
            println!("{}\n", "=========================================================".cyan());
        }

        Commands::Fix { path, rule } => {
            let mut scanner = Scanner::new().map_err(|e| anyhow::anyhow!(e))?;
            let report = scanner
                .scan_directory(&path)
                .map_err(|e| anyhow::anyhow!(e))?;

            let finding = report
                .findings
                .iter()
                .find(|f| f.rule_id == rule || f.id == rule)
                .ok_or_else(|| anyhow::anyhow!("Finding with rule ID '{}' not found in scan", rule))?;

            let file_full = path.join(&finding.file_path);
            let file_context = fs::read_to_string(&file_full).unwrap_or_default();

            println!("\n{}", "=========================================================".cyan());
            println!(" {}", "AI SECURITY PATCH GENERATION (NVIDIA NEMOTRON)".bold().cyan());
            println!("{}\n", "=========================================================".cyan());

            let patch = nebius.generate_patch(finding, &file_context).await
                .map_err(|e| anyhow::anyhow!(e))?;

            println!("Target Finding: {} ({})", finding.rule_name.bold(), finding.rule_id.yellow());
            println!("Patch Target:   {}\n", patch.file_path.cyan());

            println!("Explanation:    {}", patch.explanation.italic());
            println!("\nUnified Diff:\n{}", patch.unified_diff.green());

            println!("\n{}", "---------------------------------------------------------".cyan());
            println!(" Inference Telemetry:");
            println!("   Provider:    {}", patch.telemetry.provider.cyan());
            println!("   Model:       {}", patch.telemetry.model.cyan());
            println!("   Latency:     {} ms", patch.telemetry.latency_ms);
            println!("   Safety Guard:{}", if patch.safety_check_passed { " PASSED (No restricted primitives)".green() } else { " BLOCKED".red().bold() });
            println!("{}\n", "=========================================================".cyan());
        }

        Commands::Verify { path, rule } => {
            let mut scanner = Scanner::new().map_err(|e| anyhow::anyhow!(e))?;
            let report = scanner
                .scan_directory(&path)
                .map_err(|e| anyhow::anyhow!(e))?;

            let finding = report
                .findings
                .iter()
                .find(|f| f.rule_id == rule || f.id == rule)
                .ok_or_else(|| anyhow::anyhow!("Finding with rule ID '{}' not found in scan", rule))?;

            let file_full = path.join(&finding.file_path);
            let file_context = fs::read_to_string(&file_full).unwrap_or_default();

            println!("\n{}", "=========================================================".cyan());
            println!(" {}", "AUTONOMOUS AGENT VERIFICATION LOOP (SANDBOX)".bold().cyan());
            println!("{}\n", "=========================================================".cyan());

            println!("Step 1: Generating patch with NVIDIA Nemotron...");
            let patch = nebius.generate_patch(finding, &file_context).await
                .map_err(|e| anyhow::anyhow!(e))?;
            println!("  ✔ Patch generated in {}ms", patch.telemetry.latency_ms);

            println!("Step 2: Spawning isolated sandbox workspace...");
            println!("Step 3: Applying patch diff to sandbox...");
            println!("Step 4: Executing test suite inside sandbox...");
            println!("Step 5: Re-running SecScan static taint engine...");

            let validation = AgentValidator::validate_patch(&path, finding, &patch, &report)
                .map_err(|e| anyhow::anyhow!(e))?;

            println!("\n{}", "---------------------------------------------------------".cyan());
            println!(" VERIFICATION RESULT:");
            match validation.status {
                secscan_agent::ValidationStatus::Validated => {
                    println!("   Status:                 {}", "✔ VALIDATED (MERGE READY)".green().bold());
                }
                secscan_agent::ValidationStatus::FailedTests => {
                    println!("   Status:                 {}", "❌ REJECTED (TESTS FAILED)".red().bold());
                }
                secscan_agent::ValidationStatus::VulnerabilityRemains => {
                    println!("   Status:                 {}", "❌ REJECTED (VULNERABILITY PERSISTS)".red().bold());
                }
                secscan_agent::ValidationStatus::RejectedUnsafe => {
                    println!("   Status:                 {}", "❌ BLOCKED BY SAFETY GUARD".red().bold());
                }
                secscan_agent::ValidationStatus::Error => {
                    println!("   Status:                 {}", "ERROR".red());
                }
            }

            println!("   Patch Applied:          {}", if validation.patch_applied { "Yes".green() } else { "No".red() });
            println!("   Tests Passed:           {}", if validation.tests_passed { "Yes".green() } else { "No".red() });
            if !validation.tests_passed && !validation.test_output.is_empty() {
                println!("   Test Details:           {}", validation.test_output.red());
            }
            println!("   Vulnerability Cleared:  {}", if validation.original_vulnerability_cleared { "Yes".green() } else { "No".red() });
            println!("   Security Score:         {} -> {}", format!("{}/100", validation.original_score).red(), format!("{}/100", validation.new_score).green().bold());
            println!("   Decision Rationale:     {}", validation.decision_rationale.bold());

            println!("\n{}", "=========================================================".cyan());
        }
    }

    Ok(())
}

fn print_report_banner(report: &secscan_core::models::ScanReport) {
    println!("\n{}", "=========================================================".cyan());
    println!(" {}", "SECSCAN - DETERMINISTIC CODE SECURITY ENGINE".bold().cyan());
    println!("{}\n", "=========================================================".cyan());

    println!("Repository:     {}", report.repository_path.yellow());
    println!("Files Scanned:  {}", report.files_scanned);
    println!("Lines Analyzed: {}", report.lines_analyzed);
    println!("Scan Duration:  {}ms", report.scan_duration_ms);

    let score_color = if report.security_score >= 80 {
        format!("{}/100", report.security_score).green()
    } else if report.security_score >= 50 {
        format!("{}/100", report.security_score).yellow()
    } else {
        format!("{}/100", report.security_score).red()
    };
    println!("Security Score: {}", score_color.bold());
    println!("---------------------------------------------------------");

    println!(
        "Critical: {} | High: {} | Medium: {} | Low: {}\n",
        report.severity_breakdown.get("CRITICAL").unwrap_or(&0).to_string().red().bold(),
        report.severity_breakdown.get("HIGH").unwrap_or(&0).to_string().magenta().bold(),
        report.severity_breakdown.get("MEDIUM").unwrap_or(&0).to_string().yellow(),
        report.severity_breakdown.get("LOW").unwrap_or(&0).to_string().blue()
    );

    if report.findings.is_empty() {
        println!("{}", "✔ No security vulnerabilities detected!".green().bold());
        return;
    }

    println!("{}", "DETAILED SECURITY FINDINGS:".bold().underline());

    for (i, finding) in report.findings.iter().enumerate() {
        let sev_label = match finding.severity {
            secscan_core::models::Severity::Critical => "[CRITICAL]".red().bold(),
            secscan_core::models::Severity::High => "[HIGH]".magenta().bold(),
            secscan_core::models::Severity::Medium => "[MEDIUM]".yellow().bold(),
            secscan_core::models::Severity::Low => "[LOW]".blue(),
            secscan_core::models::Severity::Info => "[INFO]".white(),
        };

        println!(
            "\n{}. {} {} - {}",
            i + 1,
            sev_label,
            finding.rule_name.bold(),
            format!("{}:{}", finding.file_path, finding.line).cyan()
        );
        println!("   Rule ID:    {}", finding.rule_id);
        println!("   Confidence: {:.0}%", finding.confidence * 100.0);

        if finding.source.is_some() || finding.sink.is_some() {
            println!("   {}", "Data-Flow Taint Graph:".bold());
            if let Some(ref src) = finding.source {
                println!("     [SOURCE]      L{}: {} ({})", src.line, src.variable.red(), src.description);
            }
            for prop in &finding.propagation {
                println!("        ↓");
                println!("     [PROPAGATION] L{}: {} ({})", prop.line, prop.variable.yellow(), prop.description);
            }
            if let Some(ref sink) = finding.sink {
                println!("        ↓");
                println!("     [SINK]        L{}: {} ({})", sink.line, sink.variable.red().bold(), sink.description);
            }
        }

        if !finding.code_snippet.is_empty() {
            println!("   Code Snippet: {}", finding.code_snippet.italic());
        }
        println!("   Remediation:  {}", finding.recommended_fix.green());
    }

    println!("\n{}", "=========================================================".cyan());
}
