use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use secscan_core::sarif::SarifExporter;
use secscan_core::Scanner;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "secscan")]
#[command(about = "AI-Powered Code Security Analyzer - Deterministic Static Analysis Core")]
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
        /// Target directory path to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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
                        return Ok(());
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

                        // If data-flow taint steps exist, print the graph
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
            }

            Ok(())
        }
    }
}
