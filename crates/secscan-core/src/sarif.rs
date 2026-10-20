use crate::models::{Finding, ScanReport, Severity};
use serde_json::{json, Value};

pub struct SarifExporter;

impl SarifExporter {
    pub fn to_sarif(report: &ScanReport) -> Value {
        let results: Vec<Value> = report
            .findings
            .iter()
            .map(|f| {
                let level = match f.severity {
                    Severity::Critical | Severity::High => "error",
                    Severity::Medium => "warning",
                    Severity::Low | Severity::Info => "note",
                };

                let mut result = json!({
                    "ruleId": f.rule_id,
                    "level": level,
                    "message": {
                        "text": format!("{}: {}", f.rule_name, f.recommended_fix)
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file_path
                            },
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column
                            }
                        }
                    }]
                });

                // If data-flow graph exists, add codeFlows to SARIF
                if f.source.is_some() || !f.propagation.is_empty() || f.sink.is_some() {
                    let mut thread_flow_locations = Vec::new();

                    if let Some(ref src) = f.source {
                        thread_flow_locations.push(json!({
                            "location": {
                                "message": { "text": src.description },
                                "physicalLocation": {
                                    "artifactLocation": { "uri": f.file_path },
                                    "region": { "startLine": src.line, "startColumn": src.column }
                                }
                            }
                        }));
                    }

                    for prop in &f.propagation {
                        thread_flow_locations.push(json!({
                            "location": {
                                "message": { "text": prop.description },
                                "physicalLocation": {
                                    "artifactLocation": { "uri": f.file_path },
                                    "region": { "startLine": prop.line, "startColumn": prop.column }
                                }
                            }
                        }));
                    }

                    if let Some(ref sink) = f.sink {
                        thread_flow_locations.push(json!({
                            "location": {
                                "message": { "text": sink.description },
                                "physicalLocation": {
                                    "artifactLocation": { "uri": f.file_path },
                                    "region": { "startLine": sink.line, "startColumn": sink.column }
                                }
                            }
                        }));
                    }

                    result["codeFlows"] = json!([{
                        "threadFlows": [{
                            "locations": thread_flow_locations
                        }]
                    }]);
                }

                result
            })
            .collect();

        json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SecScan-Rust",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/secscan-ai/secscan",
                        "rules": [
                            { "id": "SEC-001", "name": "SQL Injection" },
                            { "id": "SEC-002", "name": "Command Injection" },
                            { "id": "SEC-003", "name": "Path Traversal" },
                            { "id": "SEC-004", "name": "Hard-coded Secret / Credential" },
                            { "id": "SEC-005", "name": "Weak Cryptographic Hash" },
                            { "id": "SEC-006", "name": "Insecure Randomness" },
                            { "id": "SEC-008", "name": "Vulnerable Dependency" }
                        ]
                    }
                },
                "results": results
            }]
        })
    }
}
