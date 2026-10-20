use axum::{
    extract::Json,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use secscan_agent::AgentValidator;
use secscan_core::Scanner;
use secscan_nebius::NebiusClient;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use tower_http::cors::CorsLayer;

#[derive(Deserialize)]
struct ScanRequest {
    path: String,
}

#[derive(Deserialize)]
struct ActionRequest {
    path: String,
    rule_id: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    inference_provider: &'static str,
    recommended_model: &'static str,
    engine: &'static str,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/assets/logo.png", get(serve_logo))
        .route("/api/health", get(health_check))
        .route("/api/scan", post(handle_scan))
        .route("/api/explain", post(handle_explain))
        .route("/api/fix", post(handle_fix))
        .route("/api/verify", post(handle_verify))
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("\n=========================================================");
    println!(" SECSCAN WEB DASHBOARD & API SERVER");
    println!(" Powered by Rust Static Core + NVIDIA Nemotron on Nebius");
    println!(" Listening at http://localhost:3000");
    println!("=========================================================\n");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        inference_provider: "Nebius Token Factory",
        recommended_model: "nvidia/llama-3.1-nemotron-70b-instruct",
        engine: "SecScan Rust AST & Taint Core v1.0",
    })
}

async fn handle_scan(Json(req): Json<ScanRequest>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let path = PathBuf::from(&req.path);
    if !path.exists() {
        return Err((StatusCode::BAD_REQUEST, format!("Path not found: {}", req.path)));
    }

    let mut scanner = Scanner::new().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let report = scanner
        .scan_directory(&path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(report))
}

async fn handle_explain(Json(req): Json<ActionRequest>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let path = PathBuf::from(&req.path);
    let mut scanner = Scanner::new().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let report = scanner
        .scan_directory(&path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == req.rule_id || f.id == req.rule_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Finding not found".to_string()))?;

    let file_full = path.join(&finding.file_path);
    let file_context = fs::read_to_string(&file_full).unwrap_or_default();

    let nebius = NebiusClient::new();
    let explanation = nebius
        .explain_finding(finding, &file_context)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(explanation))
}

async fn handle_fix(Json(req): Json<ActionRequest>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let path = PathBuf::from(&req.path);
    let mut scanner = Scanner::new().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let report = scanner
        .scan_directory(&path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == req.rule_id || f.id == req.rule_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Finding not found".to_string()))?;

    let file_full = path.join(&finding.file_path);
    let file_context = fs::read_to_string(&file_full).unwrap_or_default();

    let nebius = NebiusClient::new();
    let patch = nebius
        .generate_patch(finding, &file_context)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(patch))
}

async fn handle_verify(Json(req): Json<ActionRequest>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let path = PathBuf::from(&req.path);
    let mut scanner = Scanner::new().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let report = scanner
        .scan_directory(&path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == req.rule_id || f.id == req.rule_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Finding not found".to_string()))?;

    let file_full = path.join(&finding.file_path);
    let file_context = fs::read_to_string(&file_full).unwrap_or_default();

    let nebius = NebiusClient::new();
    let patch = nebius
        .generate_patch(finding, &file_context)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let validation = AgentValidator::validate_patch(&path, finding, &patch, &report)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(validation))
}

async fn serve_dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn serve_logo() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/png")],
        include_bytes!("logo.png").as_slice(),
    )
}
