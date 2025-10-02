use super::*;
use super::server::AppState;
use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub name: String,
    pub project_path: String,
}

#[derive(Deserialize)]
pub struct AnalyzeFileRequest {
    pub file_path: String,
    pub content: Option<String>,
}

#[derive(Deserialize)]
pub struct AnalyzeCodeRequest {
    pub code: String,
    pub filename: Option<String>,
}

#[derive(Deserialize)]
pub struct AnalyzeWorkspaceRequest {
    pub workspace_path: String,
    pub exclude_patterns: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct ExportQuery {
    pub format: Option<String>, // json, html, pdf, csv
}

// Main dashboard page
pub async fn serve_dashboard() -> impl IntoResponse {
    Html(include_str!("../../../web/dashboard.html"))
}

// Session management endpoints
pub async fn list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let dashboard_state = state.dashboard_state.read().unwrap();
    let sessions: Vec<&AnalysisSession> = dashboard_state.sessions.values().collect();

    Json(ApiResponse::success(sessions))
}

pub async fn create_session(
    State(state): State<AppState>,
    Json(request): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    let session_id = Uuid::new_v4();
    let session = AnalysisSession {
        id: session_id,
        name: request.name,
        created_at: chrono::Utc::now(),
        last_updated: chrono::Utc::now(),
        project_path: request.project_path,
        analysis_results: Vec::new(),
        status: SessionStatus::Active,
    };

    {
        let mut dashboard_state = state.dashboard_state.write().unwrap();
        dashboard_state.sessions.insert(session_id, session.clone());
        dashboard_state.active_session = Some(session_id);
    }

    // Broadcast update
    let message = WebSocketMessage {
        message_type: MessageType::SessionUpdate,
        session_id: Some(session_id),
        data: serde_json::to_value(&session).unwrap(),
        timestamp: chrono::Utc::now(),
    };
    broadcast_to_websockets(&state, message).await;

    Json(ApiResponse::success(session))
}

pub async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let dashboard_state = state.dashboard_state.read().unwrap();

    match dashboard_state.sessions.get(&id) {
        Some(session) => Json(ApiResponse::success(session.clone())),
        None => {
            drop(dashboard_state);
            (StatusCode::NOT_FOUND, Json(ApiResponse::error("Session not found".to_string()))).into_response()
        }
    }
}

pub async fn delete_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let removed = {
        let mut dashboard_state = state.dashboard_state.write().unwrap();
        dashboard_state.sessions.remove(&id).is_some()
    };

    if removed {
        let message = WebSocketMessage {
            message_type: MessageType::SessionUpdate,
            session_id: Some(id),
            data: serde_json::json!({"deleted": true}),
            timestamp: chrono::Utc::now(),
        };
        broadcast_to_websockets(&state, message).await;

        Json(ApiResponse::success("Session deleted"))
    } else {
        (StatusCode::NOT_FOUND, Json(ApiResponse::error("Session not found".to_string()))).into_response()
    }
}

pub async fn analyze_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let project_path = {
        let dashboard_state = state.dashboard_state.read().unwrap();
        match dashboard_state.sessions.get(&id) {
            Some(session) => session.project_path.clone(),
            None => return (StatusCode::NOT_FOUND, Json(ApiResponse::error("Session not found".to_string()))).into_response(),
        }
    };

    // Update session status to analyzing
    {
        let mut dashboard_state = state.dashboard_state.write().unwrap();
        if let Some(session) = dashboard_state.sessions.get_mut(&id) {
            session.status = SessionStatus::Analyzing;
            session.last_updated = chrono::Utc::now();
        }
    }

    // Broadcast status update
    let message = WebSocketMessage {
        message_type: MessageType::AnalysisProgress,
        session_id: Some(id),
        data: serde_json::json!({"status": "analyzing", "progress": 0}),
        timestamp: chrono::Utc::now(),
    };
    broadcast_to_websockets(&state, message).await;

    // Start analysis in background
    let state_clone = state.clone();
    tokio::spawn(async move {
        let result = perform_session_analysis(state_clone, id, project_path).await;

        // Update session with results
        {
            let mut dashboard_state = state_clone.dashboard_state.write().unwrap();
            if let Some(session) = dashboard_state.sessions.get_mut(&id) {
                match result {
                    Ok(analysis_result) => {
                        session.analysis_results.push(analysis_result);
                        session.status = SessionStatus::Completed;
                    }
                    Err(error) => {
                        session.status = SessionStatus::Error(error);
                    }
                }
                session.last_updated = chrono::Utc::now();
            }
        }

        // Broadcast completion
        let message = WebSocketMessage {
            message_type: MessageType::AnalysisProgress,
            session_id: Some(id),
            data: serde_json::json!({"status": "completed", "progress": 100}),
            timestamp: chrono::Utc::now(),
        };
        broadcast_to_websockets(&state_clone, message).await;
    });

    Json(ApiResponse::success("Analysis started"))
}

pub async fn get_session_findings(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let dashboard_state = state.dashboard_state.read().unwrap();

    match dashboard_state.sessions.get(&id) {
        Some(session) => {
            let all_findings: Vec<&SecurityFinding> = session.analysis_results
                .iter()
                .flat_map(|result| &result.findings)
                .collect();
            Json(ApiResponse::success(all_findings))
        }
        None => {
            drop(dashboard_state);
            (StatusCode::NOT_FOUND, Json(ApiResponse::error("Session not found".to_string()))).into_response()
        }
    }
}

pub async fn export_session_report(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ExportQuery>,
) -> impl IntoResponse {
    let dashboard_state = state.dashboard_state.read().unwrap();

    let session = match dashboard_state.sessions.get(&id) {
        Some(session) => session,
        None => {
            drop(dashboard_state);
            return (StatusCode::NOT_FOUND, Json(ApiResponse::error("Session not found".to_string()))).into_response();
        }
    };

    let format = query.format.as_deref().unwrap_or("json");

    match format {
        "json" => {
            let report = generate_json_report(session);
            Json(ApiResponse::success(report)).into_response()
        }
        "html" => {
            let report = generate_html_report(session);
            (
                StatusCode::OK,
                [("content-type", "text/html")],
                report
            ).into_response()
        }
        "csv" => {
            let report = generate_csv_report(session);
            (
                StatusCode::OK,
                [("content-type", "text/csv")],
                report
            ).into_response()
        }
        _ => {
            drop(dashboard_state);
            (StatusCode::BAD_REQUEST, Json(ApiResponse::error("Unsupported export format".to_string()))).into_response()
        }
    }
}

// Analysis endpoints
pub async fn analyze_file(
    State(state): State<AppState>,
    Json(request): Json<AnalyzeFileRequest>,
) -> impl IntoResponse {
    let content = match request.content {
        Some(content) => content,
        None => {
            match std::fs::read_to_string(&request.file_path) {
                Ok(content) => content,
                Err(e) => return Json(ApiResponse::error(format!("Failed to read file: {}", e))),
            }
        }
    };

    match perform_file_analysis(&state, &request.file_path, &content).await {
        Ok(findings) => Json(ApiResponse::success(findings)),
        Err(e) => Json(ApiResponse::error(e)),
    }
}

pub async fn analyze_code(
    State(state): State<AppState>,
    Json(request): Json<AnalyzeCodeRequest>,
) -> impl IntoResponse {
    let filename = request.filename.unwrap_or_else(|| "inline.sol".to_string());

    match perform_file_analysis(&state, &filename, &request.code).await {
        Ok(findings) => Json(ApiResponse::success(findings)),
        Err(e) => Json(ApiResponse::error(e)),
    }
}

pub async fn analyze_workspace(
    State(state): State<AppState>,
    Json(request): Json<AnalyzeWorkspaceRequest>,
) -> impl IntoResponse {
    match perform_workspace_analysis(&state, &request.workspace_path, request.exclude_patterns).await {
        Ok(results) => Json(ApiResponse::success(results)),
        Err(e) => Json(ApiResponse::error(e)),
    }
}

// Stats and metrics
pub async fn get_server_stats(State(state): State<AppState>) -> impl IntoResponse {
    let dashboard_state = state.dashboard_state.read().unwrap();
    Json(ApiResponse::success(&dashboard_state.server_stats))
}

pub async fn get_analysis_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let dashboard_state = state.dashboard_state.read().unwrap();

    let total_findings = dashboard_state.sessions.values()
        .map(|session| session.analysis_results.iter()
            .map(|result| result.findings.len())
            .sum::<usize>())
        .sum::<usize>();

    let severity_breakdown: HashMap<&str, usize> = dashboard_state.sessions.values()
        .flat_map(|session| &session.analysis_results)
        .flat_map(|result| &result.findings)
        .fold(HashMap::new(), |mut acc, finding| {
            let severity = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            *acc.entry(severity).or_insert(0) += 1;
            acc
        });

    let metrics = serde_json::json!({
        "total_sessions": dashboard_state.sessions.len(),
        "total_findings": total_findings,
        "severity_breakdown": severity_breakdown,
        "active_sessions": dashboard_state.sessions.values()
            .filter(|s| matches!(s.status, SessionStatus::Active | SessionStatus::Analyzing))
            .count(),
    });

    Json(ApiResponse::success(metrics))
}

// WebSocket handler
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

async fn handle_websocket(
    socket: axum::extract::ws::WebSocket,
    state: AppState,
) {
    use axum::extract::ws::{Message, WebSocket};
    use futures_util::{sink::SinkExt, stream::StreamExt};

    let (mut sender, mut receiver) = socket.split();
    let connection_id = Uuid::new_v4();

    // Create channel for this connection
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Store connection
    {
        let mut connections = state.websocket_connections.write().unwrap();
        connections.insert(connection_id, tx);
    }

    // Send initial state
    let dashboard_state = state.dashboard_state.read().unwrap();
    let initial_message = WebSocketMessage {
        message_type: MessageType::StatusUpdate,
        session_id: None,
        data: serde_json::to_value(&*dashboard_state).unwrap(),
        timestamp: chrono::Utc::now(),
    };
    drop(dashboard_state);

    if let Ok(msg) = serde_json::to_string(&initial_message) {
        let _ = sender.send(Message::Text(msg)).await;
    }

    // Handle incoming messages
    let state_clone = state.clone();
    let receive_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = receiver.next().await {
            // Handle client messages (if needed)
            if let Ok(client_message) = serde_json::from_str::<serde_json::Value>(&text) {
                // Process client requests here
                println!("Received client message: {}", client_message);
            }
        }
    });

    // Handle outgoing messages
    let send_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if sender.send(Message::Text(message)).await.is_err() {
                break;
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = receive_task => {},
        _ = send_task => {},
    }

    // Clean up connection
    {
        let mut connections = state.websocket_connections.write().unwrap();
        connections.remove(&connection_id);
    }
}

// Helper functions
async fn perform_session_analysis(
    state: AppState,
    session_id: Uuid,
    project_path: String,
) -> Result<AnalysisResult, String> {
    // Placeholder implementation
    // In real implementation, this would use the analysis engine

    let findings = vec![
        SecurityFinding {
            id: "example_1".to_string(),
            detector: "reentrancy".to_string(),
            severity: Severity::High,
            title: "Potential reentrancy vulnerability".to_string(),
            description: "This function may be vulnerable to reentrancy attacks".to_string(),
            file_path: format!("{}/example.sol", project_path),
            line: 42,
            column: 8,
            end_line: Some(45),
            end_column: Some(12),
            confidence: 0.85,
            suggested_fix: Some("Add nonReentrant modifier".to_string()),
            gas_impact: Some("Medium".to_string()),
            references: vec!["https://consensys.github.io/smart-contract-best-practices/".to_string()],
            cwe: vec!["CWE-682".to_string()],
            tags: vec!["reentrancy".to_string(), "external-call".to_string()],
        }
    ];

    let metrics = AnalysisMetrics {
        total_lines: 150,
        total_functions: 8,
        total_contracts: 2,
        analysis_time_ms: 1250,
        complexity_score: 3.2,
        gas_estimation: Some(450000),
    };

    Ok(AnalysisResult {
        id: Uuid::new_v4(),
        file_path: project_path,
        analysis_time: chrono::Utc::now(),
        findings,
        metrics,
        risk_score: 65.5,
    })
}

async fn perform_file_analysis(
    state: &AppState,
    file_path: &str,
    content: &str,
) -> Result<Vec<SecurityFinding>, String> {
    // Placeholder implementation
    Ok(vec![])
}

async fn perform_workspace_analysis(
    state: &AppState,
    workspace_path: &str,
    exclude_patterns: Option<Vec<String>>,
) -> Result<Vec<AnalysisResult>, String> {
    // Placeholder implementation
    Ok(vec![])
}

async fn broadcast_to_websockets(state: &AppState, message: WebSocketMessage) {
    let message_str = serde_json::to_string(&message).unwrap();
    let connections = state.websocket_connections.read().unwrap();

    for (_, sender) in connections.iter() {
        let _ = sender.send(message_str.clone());
    }
}

fn generate_json_report(session: &AnalysisSession) -> serde_json::Value {
    serde_json::to_value(session).unwrap()
}

fn generate_html_report(session: &AnalysisSession) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .finding {{ border-left: 4px solid #dc3545; margin: 15px 0; padding: 15px; background: #f8f9fa; }}
        .severity-critical {{ border-color: #dc3545; }}
        .severity-high {{ border-color: #fd7e14; }}
        .severity-medium {{ border-color: #ffc107; }}
        .severity-low {{ border-color: #28a745; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Analysis Report</h1>
        <p><strong>Session:</strong> {}</p>
        <p><strong>Project:</strong> {}</p>
        <p><strong>Generated:</strong> {}</p>
    </div>

    <h2>Summary</h2>
    <p>Total findings: {}</p>

    <h2>Findings</h2>
    {}
</body>
</html>
        "#,
        session.name,
        session.name,
        session.project_path,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        session.analysis_results.iter().map(|r| r.findings.len()).sum::<usize>(),
        session.analysis_results.iter()
            .flat_map(|r| &r.findings)
            .map(|f| format!(
                r#"<div class="finding severity-{}">
                    <h3>{}</h3>
                    <p><strong>File:</strong> {}:{}</p>
                    <p><strong>Severity:</strong> {:?}</p>
                    <p>{}</p>
                </div>"#,
                format!("{:?}", f.severity).to_lowercase(),
                f.title,
                f.file_path,
                f.line,
                f.severity,
                f.description
            ))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn generate_csv_report(session: &AnalysisSession) -> String {
    let mut csv = "File,Line,Severity,Detector,Title,Description\n".to_string();

    for result in &session.analysis_results {
        for finding in &result.findings {
            csv.push_str(&format!(
                "{},{},{:?},{},{},{}\n",
                finding.file_path,
                finding.line,
                finding.severity,
                finding.detector,
                finding.title.replace(',', ";"),
                finding.description.replace(',', ";")
            ));
        }
    }

    csv
}