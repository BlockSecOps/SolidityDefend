use super::*;
use crate::analysis::AnalysisEngine;
use crate::detectors::DetectorEngine;
use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use uuid::Uuid;

pub struct WebDashboard {
    config: DashboardConfig,
    state: Arc<RwLock<DashboardState>>,
    analysis_engine: Arc<AnalysisEngine>,
    detector_engine: Arc<DetectorEngine>,
    websocket_connections: Arc<RwLock<HashMap<Uuid, tokio::sync::mpsc::UnboundedSender<String>>>>,
}

impl WebDashboard {
    pub fn new(config: DashboardConfig) -> Self {
        let state = Arc::new(RwLock::new(DashboardState {
            sessions: HashMap::new(),
            active_session: None,
            total_analyses: 0,
            total_findings: 0,
            server_stats: ServerStats {
                uptime: chrono::Duration::zero(),
                total_requests: 0,
                active_connections: 0,
                memory_usage: 0,
            },
        }));

        Self {
            config,
            state,
            analysis_engine: Arc::new(AnalysisEngine::new()),
            detector_engine: Arc::new(DetectorEngine::new()),
            websocket_connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = self.create_router();

        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await?;

        println!("SolidityDefend Web Dashboard starting on http://{}", addr);
        println!("Dashboard features:");
        println!("  - Real-time analysis visualization");
        println!("  - Interactive security reports");
        println!("  - WebSocket support for live updates");
        println!("  - REST API for programmatic access");

        axum::serve(listener, app).await?;

        Ok(())
    }

    fn create_router(&self) -> Router {
        let shared_state = AppState {
            dashboard_state: self.state.clone(),
            analysis_engine: self.analysis_engine.clone(),
            detector_engine: self.detector_engine.clone(),
            websocket_connections: self.websocket_connections.clone(),
        };

        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let mut router = Router::new()
            // Main dashboard page
            .route("/", get(serve_dashboard))

            // API endpoints
            .route("/api/sessions", get(list_sessions).post(create_session))
            .route("/api/sessions/:id", get(get_session).delete(delete_session))
            .route("/api/sessions/:id/analyze", post(analyze_session))
            .route("/api/sessions/:id/findings", get(get_session_findings))
            .route("/api/sessions/:id/export", get(export_session_report))

            // Analysis endpoints
            .route("/api/analyze/file", post(analyze_file))
            .route("/api/analyze/code", post(analyze_code))
            .route("/api/analyze/workspace", post(analyze_workspace))

            // Metrics and stats
            .route("/api/stats", get(get_server_stats))
            .route("/api/metrics", get(get_analysis_metrics))

            // WebSocket endpoint
            .route("/ws", get(websocket_handler))

            .layer(ServiceBuilder::new().layer(cors))
            .with_state(shared_state);

        // Serve static files if path is configured
        if let Some(static_path) = &self.config.static_files_path {
            router = router.nest_service("/static", ServeDir::new(static_path));
        }

        router
    }

    pub async fn create_session(&self, name: String, project_path: String) -> Result<Uuid, String> {
        let session_id = Uuid::new_v4();
        let session = AnalysisSession {
            id: session_id,
            name,
            created_at: chrono::Utc::now(),
            last_updated: chrono::Utc::now(),
            project_path,
            analysis_results: Vec::new(),
            status: SessionStatus::Active,
        };

        {
            let mut state = self.state.write().unwrap();
            state.sessions.insert(session_id, session);
            state.active_session = Some(session_id);
        }

        self.broadcast_state_update().await;
        Ok(session_id)
    }

    pub async fn analyze_session(&self, session_id: Uuid) -> Result<(), String> {
        let project_path = {
            let state = self.state.read().unwrap();
            state.sessions.get(&session_id)
                .map(|s| s.project_path.clone())
                .ok_or_else(|| "Session not found".to_string())?
        };

        // Update session status
        {
            let mut state = self.state.write().unwrap();
            if let Some(session) = state.sessions.get_mut(&session_id) {
                session.status = SessionStatus::Analyzing;
                session.last_updated = chrono::Utc::now();
            }
        }

        self.broadcast_session_update(session_id).await;

        // Perform analysis in background
        let analysis_engine = self.analysis_engine.clone();
        let detector_engine = self.detector_engine.clone();
        let state = self.state.clone();
        let connections = self.websocket_connections.clone();

        tokio::spawn(async move {
            let result = Self::perform_analysis(
                analysis_engine,
                detector_engine,
                &project_path,
                session_id,
                state.clone(),
                connections.clone(),
            ).await;

            // Update session with results
            {
                let mut state_guard = state.write().unwrap();
                if let Some(session) = state_guard.sessions.get_mut(&session_id) {
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

            // Broadcast final update
            Self::broadcast_session_update_static(session_id, connections).await;
        });

        Ok(())
    }

    async fn perform_analysis(
        analysis_engine: Arc<AnalysisEngine>,
        detector_engine: Arc<DetectorEngine>,
        project_path: &str,
        session_id: Uuid,
        state: Arc<RwLock<DashboardState>>,
        connections: Arc<RwLock<HashMap<Uuid, tokio::sync::mpsc::UnboundedSender<String>>>>,
    ) -> Result<AnalysisResult, String> {
        // Find Solidity files in project
        let solidity_files = Self::find_solidity_files(project_path)?;

        let mut all_findings = Vec::new();
        let start_time = std::time::Instant::now();

        for file_path in solidity_files {
            // Read file content
            let content = std::fs::read_to_string(&file_path)
                .map_err(|e| format!("Failed to read file {}: {}", file_path, e))?;

            // Parse and analyze
            let ast = analysis_engine.parse(&content)
                .map_err(|e| format!("Parse error in {}: {}", file_path, e))?;

            let findings = detector_engine.analyze(&ast, &content);

            // Convert findings to dashboard format
            for finding in findings {
                let dashboard_finding = SecurityFinding {
                    id: format!("{}_{}", finding.detector_id, finding.location.line),
                    detector: finding.detector_id,
                    severity: match finding.severity.as_str() {
                        "Critical" => Severity::Critical,
                        "High" => Severity::High,
                        "Medium" => Severity::Medium,
                        "Low" => Severity::Low,
                        _ => Severity::Info,
                    },
                    title: finding.message.clone(),
                    description: finding.description.unwrap_or(finding.message),
                    file_path: file_path.clone(),
                    line: finding.location.line,
                    column: finding.location.column,
                    end_line: finding.location.end_line,
                    end_column: finding.location.end_column,
                    confidence: finding.confidence,
                    suggested_fix: finding.suggested_fix,
                    gas_impact: finding.gas_impact,
                    references: finding.references.unwrap_or_default(),
                    cwe: finding.cwe.map(|c| vec![c.to_string()]).unwrap_or_default(),
                    tags: finding.tags.unwrap_or_default(),
                };

                all_findings.push(dashboard_finding.clone());

                // Broadcast new finding in real-time
                let message = WebSocketMessage {
                    message_type: MessageType::NewFinding,
                    session_id: Some(session_id),
                    data: serde_json::to_value(&dashboard_finding).unwrap(),
                    timestamp: chrono::Utc::now(),
                };

                Self::broadcast_websocket_message_static(connections.clone(), message).await;
            }
        }

        let analysis_time = start_time.elapsed();

        // Calculate metrics
        let metrics = AnalysisMetrics {
            total_lines: 0, // Would calculate from actual analysis
            total_functions: 0, // Would extract from AST
            total_contracts: 0, // Would extract from AST
            analysis_time_ms: analysis_time.as_millis() as u64,
            complexity_score: 0.0, // Would calculate based on analysis
            gas_estimation: None,
        };

        // Calculate risk score
        let risk_score = Self::calculate_risk_score(&all_findings);

        Ok(AnalysisResult {
            id: Uuid::new_v4(),
            file_path: project_path.to_string(),
            analysis_time: chrono::Utc::now(),
            findings: all_findings,
            metrics,
            risk_score,
        })
    }

    fn find_solidity_files(project_path: &str) -> Result<Vec<String>, String> {
        let mut files = Vec::new();

        fn visit_dir(dir: &std::path::Path, files: &mut Vec<String>) -> std::io::Result<()> {
            if dir.is_dir() {
                for entry in std::fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        visit_dir(&path, files)?;
                    } else if let Some(extension) = path.extension() {
                        if extension == "sol" {
                            if let Some(path_str) = path.to_str() {
                                files.push(path_str.to_string());
                            }
                        }
                    }
                }
            }
            Ok(())
        }

        visit_dir(std::path::Path::new(project_path), &mut files)
            .map_err(|e| format!("Failed to scan directory: {}", e))?;

        Ok(files)
    }

    fn calculate_risk_score(findings: &[SecurityFinding]) -> f64 {
        let mut score = 0.0;
        for finding in findings {
            let severity_weight = match finding.severity {
                Severity::Critical => 10.0,
                Severity::High => 5.0,
                Severity::Medium => 2.0,
                Severity::Low => 1.0,
                Severity::Info => 0.1,
            };
            score += severity_weight * finding.confidence;
        }
        (score / 10.0).min(100.0)
    }

    async fn broadcast_state_update(&self) {
        let state = {
            let state = self.state.read().unwrap();
            state.clone()
        };

        let message = WebSocketMessage {
            message_type: MessageType::StatusUpdate,
            session_id: None,
            data: serde_json::to_value(&state).unwrap(),
            timestamp: chrono::Utc::now(),
        };

        self.broadcast_websocket_message(message).await;
    }

    async fn broadcast_session_update(&self, session_id: Uuid) {
        Self::broadcast_session_update_static(session_id, self.websocket_connections.clone()).await;
    }

    async fn broadcast_session_update_static(
        session_id: Uuid,
        connections: Arc<RwLock<HashMap<Uuid, tokio::sync::mpsc::UnboundedSender<String>>>>
    ) {
        let message = WebSocketMessage {
            message_type: MessageType::SessionUpdate,
            session_id: Some(session_id),
            data: serde_json::json!({"session_id": session_id}),
            timestamp: chrono::Utc::now(),
        };

        Self::broadcast_websocket_message_static(connections, message).await;
    }

    async fn broadcast_websocket_message(&self, message: WebSocketMessage) {
        Self::broadcast_websocket_message_static(self.websocket_connections.clone(), message).await;
    }

    async fn broadcast_websocket_message_static(
        connections: Arc<RwLock<HashMap<Uuid, tokio::sync::mpsc::UnboundedSender<String>>>>,
        message: WebSocketMessage
    ) {
        let message_str = serde_json::to_string(&message).unwrap();
        let connections = connections.read().unwrap();

        for (_, sender) in connections.iter() {
            let _ = sender.send(message_str.clone());
        }
    }
}

#[derive(Clone)]
struct AppState {
    dashboard_state: Arc<RwLock<DashboardState>>,
    analysis_engine: Arc<AnalysisEngine>,
    detector_engine: Arc<DetectorEngine>,
    websocket_connections: Arc<RwLock<HashMap<Uuid, tokio::sync::mpsc::UnboundedSender<String>>>>,
}

// Placeholder implementations for missing types
mod placeholders {
    pub struct AnalysisEngine;
    impl AnalysisEngine {
        pub fn new() -> Self { Self }
        pub fn parse(&self, _content: &str) -> Result<crate::ast::SourceUnit, String> {
            Err("Not implemented".to_string())
        }
    }
}

use placeholders::*;