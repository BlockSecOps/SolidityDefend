pub mod server;
pub mod handlers;
pub mod websocket;
pub mod static_files;

pub use server::WebDashboard;
pub use handlers::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub port: u16,
    pub host: String,
    pub enable_real_time: bool,
    pub enable_websockets: bool,
    pub cors_origins: Vec<String>,
    pub static_files_path: Option<String>,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            host: "127.0.0.1".to_string(),
            enable_real_time: true,
            enable_websockets: true,
            cors_origins: vec!["http://localhost:3000".to_string()],
            static_files_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSession {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub project_path: String,
    pub analysis_results: Vec<AnalysisResult>,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionStatus {
    Active,
    Analyzing,
    Completed,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub id: Uuid,
    pub file_path: String,
    pub analysis_time: chrono::DateTime<chrono::Utc>,
    pub findings: Vec<SecurityFinding>,
    pub metrics: AnalysisMetrics,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub detector: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub end_column: Option<usize>,
    pub confidence: f64,
    pub suggested_fix: Option<String>,
    pub gas_impact: Option<String>,
    pub references: Vec<String>,
    pub cwe: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetrics {
    pub total_lines: usize,
    pub total_functions: usize,
    pub total_contracts: usize,
    pub analysis_time_ms: u64,
    pub complexity_score: f64,
    pub gas_estimation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardState {
    pub sessions: HashMap<Uuid, AnalysisSession>,
    pub active_session: Option<Uuid>,
    pub total_analyses: usize,
    pub total_findings: usize,
    pub server_stats: ServerStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub uptime: chrono::Duration,
    pub total_requests: usize,
    pub active_connections: usize,
    pub memory_usage: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            timestamp: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub message_type: MessageType,
    pub session_id: Option<Uuid>,
    pub data: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType {
    SessionUpdate,
    AnalysisProgress,
    NewFinding,
    Error,
    StatusUpdate,
}