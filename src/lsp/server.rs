use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tower_lsp::jsonrpc::{Error, Result};
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

/// LSP server implementation for SolidityDefend
/// Provides real-time security analysis integration for IDEs

#[derive(Debug)]
pub struct SolidityDefendLsp {
    client: Client,
    document_map: Arc<RwLock<HashMap<Url, DocumentState>>>,
    workspace_root: Arc<RwLock<Option<PathBuf>>>,
    config: Arc<RwLock<LspConfig>>,
    analyzer: Arc<SecurityAnalyzer>,
    diagnostics_sender: mpsc::UnboundedSender<DiagnosticUpdate>,
}

#[derive(Debug, Clone)]
struct DocumentState {
    uri: Url,
    text: String,
    version: i32,
    language_id: String,
    last_analysis: Option<AnalysisResult>,
}

#[derive(Debug, Clone)]
struct LspConfig {
    enable_real_time_analysis: bool,
    analysis_delay_ms: u64,
    max_diagnostics_per_file: usize,
    enable_quick_fixes: bool,
    enable_hover_info: bool,
    detector_configuration: DetectorConfig,
}

impl Default for LspConfig {
    fn default() -> Self {
        Self {
            enable_real_time_analysis: true,
            analysis_delay_ms: 500,
            max_diagnostics_per_file: 100,
            enable_quick_fixes: true,
            enable_hover_info: true,
            detector_configuration: DetectorConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct DetectorConfig {
    enabled_detectors: Vec<String>,
    severity_filter: Option<DiagnosticSeverity>,
    exclude_patterns: Vec<String>,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            enabled_detectors: vec![
                "reentrancy".to_string(),
                "missing-access-control".to_string(),
                "dangerous-selfdestruct".to_string(),
                "unchecked-return-value".to_string(),
            ],
            severity_filter: None,
            exclude_patterns: vec!["test/**".to_string(), "mock/**".to_string()],
        }
    }
}

#[derive(Debug)]
struct SecurityAnalyzer {
    // This will fail until security analysis is implemented
}

impl SecurityAnalyzer {
    fn new() -> Self {
        Self {}
    }

    async fn analyze_document(&self, _document: &DocumentState) -> Result<AnalysisResult> {
        // This will fail until analysis is implemented
        Err(Error::method_not_found())
    }

    async fn get_hover_info(&self, _document: &DocumentState, _position: Position) -> Result<Option<Hover>> {
        // This will fail until hover info is implemented
        Err(Error::method_not_found())
    }

    async fn get_code_actions(&self, _document: &DocumentState, _range: Range, _context: &CodeActionContext) -> Result<Vec<CodeActionOrCommand>> {
        // This will fail until code actions are implemented
        Err(Error::method_not_found())
    }
}

#[derive(Debug, Clone)]
struct AnalysisResult {
    diagnostics: Vec<Diagnostic>,
    symbols: Vec<DocumentSymbol>,
    analysis_time_ms: u64,
}

#[derive(Debug)]
struct DiagnosticUpdate {
    uri: Url,
    version: Option<i32>,
    diagnostics: Vec<Diagnostic>,
}

impl SolidityDefendLsp {
    pub fn new(client: Client) -> Self {
        let (diagnostics_sender, mut diagnostics_receiver) = mpsc::unbounded_channel();

        // Spawn background task for handling diagnostics
        let client_clone = client.clone();
        tokio::spawn(async move {
            while let Some(update) = diagnostics_receiver.recv().await {
                let params = PublishDiagnosticsParams {
                    uri: update.uri,
                    version: update.version,
                    diagnostics: update.diagnostics,
                };
                let _ = client_clone.publish_diagnostics(params).await;
            }
        });

        Self {
            client,
            document_map: Arc::new(RwLock::new(HashMap::new())),
            workspace_root: Arc::new(RwLock::new(None)),
            config: Arc::new(RwLock::new(LspConfig::default())),
            analyzer: Arc::new(SecurityAnalyzer::new()),
            diagnostics_sender,
        }
    }

    async fn analyze_document_async(&self, uri: Url) -> Result<()> {
        let document = {
            let docs = self.document_map.read().unwrap();
            docs.get(&uri).cloned()
        };

        if let Some(doc) = document {
            // This will fail until analysis is implemented
            match self.analyzer.analyze_document(&doc).await {
                Ok(result) => {
                    // Update document state with analysis result
                    {
                        let mut docs = self.document_map.write().unwrap();
                        if let Some(doc_state) = docs.get_mut(&uri) {
                            doc_state.last_analysis = Some(result.clone());
                        }
                    }

                    // Send diagnostics
                    let update = DiagnosticUpdate {
                        uri,
                        version: Some(doc.version),
                        diagnostics: result.diagnostics,
                    };

                    let _ = self.diagnostics_sender.send(update);
                }
                Err(e) => {
                    // Log error and send empty diagnostics
                    let update = DiagnosticUpdate {
                        uri,
                        version: Some(doc.version),
                        diagnostics: vec![],
                    };

                    let _ = self.diagnostics_sender.send(update);
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    fn schedule_analysis(&self, uri: Url) {
        let analyzer = self.analyzer.clone();
        let sender = self.diagnostics_sender.clone();
        let document_map = self.document_map.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            // Add delay for debouncing
            let delay_ms = config.read().unwrap().analysis_delay_ms;
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

            // This will fail until analysis is implemented
            // The actual implementation would analyze the document here
        });
    }

    fn is_solidity_file(&self, uri: &Url) -> bool {
        if let Some(path) = uri.to_file_path().ok() {
            if let Some(extension) = path.extension() {
                return extension == "sol";
            }
        }
        false
    }

    fn should_analyze_file(&self, uri: &Url) -> bool {
        if !self.is_solidity_file(uri) {
            return false;
        }

        let config = self.config.read().unwrap();
        let path = uri.path();

        // Check exclude patterns
        for pattern in &config.detector_configuration.exclude_patterns {
            if path.contains(pattern) {
                return false;
            }
        }

        true
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for SolidityDefendLsp {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        // Store workspace root
        if let Some(uri) = params.root_uri {
            if let Ok(path) = uri.to_file_path() {
                *self.workspace_root.write().unwrap() = Some(path);
            }
        }

        // This will fail until LSP capabilities are properly implemented
        Err(Error::method_not_found())

        #[allow(unreachable_code)]
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::INCREMENTAL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                workspace_symbol_provider: Some(OneOf::Left(true)),
                diagnostic_provider: Some(DiagnosticServerCapabilities::Options(
                    DiagnosticOptions {
                        identifier: Some("soliditydefend".to_string()),
                        inter_file_dependencies: true,
                        workspace_diagnostics: true,
                        work_done_progress_options: WorkDoneProgressOptions::default(),
                    },
                )),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "SolidityDefend LSP".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "SolidityDefend LSP server initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) -> Result<()> {
        let uri = params.text_document.uri.clone();

        // Store document state
        {
            let mut docs = self.document_map.write().unwrap();
            docs.insert(
                uri.clone(),
                DocumentState {
                    uri: uri.clone(),
                    text: params.text_document.text,
                    version: params.text_document.version,
                    language_id: params.text_document.language_id,
                    last_analysis: None,
                },
            );
        }

        // Schedule analysis if applicable
        if self.should_analyze_file(&uri) {
            // This will fail until analysis scheduling is implemented
            return Err(Error::method_not_found());
        }

        Ok(())
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) -> Result<()> {
        let uri = params.text_document.uri.clone();

        // Update document state
        {
            let mut docs = self.document_map.write().unwrap();
            if let Some(doc) = docs.get_mut(&uri) {
                // Apply changes
                for change in params.content_changes {
                    if let Some(range) = change.range {
                        // Incremental change - this would need proper text manipulation
                        // For now, just replace the entire content
                        doc.text = change.text;
                    } else {
                        // Full document change
                        doc.text = change.text;
                    }
                }
                doc.version = params.text_document.version;
                doc.last_analysis = None; // Invalidate previous analysis
            }
        }

        // Schedule re-analysis
        if self.should_analyze_file(&uri) {
            // This will fail until analysis scheduling is implemented
            return Err(Error::method_not_found());
        }

        Ok(())
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) -> Result<()> {
        // Remove document from memory
        {
            let mut docs = self.document_map.write().unwrap();
            docs.remove(&params.text_document.uri);
        }

        // Clear diagnostics
        let update = DiagnosticUpdate {
            uri: params.text_document.uri,
            version: None,
            diagnostics: vec![],
        };

        let _ = self.diagnostics_sender.send(update);

        Ok(())
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        let document = {
            let docs = self.document_map.read().unwrap();
            docs.get(&uri).cloned()
        };

        if let Some(doc) = document {
            // This will fail until hover implementation is ready
            return self.analyzer.get_hover_info(&doc, position).await;
        }

        Ok(None)
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let uri = params.text_document.uri;
        let range = params.range;
        let context = params.context;

        let document = {
            let docs = self.document_map.read().unwrap();
            docs.get(&uri).cloned()
        };

        if let Some(doc) = document {
            // This will fail until code actions are implemented
            let actions = self.analyzer.get_code_actions(&doc, range, &context).await?;
            return Ok(Some(actions));
        }

        Ok(None)
    }

    async fn document_symbol(&self, params: DocumentSymbolParams) -> Result<Option<DocumentSymbolResponse>> {
        let uri = params.text_document.uri;

        let document = {
            let docs = self.document_map.read().unwrap();
            docs.get(&uri).cloned()
        };

        if let Some(doc) = document {
            if let Some(analysis) = &doc.last_analysis {
                return Ok(Some(DocumentSymbolResponse::Nested(analysis.symbols.clone())));
            }
        }

        // This will fail until symbol extraction is implemented
        Err(Error::method_not_found())
    }

    async fn workspace_symbol(&self, params: WorkspaceSymbolParams) -> Result<Option<Vec<SymbolInformation>>> {
        // This will fail until workspace symbol search is implemented
        Err(Error::method_not_found())
    }

    async fn diagnostic(&self, params: DocumentDiagnosticParams) -> Result<DocumentDiagnosticReportResult> {
        let uri = params.text_document.uri;

        let document = {
            let docs = self.document_map.read().unwrap();
            docs.get(&uri).cloned()
        };

        if let Some(doc) = document {
            if let Some(analysis) = &doc.last_analysis {
                return Ok(DocumentDiagnosticReportResult::Report(
                    DocumentDiagnosticReport::Full(RelatedFullDocumentDiagnosticReport {
                        related_documents: None,
                        full_document_diagnostic_report: FullDocumentDiagnosticReport {
                            result_id: None,
                            items: analysis.diagnostics.clone(),
                        },
                    }),
                ));
            }
        }

        // This will fail until diagnostic generation is implemented
        Err(Error::method_not_found())
    }
}

/// LSP server builder for configuration
pub struct LspServerBuilder {
    config: LspConfig,
}

impl LspServerBuilder {
    pub fn new() -> Self {
        Self {
            config: LspConfig::default(),
        }
    }

    pub fn with_real_time_analysis(mut self, enabled: bool) -> Self {
        self.config.enable_real_time_analysis = enabled;
        self
    }

    pub fn with_analysis_delay(mut self, delay_ms: u64) -> Self {
        self.config.analysis_delay_ms = delay_ms;
        self
    }

    pub fn with_detector_config(mut self, config: DetectorConfig) -> Self {
        self.config.detector_configuration = config;
        self
    }

    pub fn build(self) -> Result<(LspService<SolidityDefendLsp>, tokio::net::TcpListener)> {
        // This will fail until LSP service creation is implemented
        Err(Error::method_not_found())
    }

    pub async fn run_stdio(self) -> Result<()> {
        // This will fail until stdio server is implemented
        Err(Error::method_not_found())
    }

    pub async fn run_tcp(self, addr: &str) -> Result<()> {
        // This will fail until TCP server is implemented
        Err(Error::method_not_found())
    }
}

impl Default for LspServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for LSP server
pub mod utils {
    use super::*;

    /// Convert SolidityDefend severity to LSP diagnostic severity
    pub fn severity_to_diagnostic_severity(severity: &str) -> DiagnosticSeverity {
        match severity.to_lowercase().as_str() {
            "critical" => DiagnosticSeverity::ERROR,
            "high" => DiagnosticSeverity::ERROR,
            "medium" => DiagnosticSeverity::WARNING,
            "low" => DiagnosticSeverity::INFORMATION,
            "info" => DiagnosticSeverity::HINT,
            _ => DiagnosticSeverity::WARNING,
        }
    }

    /// Create a diagnostic from finding
    pub fn create_diagnostic_from_finding(finding: &Finding) -> Diagnostic {
        Diagnostic {
            range: Range {
                start: Position {
                    line: finding.line as u32,
                    character: finding.column as u32,
                },
                end: Position {
                    line: finding.line as u32,
                    character: (finding.column + finding.length) as u32,
                },
            },
            severity: Some(severity_to_diagnostic_severity(&finding.severity)),
            code: Some(NumberOrString::String(finding.detector_id.clone())),
            code_description: finding.cwe.map(|cwe| CodeDescription {
                href: Url::parse(&format!("https://cwe.mitre.org/data/definitions/{}.html", cwe))
                    .unwrap(),
            }),
            source: Some("SolidityDefend".to_string()),
            message: finding.message.clone(),
            related_information: None,
            tags: None,
            data: None,
        }
    }

    /// Extract position from line and column
    pub fn extract_position_info(text: &str, line: u32, character: u32) -> Option<String> {
        let lines: Vec<&str> = text.lines().collect();
        if let Some(target_line) = lines.get(line as usize) {
            if let Some(char_at_pos) = target_line.chars().nth(character as usize) {
                return Some(char_at_pos.to_string());
            }
        }
        None
    }
}

/// Placeholder types until proper integration
#[derive(Debug, Clone)]
pub struct Finding {
    pub detector_id: String,
    pub message: String,
    pub severity: String,
    pub line: usize,
    pub column: usize,
    pub length: usize,
    pub cwe: Option<u32>,
}

/// Errors specific to LSP server
#[derive(Debug, thiserror::Error)]
pub enum LspServerError {
    #[error("Server not implemented: {0}")]
    NotImplemented(String),

    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON-RPC error: {0}")]
    JsonRpcError(#[from] tower_lsp::jsonrpc::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsp_config_defaults() {
        let config = LspConfig::default();

        assert!(config.enable_real_time_analysis);
        assert_eq!(config.analysis_delay_ms, 500);
        assert_eq!(config.max_diagnostics_per_file, 100);
        assert!(config.enable_quick_fixes);
        assert!(config.enable_hover_info);
    }

    #[test]
    fn test_detector_config_defaults() {
        let config = DetectorConfig::default();

        assert!(config.enabled_detectors.contains(&"reentrancy".to_string()));
        assert!(config.enabled_detectors.contains(&"missing-access-control".to_string()));
        assert!(config.exclude_patterns.contains(&"test/**".to_string()));
    }

    #[test]
    fn test_severity_conversion() {
        use utils::severity_to_diagnostic_severity;

        assert_eq!(severity_to_diagnostic_severity("critical"), DiagnosticSeverity::ERROR);
        assert_eq!(severity_to_diagnostic_severity("high"), DiagnosticSeverity::ERROR);
        assert_eq!(severity_to_diagnostic_severity("medium"), DiagnosticSeverity::WARNING);
        assert_eq!(severity_to_diagnostic_severity("low"), DiagnosticSeverity::INFORMATION);
        assert_eq!(severity_to_diagnostic_severity("info"), DiagnosticSeverity::HINT);
    }

    #[test]
    fn test_diagnostic_creation() {
        use utils::create_diagnostic_from_finding;

        let finding = Finding {
            detector_id: "test-detector".to_string(),
            message: "Test vulnerability".to_string(),
            severity: "high".to_string(),
            line: 10,
            column: 5,
            length: 8,
            cwe: Some(123),
        };

        let diagnostic = create_diagnostic_from_finding(&finding);

        assert_eq!(diagnostic.range.start.line, 10);
        assert_eq!(diagnostic.range.start.character, 5);
        assert_eq!(diagnostic.range.end.character, 13);
        assert_eq!(diagnostic.severity, Some(DiagnosticSeverity::ERROR));
        assert_eq!(diagnostic.message, "Test vulnerability");
        assert_eq!(diagnostic.source, Some("SolidityDefend".to_string()));
    }

    #[test]
    #[should_panic(expected = "method_not_found")]
    fn test_lsp_server_builder_fails() {
        // This should fail because LSP server creation is not implemented
        let builder = LspServerBuilder::new();
        let _result = builder.build().unwrap();
    }

    #[test]
    fn test_position_extraction() {
        use utils::extract_position_info;

        let text = "line 0\nline 1\nline 2";

        assert_eq!(extract_position_info(text, 0, 0), Some("l".to_string()));
        assert_eq!(extract_position_info(text, 1, 5), Some("1".to_string()));
        assert_eq!(extract_position_info(text, 2, 0), Some("l".to_string()));
        assert_eq!(extract_position_info(text, 10, 0), None);
    }
}