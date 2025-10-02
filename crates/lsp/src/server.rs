use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::RwLock;
use tower_lsp::jsonrpc;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use cache::CacheManager;
use detectors::registry::DetectorRegistry;
use detectors::types::Finding;
use fixes::FixEngine;

/// SolidityDefend Language Server
pub struct SolidityDefendLanguageServer {
    /// LSP client for sending notifications/requests to the editor
    client: Client,
    /// Document store for open files
    documents: Arc<DashMap<Url, DocumentState>>,
    /// Cache manager for faster re-analysis
    cache_manager: Arc<CacheManager>,
    /// Detector registry
    detector_registry: Arc<DetectorRegistry>,
    /// Fix engine for code actions
    fix_engine: Arc<FixEngine>,
    /// Server state
    state: Arc<RwLock<ServerState>>,
}

/// State of a document in the LSP server
#[derive(Debug, Clone)]
struct DocumentState {
    /// Document URI
    uri: Url,
    /// Document content
    content: String,
    /// Document version (incremented on each change)
    version: i32,
    /// Last analysis results
    findings: Vec<Finding>,
    /// Analysis metadata
    last_analyzed: Option<std::time::SystemTime>,
}

/// Overall server state
#[derive(Debug, Default)]
struct ServerState {
    /// Client capabilities
    client_capabilities: Option<ClientCapabilities>,
    /// Server initialization status
    initialized: bool,
    /// Analysis settings
    analysis_settings: AnalysisSettings,
}

/// Analysis configuration settings
#[derive(Debug, Clone)]
struct AnalysisSettings {
    /// Whether to run analysis on document change
    analyze_on_change: bool,
    /// Whether to run analysis on document save
    analyze_on_save: bool,
    /// Analysis debounce delay in milliseconds
    debounce_ms: u64,
    /// Maximum number of findings to report per document
    max_findings: usize,
}

impl Default for AnalysisSettings {
    fn default() -> Self {
        Self {
            analyze_on_change: true,
            analyze_on_save: true,
            debounce_ms: 500,
            max_findings: 100,
        }
    }
}

impl SolidityDefendLanguageServer {
    pub fn new(client: Client) -> Result<Self> {
        let cache_config = cache::CacheConfig::default();
        let cache_manager = Arc::new(CacheManager::new(cache_config)?);
        let detector_registry = Arc::new(DetectorRegistry::new());
        let fix_engine = Arc::new(FixEngine::new()?);

        Ok(Self {
            client,
            documents: Arc::new(DashMap::new()),
            cache_manager,
            detector_registry,
            fix_engine,
            state: Arc::new(RwLock::new(ServerState::default())),
        })
    }

    /// Analyze a document and return findings
    async fn analyze_document(&self, uri: &Url, _content: &str) -> Result<Vec<Finding>> {
        // TODO: Implement proper parsing and analysis integration
        // For now, return empty findings to get the LSP server compiling

        self.client
            .log_message(MessageType::INFO, format!("Analysis requested for {}", uri))
            .await;

        // Placeholder: in a real implementation, we would:
        // 1. Parse the Solidity source code using the parser crate
        // 2. Create an AnalysisContext with proper contract and symbol information
        // 3. Run the detector registry on the analysis context
        // 4. Return the findings

        Ok(vec![])
    }

    /// Convert findings to LSP diagnostics
    fn findings_to_diagnostics(&self, findings: &[Finding]) -> Vec<Diagnostic> {
        findings
            .iter()
            .map(|finding| {
                let range = Range {
                    start: Position {
                        line: finding.primary_location.line.saturating_sub(1) as u32,
                        character: finding.primary_location.column.saturating_sub(1) as u32,
                    },
                    end: Position {
                        line: finding.primary_location.line.saturating_sub(1) as u32,
                        character: (finding.primary_location.column + finding.primary_location.length).saturating_sub(1) as u32,
                    },
                };

                let severity = match finding.severity {
                    detectors::types::Severity::Critical | detectors::types::Severity::High => DiagnosticSeverity::ERROR,
                    detectors::types::Severity::Medium => DiagnosticSeverity::WARNING,
                    detectors::types::Severity::Low | detectors::types::Severity::Info => DiagnosticSeverity::INFORMATION,
                };

                let mut diagnostic = Diagnostic {
                    range,
                    severity: Some(severity),
                    code: Some(NumberOrString::String(finding.detector_id.0.clone())),
                    code_description: None,
                    source: Some("soliditydefend".to_string()),
                    message: finding.message.clone(),
                    related_information: None,
                    tags: None,
                    data: None,
                };

                // Add CWE information if available
                if !finding.cwe_ids.is_empty() {
                    let cwe_info = finding.cwe_ids
                        .iter()
                        .map(|cwe| format!("CWE-{}", cwe))
                        .collect::<Vec<_>>()
                        .join(", ");
                    diagnostic.message = format!("{} ({})", diagnostic.message, cwe_info);
                }

                diagnostic
            })
            .collect()
    }

    /// Publish diagnostics for a document
    async fn publish_diagnostics(&self, uri: Url, findings: &[Finding]) {
        let diagnostics = self.findings_to_diagnostics(findings);

        self.client
            .publish_diagnostics(uri, diagnostics, None)
            .await;
    }

    /// Handle document change with debouncing
    async fn handle_document_change(&self, uri: Url, content: String, version: i32) {
        // Update document state
        let mut doc_state = DocumentState {
            uri: uri.clone(),
            content: content.clone(),
            version,
            findings: vec![],
            last_analyzed: None,
        };

        // Check if we should analyze on change
        let should_analyze = {
            let state = self.state.read().await;
            state.analysis_settings.analyze_on_change
        };

        if should_analyze {
            // Perform analysis
            match self.analyze_document(&uri, &content).await {
                Ok(findings) => {
                    doc_state.findings = findings.clone();
                    doc_state.last_analyzed = Some(std::time::SystemTime::now());

                    // Publish diagnostics
                    self.publish_diagnostics(uri.clone(), &findings).await;
                }
                Err(e) => {
                    self.client
                        .log_message(
                            MessageType::ERROR,
                            format!("Analysis failed for {}: {}", uri, e),
                        )
                        .await;
                }
            }
        }

        // Store document state
        self.documents.insert(uri, doc_state);
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for SolidityDefendLanguageServer {
    async fn initialize(&self, params: InitializeParams) -> jsonrpc::Result<InitializeResult> {
        {
            let mut state = self.state.write().await;
            state.client_capabilities = Some(params.capabilities);
            state.initialized = true;
        }

        self.client
            .log_message(MessageType::INFO, "SolidityDefend LSP server initialized")
            .await;

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::INCREMENTAL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                diagnostic_provider: Some(DiagnosticServerCapabilities::Options(
                    DiagnosticOptions {
                        identifier: Some("soliditydefend".to_string()),
                        inter_file_dependencies: false,
                        workspace_diagnostics: false,
                        work_done_progress_options: WorkDoneProgressOptions::default(),
                    },
                )),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "SolidityDefend LSP".to_string(),
                version: Some("0.1.0".to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "SolidityDefend LSP server is ready")
            .await;
    }

    async fn shutdown(&self) -> jsonrpc::Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let content = params.text_document.text;
        let version = params.text_document.version;

        self.handle_document_change(uri, content, version).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let version = params.text_document.version;

        // Get current document content and apply changes
        if let Some(mut doc) = self.documents.get_mut(&uri) {
            for change in params.content_changes {
                if let Some(_range) = change.range {
                    // Apply incremental change (simplified implementation)
                    // In a real implementation, you'd properly handle incremental changes
                    doc.content = change.text;
                } else {
                    // Full document change
                    doc.content = change.text;
                }
            }

            let content = doc.content.clone();
            drop(doc); // Release the lock

            self.handle_document_change(uri, content, version).await;
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;

        // Check if we should analyze on save
        let should_analyze = {
            let state = self.state.read().await;
            state.analysis_settings.analyze_on_save
        };

        if should_analyze {
            if let Some(doc) = self.documents.get(&uri) {
                let content = doc.content.clone();
                drop(doc);

                match self.analyze_document(&uri, &content).await {
                    Ok(findings) => {
                        // Update document state
                        if let Some(mut doc) = self.documents.get_mut(&uri) {
                            doc.findings = findings.clone();
                            doc.last_analyzed = Some(std::time::SystemTime::now());
                        }

                        // Publish diagnostics
                        self.publish_diagnostics(uri, &findings).await;
                    }
                    Err(e) => {
                        self.client
                            .log_message(
                                MessageType::ERROR,
                                format!("Analysis failed for {}: {}", uri, e),
                            )
                            .await;
                    }
                }
            }
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.documents.remove(&uri);

        // Clear diagnostics
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    async fn hover(&self, params: HoverParams) -> jsonrpc::Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        if let Some(doc) = self.documents.get(uri) {
            // Find finding at the given position
            for finding in &doc.findings {
                let finding_range = Range {
                    start: Position {
                        line: finding.primary_location.line.saturating_sub(1) as u32,
                        character: finding.primary_location.column.saturating_sub(1) as u32,
                    },
                    end: Position {
                        line: finding.primary_location.line.saturating_sub(1) as u32,
                        character: (finding.primary_location.column + finding.primary_location.length).saturating_sub(1) as u32,
                    },
                };

                if position >= finding_range.start && position <= finding_range.end {
                    let mut content = format!("**{}**\n\n{}", finding.detector_id.0, finding.message);

                    if !finding.cwe_ids.is_empty() {
                        content.push_str(&format!(
                            "\n\n**Security Issues:** {}",
                            finding.cwe_ids
                                .iter()
                                .map(|cwe| format!("CWE-{}", cwe))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }

                    if let Some(ref suggestion) = finding.fix_suggestion {
                        content.push_str(&format!("\n\n**Fix Suggestion:** {}", suggestion));
                    }

                    return Ok(Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value: content,
                        }),
                        range: Some(finding_range),
                    }));
                }
            }
        }

        Ok(None)
    }

    async fn code_action(&self, params: CodeActionParams) -> jsonrpc::Result<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;

        if let Some(doc) = self.documents.get(uri) {
            let mut actions = Vec::new();

            // Find findings in the requested range
            for finding in &doc.findings {
                let finding_range = Range {
                    start: Position {
                        line: finding.primary_location.line.saturating_sub(1) as u32,
                        character: finding.primary_location.column.saturating_sub(1) as u32,
                    },
                    end: Position {
                        line: finding.primary_location.line.saturating_sub(1) as u32,
                        character: (finding.primary_location.column + finding.primary_location.length).saturating_sub(1) as u32,
                    },
                };

                // Check if finding overlaps with requested range
                if finding_range.start <= params.range.end && finding_range.end >= params.range.start {
                    if let Some(ref suggestion) = finding.fix_suggestion {
                        let action = CodeAction {
                            title: format!("Fix: {}", suggestion),
                            kind: Some(CodeActionKind::QUICKFIX),
                            diagnostics: Some(vec![Diagnostic {
                                range: finding_range,
                                severity: Some(DiagnosticSeverity::ERROR),
                                code: Some(NumberOrString::String(finding.detector_id.0.clone())),
                                source: Some("soliditydefend".to_string()),
                                message: finding.message.clone(),
                                ..Default::default()
                            }]),
                            edit: None, // TODO: Implement workspace edits based on fix suggestions
                            command: None,
                            is_preferred: Some(true),
                            disabled: None,
                            data: None,
                        };

                        actions.push(CodeActionOrCommand::CodeAction(action));
                    }
                }
            }

            if !actions.is_empty() {
                return Ok(Some(actions));
            }
        }

        Ok(None)
    }
}

/// Create and start the LSP server
pub async fn start_lsp_server() -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| {
        SolidityDefendLanguageServer::new(client).unwrap()
    });

    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(())
}