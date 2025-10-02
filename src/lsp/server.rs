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
    detector_engine: crate::detectors::DetectorEngine,
    ast_parser: crate::parser::SolidityParser,
}

impl SecurityAnalyzer {
    fn new() -> Self {
        Self {
            detector_engine: crate::detectors::DetectorEngine::new(),
            ast_parser: crate::parser::SolidityParser::new(),
        }
    }

    async fn analyze_document(&self, document: &DocumentState) -> Result<AnalysisResult> {
        let start_time = std::time::Instant::now();

        // Parse the Solidity code
        let ast = match self.ast_parser.parse(&document.text) {
            Ok(ast) => ast,
            Err(e) => {
                return Ok(AnalysisResult {
                    diagnostics: vec![Diagnostic {
                        range: Range {
                            start: Position { line: 0, character: 0 },
                            end: Position { line: 0, character: 10 },
                        },
                        severity: Some(DiagnosticSeverity::ERROR),
                        code: Some(NumberOrString::String("parse-error".to_string())),
                        source: Some("SolidityDefend".to_string()),
                        message: format!("Parse error: {}", e),
                        related_information: None,
                        tags: None,
                        data: None,
                    }],
                    symbols: vec![],
                    analysis_time_ms: start_time.elapsed().as_millis() as u64,
                });
            }
        };

        // Run security analysis
        let security_findings = self.detector_engine.analyze(&ast, &document.text);

        // Convert findings to diagnostics
        let mut diagnostics = Vec::new();
        for finding in security_findings {
            diagnostics.push(self.finding_to_diagnostic(finding));
        }

        // Extract document symbols
        let symbols = self.extract_symbols(&ast);

        Ok(AnalysisResult {
            diagnostics,
            symbols,
            analysis_time_ms: start_time.elapsed().as_millis() as u64,
        })
    }

    async fn get_hover_info(&self, document: &DocumentState, position: Position) -> Result<Option<Hover>> {
        if let Ok(ast) = self.ast_parser.parse(&document.text) {
            if let Some(hover_info) = self.get_hover_at_position(&ast, &document.text, position) {
                return Ok(Some(Hover {
                    contents: HoverContents::Markup(MarkupContent {
                        kind: MarkupKind::Markdown,
                        value: hover_info,
                    }),
                    range: None,
                }));
            }
        }
        Ok(None)
    }

    async fn get_code_actions(&self, document: &DocumentState, range: Range, context: &CodeActionContext) -> Result<Vec<CodeActionOrCommand>> {
        let mut actions = Vec::new();

        // Generate quick fixes for diagnostics
        for diagnostic in &context.diagnostics {
            if let Some(action) = self.create_quick_fix(document, diagnostic) {
                actions.push(CodeActionOrCommand::CodeAction(action));
            }
        }

        // Add refactoring actions
        actions.extend(self.get_refactoring_actions(document, range));

        // Add security enhancement actions
        actions.extend(self.get_security_enhancement_actions(document));

        Ok(actions)
    }

    fn finding_to_diagnostic(&self, finding: crate::detectors::Finding) -> Diagnostic {
        let severity = match finding.severity.as_str() {
            "Critical" => DiagnosticSeverity::ERROR,
            "High" => DiagnosticSeverity::ERROR,
            "Medium" => DiagnosticSeverity::WARNING,
            "Low" => DiagnosticSeverity::INFORMATION,
            "Info" => DiagnosticSeverity::HINT,
            _ => DiagnosticSeverity::WARNING,
        };

        Diagnostic {
            range: Range {
                start: Position {
                    line: finding.location.line.saturating_sub(1) as u32,
                    character: finding.location.column as u32,
                },
                end: Position {
                    line: finding.location.end_line.unwrap_or(finding.location.line).saturating_sub(1) as u32,
                    character: finding.location.end_column.unwrap_or(finding.location.column + 10) as u32,
                },
            },
            severity: Some(severity),
            code: Some(NumberOrString::String(finding.detector_id)),
            code_description: Some(CodeDescription {
                href: url::Url::parse(&format!("https://docs.soliditydefend.dev/detectors/{}", finding.detector_id)).unwrap(),
            }),
            source: Some("SolidityDefend".to_string()),
            message: finding.message,
            related_information: finding.suggested_fix.map(|fix| {
                vec![DiagnosticRelatedInformation {
                    location: Location {
                        uri: url::Url::parse("file:///").unwrap(),
                        range: Range {
                            start: Position { line: 0, character: 0 },
                            end: Position { line: 0, character: 0 },
                        },
                    },
                    message: format!("Suggested fix: {}", fix),
                }]
            }),
            tags: None,
            data: None,
        }
    }

    fn extract_symbols(&self, ast: &crate::ast::SourceUnit) -> Vec<DocumentSymbol> {
        let mut symbols = Vec::new();

        for contract in &ast.contracts {
            let contract_symbol = DocumentSymbol {
                name: contract.name.clone(),
                detail: Some(format!("contract {}", contract.name)),
                kind: SymbolKind::CLASS,
                tags: None,
                deprecated: Some(false),
                range: Range {
                    start: Position { line: contract.location.line as u32, character: contract.location.column as u32 },
                    end: Position { line: contract.location.end_line.unwrap_or(contract.location.line) as u32, character: contract.location.end_column.unwrap_or(contract.location.column + 10) as u32 },
                },
                selection_range: Range {
                    start: Position { line: contract.location.line as u32, character: contract.location.column as u32 },
                    end: Position { line: contract.location.line as u32, character: (contract.location.column + contract.name.len()) as u32 },
                },
                children: Some(self.extract_contract_children(contract)),
            };
            symbols.push(contract_symbol);
        }

        symbols
    }

    fn extract_contract_children(&self, contract: &crate::ast::Contract) -> Vec<DocumentSymbol> {
        let mut children = Vec::new();

        // Add functions
        for function in &contract.functions {
            let function_symbol = DocumentSymbol {
                name: function.name.clone(),
                detail: Some(format!("function {}", function.name)),
                kind: SymbolKind::FUNCTION,
                tags: None,
                deprecated: Some(false),
                range: Range {
                    start: Position { line: function.location.line as u32, character: function.location.column as u32 },
                    end: Position { line: function.location.end_line.unwrap_or(function.location.line) as u32, character: function.location.end_column.unwrap_or(function.location.column + 10) as u32 },
                },
                selection_range: Range {
                    start: Position { line: function.location.line as u32, character: function.location.column as u32 },
                    end: Position { line: function.location.line as u32, character: (function.location.column + function.name.len()) as u32 },
                },
                children: None,
            };
            children.push(function_symbol);
        }

        // Add state variables
        for variable in &contract.state_variables {
            let variable_symbol = DocumentSymbol {
                name: variable.name.clone(),
                detail: Some(format!("{} {}", variable.type_name, variable.name)),
                kind: SymbolKind::FIELD,
                tags: None,
                deprecated: Some(false),
                range: Range {
                    start: Position { line: variable.location.line as u32, character: variable.location.column as u32 },
                    end: Position { line: variable.location.end_line.unwrap_or(variable.location.line) as u32, character: variable.location.end_column.unwrap_or(variable.location.column + 10) as u32 },
                },
                selection_range: Range {
                    start: Position { line: variable.location.line as u32, character: variable.location.column as u32 },
                    end: Position { line: variable.location.line as u32, character: (variable.location.column + variable.name.len()) as u32 },
                },
                children: None,
            };
            children.push(variable_symbol);
        }

        children
    }

    fn get_hover_at_position(&self, ast: &crate::ast::SourceUnit, source: &str, position: Position) -> Option<String> {
        // Find the symbol at the given position
        let line = position.line as usize + 1;
        let column = position.character as usize;

        // Check contracts
        for contract in &ast.contracts {
            if self.is_position_in_range(line, column, &contract.location) {
                return Some(format!("**Contract:** `{}`\n\nSolidity smart contract", contract.name));
            }

            // Check functions
            for function in &contract.functions {
                if self.is_position_in_range(line, column, &function.location) {
                    let mut info = format!("**Function:** `{}`\n\n", function.name);

                    if let Some(visibility) = &function.visibility {
                        info.push_str(&format!("**Visibility:** {}\n", visibility));
                    }

                    if !function.modifiers.is_empty() {
                        info.push_str(&format!("**Modifiers:** {}\n", function.modifiers.join(", ")));
                    }

                    // Add security analysis
                    let security_notes = self.get_function_security_notes(function);
                    if !security_notes.is_empty() {
                        info.push_str("\n**Security Notes:**\n");
                        for note in security_notes {
                            info.push_str(&format!("- {}\n", note));
                        }
                    }

                    return Some(info);
                }
            }

            // Check state variables
            for variable in &contract.state_variables {
                if self.is_position_in_range(line, column, &variable.location) {
                    let mut info = format!("**State Variable:** `{}`\n\n", variable.name);
                    info.push_str(&format!("**Type:** {}\n", variable.type_name));
                    info.push_str(&format!("**Visibility:** {}\n", variable.visibility));

                    // Add security analysis for state variables
                    let security_notes = self.get_variable_security_notes(variable);
                    if !security_notes.is_empty() {
                        info.push_str("\n**Security Notes:**\n");
                        for note in security_notes {
                            info.push_str(&format!("- {}\n", note));
                        }
                    }

                    return Some(info);
                }
            }
        }

        None
    }

    fn is_position_in_range(&self, line: usize, column: usize, location: &crate::ast::Location) -> bool {
        if line < location.line || line > location.end_line.unwrap_or(location.line) {
            return false;
        }

        if line == location.line && column < location.column {
            return false;
        }

        if line == location.end_line.unwrap_or(location.line) && column > location.end_column.unwrap_or(location.column + 10) {
            return false;
        }

        true
    }

    fn get_function_security_notes(&self, function: &crate::ast::Function) -> Vec<String> {
        let mut notes = Vec::new();

        // Check for common security patterns
        if function.visibility.as_deref() == Some("public") && function.modifiers.is_empty() {
            notes.push("Consider adding access control modifiers for public functions".to_string());
        }

        if function.name.contains("withdraw") && !function.modifiers.contains(&"nonReentrant".to_string()) {
            notes.push("Withdrawal functions should include reentrancy protection".to_string());
        }

        if function.name.contains("transfer") || function.name.contains("send") {
            notes.push("Ensure proper error handling for transfer operations".to_string());
        }

        notes
    }

    fn get_variable_security_notes(&self, variable: &crate::ast::StateVariable) -> Vec<String> {
        let mut notes = Vec::new();

        if variable.visibility == "public" && variable.type_name.contains("mapping") {
            notes.push("Public mappings expose all keys and values".to_string());
        }

        if variable.name.to_lowercase().contains("owner") && variable.visibility != "private" {
            notes.push("Owner variables should typically be private with getter functions".to_string());
        }

        notes
    }

    fn create_quick_fix(&self, document: &DocumentState, diagnostic: &Diagnostic) -> Option<CodeAction> {
        if let Some(NumberOrString::String(code)) = &diagnostic.code {
            match code.as_str() {
                "tx-origin" => {
                    return Some(CodeAction {
                        title: "Replace tx.origin with msg.sender".to_string(),
                        kind: Some(CodeActionKind::QUICKFIX),
                        diagnostics: Some(vec![diagnostic.clone()]),
                        edit: Some(WorkspaceEdit {
                            changes: Some(HashMap::from([(
                                document.uri.clone(),
                                vec![TextEdit {
                                    range: diagnostic.range,
                                    new_text: "msg.sender".to_string(),
                                }]
                            )])),
                            document_changes: None,
                            change_annotations: None,
                        }),
                        command: None,
                        is_preferred: Some(true),
                        disabled: None,
                        data: None,
                    });
                }
                "missing-access-control" => {
                    return Some(CodeAction {
                        title: "Add onlyOwner modifier".to_string(),
                        kind: Some(CodeActionKind::QUICKFIX),
                        diagnostics: Some(vec![diagnostic.clone()]),
                        edit: Some(self.create_access_control_fix(&document.text, diagnostic.range)),
                        command: None,
                        is_preferred: Some(true),
                        disabled: None,
                        data: None,
                    });
                }
                "reentrancy" => {
                    return Some(CodeAction {
                        title: "Add nonReentrant modifier".to_string(),
                        kind: Some(CodeActionKind::QUICKFIX),
                        diagnostics: Some(vec![diagnostic.clone()]),
                        edit: Some(self.create_reentrancy_fix(&document.text, diagnostic.range)),
                        command: None,
                        is_preferred: Some(true),
                        disabled: None,
                        data: None,
                    });
                }
                _ => {}
            }
        }
        None
    }

    fn get_refactoring_actions(&self, document: &DocumentState, range: Range) -> Vec<CodeActionOrCommand> {
        let mut actions = Vec::new();

        // Extract function
        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: "Extract to function".to_string(),
            kind: Some(CodeActionKind::REFACTOR_EXTRACT),
            diagnostics: None,
            edit: None,
            command: Some(Command {
                title: "Extract to function".to_string(),
                command: "soliditydefend.extractFunction".to_string(),
                arguments: Some(vec![serde_json::to_value(range).unwrap()]),
            }),
            is_preferred: None,
            disabled: None,
            data: None,
        }));

        // Extract modifier
        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: "Extract to modifier".to_string(),
            kind: Some(CodeActionKind::REFACTOR_EXTRACT),
            diagnostics: None,
            edit: None,
            command: Some(Command {
                title: "Extract to modifier".to_string(),
                command: "soliditydefend.extractModifier".to_string(),
                arguments: Some(vec![serde_json::to_value(range).unwrap()]),
            }),
            is_preferred: None,
            disabled: None,
            data: None,
        }));

        // Inline function
        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: "Inline function".to_string(),
            kind: Some(CodeActionKind::REFACTOR_INLINE),
            diagnostics: None,
            edit: None,
            command: Some(Command {
                title: "Inline function".to_string(),
                command: "soliditydefend.inlineFunction".to_string(),
                arguments: Some(vec![serde_json::to_value(range).unwrap()]),
            }),
            is_preferred: None,
            disabled: None,
            data: None,
        }));

        actions
    }

    fn get_security_enhancement_actions(&self, document: &DocumentState) -> Vec<CodeActionOrCommand> {
        let mut actions = Vec::new();

        // Add reentrancy guard to contract
        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: "Add reentrancy guard to contract".to_string(),
            kind: Some(CodeActionKind::REFACTOR),
            diagnostics: None,
            edit: None,
            command: Some(Command {
                title: "Add reentrancy guard".to_string(),
                command: "soliditydefend.addReentrancyGuard".to_string(),
                arguments: None,
            }),
            is_preferred: None,
            disabled: None,
            data: None,
        }));

        // Add access control
        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: "Add access control pattern".to_string(),
            kind: Some(CodeActionKind::REFACTOR),
            diagnostics: None,
            edit: None,
            command: Some(Command {
                title: "Add access control".to_string(),
                command: "soliditydefend.addAccessControl".to_string(),
                arguments: None,
            }),
            is_preferred: None,
            disabled: None,
            data: None,
        }));

        // Add pause functionality
        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: "Add pausable pattern".to_string(),
            kind: Some(CodeActionKind::REFACTOR),
            diagnostics: None,
            edit: None,
            command: Some(Command {
                title: "Add pausable".to_string(),
                command: "soliditydefend.addPausable".to_string(),
                arguments: None,
            }),
            is_preferred: None,
            disabled: None,
            data: None,
        }));

        actions
    }

    fn create_access_control_fix(&self, text: &str, range: Range) -> WorkspaceEdit {
        // Find the function declaration and add onlyOwner modifier
        let lines: Vec<&str> = text.lines().collect();
        let function_line_idx = range.start.line as usize;

        if let Some(line) = lines.get(function_line_idx) {
            if line.trim_start().starts_with("function") {
                let new_text = line.replace(" {", " onlyOwner {");
                return WorkspaceEdit {
                    changes: Some(HashMap::from([(
                        url::Url::parse("file:///").unwrap(), // Should use actual URI
                        vec![TextEdit {
                            range: Range {
                                start: Position { line: function_line_idx as u32, character: 0 },
                                end: Position { line: function_line_idx as u32, character: line.len() as u32 },
                            },
                            new_text,
                        }]
                    )])),
                    document_changes: None,
                    change_annotations: None,
                };
            }
        }

        WorkspaceEdit {
            changes: None,
            document_changes: None,
            change_annotations: None,
        }
    }

    fn create_reentrancy_fix(&self, text: &str, range: Range) -> WorkspaceEdit {
        // Find the function declaration and add nonReentrant modifier
        let lines: Vec<&str> = text.lines().collect();
        let function_line_idx = range.start.line as usize;

        if let Some(line) = lines.get(function_line_idx) {
            if line.trim_start().starts_with("function") {
                let new_text = line.replace(" {", " nonReentrant {");
                return WorkspaceEdit {
                    changes: Some(HashMap::from([(
                        url::Url::parse("file:///").unwrap(), // Should use actual URI
                        vec![TextEdit {
                            range: Range {
                                start: Position { line: function_line_idx as u32, character: 0 },
                                end: Position { line: function_line_idx as u32, character: line.len() as u32 },
                            },
                            new_text,
                        }]
                    )])),
                    document_changes: None,
                    change_annotations: None,
                };
            }
        }

        WorkspaceEdit {
            changes: None,
            document_changes: None,
            change_annotations: None,
        }
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

            // Get document from map
            let document = {
                let docs = document_map.read().unwrap();
                docs.get(&uri).cloned()
            };

            if let Some(doc) = document {
                // Perform analysis
                match analyzer.analyze_document(&doc).await {
                    Ok(result) => {
                        // Update document state with analysis result
                        {
                            let mut docs = document_map.write().unwrap();
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

                        let _ = sender.send(update);
                    }
                    Err(_) => {
                        // Send empty diagnostics on error
                        let update = DiagnosticUpdate {
                            uri,
                            version: Some(doc.version),
                            diagnostics: vec![],
                        };

                        let _ = sender.send(update);
                    }
                }
            }
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
                completion_provider: Some(CompletionOptions {
                    resolve_provider: Some(false),
                    trigger_characters: Some(vec![".".to_string(), " ".to_string()]),
                    work_done_progress_options: WorkDoneProgressOptions::default(),
                    all_commit_characters: None,
                    completion_item: None,
                }),
                code_lens_provider: Some(CodeLensOptions {
                    resolve_provider: Some(true),
                }),
                document_formatting_provider: Some(OneOf::Left(true)),
                document_range_formatting_provider: Some(OneOf::Left(true)),
                rename_provider: Some(OneOf::Left(true)),
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
            self.schedule_analysis(uri.clone());
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
            self.schedule_analysis(uri.clone());
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