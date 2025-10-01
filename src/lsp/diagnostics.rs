use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::time::interval;
use tower_lsp::lsp_types::*;
use serde::{Deserialize, Serialize};

/// Real-time diagnostics system for SolidityDefend LSP
/// Provides efficient, incremental analysis with debouncing and caching

#[derive(Debug)]
pub struct DiagnosticsEngine {
    /// Active document tracking
    documents: Arc<RwLock<HashMap<Url, DocumentInfo>>>,
    /// Diagnostics cache for fast retrieval
    diagnostics_cache: Arc<RwLock<HashMap<Url, CachedDiagnostics>>>,
    /// Analysis scheduler for debouncing
    scheduler: AnalysisScheduler,
    /// Configuration for diagnostics behavior
    config: DiagnosticsConfig,
    /// Channel for publishing diagnostics
    publisher: DiagnosticsPublisher,
    /// Dependency tracker for cross-file analysis
    dependency_tracker: Arc<RwLock<DependencyTracker>>,
}

#[derive(Debug, Clone)]
pub struct DocumentInfo {
    pub uri: Url,
    pub text: String,
    pub version: i32,
    pub language_id: String,
    pub last_modified: Instant,
    pub analysis_state: AnalysisState,
    pub syntax_tree: Option<SyntaxTree>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisState {
    /// Document is clean and analyzed
    Analyzed,
    /// Document has been modified and needs analysis
    Dirty,
    /// Document is currently being analyzed
    Analyzing,
    /// Analysis failed
    Error(String),
}

#[derive(Debug, Clone)]
pub struct CachedDiagnostics {
    pub diagnostics: Vec<Diagnostic>,
    pub timestamp: Instant,
    pub document_version: i32,
    pub analysis_duration: Duration,
    pub cache_key: String,
}

#[derive(Debug, Clone)]
pub struct DiagnosticsConfig {
    /// Debounce delay for analysis triggers
    pub debounce_delay: Duration,
    /// Maximum number of diagnostics per file
    pub max_diagnostics: usize,
    /// Enable incremental analysis
    pub incremental_analysis: bool,
    /// Enable cross-file analysis
    pub cross_file_analysis: bool,
    /// Severity filter
    pub min_severity: Option<DiagnosticSeverity>,
    /// Detector configuration
    pub detector_config: DetectorConfiguration,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            debounce_delay: Duration::from_millis(500),
            max_diagnostics: 100,
            incremental_analysis: true,
            cross_file_analysis: true,
            min_severity: None,
            detector_config: DetectorConfiguration::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectorConfiguration {
    pub enabled_detectors: HashSet<String>,
    pub detector_settings: HashMap<String, DetectorSettings>,
    pub custom_rules: Vec<CustomRule>,
}

impl Default for DetectorConfiguration {
    fn default() -> Self {
        let mut enabled_detectors = HashSet::new();
        enabled_detectors.insert("reentrancy".to_string());
        enabled_detectors.insert("missing-access-control".to_string());
        enabled_detectors.insert("dangerous-selfdestruct".to_string());
        enabled_detectors.insert("unchecked-return-value".to_string());

        Self {
            enabled_detectors,
            detector_settings: HashMap::new(),
            custom_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectorSettings {
    pub severity_override: Option<DiagnosticSeverity>,
    pub enabled: bool,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
}

/// Manages analysis scheduling with debouncing
#[derive(Debug)]
pub struct AnalysisScheduler {
    pending_analysis: Arc<RwLock<HashMap<Url, Instant>>>,
    analysis_sender: mpsc::UnboundedSender<AnalysisRequest>,
}

#[derive(Debug, Clone)]
pub struct AnalysisRequest {
    pub uri: Url,
    pub document_version: i32,
    pub request_time: Instant,
    pub priority: AnalysisPriority,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnalysisPriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Immediate = 4,
}

/// Publishes diagnostics to LSP client
#[derive(Debug)]
pub struct DiagnosticsPublisher {
    publisher_sender: mpsc::UnboundedSender<DiagnosticsUpdate>,
}

#[derive(Debug, Clone)]
pub struct DiagnosticsUpdate {
    pub uri: Url,
    pub version: Option<i32>,
    pub diagnostics: Vec<Diagnostic>,
    pub related_files: Vec<Url>,
}

/// Tracks dependencies between files for cross-file analysis
#[derive(Debug, Default)]
pub struct DependencyTracker {
    /// Maps file URI to its dependencies
    dependencies: HashMap<Url, HashSet<Url>>,
    /// Maps file URI to files that depend on it
    dependents: HashMap<Url, HashSet<Url>>,
    /// Import resolution cache
    import_cache: HashMap<String, Url>,
}

/// Placeholder for syntax tree
#[derive(Debug, Clone)]
pub struct SyntaxTree {
    // This will be implemented when parser is available
    pub root: SyntaxNode,
}

#[derive(Debug, Clone)]
pub struct SyntaxNode {
    pub kind: String,
    pub text: String,
    pub range: Range,
    pub children: Vec<SyntaxNode>,
}

impl DiagnosticsEngine {
    /// Create a new diagnostics engine
    pub fn new(config: DiagnosticsConfig) -> Self {
        let (analysis_sender, analysis_receiver) = mpsc::unbounded_channel();
        let (publisher_sender, publisher_receiver) = mpsc::unbounded_channel();

        let documents = Arc::new(RwLock::new(HashMap::new()));
        let diagnostics_cache = Arc::new(RwLock::new(HashMap::new()));
        let dependency_tracker = Arc::new(RwLock::new(DependencyTracker::default()));

        // Spawn analysis worker
        Self::spawn_analysis_worker(
            analysis_receiver,
            documents.clone(),
            diagnostics_cache.clone(),
            dependency_tracker.clone(),
            config.clone(),
            publisher_sender.clone(),
        );

        // Spawn publisher worker
        Self::spawn_publisher_worker(publisher_receiver);

        Self {
            documents,
            diagnostics_cache,
            scheduler: AnalysisScheduler {
                pending_analysis: Arc::new(RwLock::new(HashMap::new())),
                analysis_sender,
            },
            config,
            publisher: DiagnosticsPublisher { publisher_sender },
            dependency_tracker,
        }
    }

    /// Add or update a document
    pub async fn update_document(&self, uri: Url, text: String, version: i32, language_id: String) -> Result<(), DiagnosticsError> {
        // This will fail until document management is implemented
        Err(DiagnosticsError::NotImplemented(
            "Document update not implemented".to_string()
        ))
    }

    /// Remove a document
    pub async fn remove_document(&self, uri: &Url) -> Result<(), DiagnosticsError> {
        // This will fail until document management is implemented
        Err(DiagnosticsError::NotImplemented(
            "Document removal not implemented".to_string()
        ))
    }

    /// Get current diagnostics for a document
    pub fn get_diagnostics(&self, uri: &Url) -> Option<Vec<Diagnostic>> {
        let cache = self.diagnostics_cache.read().unwrap();
        cache.get(uri).map(|cached| cached.diagnostics.clone())
    }

    /// Schedule analysis for a document
    pub fn schedule_analysis(&self, uri: Url, version: i32, priority: AnalysisPriority) -> Result<(), DiagnosticsError> {
        // This will fail until analysis scheduling is implemented
        Err(DiagnosticsError::NotImplemented(
            "Analysis scheduling not implemented".to_string()
        ))
    }

    /// Force immediate analysis
    pub async fn analyze_now(&self, uri: &Url) -> Result<Vec<Diagnostic>, DiagnosticsError> {
        // This will fail until immediate analysis is implemented
        Err(DiagnosticsError::NotImplemented(
            "Immediate analysis not implemented".to_string()
        ))
    }

    /// Update configuration
    pub fn update_config(&mut self, config: DiagnosticsConfig) {
        self.config = config;
    }

    /// Get analysis statistics
    pub fn get_statistics(&self) -> DiagnosticsStatistics {
        let documents = self.documents.read().unwrap();
        let cache = self.diagnostics_cache.read().unwrap();

        DiagnosticsStatistics {
            total_documents: documents.len(),
            analyzed_documents: documents.values().filter(|d| d.analysis_state == AnalysisState::Analyzed).count(),
            pending_analysis: documents.values().filter(|d| d.analysis_state == AnalysisState::Dirty).count(),
            cache_size: cache.len(),
            total_diagnostics: cache.values().map(|c| c.diagnostics.len()).sum(),
        }
    }

    /// Spawn background worker for analysis
    fn spawn_analysis_worker(
        mut receiver: mpsc::UnboundedReceiver<AnalysisRequest>,
        documents: Arc<RwLock<HashMap<Url, DocumentInfo>>>,
        cache: Arc<RwLock<HashMap<Url, CachedDiagnostics>>>,
        dependencies: Arc<RwLock<DependencyTracker>>,
        config: DiagnosticsConfig,
        publisher: mpsc::UnboundedSender<DiagnosticsUpdate>,
    ) {
        tokio::spawn(async move {
            while let Some(request) = receiver.recv().await {
                // This will fail until analysis worker is implemented
                eprintln!("Analysis worker not implemented for: {}", request.uri);
            }
        });
    }

    /// Spawn background worker for publishing diagnostics
    fn spawn_publisher_worker(mut receiver: mpsc::UnboundedReceiver<DiagnosticsUpdate>) {
        tokio::spawn(async move {
            while let Some(update) = receiver.recv().await {
                // This will fail until diagnostics publishing is implemented
                eprintln!("Diagnostics publisher not implemented for: {}", update.uri);
            }
        });
    }

    /// Analyze a single document
    async fn analyze_document(&self, uri: &Url) -> Result<Vec<Diagnostic>, DiagnosticsError> {
        // This will fail until document analysis is implemented
        Err(DiagnosticsError::NotImplemented(
            "Document analysis not implemented".to_string()
        ))
    }

    /// Parse document syntax
    fn parse_syntax(&self, text: &str, language_id: &str) -> Result<SyntaxTree, DiagnosticsError> {
        // This will fail until syntax parsing is implemented
        Err(DiagnosticsError::NotImplemented(
            "Syntax parsing not implemented".to_string()
        ))
    }

    /// Update dependency information
    fn update_dependencies(&self, uri: &Url, syntax_tree: &SyntaxTree) -> Result<(), DiagnosticsError> {
        // This will fail until dependency tracking is implemented
        Err(DiagnosticsError::NotImplemented(
            "Dependency tracking not implemented".to_string()
        ))
    }

    /// Get files that depend on the given file
    pub fn get_dependents(&self, uri: &Url) -> Vec<Url> {
        let tracker = self.dependency_tracker.read().unwrap();
        tracker.dependents.get(uri).cloned().unwrap_or_default().into_iter().collect()
    }

    /// Clear diagnostics for a file
    pub fn clear_diagnostics(&self, uri: &Url) -> Result<(), DiagnosticsError> {
        // This will fail until diagnostics clearing is implemented
        Err(DiagnosticsError::NotImplemented(
            "Diagnostics clearing not implemented".to_string()
        ))
    }
}

/// Statistics about diagnostics engine performance
#[derive(Debug, Clone)]
pub struct DiagnosticsStatistics {
    pub total_documents: usize,
    pub analyzed_documents: usize,
    pub pending_analysis: usize,
    pub cache_size: usize,
    pub total_diagnostics: usize,
}

/// Specialized diagnostics filters
pub struct DiagnosticsFilter {
    severity_filter: Option<DiagnosticSeverity>,
    detector_filter: Option<HashSet<String>>,
    range_filter: Option<Range>,
}

impl DiagnosticsFilter {
    pub fn new() -> Self {
        Self {
            severity_filter: None,
            detector_filter: None,
            range_filter: None,
        }
    }

    pub fn with_severity(mut self, severity: DiagnosticSeverity) -> Self {
        self.severity_filter = Some(severity);
        self
    }

    pub fn with_detectors(mut self, detectors: HashSet<String>) -> Self {
        self.detector_filter = Some(detectors);
        self
    }

    pub fn with_range(mut self, range: Range) -> Self {
        self.range_filter = Some(range);
        self
    }

    pub fn apply(&self, diagnostics: Vec<Diagnostic>) -> Vec<Diagnostic> {
        diagnostics.into_iter().filter(|d| self.matches(d)).collect()
    }

    fn matches(&self, diagnostic: &Diagnostic) -> bool {
        // Check severity filter
        if let Some(min_severity) = &self.severity_filter {
            if let Some(severity) = &diagnostic.severity {
                if severity > min_severity {
                    return false;
                }
            }
        }

        // Check detector filter
        if let Some(allowed_detectors) = &self.detector_filter {
            if let Some(code) = &diagnostic.code {
                let detector_id = match code {
                    NumberOrString::String(s) => s.clone(),
                    NumberOrString::Number(n) => n.to_string(),
                };
                if !allowed_detectors.contains(&detector_id) {
                    return false;
                }
            }
        }

        // Check range filter
        if let Some(filter_range) = &self.range_filter {
            if !self.ranges_overlap(&diagnostic.range, filter_range) {
                return false;
            }
        }

        true
    }

    fn ranges_overlap(&self, range1: &Range, range2: &Range) -> bool {
        // Simple overlap check
        !(range1.end < range2.start || range2.end < range1.start)
    }
}

impl Default for DiagnosticsFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch diagnostics operations for performance
pub struct DiagnosticsBatch {
    operations: Vec<BatchOperation>,
}

#[derive(Debug)]
enum BatchOperation {
    Update { uri: Url, diagnostics: Vec<Diagnostic> },
    Clear { uri: Url },
    Analyze { uri: Url, priority: AnalysisPriority },
}

impl DiagnosticsBatch {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    pub fn update_diagnostics(mut self, uri: Url, diagnostics: Vec<Diagnostic>) -> Self {
        self.operations.push(BatchOperation::Update { uri, diagnostics });
        self
    }

    pub fn clear_diagnostics(mut self, uri: Url) -> Self {
        self.operations.push(BatchOperation::Clear { uri });
        self
    }

    pub fn schedule_analysis(mut self, uri: Url, priority: AnalysisPriority) -> Self {
        self.operations.push(BatchOperation::Analyze { uri, priority });
        self
    }

    pub async fn execute(self, engine: &DiagnosticsEngine) -> Result<(), DiagnosticsError> {
        // This will fail until batch execution is implemented
        Err(DiagnosticsError::NotImplemented(
            "Batch execution not implemented".to_string()
        ))
    }
}

impl Default for DiagnosticsBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur in diagnostics engine
#[derive(Debug, thiserror::Error)]
pub enum DiagnosticsError {
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Dependency error: {0}")]
    DependencyError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostics_config_defaults() {
        let config = DiagnosticsConfig::default();

        assert_eq!(config.debounce_delay, Duration::from_millis(500));
        assert_eq!(config.max_diagnostics, 100);
        assert!(config.incremental_analysis);
        assert!(config.cross_file_analysis);
        assert!(config.detector_config.enabled_detectors.contains("reentrancy"));
    }

    #[test]
    #[should_panic(expected = "Document update not implemented")]
    fn test_document_update_fails() {
        let engine = DiagnosticsEngine::new(DiagnosticsConfig::default());
        let uri = Url::parse("file:///test.sol").unwrap();

        // This should fail because document update is not implemented
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            engine.update_document(uri, "content".to_string(), 1, "solidity".to_string()).await.unwrap();
        });
    }

    #[test]
    #[should_panic(expected = "Analysis scheduling not implemented")]
    fn test_analysis_scheduling_fails() {
        let engine = DiagnosticsEngine::new(DiagnosticsConfig::default());
        let uri = Url::parse("file:///test.sol").unwrap();

        // This should fail because analysis scheduling is not implemented
        engine.schedule_analysis(uri, 1, AnalysisPriority::Normal).unwrap();
    }

    #[test]
    fn test_diagnostics_filter() {
        let mut filter = DiagnosticsFilter::new();
        filter = filter.with_severity(DiagnosticSeverity::WARNING);

        let diagnostic = Diagnostic {
            range: Range {
                start: Position { line: 0, character: 0 },
                end: Position { line: 0, character: 10 },
            },
            severity: Some(DiagnosticSeverity::ERROR),
            code: None,
            message: "Test error".to_string(),
            source: None,
            related_information: None,
            tags: None,
            code_description: None,
            data: None,
        };

        let diagnostics = vec![diagnostic];
        let filtered = filter.apply(diagnostics);

        // Should include ERROR severity diagnostic when filter is WARNING
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_diagnostics_batch() {
        let batch = DiagnosticsBatch::new()
            .update_diagnostics(Url::parse("file:///test1.sol").unwrap(), vec![])
            .clear_diagnostics(Url::parse("file:///test2.sol").unwrap())
            .schedule_analysis(Url::parse("file:///test3.sol").unwrap(), AnalysisPriority::High);

        assert_eq!(batch.operations.len(), 3);
    }

    #[test]
    fn test_analysis_priority_ordering() {
        assert!(AnalysisPriority::Immediate > AnalysisPriority::High);
        assert!(AnalysisPriority::High > AnalysisPriority::Normal);
        assert!(AnalysisPriority::Normal > AnalysisPriority::Low);
    }

    #[test]
    fn test_diagnostics_statistics() {
        let engine = DiagnosticsEngine::new(DiagnosticsConfig::default());
        let stats = engine.get_statistics();

        assert_eq!(stats.total_documents, 0);
        assert_eq!(stats.analyzed_documents, 0);
        assert_eq!(stats.pending_analysis, 0);
        assert_eq!(stats.cache_size, 0);
        assert_eq!(stats.total_diagnostics, 0);
    }

    #[test]
    #[should_panic(expected = "Immediate analysis not implemented")]
    fn test_immediate_analysis_fails() {
        let engine = DiagnosticsEngine::new(DiagnosticsConfig::default());
        let uri = Url::parse("file:///test.sol").unwrap();

        // This should fail because immediate analysis is not implemented
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            engine.analyze_now(&uri).await.unwrap();
        });
    }

    #[test]
    fn test_dependency_tracker() {
        let engine = DiagnosticsEngine::new(DiagnosticsConfig::default());
        let uri = Url::parse("file:///test.sol").unwrap();

        let dependents = engine.get_dependents(&uri);
        assert!(dependents.is_empty());
    }
}