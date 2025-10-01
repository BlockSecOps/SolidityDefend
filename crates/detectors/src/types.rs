use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;

use ast::{Contract, Function, Statement, Expression, Modifier};
use semantic::SymbolTable;
// Temporarily disabled due to CFG compilation errors
// use cfg::ControlFlowGraph;
// use dataflow::{DataFlowAnalysis, TaintAnalysis};

/// Unique identifier for a detector
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DetectorId(pub String);

impl DetectorId {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl std::fmt::Display for DetectorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Severity level of a security finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Informational findings that don't represent security issues
    Info,
    /// Low-impact issues that have minimal security implications
    Low,
    /// Medium-impact issues that could affect contract security
    Medium,
    /// High-impact issues that pose significant security risks
    High,
    /// Critical issues that could lead to loss of funds or contract compromise
    Critical,
}

impl Severity {
    /// Get the numeric score for this severity level
    pub fn score(&self) -> u8 {
        match self {
            Severity::Info => 1,
            Severity::Low => 2,
            Severity::Medium => 4,
            Severity::High => 7,
            Severity::Critical => 10,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Confidence level in the accuracy of a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    /// Low confidence - might be a false positive
    Low,
    /// Medium confidence - likely correct but needs review
    Medium,
    /// High confidence - very likely to be a real issue
    High,
    /// Maximum confidence - definitely a security issue
    Confirmed,
}

impl Confidence {
    /// Get the numeric score for this confidence level
    pub fn score(&self) -> u8 {
        match self {
            Confidence::Low => 3,
            Confidence::Medium => 6,
            Confidence::High => 8,
            Confidence::Confirmed => 10,
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Low => write!(f, "LOW"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::High => write!(f, "HIGH"),
            Confidence::Confirmed => write!(f, "CONFIRMED"),
        }
    }
}

/// Location in source code
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// File path
    pub file: String,
    /// Line number (1-based)
    pub line: u32,
    /// Column number (1-based)
    pub column: u32,
    /// Length of the affected code
    pub length: u32,
}

impl SourceLocation {
    pub fn new(file: String, line: u32, column: u32, length: u32) -> Self {
        Self { file, line, column, length }
    }
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// A security finding from a detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Detector that produced this finding
    pub detector_id: DetectorId,
    /// Severity of the issue
    pub severity: Severity,
    /// Confidence in the finding
    pub confidence: Confidence,
    /// Human-readable description of the issue
    pub message: String,
    /// Primary location where the issue occurs
    pub primary_location: SourceLocation,
    /// Additional locations related to the issue
    pub secondary_locations: Vec<SourceLocation>,
    /// Common Weakness Enumeration (CWE) identifiers
    pub cwe_ids: Vec<u32>,
    /// Additional metadata specific to the detector
    pub metadata: HashMap<String, String>,
    /// Suggested fix or mitigation
    pub fix_suggestion: Option<String>,
}

impl Finding {
    pub fn new(
        detector_id: DetectorId,
        severity: Severity,
        confidence: Confidence,
        message: String,
        primary_location: SourceLocation,
    ) -> Self {
        Self {
            detector_id,
            severity,
            confidence,
            message,
            primary_location,
            secondary_locations: Vec::new(),
            cwe_ids: Vec::new(),
            metadata: HashMap::new(),
            fix_suggestion: None,
        }
    }

    /// Add a secondary location to this finding
    pub fn with_secondary_location(mut self, location: SourceLocation) -> Self {
        self.secondary_locations.push(location);
        self
    }

    /// Add a CWE identifier to this finding
    pub fn with_cwe(mut self, cwe_id: u32) -> Self {
        self.cwe_ids.push(cwe_id);
        self
    }

    /// Add metadata to this finding
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Add a fix suggestion to this finding
    pub fn with_fix_suggestion(mut self, fix: String) -> Self {
        self.fix_suggestion = Some(fix);
        self
    }

    /// Calculate a composite risk score based on severity and confidence
    pub fn risk_score(&self) -> u16 {
        (self.severity.score() as u16) * (self.confidence.score() as u16)
    }
}

/// Analysis context provided to detectors
pub struct AnalysisContext<'arena> {
    /// The contract being analyzed
    pub contract: Contract<'arena>,
    /// Symbol table with semantic information
    pub symbols: SymbolTable,
    /// Control flow graph for each function (temporarily disabled)
    // pub cfgs: HashMap<String, ControlFlowGraph>,
    /// Data flow analysis results (temporarily disabled)
    // pub dataflow: Option<Box<dyn DataFlowAnalysis>>,
    /// Taint analysis results (temporarily disabled)
    // pub taint: Option<TaintAnalysis>,
    /// Source file content for location mapping
    pub source: String,
    /// File path being analyzed
    pub file_path: String,
}

impl<'arena> AnalysisContext<'arena> {
    pub fn new(
        contract: Contract<'arena>,
        symbols: SymbolTable,
        source: String,
        file_path: String,
    ) -> Self {
        Self {
            contract,
            symbols,
            // cfgs: HashMap::new(),
            // dataflow: None,
            // taint: None,
            source,
            file_path,
        }
    }

    /// Add CFG for a function (temporarily disabled)
    // pub fn add_cfg(&mut self, function_name: String, cfg: ControlFlowGraph) {
    //     self.cfgs.insert(function_name, cfg);
    // }

    /// Set data flow analysis results (temporarily disabled)
    // pub fn set_dataflow(&mut self, dataflow: Box<dyn DataFlowAnalysis>) {
    //     self.dataflow = Some(dataflow);
    // }

    /// Set taint analysis results (temporarily disabled)
    // pub fn set_taint(&mut self, taint: TaintAnalysis) {
    //     self.taint = Some(taint);
    // }

    /// Get the CFG for a specific function (temporarily disabled)
    // pub fn get_cfg(&self, function_name: &str) -> Option<&ControlFlowGraph> {
    //     self.cfgs.get(function_name)
    // }

    /// Get all functions in the contract
    pub fn get_functions(&self) -> Vec<&Function> {
        self.contract.functions.iter().collect()
    }

    /// Get all modifiers in the contract
    pub fn get_modifiers(&self) -> Vec<&Modifier> {
        self.contract.modifiers.iter().collect()
    }

    /// Create a source location from line and column information
    pub fn create_location(&self, line: u32, column: u32, length: u32) -> SourceLocation {
        SourceLocation::new(self.file_path.clone(), line, column, length)
    }
}

/// Result of running multiple detectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// All findings from detectors
    pub findings: Vec<Finding>,
    /// Statistics about the analysis
    pub stats: AnalysisStats,
    /// Errors encountered during analysis
    pub errors: Vec<String>,
}

impl AnalysisResult {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            stats: AnalysisStats::new(),
            errors: Vec::new(),
        }
    }

    /// Add a finding to the results
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Add an error to the results
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }

    /// Get findings with a specific severity or higher
    pub fn findings_with_severity(&self, min_severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= min_severity)
            .collect()
    }

    /// Get findings with a specific confidence or higher
    pub fn findings_with_confidence(&self, min_confidence: Confidence) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.confidence >= min_confidence)
            .collect()
    }

    /// Get findings from a specific detector
    pub fn findings_from_detector(&self, detector_id: &DetectorId) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.detector_id == *detector_id)
            .collect()
    }
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStats {
    /// Number of detectors run
    pub detectors_run: usize,
    /// Total execution time in milliseconds
    pub total_time_ms: u64,
    /// Number of findings by severity
    pub findings_by_severity: HashMap<String, usize>,
    /// Number of findings by detector
    pub findings_by_detector: HashMap<String, usize>,
}

impl AnalysisStats {
    pub fn new() -> Self {
        Self {
            detectors_run: 0,
            total_time_ms: 0,
            findings_by_severity: HashMap::new(),
            findings_by_detector: HashMap::new(),
        }
    }

    /// Update statistics with a new finding
    pub fn record_finding(&mut self, finding: &Finding) {
        let severity_key = finding.severity.to_string();
        *self.findings_by_severity.entry(severity_key).or_insert(0) += 1;

        let detector_key = finding.detector_id.to_string();
        *self.findings_by_detector.entry(detector_key).or_insert(0) += 1;
    }
}

impl Default for AnalysisStats {
    fn default() -> Self {
        Self::new()
    }
}