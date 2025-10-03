//! Advanced taint analysis for data flow tracking
//!
//! This module provides sophisticated taint analysis capabilities to track
//! the flow of untrusted data through smart contracts and detect potential
//! security vulnerabilities.

pub mod analyzer;
pub mod propagation;
pub mod sources;
pub mod sinks;
pub mod sanitizers;

pub use analyzer::TaintAnalyzer;
pub use propagation::{TaintPropagator, PropagationRule};
pub use sources::{TaintSource, TaintSourceDetector};
pub use sinks::{TaintSink, TaintSinkDetector};
pub use sanitizers::{TaintSanitizer, SanitizerDetector};

use crate::types::{AnalysisContext, Severity};
use std::collections::{HashMap, HashSet};

/// Represents tainted data in the analysis
#[derive(Debug, Clone, PartialEq)]
pub struct TaintedData {
    pub source: TaintSource,
    pub current_location: SourceLocation,
    pub taint_type: TaintType,
    pub confidence: f64,
    pub propagation_path: Vec<PropagationStep>,
}

/// Source location in the code
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub function: String,
}

/// Type of taint
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum TaintType {
    UserInput,           // Data from user input (msg.sender, tx.origin, etc.)
    ExternalCall,        // Data from external contract calls
    ExternalData,        // Data from external sources (oracles, etc.)
    UntrustedStorage,    // Data from untrusted storage locations
    ArbitraryData,       // Arbitrary data that can be controlled
    TimeDependent,       // Time-dependent data (block.timestamp, etc.)
    AddressDependent,    // Address-dependent data
    NumericOverflow,     // Data that may cause numeric overflow
    Custom(String),      // Custom taint type
}

/// Step in taint propagation
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct PropagationStep {
    pub from_location: SourceLocation,
    pub to_location: SourceLocation,
    pub operation: String,
    pub propagation_type: PropagationType,
}

/// Type of taint propagation
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum PropagationType {
    Direct,              // Direct assignment
    Arithmetic,          // Arithmetic operation
    Comparison,          // Comparison operation
    FunctionCall,        // Function call
    Return,              // Function return
    Storage,             // Storage write/read
    Memory,              // Memory operation
    Event,               // Event emission
    ExternalCall,        // External contract call
}

/// Result of taint analysis
#[derive(Debug, Clone)]
pub struct TaintAnalysisResult {
    pub findings: Vec<TaintFinding>,
    pub taint_map: HashMap<SourceLocation, Vec<TaintedData>>,
    pub data_flow_graph: DataFlowGraph,
    pub statistics: TaintStatistics,
}

/// Taint analysis finding
#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub taint_path: Vec<PropagationStep>,
    pub severity: Severity,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f64,
    pub false_positive_likelihood: f64,
}

/// Data flow graph for visualization
#[derive(Debug, Clone)]
pub struct DataFlowGraph {
    pub nodes: Vec<DataFlowNode>,
    pub edges: Vec<DataFlowEdge>,
}

/// Node in data flow graph
#[derive(Debug, Clone)]
pub struct DataFlowNode {
    pub id: String,
    pub location: SourceLocation,
    pub node_type: DataFlowNodeType,
    pub taint_level: f64,
}

/// Type of data flow node
#[derive(Debug, Clone, PartialEq)]
pub enum DataFlowNodeType {
    Source,
    Sink,
    Propagation,
    Sanitizer,
    Branch,
    Loop,
    Function,
}

/// Edge in data flow graph
#[derive(Debug, Clone)]
pub struct DataFlowEdge {
    pub from: String,
    pub to: String,
    pub edge_type: PropagationType,
    pub taint_preserved: f64, // How much taint is preserved (0.0 - 1.0)
}

/// Statistics from taint analysis
#[derive(Debug, Clone)]
pub struct TaintStatistics {
    pub total_sources: usize,
    pub total_sinks: usize,
    pub total_paths: usize,
    pub vulnerable_paths: usize,
    pub sanitized_paths: usize,
    pub max_path_length: usize,
    pub avg_path_length: f64,
    pub taint_coverage: f64,
}

/// Configuration for taint analysis
#[derive(Debug, Clone)]
pub struct TaintAnalysisConfig {
    pub max_propagation_depth: usize,
    pub min_confidence_threshold: f64,
    pub enable_interprocedural: bool,
    pub enable_cross_contract: bool,
    pub track_implicit_flows: bool,
    pub sanitizer_strictness: SanitizerStrictness,
    pub custom_sources: Vec<String>,
    pub custom_sinks: Vec<String>,
    pub custom_sanitizers: Vec<String>,
}

/// Strictness level for sanitizer detection
#[derive(Debug, Clone, PartialEq)]
pub enum SanitizerStrictness {
    Strict,   // Only well-known sanitizers are trusted
    Moderate, // Heuristic-based sanitizer detection
    Lenient,  // Assume most validations are sanitizers
}

impl Default for TaintAnalysisConfig {
    fn default() -> Self {
        Self {
            max_propagation_depth: 100,
            min_confidence_threshold: 0.5,
            enable_interprocedural: true,
            enable_cross_contract: false,
            track_implicit_flows: true,
            sanitizer_strictness: SanitizerStrictness::Moderate,
            custom_sources: Vec::new(),
            custom_sinks: Vec::new(),
            custom_sanitizers: Vec::new(),
        }
    }
}

/// Common taint analysis utilities
pub struct TaintUtils;

impl TaintUtils {
    /// Check if a location is a potential taint source
    pub fn is_taint_source(location: &SourceLocation, code: &str) -> Option<TaintSource> {
        let line_content = Self::get_line_content(code, location.line)?;

        // Check for common taint sources
        if line_content.contains("msg.sender") {
            Some(TaintSource::MessageSender)
        } else if line_content.contains("tx.origin") {
            Some(TaintSource::TransactionOrigin)
        } else if line_content.contains("msg.data") {
            Some(TaintSource::MessageData)
        } else if line_content.contains("msg.value") {
            Some(TaintSource::MessageValue)
        } else if line_content.contains("block.timestamp") || line_content.contains("now") {
            Some(TaintSource::BlockTimestamp)
        } else if line_content.contains("block.number") {
            Some(TaintSource::BlockNumber)
        } else if line_content.contains("blockhash") {
            Some(TaintSource::BlockHash)
        } else if line_content.contains("call(") || line_content.contains("delegatecall(") {
            Some(TaintSource::ExternalCall)
        } else {
            None
        }
    }

    /// Check if a location is a potential taint sink
    pub fn is_taint_sink(location: &SourceLocation, code: &str) -> Option<TaintSink> {
        let line_content = Self::get_line_content(code, location.line)?;

        if line_content.contains("call(") || line_content.contains("delegatecall(") {
            Some(TaintSink::ExternalCall)
        } else if line_content.contains("selfdestruct") {
            Some(TaintSink::SelfDestruct)
        } else if line_content.contains("transfer(") || line_content.contains("send(") {
            Some(TaintSink::EtherTransfer)
        } else if line_content.contains("approve(") {
            Some(TaintSink::TokenApproval)
        } else if line_content.contains("=") && !line_content.contains("==") {
            Some(TaintSink::StateModification)
        } else {
            None
        }
    }

    /// Check if a location contains sanitization
    pub fn is_sanitizer(location: &SourceLocation, code: &str) -> Option<TaintSanitizer> {
        let line_content = Self::get_line_content(code, location.line)?;

        if line_content.contains("require(") {
            Some(TaintSanitizer::RequireStatement)
        } else if line_content.contains("assert(") {
            Some(TaintSanitizer::AssertStatement)
        } else if line_content.contains("revert(") {
            Some(TaintSanitizer::RevertStatement)
        } else if line_content.contains("onlyOwner") || line_content.contains("onlyAdmin") {
            Some(TaintSanitizer::AccessControl)
        } else if Self::contains_bounds_check(&line_content) {
            Some(TaintSanitizer::BoundsCheck)
        } else if Self::contains_null_check(&line_content) {
            Some(TaintSanitizer::NullCheck)
        } else {
            None
        }
    }

    /// Calculate taint propagation factor
    pub fn calculate_propagation_factor(operation: &str, taint_type: &TaintType) -> f64 {
        match operation {
            "=" => 1.0,  // Direct assignment preserves all taint
            "+" | "-" | "*" | "/" => 0.8,  // Arithmetic may reduce taint slightly
            "==" | "!=" | "<" | ">" => 0.3,  // Comparisons reduce taint significantly
            "&&" | "||" => 0.5,  // Logical operations
            "keccak256" | "sha256" => 0.1,  // Hashing reduces taint significantly
            _ => 0.6,  // Default propagation factor
        }
    }

    /// Estimate false positive likelihood
    pub fn estimate_false_positive_likelihood(
        path: &[PropagationStep],
        sanitizers: &[TaintSanitizer]
    ) -> f64 {
        let mut fp_likelihood: f64 = 0.1; // Base false positive rate

        // Increase likelihood if path is very long
        if path.len() > 10 {
            fp_likelihood += 0.2;
        }

        // Decrease likelihood if strong sanitizers are present
        for sanitizer in sanitizers {
            match sanitizer {
                TaintSanitizer::RequireStatement => fp_likelihood *= 0.7,
                TaintSanitizer::AccessControl => fp_likelihood *= 0.5,
                TaintSanitizer::BoundsCheck => fp_likelihood *= 0.8,
                _ => fp_likelihood *= 0.9,
            }
        }

        fp_likelihood.min(0.9).max(0.01)
    }

    fn get_line_content(code: &str, line_number: usize) -> Option<String> {
        code.lines().nth(line_number.saturating_sub(1)).map(|s| s.to_string())
    }

    fn contains_bounds_check(line: &str) -> bool {
        line.contains("> 0") || line.contains("< length") ||
        line.contains(">=") || line.contains("<=") ||
        line.contains("bounds") || line.contains("range")
    }

    fn contains_null_check(line: &str) -> bool {
        line.contains("!= address(0)") || line.contains("!= 0") ||
        line.contains("== address(0)") || line.contains("== 0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_type_equality() {
        assert_eq!(TaintType::UserInput, TaintType::UserInput);
        assert_ne!(TaintType::UserInput, TaintType::ExternalCall);
    }

    #[test]
    fn test_propagation_type_equality() {
        assert_eq!(PropagationType::Direct, PropagationType::Direct);
        assert_ne!(PropagationType::Direct, PropagationType::Arithmetic);
    }

    #[test]
    fn test_taint_utils_source_detection() {
        let location = SourceLocation {
            file: "test.sol".to_string(),
            line: 1,
            column: 1,
            function: "test".to_string(),
        };

        let code = "address sender = msg.sender;";
        let source = TaintUtils::is_taint_source(&location, code);
        assert_eq!(source, Some(TaintSource::MessageSender));
    }

    #[test]
    fn test_propagation_factor_calculation() {
        assert_eq!(TaintUtils::calculate_propagation_factor("=", &TaintType::UserInput), 1.0);
        assert_eq!(TaintUtils::calculate_propagation_factor("+", &TaintType::UserInput), 0.8);
        assert_eq!(TaintUtils::calculate_propagation_factor("==", &TaintType::UserInput), 0.3);
    }

    #[test]
    fn test_config_default() {
        let config = TaintAnalysisConfig::default();
        assert_eq!(config.max_propagation_depth, 100);
        assert_eq!(config.min_confidence_threshold, 0.5);
        assert!(config.enable_interprocedural);
    }
}