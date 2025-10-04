use std::collections::{HashMap, HashSet};
use anyhow::Result;
use serde::{Deserialize, Serialize};

use ir::{BlockId, ValueId, Instruction};
use cfg::ControlFlowGraph;
use crate::analysis::{DataFlowAnalysis, DataFlowDirection, DataFlowResult, utils};

/// Taint analysis for tracking data flow from sources to sinks
///
/// This analysis tracks how "tainted" (potentially dangerous) data flows through
/// a program from sources (user input, external data) to sinks (dangerous operations).
pub struct TaintAnalysis<'a> {
    cfg: &'a ControlFlowGraph,
    /// Sources of taint (e.g., user input parameters)
    taint_sources: HashMap<String, TaintSource>,
    /// Sinks where tainted data is dangerous (e.g., assembly operations)
    taint_sinks: HashMap<String, TaintSink>,
    /// Sanitizers that remove taint
    sanitizers: HashMap<String, TaintSanitizer>,
    /// Propagation rules for different instruction types
    propagation_rules: Vec<PropagationRule>,
    /// Whether to track detailed taint paths
    track_paths: bool,
}

/// A source of taint in the program
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaintSource {
    /// Function parameter
    Parameter(String),
    /// Global variable
    Global(String),
    /// External function call result
    ExternalCall(String),
    /// Storage read
    StorageRead,
    /// Message data (msg.data, msg.sender, etc.)
    MessageData(String),
    /// User-defined source
    Custom(String),
}

/// A sink where tainted data is dangerous
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaintSink {
    /// Assembly function call
    AssemblyFunction(String),
    /// Regular function call
    Function(String),
    /// Storage write
    StorageWrite,
    /// External call
    ExternalCall(String),
    /// Return value
    Return,
    /// User-defined sink
    Custom(String),
}

/// A sanitizer that removes taint
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaintSanitizer {
    /// Function call that sanitizes (e.g., require, assert)
    Function(String),
    /// Type cast that sanitizes
    TypeCast(String),
    /// Validation pattern
    Validation(String),
    /// User-defined sanitizer
    Custom(String),
}

/// Rules for how taint propagates through different operations
#[derive(Debug, Clone, PartialEq)]
pub enum PropagationRule {
    /// Taint propagates through arithmetic operations
    Arithmetic,
    /// Taint propagates through function calls
    FunctionCall,
    /// Taint propagates through memory operations
    Memory,
    /// Taint propagates through array/struct access
    FieldAccess,
    /// Taint propagates conditionally
    Conditional,
}

/// State for taint analysis
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TaintState {
    /// Map from variable to its taint information
    tainted_variables: HashMap<ValueId, TaintInfo>,
    /// Whether the return value is tainted
    return_tainted: Option<TaintInfo>,
}

/// Information about how a variable is tainted
#[derive(Debug, Clone, PartialEq)]
pub struct TaintInfo {
    /// Whether the variable is definitely tainted
    is_tainted: bool,
    /// Whether the variable is conditionally tainted
    is_conditional: bool,
    /// Sources that contribute to this taint
    sources: HashSet<String>,
    /// Path of taint propagation (if tracking is enabled)
    taint_path: Option<Vec<TaintStep>>,
    /// Confidence level of taint (0.0 to 1.0)
    confidence: f64,
}

/// A step in the taint propagation path
#[derive(Debug, Clone, PartialEq)]
pub struct TaintStep {
    /// The variable at this step
    pub variable: String,
    /// The block where this step occurs
    pub block_id: BlockId,
    /// The instruction that causes this step
    pub instruction_index: usize,
    /// Type of propagation
    pub propagation_type: PropagationType,
}

/// Type of taint propagation
#[derive(Debug, Clone, PartialEq)]
pub enum PropagationType {
    /// Direct assignment
    Assignment,
    /// Arithmetic operation
    Arithmetic,
    /// Function call
    FunctionCall,
    /// Memory access
    MemoryAccess,
    /// Conditional propagation
    Conditional,
    /// Sanitization
    Sanitization,
}

/// A taint violation (tainted data reaching a sink)
#[derive(Debug, Clone)]
pub struct TaintViolation {
    /// The source of the taint
    pub source: String,
    /// The sink where tainted data is used
    pub sink: String,
    /// The variable that carries the taint to the sink
    pub tainted_variable: ValueId,
    /// The block where the violation occurs
    pub block_id: BlockId,
    /// Severity of the violation
    pub severity: TaintViolationSeverity,
    /// Detailed path of taint propagation
    pub taint_path: Vec<TaintStep>,
    /// Confidence in this violation
    pub confidence: f64,
}

/// Severity levels for taint violations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Result of taint analysis
#[derive(Debug, Clone)]
pub struct TaintAnalysisResult {
    /// The data flow result
    pub dataflow_result: DataFlowResult<TaintState>,
    /// Detected taint violations
    pub violations: Vec<TaintViolation>,
    /// Summary statistics
    pub statistics: TaintStatistics,
}

/// Statistics about taint analysis
#[derive(Debug, Clone)]
pub struct TaintStatistics {
    /// Total number of tainted variables
    pub total_tainted: usize,
    /// Number of sources
    pub source_count: usize,
    /// Number of sinks
    pub sink_count: usize,
    /// Number of violations by severity
    pub violations_by_severity: HashMap<TaintViolationSeverity, usize>,
}

impl TaintInfo {
    /// Create new taint info
    pub fn new(is_tainted: bool, sources: HashSet<String>) -> Self {
        Self {
            is_tainted,
            is_conditional: false,
            sources,
            taint_path: None,
            confidence: if is_tainted { 1.0 } else { 0.0 },
        }
    }

    /// Create conditional taint info
    pub fn conditional(sources: HashSet<String>) -> Self {
        Self {
            is_tainted: false,
            is_conditional: true,
            sources,
            taint_path: None,
            confidence: 0.5,
        }
    }

    /// Merge with another taint info
    pub fn merge_with(&mut self, other: &Self) {
        self.is_tainted = self.is_tainted || other.is_tainted;
        self.is_conditional = self.is_conditional || other.is_conditional;
        self.sources.extend(other.sources.iter().cloned());
        self.confidence = self.confidence.max(other.confidence);

        // Merge paths if both exist
        if let (Some(ref mut self_path), Some(ref other_path)) = (&mut self.taint_path, &other.taint_path) {
            self_path.extend(other_path.iter().cloned());
        } else if other.taint_path.is_some() {
            self.taint_path = other.taint_path.clone();
        }
    }

    /// Apply sanitization
    pub fn sanitize(&mut self) {
        self.is_tainted = false;
        self.is_conditional = false;
        self.confidence = 0.0;
        self.sources.clear();
    }
}

impl TaintState {
    /// Create a new empty taint state
    pub fn new() -> Self {
        Self {
            tainted_variables: HashMap::new(),
            return_tainted: None,
        }
    }

    /// Mark a variable as tainted
    pub fn set_tainted(&mut self, variable: ValueId, taint_info: TaintInfo) {
        self.tainted_variables.insert(variable, taint_info);
    }

    /// Check if a variable is tainted
    pub fn is_tainted(&self, variable: &str) -> bool {
        // For string lookup, we'd need a mapping from names to ValueIds
        // This is a simplified implementation
        false
    }

    /// Check if a variable is conditionally tainted
    pub fn is_conditionally_tainted(&self, variable: &str) -> bool {
        // Simplified implementation
        false
    }

    /// Check if the return value is tainted
    pub fn is_tainted_return(&self) -> bool {
        self.return_tainted.as_ref().map(|info| info.is_tainted).unwrap_or(false)
    }

    /// Check if the return value is conditionally tainted
    pub fn is_conditionally_tainted_return(&self) -> bool {
        self.return_tainted.as_ref().map(|info| info.is_conditional).unwrap_or(false)
    }

    /// Get taint info for a variable
    pub fn get_taint_info(&self, variable: ValueId) -> Option<&TaintInfo> {
        self.tainted_variables.get(&variable)
    }

    /// Remove taint from a variable
    pub fn remove_taint(&mut self, variable: ValueId) {
        self.tainted_variables.remove(&variable);
    }

    /// Union with another taint state
    pub fn union_with(&mut self, other: &Self) {
        for (var, other_info) in &other.tainted_variables {
            if let Some(existing_info) = self.tainted_variables.get_mut(var) {
                existing_info.merge_with(other_info);
            } else {
                self.tainted_variables.insert(*var, other_info.clone());
            }
        }

        // Merge return taint
        if let Some(ref other_return) = other.return_tainted {
            if let Some(ref mut self_return) = self.return_tainted {
                self_return.merge_with(other_return);
            } else {
                self.return_tainted = Some(other_return.clone());
            }
        }
    }

    /// Get all tainted variables
    pub fn get_tainted_variables(&self) -> HashSet<ValueId> {
        self.tainted_variables.keys().cloned().collect()
    }

    /// Apply sanitization to all variables from specific sources
    pub fn sanitize_sources(&mut self, sanitized_sources: &HashSet<String>) {
        for taint_info in self.tainted_variables.values_mut() {
            if taint_info.sources.iter().any(|s| sanitized_sources.contains(s)) {
                taint_info.sanitize();
            }
        }

        if let Some(ref mut return_info) = self.return_tainted {
            if return_info.sources.iter().any(|s| sanitized_sources.contains(s)) {
                return_info.sanitize();
            }
        }

        // Remove completely sanitized variables
        self.tainted_variables.retain(|_, info| info.is_tainted || info.is_conditional);

        if let Some(ref return_info) = self.return_tainted {
            if !return_info.is_tainted && !return_info.is_conditional {
                self.return_tainted = None;
            }
        }
    }
}

impl<'a> TaintAnalysis<'a> {
    /// Create a new taint analysis
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self {
            cfg,
            taint_sources: HashMap::new(),
            taint_sinks: HashMap::new(),
            sanitizers: HashMap::new(),
            propagation_rules: vec![
                PropagationRule::Arithmetic,
                PropagationRule::Memory,
                PropagationRule::FieldAccess,
            ],
            track_paths: false,
        }
    }

    /// Add a taint source
    pub fn add_source(&mut self, name: String, source: TaintSource) {
        self.taint_sources.insert(name, source);
    }

    /// Add a taint sink
    pub fn add_sink(&mut self, name: String, sink: TaintSink) {
        self.taint_sinks.insert(name, sink);
    }

    /// Add a sanitizer
    pub fn add_sanitizer(&mut self, name: String, sanitizer: TaintSanitizer) {
        self.sanitizers.insert(name, sanitizer);
    }

    /// Enable path tracking
    pub fn enable_path_tracking(&mut self) {
        self.track_paths = true;
    }

    /// Add a propagation rule
    pub fn add_propagation_rule(&mut self, rule: PropagationRule) {
        self.propagation_rules.push(rule);
    }

    /// Check if an instruction is a taint source
    fn is_source(&self, instruction: &Instruction) -> Option<HashSet<String>> {
        // This would need to be implemented based on the specific instruction
        // and the configured sources
        None
    }

    /// Check if an instruction is a taint sink
    fn is_sink(&self, instruction: &Instruction) -> Option<String> {
        // This would need to be implemented based on the specific instruction
        // and the configured sinks
        None
    }

    /// Check if an instruction is a sanitizer
    fn is_sanitizer(&self, instruction: &Instruction) -> Option<HashSet<String>> {
        // This would need to be implemented based on the specific instruction
        // and the configured sanitizers
        None
    }

    /// Propagate taint through an instruction
    fn propagate_taint(&self, state: &TaintState, instruction: &Instruction) -> TaintState {
        let mut new_state = state.clone();

        // Check for sources
        if let Some(sources) = self.is_source(instruction) {
            if let Some(defined_var) = utils::get_instruction_definition(instruction) {
                let taint_info = TaintInfo::new(true, sources);
                new_state.set_tainted(defined_var, taint_info);
            }
            return new_state;
        }

        // Check for sanitizers
        if let Some(sanitized_sources) = self.is_sanitizer(instruction) {
            new_state.sanitize_sources(&sanitized_sources);
            return new_state;
        }

        // Propagate taint through different instruction types
        match instruction {
            Instruction::Add(target, lhs, rhs) |
            Instruction::Sub(target, lhs, rhs) |
            Instruction::Mul(target, lhs, rhs) |
            Instruction::Div(target, lhs, rhs) => {
                if self.propagation_rules.contains(&PropagationRule::Arithmetic) {
                    let mut sources = HashSet::new();
                    let mut is_tainted = false;

                    // Check if any operand is tainted
                    if let Some(lhs_var) = utils::extract_variable_id(lhs) {
                        if let Some(lhs_info) = state.get_taint_info(lhs_var) {
                            if lhs_info.is_tainted {
                                is_tainted = true;
                                sources.extend(lhs_info.sources.iter().cloned());
                            }
                        }
                    }

                    if let Some(rhs_var) = utils::extract_variable_id(rhs) {
                        if let Some(rhs_info) = state.get_taint_info(rhs_var) {
                            if rhs_info.is_tainted {
                                is_tainted = true;
                                sources.extend(rhs_info.sources.iter().cloned());
                            }
                        }
                    }

                    if is_tainted {
                        let taint_info = TaintInfo::new(true, sources);
                        new_state.set_tainted(*target, taint_info);
                    }
                }
            },
            Instruction::Load(target, address) => {
                if self.propagation_rules.contains(&PropagationRule::Memory) {
                    if let Some(addr_var) = utils::extract_variable_id(address) {
                        if let Some(addr_info) = state.get_taint_info(addr_var) {
                            if addr_info.is_tainted {
                                let taint_info = TaintInfo::new(true, addr_info.sources.clone());
                                new_state.set_tainted(*target, taint_info);
                            }
                        }
                    }
                }
            },
            Instruction::Store(address, value) => {
                // Storage writes are potential sinks
                if let Some(value_var) = utils::extract_variable_id(value) {
                    if let Some(value_info) = state.get_taint_info(value_var) {
                        if value_info.is_tainted {
                            // This could trigger a violation if storage writes are configured as sinks
                        }
                    }
                }
            },
            Instruction::Return(Some(value)) => {
                if let Some(ret_var) = utils::extract_variable_id(value) {
                    if let Some(ret_info) = state.get_taint_info(ret_var) {
                        new_state.return_tainted = Some(ret_info.clone());
                    }
                }
            },
            Instruction::Phi(target, phi_args) => {
                let mut merged_sources = HashSet::new();
                let mut is_tainted = false;
                let mut is_conditional = false;

                for (value, _) in phi_args {
                    if let Some(phi_var) = utils::extract_variable_id(value) {
                        if let Some(phi_info) = state.get_taint_info(phi_var) {
                            if phi_info.is_tainted {
                                is_tainted = true;
                                merged_sources.extend(phi_info.sources.iter().cloned());
                            } else if phi_info.is_conditional {
                                is_conditional = true;
                                merged_sources.extend(phi_info.sources.iter().cloned());
                            }
                        }
                    }
                }

                if is_tainted || is_conditional {
                    let mut taint_info = if is_tainted {
                        TaintInfo::new(true, merged_sources)
                    } else {
                        TaintInfo::conditional(merged_sources)
                    };

                    if is_tainted && is_conditional {
                        taint_info.is_conditional = true;
                    }

                    new_state.set_tainted(*target, taint_info);
                }
            },
            _ => {
                // Handle other instruction types as needed
            }
        }

        new_state
    }

    /// Detect taint violations in the analysis result
    pub fn detect_violations(&self, result: &DataFlowResult<TaintState>) -> Vec<TaintViolation> {
        let mut violations = Vec::new();

        for (block_id, block_node) in self.cfg.basic_blocks() {
            let instructions = &block_node.instructions;
            if let Some(block_state) = result.get_exit_state(block_id) {
                for (instr_index, instruction) in instructions.iter().enumerate() {
                    if let Some(sink_name) = self.is_sink(instruction) {
                        // Check if any used variables are tainted
                        let used_vars = utils::get_instruction_uses(instruction);
                        for used_var in used_vars {
                            if let Some(taint_info) = block_state.get_taint_info(used_var) {
                                if taint_info.is_tainted {
                                    for source in &taint_info.sources {
                                        let violation = TaintViolation {
                                            source: source.clone(),
                                            sink: sink_name.clone(),
                                            tainted_variable: used_var,
                                            block_id: block_id,
                                            severity: self.assess_severity(&sink_name, taint_info),
                                            taint_path: taint_info.taint_path.clone().unwrap_or_default(),
                                            confidence: taint_info.confidence,
                                        };
                                        violations.push(violation);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        violations
    }

    /// Assess the severity of a taint violation
    fn assess_severity(&self, sink_name: &str, taint_info: &TaintInfo) -> TaintViolationSeverity {
        // This is a simplified assessment - in practice, this would be more sophisticated
        match sink_name {
            name if name.contains("assembly") || name.contains("delegatecall") => TaintViolationSeverity::Critical,
            name if name.contains("call") => TaintViolationSeverity::High,
            name if name.contains("storage") => TaintViolationSeverity::Medium,
            _ => TaintViolationSeverity::Low,
        }
    }

    /// Perform complete taint analysis
    pub fn analyze_taint(&mut self) -> Result<TaintAnalysisResult> {
        let dataflow_result = self.analyze()?;
        let violations = self.detect_violations(&dataflow_result);

        // Compute statistics
        let mut total_tainted = 0;
        let mut violations_by_severity = HashMap::new();

        for state in dataflow_result.exit_states.values() {
            total_tainted += state.get_tainted_variables().len();
        }

        for violation in &violations {
            *violations_by_severity.entry(violation.severity.clone()).or_insert(0) += 1;
        }

        let statistics = TaintStatistics {
            total_tainted,
            source_count: self.taint_sources.len(),
            sink_count: self.taint_sinks.len(),
            violations_by_severity,
        };

        Ok(TaintAnalysisResult {
            dataflow_result,
            violations,
            statistics,
        })
    }

    /// Generate analysis report
    pub fn generate_report(&self, result: &TaintAnalysisResult) -> String {
        let mut report = String::new();

        report.push_str("=== Taint Analysis Report ===\n\n");

        // Overall statistics
        report.push_str("Analysis Statistics:\n");
        report.push_str(&format!("  Converged: {}\n", result.dataflow_result.converged));
        report.push_str(&format!("  Iterations: {}\n", result.dataflow_result.iterations));
        report.push_str(&format!("  Total tainted variables: {}\n", result.statistics.total_tainted));
        report.push_str(&format!("  Sources: {}\n", result.statistics.source_count));
        report.push_str(&format!("  Sinks: {}\n", result.statistics.sink_count));

        // Violations by severity
        report.push_str("\nViolations by Severity:\n");
        for (severity, count) in &result.statistics.violations_by_severity {
            report.push_str(&format!("  {:?}: {}\n", severity, count));
        }

        // Detailed violations
        if !result.violations.is_empty() {
            report.push_str("\nDetailed Violations:\n");
            for (i, violation) in result.violations.iter().enumerate() {
                report.push_str(&format!("{}. Source: {} -> Sink: {} (Severity: {:?})\n",
                    i + 1, violation.source, violation.sink, violation.severity));
                report.push_str(&format!("   Block: {}, Variable: {}, Confidence: {:.2}\n",
                    violation.block_id.0, violation.tainted_variable.0, violation.confidence));

                if !violation.taint_path.is_empty() {
                    report.push_str("   Taint Path:\n");
                    for step in &violation.taint_path {
                        report.push_str(&format!("     {} (Block {}) -> {:?}\n",
                            step.variable, step.block_id.0, step.propagation_type));
                    }
                }
                report.push_str("\n");
            }
        }

        report
    }
}

impl<'a> DataFlowAnalysis for TaintAnalysis<'a> {
    type State = TaintState;

    fn direction(&self) -> DataFlowDirection {
        DataFlowDirection::Forward
    }

    fn initial_state(&self) -> Self::State {
        TaintState::new()
    }

    fn boundary_state(&self) -> Self::State {
        // Entry point may have tainted parameters
        let state = TaintState::new();

        // Initialize tainted parameters based on configured sources
        // This would need access to function parameters
        // For now, return empty state

        state
    }

    fn transfer_instruction(&self, state: &Self::State, instruction: &Instruction) -> Self::State {
        self.propagate_taint(state, instruction)
    }

    fn meet(&self, states: &[Self::State]) -> Self::State {
        let mut result = TaintState::new();

        for state in states {
            result.union_with(state);
        }

        result
    }

    fn analyze(&mut self) -> Result<DataFlowResult<Self::State>> {
        use crate::analysis::DataFlowEngine;
        DataFlowEngine::analyze(self)
    }

    fn cfg(&self) -> &ControlFlowGraph {
        self.cfg
    }
}

// Convenience functions for common taint sources and sinks
impl TaintAnalysis<'_> {
    /// Add common Solidity taint sources
    pub fn add_solidity_sources(&mut self) {
        self.add_source("msg.sender".to_string(), TaintSource::MessageData("sender".to_string()));
        self.add_source("msg.value".to_string(), TaintSource::MessageData("value".to_string()));
        self.add_source("msg.data".to_string(), TaintSource::MessageData("data".to_string()));
        self.add_source("tx.origin".to_string(), TaintSource::MessageData("origin".to_string()));
        self.add_source("block.timestamp".to_string(), TaintSource::MessageData("timestamp".to_string()));
    }

    /// Add common Solidity taint sinks
    pub fn add_solidity_sinks(&mut self) {
        self.add_sink("delegatecall".to_string(), TaintSink::ExternalCall("delegatecall".to_string()));
        self.add_sink("call".to_string(), TaintSink::ExternalCall("call".to_string()));
        self.add_sink("staticcall".to_string(), TaintSink::ExternalCall("staticcall".to_string()));
        self.add_sink("selfdestruct".to_string(), TaintSink::Function("selfdestruct".to_string()));
        self.add_sink("suicide".to_string(), TaintSink::Function("suicide".to_string()));
    }

    /// Add common Solidity sanitizers
    pub fn add_solidity_sanitizers(&mut self) {
        self.add_sanitizer("require".to_string(), TaintSanitizer::Function("require".to_string()));
        self.add_sanitizer("assert".to_string(), TaintSanitizer::Function("assert".to_string()));
        self.add_sanitizer("revert".to_string(), TaintSanitizer::Function("revert".to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfg::{ControlFlowGraph, EdgeType};
    use ir::{Instruction, IrValue, ValueId};

    fn create_taint_test_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new("test_taint".to_string());

        let block1 = BlockId(1);
        let block2 = BlockId(2);

        // Block 1: tainted_var = input, clean_var = 42
        let instructions1 = vec![
            Instruction::Add(ValueId(1), IrValue::Value(ValueId(0)), IrValue::ConstantInt(0)), // tainted_var = input
            Instruction::Add(ValueId(2), IrValue::ConstantInt(42), IrValue::ConstantInt(0)), // clean_var = 42
        ];

        // Block 2: result = tainted_var + clean_var
        let instructions2 = vec![
            Instruction::Add(ValueId(3), IrValue::Value(ValueId(1)), IrValue::Value(ValueId(2))), // result = tainted + clean
            Instruction::Return(Some(IrValue::Value(ValueId(3)))), // return result
        ];

        cfg.add_block(block1, instructions1);
        cfg.add_block(block2, instructions2);

        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();

        cfg
    }

    #[test]
    fn test_taint_analysis_basic() {
        let cfg = create_taint_test_cfg();
        let mut analysis = TaintAnalysis::new(&cfg);

        // Configure taint source
        analysis.add_source("input".to_string(), TaintSource::Parameter("input".to_string()));

        let result = analysis.analyze();
        assert!(result.is_ok());

        let taint_result = result.unwrap();
        assert!(taint_result.converged);

        // The analysis framework is set up, but specific taint propagation
        // would need more detailed implementation
    }

    #[test]
    fn test_taint_info_operations() {
        let mut info1 = TaintInfo::new(true, {
            let mut sources = HashSet::new();
            sources.insert("source1".to_string());
            sources
        });

        let info2 = TaintInfo::new(true, {
            let mut sources = HashSet::new();
            sources.insert("source2".to_string());
            sources
        });

        info1.merge_with(&info2);

        assert!(info1.is_tainted);
        assert_eq!(info1.sources.len(), 2);
        assert!(info1.sources.contains("source1"));
        assert!(info1.sources.contains("source2"));
    }

    #[test]
    fn test_taint_state_operations() {
        let mut state = TaintState::new();

        let taint_info = TaintInfo::new(true, {
            let mut sources = HashSet::new();
            sources.insert("test_source".to_string());
            sources
        });

        state.set_tainted(ValueId(1), taint_info);

        assert!(state.get_taint_info(ValueId(1)).is_some());
        assert!(state.get_taint_info(ValueId(1)).unwrap().is_tainted);
    }

    #[test]
    fn test_sanitization() {
        let mut state = TaintState::new();

        let mut taint_info = TaintInfo::new(true, {
            let mut sources = HashSet::new();
            sources.insert("sanitized_source".to_string());
            sources
        });

        state.set_tainted(ValueId(1), taint_info);

        let sanitized_sources = {
            let mut set = HashSet::new();
            set.insert("sanitized_source".to_string());
            set
        };

        state.sanitize_sources(&sanitized_sources);

        // The variable should no longer be tainted
        assert!(state.get_taint_info(ValueId(1)).is_none());
    }
}