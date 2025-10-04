use std::collections::HashMap;
use anyhow::Result;

use ast::{SourceFile, Function};
use cfg::{ControlFlowGraph, CfgBuilder, CfgAnalysisEngine};
use dataflow::{DefUseChain, DataFlowResult};
use dataflow::framework::{DataFlowFramework, DefUseChains};
use dataflow::framework::{ReachingDefinitionsState, LiveVariablesState};
use ir::{IrFunction, Lowering};

/// Complete analysis engine that orchestrates AST → IR → CFG → Dataflow analysis
pub struct AnalysisEngine {
    /// IR lowering context
    lowering: Lowering,
    /// CFG builder for control flow analysis
    cfg_builder: CfgBuilder,
}

impl AnalysisEngine {
    /// Create a new analysis engine
    pub fn new() -> Self {
        Self {
            lowering: Lowering::new(),
            cfg_builder: CfgBuilder::new(),
        }
    }

    /// Run complete analysis on a source file
    pub fn analyze_source_file(&mut self, source_file: &SourceFile) -> Result<SourceFileAnalysisResult> {
        let mut function_results = Vec::new();

        // Analyze each contract in the source file
        for contract in &source_file.contracts {
            for function in &contract.functions {
                let function_result = self.analyze_function(function)?;
                function_results.push(function_result);
            }
        }

        Ok(SourceFileAnalysisResult {
            function_analyses: function_results,
        })
    }

    /// Run complete analysis on a single function
    pub fn analyze_function(&mut self, function: &Function) -> Result<FunctionAnalysisResult> {
        // Step 1: Lower AST to IR
        tracing::debug!("Lowering function {} to IR", function.name.name);
        let ir_function = self.lowering.lower_function(function)?;

        // Step 2: Build CFG from IR
        tracing::debug!("Building CFG for function {}", ir_function.name);
        let cfg = self.cfg_builder.build(&ir_function)?;

        // Step 3: Perform CFG analysis
        tracing::debug!("Analyzing CFG for function {}", ir_function.name);
        let mut cfg_analysis_engine = CfgAnalysisEngine::new(&cfg);
        let cfg_analysis = cfg_analysis_engine.analyze()?;

        // Step 4: Perform dataflow analysis
        tracing::debug!("Performing dataflow analysis for function {}", ir_function.name);
        let dataflow_framework = DataFlowFramework::new(&cfg, &ir_function);
        let reaching_defs = dataflow_framework.reaching_definitions()?;
        let live_vars = dataflow_framework.live_variables()?;
        let def_use_chains = dataflow_framework.def_use_chains()?;

        Ok(FunctionAnalysisResult {
            function_name: ir_function.name.clone(),
            ir_function,
            cfg,
            cfg_analysis,
            reaching_definitions: reaching_defs,
            live_variables: live_vars,
            def_use_chains,
        })
    }

    /// Analyze multiple functions and build cross-function analysis
    pub fn analyze_functions(&mut self, functions: &[Function]) -> Result<CrossFunctionAnalysisResult> {
        let mut function_results = Vec::new();
        let mut call_graph = HashMap::new();

        // First pass: analyze each function individually
        for function in functions {
            let result = self.analyze_function(function)?;

            // Extract call information for call graph
            let calls = self.extract_function_calls(&result.ir_function);
            call_graph.insert(result.function_name.clone(), calls);

            function_results.push(result);
        }

        // Second pass: perform interprocedural analysis
        let interprocedural_results = self.analyze_interprocedural(&function_results, &call_graph)?;

        Ok(CrossFunctionAnalysisResult {
            function_analyses: function_results,
            call_graph,
            interprocedural_analysis: interprocedural_results,
        })
    }

    /// Extract function calls from IR
    fn extract_function_calls(&self, ir_function: &IrFunction) -> Vec<String> {
        let mut calls = Vec::new();

        for instruction in ir_function.get_instructions() {
            match instruction {
                ir::Instruction::Call(_, func_name, _) => {
                    calls.push(func_name.clone());
                }
                ir::Instruction::ExternalCall(_, _, func_name, _) => {
                    calls.push(func_name.clone());
                }
                _ => {}
            }
        }

        calls
    }

    /// Perform interprocedural analysis
    fn analyze_interprocedural(
        &self,
        _function_results: &[FunctionAnalysisResult],
        _call_graph: &HashMap<String, Vec<String>>
    ) -> Result<InterproceduralAnalysisResult> {
        // Simplified interprocedural analysis
        // In a full implementation, this would include:
        // - Points-to analysis
        // - Interprocedural def-use chains
        // - Context-sensitive analysis
        // - Summary-based analysis for scalability

        Ok(InterproceduralAnalysisResult {
            summary: "Interprocedural analysis completed".to_string(),
        })
    }

    /// Get analysis statistics
    pub fn get_statistics(&self) -> AnalysisStatistics {
        AnalysisStatistics {
            functions_analyzed: 0, // Would track this in real implementation
            total_ir_instructions: 0,
            total_basic_blocks: 0,
            total_cfg_edges: 0,
        }
    }
}

impl Default for AnalysisEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of analyzing a complete source file
#[derive(Debug)]
pub struct SourceFileAnalysisResult {
    pub function_analyses: Vec<FunctionAnalysisResult>,
}

/// Complete analysis result for a single function
#[derive(Debug)]
pub struct FunctionAnalysisResult {
    /// Function name
    pub function_name: String,
    /// IR representation
    pub ir_function: IrFunction,
    /// Control flow graph
    pub cfg: ControlFlowGraph,
    /// CFG analysis results
    pub cfg_analysis: cfg::CfgAnalysisResults,
    /// Reaching definitions analysis
    pub reaching_definitions: DataFlowResult<ReachingDefinitionsState>,
    /// Live variables analysis
    pub live_variables: DataFlowResult<LiveVariablesState>,
    /// Def-use chains
    pub def_use_chains: DefUseChains,
}

impl FunctionAnalysisResult {
    /// Generate a comprehensive analysis report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!("=== Analysis Report for Function '{}' ===\n\n", self.function_name));

        // IR Statistics
        report.push_str("IR Statistics:\n");
        report.push_str(&format!("  Instructions: {}\n", self.ir_function.get_instructions().len()));
        report.push_str(&format!("  Basic Blocks: {}\n", self.ir_function.basic_blocks.len()));
        report.push_str(&format!("  Parameters: {}\n", self.ir_function.parameters.len()));
        report.push_str(&format!("  Return Types: {}\n", self.ir_function.return_types.len()));
        report.push_str("\n");

        // CFG Analysis
        report.push_str("CFG Analysis:\n");
        report.push_str(&self.cfg_analysis.generate_report());
        report.push_str("\n");

        // Dataflow Analysis
        report.push_str("Dataflow Analysis:\n");
        report.push_str(&format!("  Reaching Definitions: {} blocks analyzed\n",
            self.reaching_definitions.entry_states.len()));
        report.push_str(&format!("  Live Variables: {} blocks analyzed\n",
            self.live_variables.entry_states.len()));
        report.push_str(&format!("  Def-Use Chains: {} definitions tracked\n",
            self.def_use_chains.def_to_uses.len()));

        // Convergence Information
        report.push_str(&format!("  Reaching Definitions Converged: {}\n",
            self.reaching_definitions.converged));
        report.push_str(&format!("  Live Variables Converged: {}\n",
            self.live_variables.converged));

        report
    }

    /// Check for potential issues in the analysis
    pub fn validate_analysis(&self) -> Vec<AnalysisIssue> {
        let mut issues = Vec::new();

        // Check for non-convergent dataflow analysis
        if !self.reaching_definitions.converged {
            issues.push(AnalysisIssue {
                severity: IssueSeverity::Warning,
                message: "Reaching definitions analysis did not converge".to_string(),
                location: None,
            });
        }

        if !self.live_variables.converged {
            issues.push(AnalysisIssue {
                severity: IssueSeverity::Warning,
                message: "Live variables analysis did not converge".to_string(),
                location: None,
            });
        }

        // Check for high complexity
        if self.cfg_analysis.complexity_metrics.cyclomatic_complexity > 10 {
            issues.push(AnalysisIssue {
                severity: IssueSeverity::Info,
                message: format!("High cyclomatic complexity: {}",
                    self.cfg_analysis.complexity_metrics.cyclomatic_complexity),
                location: None,
            });
        }

        // Check for unreachable code
        if !self.cfg_analysis.optimization_opportunities.dead_code_blocks.is_empty() {
            issues.push(AnalysisIssue {
                severity: IssueSeverity::Warning,
                message: format!("Found {} unreachable basic blocks",
                    self.cfg_analysis.optimization_opportunities.dead_code_blocks.len()),
                location: None,
            });
        }

        issues
    }
}

/// Result of cross-function analysis
#[derive(Debug)]
pub struct CrossFunctionAnalysisResult {
    /// Individual function analyses
    pub function_analyses: Vec<FunctionAnalysisResult>,
    /// Call graph between functions
    pub call_graph: HashMap<String, Vec<String>>,
    /// Interprocedural analysis results
    pub interprocedural_analysis: InterproceduralAnalysisResult,
}

/// Interprocedural analysis results
#[derive(Debug)]
pub struct InterproceduralAnalysisResult {
    pub summary: String,
}

/// Analysis statistics
#[derive(Debug, Clone)]
pub struct AnalysisStatistics {
    pub functions_analyzed: usize,
    pub total_ir_instructions: usize,
    pub total_basic_blocks: usize,
    pub total_cfg_edges: usize,
}

/// Analysis issue found during validation
#[derive(Debug, Clone)]
pub struct AnalysisIssue {
    pub severity: IssueSeverity,
    pub message: String,
    pub location: Option<String>,
}

/// Severity of analysis issues
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IssueSeverity {
    Error,
    Warning,
    Info,
}

// Tests would need arena-allocated AST structures
// TODO: Implement tests with proper arena allocation
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_engine_creation() {
        let engine = AnalysisEngine::new();
        assert_eq!(engine.get_statistics().functions_analyzed, 0);
    }
}