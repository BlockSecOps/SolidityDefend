use std::collections::{HashMap, HashSet};
use anyhow::Result;

use ir::BlockId;
use crate::graph::ControlFlowGraph;
use crate::builder::{LoopAnalysis, NaturalLoop};
use crate::dominance::DominatorTree;
use crate::blocks::{BasicBlockAnalyzer, BasicBlockInfo};

/// Comprehensive CFG analysis combining multiple analysis types
pub struct CfgAnalysisEngine<'a> {
    cfg: &'a ControlFlowGraph,
    dominator_tree: Option<DominatorTree>,
    loop_analysis: Option<LoopAnalysis<'a>>,
    block_info: Option<BasicBlockInfo>,
}

impl<'a> CfgAnalysisEngine<'a> {
    /// Create a new CFG analysis engine
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self {
            cfg,
            dominator_tree: None,
            loop_analysis: None,
            block_info: None,
        }
    }

    /// Perform complete CFG analysis
    pub fn analyze(&mut self) -> Result<CfgAnalysisResults> {
        // Build dominator tree
        let dom_tree = DominatorTree::build(self.cfg)?;
        self.dominator_tree = Some(dom_tree.clone());

        // Perform loop analysis
        let loop_analysis = LoopAnalysis::new(self.cfg);
        let natural_loops = loop_analysis.find_natural_loops();
        self.loop_analysis = Some(loop_analysis);

        // Analyze basic blocks
        let _block_analyzer = BasicBlockAnalyzer::new();
        // For this to work, we'd need to convert from ControlFlowGraph to IrFunction
        // For now, we'll create a placeholder
        let block_info = BasicBlockInfo {
            leaders: HashSet::new(),
            terminators: HashSet::new(),
            boundaries: HashMap::new(),
            block_analyses: HashMap::new(),
        };
        self.block_info = Some(block_info);

        // Compile results
        let results = CfgAnalysisResults {
            cfg_statistics: self.cfg.statistics(),
            dominator_statistics: dom_tree.statistics(),
            natural_loops,
            complexity_metrics: self.compute_complexity_metrics()?,
            structural_properties: self.analyze_structural_properties()?,
            optimization_opportunities: self.find_optimization_opportunities()?,
        };

        Ok(results)
    }

    /// Compute complexity metrics for the CFG
    fn compute_complexity_metrics(&self) -> Result<ComplexityMetrics> {
        let stats = self.cfg.statistics();

        // McCabe's cyclomatic complexity: E - N + 2P
        // where E = edges, N = nodes, P = connected components (assume 1)
        let cyclomatic_complexity = if stats.block_count > 0 {
            stats.edge_count.saturating_sub(stats.block_count).saturating_add(2)
        } else {
            0
        };

        // Essential complexity (number of decision points)
        let essential_complexity = self.count_decision_points();

        // Nesting depth (maximum loop nesting)
        let max_nesting_depth = if let Some(ref loop_analysis) = self.loop_analysis {
            self.compute_max_nesting_depth(&loop_analysis.find_natural_loops())
        } else {
            0
        };

        Ok(ComplexityMetrics {
            cyclomatic_complexity,
            essential_complexity,
            max_nesting_depth,
            total_paths: self.estimate_total_paths(),
        })
    }

    /// Count decision points in the CFG
    fn count_decision_points(&self) -> usize {
        let mut decision_points = 0;

        for (block_id, _) in self.cfg.basic_blocks() {
            let successors = self.cfg.successors(block_id);
            if successors.len() > 1 {
                decision_points += 1;
            }
        }

        decision_points
    }

    /// Compute maximum nesting depth of loops
    fn compute_max_nesting_depth(&self, loops: &[NaturalLoop]) -> usize {
        let mut max_depth = 0;

        for loop_info in loops {
            let depth = self.compute_loop_nesting_depth(loop_info, loops);
            max_depth = max_depth.max(depth);
        }

        max_depth
    }

    /// Compute nesting depth for a specific loop
    fn compute_loop_nesting_depth(&self, target_loop: &NaturalLoop, all_loops: &[NaturalLoop]) -> usize {
        let mut depth = 1; // The loop itself

        for other_loop in all_loops {
            if other_loop.header != target_loop.header &&
               other_loop.contains(target_loop.header) {
                depth += 1;
            }
        }

        depth
    }

    /// Estimate total number of execution paths
    fn estimate_total_paths(&self) -> u64 {
        // Simplified path counting
        // In practice, this would use more sophisticated algorithms
        let decision_points = self.count_decision_points();
        if decision_points == 0 {
            1
        } else {
            2_u64.pow(decision_points as u32)
        }
    }

    /// Analyze structural properties of the CFG
    fn analyze_structural_properties(&self) -> Result<StructuralProperties> {
        let stats = self.cfg.statistics();
        let back_edges = self.cfg.back_edges();

        Ok(StructuralProperties {
            is_reducible: self.is_reducible(),
            is_acyclic: back_edges.is_empty(),
            has_multiple_entries: stats.entry_blocks > 1,
            has_multiple_exits: stats.exit_blocks > 1,
            has_unreachable_code: stats.unreachable_blocks > 0,
            is_well_structured: self.is_well_structured(),
        })
    }

    /// Check if the CFG is reducible
    fn is_reducible(&self) -> bool {
        // A CFG is reducible if it can be reduced to a single node
        // using a series of transformations that eliminate either:
        // 1. Self-loops
        // 2. Parallel edges
        // 3. Series connections

        // Simplified check: CFG is reducible if all loops are natural loops
        if let Some(ref loop_analysis) = self.loop_analysis {
            let natural_loops = loop_analysis.find_natural_loops();
            let back_edges = self.cfg.back_edges();
            natural_loops.len() == back_edges.len()
        } else {
            true // Assume reducible if no loops
        }
    }

    /// Check if the CFG is well-structured
    fn is_well_structured(&self) -> bool {
        // Well-structured CFG has:
        // 1. Single entry point
        // 2. Single exit point (or multiple with clear structure)
        // 3. No irreducible loops
        // 4. Proper nesting of control structures

        let stats = self.cfg.statistics();
        let is_single_entry = stats.entry_blocks == 1;
        let is_reducible = self.is_reducible();

        is_single_entry && is_reducible
    }

    /// Find optimization opportunities in the CFG
    fn find_optimization_opportunities(&self) -> Result<OptimizationOpportunities> {
        let unreachable_blocks = self.cfg.find_unreachable_blocks();
        let mergeable_blocks = self.cfg.find_mergeable_blocks();

        // Find empty blocks
        let empty_blocks = self.find_empty_blocks();

        // Find redundant branches
        let redundant_branches = self.find_redundant_branches();

        Ok(OptimizationOpportunities {
            dead_code_blocks: unreachable_blocks,
            mergeable_blocks,
            empty_blocks,
            redundant_branches,
            loop_optimizations: self.find_loop_optimizations(),
        })
    }

    /// Find empty blocks that can be optimized
    fn find_empty_blocks(&self) -> Vec<BlockId> {
        let mut empty_blocks = Vec::new();

        for (block_id, node) in self.cfg.basic_blocks() {
            if node.instructions.is_empty() {
                empty_blocks.push(block_id);
            }
        }

        empty_blocks
    }

    /// Find redundant branch instructions
    fn find_redundant_branches(&self) -> Vec<BlockId> {
        let mut redundant = Vec::new();

        for (block_id, _) in self.cfg.basic_blocks() {
            let successors = self.cfg.successors(block_id);

            // If a block has multiple edges to the same successor, it's redundant
            let mut unique_successors = HashSet::new();
            let mut has_duplicates = false;

            for successor in successors {
                if !unique_successors.insert(successor) {
                    has_duplicates = true;
                    break;
                }
            }

            if has_duplicates {
                redundant.push(block_id);
            }
        }

        redundant
    }

    /// Find loop optimization opportunities
    fn find_loop_optimizations(&self) -> Vec<LoopOptimization> {
        let mut optimizations = Vec::new();

        if let Some(ref loop_analysis) = self.loop_analysis {
            let natural_loops = loop_analysis.find_natural_loops();

            for loop_info in natural_loops {
                // Check for invariant code motion opportunities
                if loop_info.size() > 3 {
                    optimizations.push(LoopOptimization {
                        loop_header: loop_info.header,
                        optimization_type: LoopOptimizationType::InvariantCodeMotion,
                        description: "Large loop may benefit from invariant code motion".to_string(),
                    });
                }

                // Check for loop unrolling opportunities
                if loop_info.is_self_loop() {
                    optimizations.push(LoopOptimization {
                        loop_header: loop_info.header,
                        optimization_type: LoopOptimizationType::LoopUnrolling,
                        description: "Self-loop may benefit from unrolling".to_string(),
                    });
                }
            }
        }

        optimizations
    }
}

/// Complete analysis results for a CFG
#[derive(Debug, Clone)]
pub struct CfgAnalysisResults {
    pub cfg_statistics: crate::graph::CfgStatistics,
    pub dominator_statistics: crate::dominance::DominatorTreeStatistics,
    pub natural_loops: Vec<NaturalLoop>,
    pub complexity_metrics: ComplexityMetrics,
    pub structural_properties: StructuralProperties,
    pub optimization_opportunities: OptimizationOpportunities,
}

impl CfgAnalysisResults {
    /// Generate a comprehensive report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== CFG Analysis Report ===\n\n");

        report.push_str("CFG Statistics:\n");
        report.push_str(&format!("{}\n\n", self.cfg_statistics));

        report.push_str("Dominator Tree Statistics:\n");
        report.push_str(&format!("{}\n\n", self.dominator_statistics));

        report.push_str("Complexity Metrics:\n");
        report.push_str(&format!("{}\n\n", self.complexity_metrics));

        report.push_str("Structural Properties:\n");
        report.push_str(&format!("{}\n\n", self.structural_properties));

        report.push_str("Optimization Opportunities:\n");
        report.push_str(&format!("{}\n", self.optimization_opportunities));

        report
    }
}

/// Complexity metrics for the CFG
#[derive(Debug, Clone)]
pub struct ComplexityMetrics {
    pub cyclomatic_complexity: usize,
    pub essential_complexity: usize,
    pub max_nesting_depth: usize,
    pub total_paths: u64,
}

impl std::fmt::Display for ComplexityMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "  Cyclomatic Complexity: {}\n", self.cyclomatic_complexity)?;
        write!(f, "  Essential Complexity: {}\n", self.essential_complexity)?;
        write!(f, "  Max Nesting Depth: {}\n", self.max_nesting_depth)?;
        write!(f, "  Estimated Total Paths: {}", self.total_paths)
    }
}

/// Structural properties of the CFG
#[derive(Debug, Clone)]
pub struct StructuralProperties {
    pub is_reducible: bool,
    pub is_acyclic: bool,
    pub has_multiple_entries: bool,
    pub has_multiple_exits: bool,
    pub has_unreachable_code: bool,
    pub is_well_structured: bool,
}

impl std::fmt::Display for StructuralProperties {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "  Reducible: {}\n", self.is_reducible)?;
        write!(f, "  Acyclic: {}\n", self.is_acyclic)?;
        write!(f, "  Multiple Entries: {}\n", self.has_multiple_entries)?;
        write!(f, "  Multiple Exits: {}\n", self.has_multiple_exits)?;
        write!(f, "  Unreachable Code: {}\n", self.has_unreachable_code)?;
        write!(f, "  Well-Structured: {}", self.is_well_structured)
    }
}

/// Optimization opportunities identified in the CFG
#[derive(Debug, Clone)]
pub struct OptimizationOpportunities {
    pub dead_code_blocks: Vec<BlockId>,
    pub mergeable_blocks: Vec<BlockId>,
    pub empty_blocks: Vec<BlockId>,
    pub redundant_branches: Vec<BlockId>,
    pub loop_optimizations: Vec<LoopOptimization>,
}

impl std::fmt::Display for OptimizationOpportunities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "  Dead Code Blocks: {:?}\n", self.dead_code_blocks)?;
        write!(f, "  Mergeable Blocks: {:?}\n", self.mergeable_blocks)?;
        write!(f, "  Empty Blocks: {:?}\n", self.empty_blocks)?;
        write!(f, "  Redundant Branches: {:?}\n", self.redundant_branches)?;
        write!(f, "  Loop Optimizations: {} opportunities", self.loop_optimizations.len())
    }
}

/// Loop optimization opportunity
#[derive(Debug, Clone)]
pub struct LoopOptimization {
    pub loop_header: BlockId,
    pub optimization_type: LoopOptimizationType,
    pub description: String,
}

/// Types of loop optimizations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoopOptimizationType {
    InvariantCodeMotion,
    LoopUnrolling,
    LoopFusion,
    LoopInterchange,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{ControlFlowGraph, EdgeType};

    fn create_test_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new("test_function".to_string());

        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block3 = BlockId(3);

        cfg.add_block(block1, vec![]);
        cfg.add_block(block2, vec![]);
        cfg.add_block(block3, vec![]);

        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();
        cfg.add_edge(block2, block3, EdgeType::Unconditional).unwrap();

        cfg
    }

    #[test]
    fn test_cfg_analysis_engine() {
        let cfg = create_test_cfg();
        let mut engine = CfgAnalysisEngine::new(&cfg);

        let result = engine.analyze();
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(analysis.complexity_metrics.cyclomatic_complexity >= 1);
        assert!(!analysis.structural_properties.has_multiple_entries);
    }

    #[test]
    fn test_complexity_metrics() {
        let cfg = create_test_cfg();
        let mut engine = CfgAnalysisEngine::new(&cfg);

        let analysis = engine.analyze().unwrap();
        let metrics = &analysis.complexity_metrics;

        assert!(metrics.cyclomatic_complexity > 0);
        assert_eq!(metrics.essential_complexity, 0); // No decision points
        assert_eq!(metrics.max_nesting_depth, 0); // No loops
    }

    #[test]
    fn test_structural_properties() {
        let cfg = create_test_cfg();
        let mut engine = CfgAnalysisEngine::new(&cfg);

        let analysis = engine.analyze().unwrap();
        let props = &analysis.structural_properties;

        assert!(props.is_reducible);
        assert!(props.is_acyclic);
        assert!(!props.has_multiple_entries);
        assert!(props.is_well_structured);
    }

    #[test]
    fn test_optimization_opportunities() {
        let cfg = create_test_cfg();
        let mut engine = CfgAnalysisEngine::new(&cfg);

        let analysis = engine.analyze().unwrap();
        let opts = &analysis.optimization_opportunities;

        // Linear CFG should have some empty blocks and potential merging opportunities
        assert!(opts.dead_code_blocks.is_empty()); // All blocks should be reachable
    }

    #[test]
    fn test_report_generation() {
        let cfg = create_test_cfg();
        let mut engine = CfgAnalysisEngine::new(&cfg);

        let analysis = engine.analyze().unwrap();
        let report = analysis.generate_report();

        assert!(report.contains("CFG Analysis Report"));
        assert!(report.contains("Complexity Metrics"));
        assert!(report.contains("Structural Properties"));
        assert!(report.contains("Optimization Opportunities"));
    }
}