use std::collections::HashSet;
use anyhow::Result;

use ir::{IrFunction, BlockId, Instruction};
use crate::graph::{ControlFlowGraph, EdgeType};

/// Builder for constructing Control Flow Graphs from IR functions
pub struct CfgBuilder {
    /// Options for CFG construction
    options: CfgBuilderOptions,
}

/// Configuration options for CFG construction
#[derive(Debug, Clone)]
pub struct CfgBuilderOptions {
    /// Whether to eliminate unreachable blocks during construction
    pub eliminate_unreachable: bool,
    /// Whether to merge trivial blocks (empty blocks with single pred/succ)
    pub merge_trivial_blocks: bool,
    /// Whether to identify and mark back edges
    pub identify_back_edges: bool,
    /// Whether to perform CFG validation after construction
    pub validate_cfg: bool,
}

impl Default for CfgBuilderOptions {
    fn default() -> Self {
        Self {
            eliminate_unreachable: true,
            merge_trivial_blocks: true,
            identify_back_edges: true,
            validate_cfg: true,
        }
    }
}

impl CfgBuilder {
    /// Create a new CFG builder with default options
    pub fn new() -> Self {
        Self {
            options: CfgBuilderOptions::default(),
        }
    }

    /// Create a new CFG builder with custom options
    pub fn with_options(options: CfgBuilderOptions) -> Self {
        Self { options }
    }

    /// Build a CFG from an IR function
    pub fn build(&self, ir_function: &IrFunction) -> Result<ControlFlowGraph> {
        let mut cfg = ControlFlowGraph::new(ir_function.name.clone());

        // Phase 1: Add all basic blocks to the CFG
        self.add_basic_blocks(&mut cfg, ir_function)?;

        // Phase 2: Set the entry block
        cfg.set_entry_block(ir_function.entry_block)?;

        // Phase 3: Analyze control flow and add edges
        self.add_control_flow_edges(&mut cfg, ir_function)?;

        // Phase 4: Post-processing optimizations
        if self.options.identify_back_edges {
            self.identify_back_edges(&mut cfg)?;
        }

        if self.options.eliminate_unreachable {
            self.eliminate_unreachable_blocks(&mut cfg)?;
        }

        if self.options.merge_trivial_blocks {
            self.merge_trivial_blocks(&mut cfg)?;
        }

        // Phase 5: Validation
        if self.options.validate_cfg {
            cfg.validate()?;
        }

        Ok(cfg)
    }

    /// Add all basic blocks from IR function to CFG
    fn add_basic_blocks(&self, cfg: &mut ControlFlowGraph, ir_function: &IrFunction) -> Result<()> {
        for (block_id, basic_block) in &ir_function.basic_blocks {
            cfg.add_block(*block_id, basic_block.instructions.clone());
        }
        Ok(())
    }

    /// Analyze control flow and add edges between blocks
    fn add_control_flow_edges(&self, cfg: &mut ControlFlowGraph, ir_function: &IrFunction) -> Result<()> {
        for (block_id, basic_block) in &ir_function.basic_blocks {
            self.analyze_block_control_flow(cfg, *block_id, basic_block)?;
        }
        Ok(())
    }

    /// Analyze control flow for a single basic block
    fn analyze_block_control_flow(
        &self,
        cfg: &mut ControlFlowGraph,
        block_id: BlockId,
        basic_block: &ir::BasicBlock
    ) -> Result<()> {
        // Look at the last instruction to determine control flow
        if let Some(last_instruction) = basic_block.instructions.last() {
            match last_instruction {
                Instruction::Branch(target_block) => {
                    cfg.add_edge(block_id, *target_block, EdgeType::Unconditional)?;
                }

                Instruction::ConditionalBranch(_condition, true_block, false_block) => {
                    cfg.add_edge(block_id, *true_block, EdgeType::True)?;
                    cfg.add_edge(block_id, *false_block, EdgeType::False)?;
                }

                Instruction::Return(_) | Instruction::Revert(_) | Instruction::SelfDestruct(_) => {
                    // These are terminating instructions - no outgoing edges
                }

                _ => {
                    // For blocks without explicit control flow, try to find implicit fall-through
                    self.add_fall_through_edge(cfg, block_id, basic_block)?;
                }
            }
        } else if !basic_block.instructions.is_empty() {
            // Empty block - try to add fall-through
            self.add_fall_through_edge(cfg, block_id, basic_block)?;
        }

        Ok(())
    }

    /// Add fall-through edge for blocks without explicit control flow
    fn add_fall_through_edge(
        &self,
        _cfg: &mut ControlFlowGraph,
        _block_id: BlockId,
        _basic_block: &ir::BasicBlock
    ) -> Result<()> {
        // For now, we don't add implicit fall-through edges
        // In a real implementation, this would analyze the block layout
        // and add edges to the next sequential block if appropriate
        Ok(())
    }

    /// Identify and mark back edges in the CFG
    fn identify_back_edges(&self, cfg: &mut ControlFlowGraph) -> Result<()> {
        let back_edges = cfg.back_edges();

        // Update edge types for identified back edges
        for (from_block, to_block) in back_edges {
            // This is a simplified implementation
            // In practice, we'd need to update the actual edge data in the graph
            tracing::debug!("Identified back edge: {} -> {}", from_block, to_block);
        }

        Ok(())
    }

    /// Remove unreachable blocks from the CFG
    fn eliminate_unreachable_blocks(&self, cfg: &mut ControlFlowGraph) -> Result<()> {
        let unreachable_blocks = cfg.find_unreachable_blocks();

        if !unreachable_blocks.is_empty() {
            tracing::info!("Eliminating {} unreachable blocks", unreachable_blocks.len());
            // In a real implementation, we would remove these blocks from the graph
            // For now, just log them
            for block_id in unreachable_blocks {
                tracing::debug!("Unreachable block: {}", block_id);
            }
        }

        Ok(())
    }

    /// Merge trivial blocks (empty blocks with single predecessor and successor)
    fn merge_trivial_blocks(&self, cfg: &mut ControlFlowGraph) -> Result<()> {
        let mergeable_blocks = cfg.find_mergeable_blocks();

        if !mergeable_blocks.is_empty() {
            tracing::info!("Found {} mergeable blocks", mergeable_blocks.len());
            // In a real implementation, we would merge these blocks
            // For now, just log them
            for block_id in mergeable_blocks {
                tracing::debug!("Mergeable block: {}", block_id);
            }
        }

        Ok(())
    }
}

impl Default for CfgBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Loop analysis for identifying natural loops and loop structures
pub struct LoopAnalysis<'a> {
    cfg: &'a ControlFlowGraph,
}

impl<'a> LoopAnalysis<'a> {
    /// Create a new loop analysis for the given CFG
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self { cfg }
    }

    /// Find loop headers (blocks that are targets of back edges)
    pub fn find_loop_headers(&self) -> Vec<BlockId> {
        let back_edges = self.cfg.back_edges();
        let mut headers = HashSet::new();

        for (_from, to) in back_edges {
            headers.insert(to);
        }

        headers.into_iter().collect()
    }

    /// Find natural loops in the CFG
    pub fn find_natural_loops(&self) -> Vec<NaturalLoop> {
        let back_edges = self.cfg.back_edges();
        let mut loops = Vec::new();

        for (latch, header) in back_edges {
            let loop_blocks = self.find_loop_blocks(header, latch);
            loops.push(NaturalLoop {
                header,
                latch,
                blocks: loop_blocks,
            });
        }

        loops
    }

    /// Find all blocks that belong to a loop defined by header and latch
    fn find_loop_blocks(&self, header: BlockId, latch: BlockId) -> Vec<BlockId> {
        let mut loop_blocks = HashSet::new();
        let mut worklist = vec![latch];

        loop_blocks.insert(header);
        loop_blocks.insert(latch);

        while let Some(current) = worklist.pop() {
            for pred in self.cfg.predecessors(current) {
                if !loop_blocks.contains(&pred) {
                    loop_blocks.insert(pred);
                    worklist.push(pred);
                }
            }
        }

        loop_blocks.into_iter().collect()
    }

    /// Check if a block is inside a loop
    pub fn is_in_loop(&self, block_id: BlockId) -> bool {
        let natural_loops = self.find_natural_loops();
        natural_loops.iter().any(|loop_info| loop_info.blocks.contains(&block_id))
    }

    /// Get the nesting depth of loops at a given block
    pub fn loop_nesting_depth(&self, block_id: BlockId) -> usize {
        let natural_loops = self.find_natural_loops();
        natural_loops.iter()
            .filter(|loop_info| loop_info.blocks.contains(&block_id))
            .count()
    }

    /// Find the innermost loop containing a block
    pub fn innermost_loop(&self, block_id: BlockId) -> Option<NaturalLoop> {
        let natural_loops = self.find_natural_loops();

        // Find the loop with the smallest number of blocks that contains this block
        natural_loops.into_iter()
            .filter(|loop_info| loop_info.blocks.contains(&block_id))
            .min_by_key(|loop_info| loop_info.blocks.len())
    }
}

/// Represents a natural loop in the CFG
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    /// Loop header (target of back edge)
    pub header: BlockId,
    /// Loop latch (source of back edge)
    pub latch: BlockId,
    /// All blocks in the loop
    pub blocks: Vec<BlockId>,
}

impl NaturalLoop {
    /// Check if this loop contains another block
    pub fn contains(&self, block_id: BlockId) -> bool {
        self.blocks.contains(&block_id)
    }

    /// Get the size of the loop (number of blocks)
    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    /// Check if this is a simple loop (single basic block looping to itself)
    pub fn is_self_loop(&self) -> bool {
        self.header == self.latch && self.blocks.len() == 1
    }
}

/// Advanced CFG analysis utilities
pub struct CfgAnalysis<'a> {
    cfg: &'a ControlFlowGraph,
}

impl<'a> CfgAnalysis<'a> {
    /// Create a new CFG analysis
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self { cfg }
    }

    /// Perform depth-first search and return blocks in DFS order
    pub fn dfs_order(&self) -> Vec<BlockId> {
        let mut visited = HashSet::new();
        let mut dfs_order = Vec::new();

        if let Some(entry_block) = self.cfg.entry_block_id() {
            self.dfs_visit(entry_block, &mut visited, &mut dfs_order);
        }

        dfs_order
    }

    /// DFS visit helper
    fn dfs_visit(&self, block_id: BlockId, visited: &mut HashSet<BlockId>, order: &mut Vec<BlockId>) {
        if visited.contains(&block_id) {
            return;
        }

        visited.insert(block_id);
        order.push(block_id);

        for successor in self.cfg.successors(block_id) {
            self.dfs_visit(successor, visited, order);
        }
    }

    /// Perform breadth-first search and return blocks in BFS order
    pub fn bfs_order(&self) -> Vec<BlockId> {
        let mut visited = HashSet::new();
        let mut bfs_order = Vec::new();
        let mut queue = std::collections::VecDeque::new();

        if let Some(entry_block) = self.cfg.entry_block_id() {
            queue.push_back(entry_block);
            visited.insert(entry_block);
        }

        while let Some(current) = queue.pop_front() {
            bfs_order.push(current);

            for successor in self.cfg.successors(current) {
                if !visited.contains(&successor) {
                    visited.insert(successor);
                    queue.push_back(successor);
                }
            }
        }

        bfs_order
    }

    /// Check if the CFG is reducible (has proper control structure)
    pub fn is_reducible(&self) -> bool {
        // Simplified reducibility check
        // A CFG is reducible if every loop has a single entry point (natural loops)
        let loop_analysis = LoopAnalysis::new(self.cfg);
        let natural_loops = loop_analysis.find_natural_loops();
        let back_edges = self.cfg.back_edges();

        // If number of natural loops equals number of back edges, CFG is likely reducible
        natural_loops.len() == back_edges.len()
    }

    /// Calculate cyclomatic complexity of the CFG
    pub fn cyclomatic_complexity(&self) -> usize {
        let stats = self.cfg.statistics();
        // Cyclomatic complexity = E - N + 2 (for connected graph)
        // where E = edges, N = nodes
        if stats.block_count == 0 {
            0
        } else {
            // Use signed arithmetic to handle E - N properly, then add 2
            let complexity = stats.edge_count as i32 - stats.block_count as i32 + 2;
            complexity.max(1) as usize // Minimum complexity is 1
        }
    }

    /// Find strongly connected components
    pub fn strongly_connected_components(&self) -> Vec<Vec<BlockId>> {
        // Simplified SCC implementation using Tarjan's algorithm concepts
        let mut components = Vec::new();
        let mut visited = HashSet::new();

        // For each unvisited node, find its SCC
        for (block_id, _) in self.cfg.basic_blocks() {
            if !visited.contains(&block_id) {
                let mut component = Vec::new();
                self.collect_scc(block_id, &mut visited, &mut component);
                if !component.is_empty() {
                    components.push(component);
                }
            }
        }

        components
    }

    /// Helper to collect strongly connected component
    fn collect_scc(&self, block_id: BlockId, visited: &mut HashSet<BlockId>, component: &mut Vec<BlockId>) {
        if visited.contains(&block_id) {
            return;
        }

        visited.insert(block_id);
        component.push(block_id);

        // For simplicity, treat each block as its own SCC unless there are back edges
        for successor in self.cfg.successors(block_id) {
            if self.cfg.can_reach(successor, block_id) {
                // There's a cycle, so they're in the same SCC
                self.collect_scc(successor, visited, component);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::IrFunction;

    fn create_test_function() -> IrFunction {
        let mut ir_function = IrFunction::new(
            "test_function".to_string(),
            vec![],
            vec![],
        );

        // Add some basic blocks with simple control flow
        let block1 = ir_function.create_block();
        let block2 = ir_function.create_block();

        // Entry block branches to block1
        ir_function.add_instruction(ir_function.entry_block,
            Instruction::Branch(block1)
        ).unwrap();

        ir_function.add_instruction(block1,
            Instruction::Branch(block2)
        ).unwrap();

        ir_function.add_instruction(block2,
            Instruction::Return(None)
        ).unwrap();

        ir_function
    }

    #[test]
    fn test_cfg_builder_creation() {
        let builder = CfgBuilder::new();
        assert!(builder.options.eliminate_unreachable);
        assert!(builder.options.merge_trivial_blocks);
        assert!(builder.options.identify_back_edges);
        assert!(builder.options.validate_cfg);
    }

    #[test]
    fn test_cfg_builder_with_custom_options() {
        let options = CfgBuilderOptions {
            eliminate_unreachable: false,
            merge_trivial_blocks: false,
            identify_back_edges: false,
            validate_cfg: false,
        };

        let builder = CfgBuilder::with_options(options);
        assert!(!builder.options.eliminate_unreachable);
        assert!(!builder.options.merge_trivial_blocks);
        assert!(!builder.options.identify_back_edges);
        assert!(!builder.options.validate_cfg);
    }

    #[test]
    fn test_simple_cfg_construction() {
        let ir_function = create_test_function();
        let builder = CfgBuilder::new();

        let result = builder.build(&ir_function);
        assert!(result.is_ok());

        let cfg = result.unwrap();
        assert_eq!(cfg.statistics().block_count, 3); // entry + block1 + block2
        assert!(cfg.entry_block_id().is_some());
    }

    #[test]
    fn test_loop_analysis() {
        let mut cfg = ControlFlowGraph::new("test_loop".to_string());
        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block3 = BlockId(3);

        cfg.add_block(block1, vec![]);
        cfg.add_block(block2, vec![]);
        cfg.add_block(block3, vec![]);

        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();
        cfg.add_edge(block2, block3, EdgeType::Unconditional).unwrap();
        cfg.add_edge(block3, block2, EdgeType::Back).unwrap(); // Create loop

        let loop_analysis = LoopAnalysis::new(&cfg);
        let headers = loop_analysis.find_loop_headers();
        assert!(headers.contains(&block2));

        let natural_loops = loop_analysis.find_natural_loops();
        assert_eq!(natural_loops.len(), 1);
        assert_eq!(natural_loops[0].header, block2);
        assert_eq!(natural_loops[0].latch, block3);
    }

    #[test]
    fn test_cfg_analysis() {
        let mut cfg = ControlFlowGraph::new("test_analysis".to_string());
        let block1 = BlockId(1);
        let block2 = BlockId(2);

        cfg.add_block(block1, vec![]);
        cfg.add_block(block2, vec![]);
        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();

        let analysis = CfgAnalysis::new(&cfg);
        let dfs_order = analysis.dfs_order();
        assert_eq!(dfs_order.len(), 2);
        assert_eq!(dfs_order[0], block1);

        let bfs_order = analysis.bfs_order();
        assert_eq!(bfs_order.len(), 2);
        assert_eq!(bfs_order[0], block1);

        let complexity = analysis.cyclomatic_complexity();
        assert_eq!(complexity, 1); // Linear control flow
    }

    #[test]
    fn test_natural_loop() {
        let natural_loop = NaturalLoop {
            header: BlockId(1),
            latch: BlockId(2),
            blocks: vec![BlockId(1), BlockId(2)],
        };

        assert!(natural_loop.contains(BlockId(1)));
        assert!(natural_loop.contains(BlockId(2)));
        assert!(!natural_loop.contains(BlockId(3)));
        assert_eq!(natural_loop.size(), 2);
        assert!(!natural_loop.is_self_loop());

        let self_loop = NaturalLoop {
            header: BlockId(1),
            latch: BlockId(1),
            blocks: vec![BlockId(1)],
        };
        assert!(self_loop.is_self_loop());
    }
}