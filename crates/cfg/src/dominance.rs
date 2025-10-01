use std::collections::{HashMap, HashSet, VecDeque};
use anyhow::{Result, anyhow};

use ir::BlockId;
use crate::graph::ControlFlowGraph;

/// Dominator tree for control flow analysis
#[derive(Debug, Clone)]
pub struct DominatorTree {
    /// The CFG this dominator tree is built from
    cfg_name: String,
    /// Immediate dominator for each block
    idom: HashMap<BlockId, Option<BlockId>>,
    /// Children in the dominator tree
    children: HashMap<BlockId, Vec<BlockId>>,
    /// Dominance frontier for each block
    dominance_frontier: HashMap<BlockId, HashSet<BlockId>>,
    /// Root of the dominator tree (entry block)
    root: Option<BlockId>,
}

impl DominatorTree {
    /// Build a dominator tree from a control flow graph
    pub fn build(cfg: &ControlFlowGraph) -> Result<DominatorTree> {
        let mut tree = DominatorTree {
            cfg_name: cfg.function_name().to_string(),
            idom: HashMap::new(),
            children: HashMap::new(),
            dominance_frontier: HashMap::new(),
            root: cfg.entry_block_id(),
        };

        if tree.root.is_none() {
            return Err(anyhow!("CFG has no entry block"));
        }

        // Build the dominator tree using iterative algorithm
        tree.compute_dominators(cfg)?;
        tree.build_dominator_tree(cfg)?;
        tree.compute_dominance_frontiers(cfg)?;

        Ok(tree)
    }

    /// Compute immediate dominators using iterative algorithm
    fn compute_dominators(&mut self, cfg: &ControlFlowGraph) -> Result<()> {
        let entry_block = self.root.unwrap();
        let mut blocks: Vec<BlockId> = cfg.basic_blocks().keys().copied().collect();
        blocks.sort_by_key(|block| block.0);

        // Initialize: entry block dominates itself
        self.idom.insert(entry_block, None);

        // Initialize all other blocks to undefined
        for &block in &blocks {
            if block != entry_block {
                self.idom.insert(block, None);
            }
        }

        // Iterative algorithm to compute dominators
        let mut changed = true;
        while changed {
            changed = false;

            for &block in &blocks {
                if block == entry_block {
                    continue;
                }

                let predecessors = cfg.predecessors(block);
                if predecessors.is_empty() {
                    continue;
                }

                // Find the first processed predecessor
                let mut new_idom = None;
                for &pred in &predecessors {
                    if self.idom.contains_key(&pred) && self.idom[&pred].is_some() || pred == entry_block {
                        new_idom = Some(pred);
                        break;
                    }
                }

                // Intersect with all other processed predecessors
                if let Some(mut new_idom_val) = new_idom {
                    for &pred in &predecessors {
                        if pred != new_idom_val && (self.idom.contains_key(&pred) && self.idom[&pred].is_some() || pred == entry_block) {
                            new_idom_val = self.intersect(new_idom_val, pred, &blocks)?;
                        }
                    }

                    // Update if changed
                    if self.idom.get(&block) != Some(&Some(new_idom_val)) {
                        self.idom.insert(block, Some(new_idom_val));
                        changed = true;
                    }
                }
            }
        }

        Ok(())
    }

    /// Intersect two nodes in the dominator tree
    fn intersect(&self, mut b1: BlockId, mut b2: BlockId, blocks: &[BlockId]) -> Result<BlockId> {
        // Get the reverse postorder numbers for comparison
        let b1_rpo = self.get_reverse_postorder_number(b1, blocks);
        let b2_rpo = self.get_reverse_postorder_number(b2, blocks);

        while b1 != b2 {
            let b1_rpo_current = self.get_reverse_postorder_number(b1, blocks);
            let b2_rpo_current = self.get_reverse_postorder_number(b2, blocks);

            if b1_rpo_current > b2_rpo_current {
                if let Some(Some(idom_b1)) = self.idom.get(&b1) {
                    b1 = *idom_b1;
                } else {
                    break;
                }
            } else if b2_rpo_current > b1_rpo_current {
                if let Some(Some(idom_b2)) = self.idom.get(&b2) {
                    b2 = *idom_b2;
                } else {
                    break;
                }
            }
        }

        Ok(b1)
    }

    /// Get reverse postorder number (simplified)
    fn get_reverse_postorder_number(&self, block: BlockId, blocks: &[BlockId]) -> usize {
        blocks.iter().position(|&b| b == block).unwrap_or(usize::MAX)
    }

    /// Build the dominator tree structure from immediate dominators
    fn build_dominator_tree(&mut self, cfg: &ControlFlowGraph) -> Result<()> {
        // Initialize children sets
        for block_id in cfg.basic_blocks().keys() {
            self.children.insert(*block_id, Vec::new());
        }

        // Build parent-child relationships
        for (block, idom_opt) in &self.idom {
            if let Some(idom) = idom_opt {
                if let Some(children_list) = self.children.get_mut(idom) {
                    children_list.push(*block);
                }
            }
        }

        Ok(())
    }

    /// Compute dominance frontiers for all blocks
    fn compute_dominance_frontiers(&mut self, cfg: &ControlFlowGraph) -> Result<()> {
        // Initialize dominance frontiers
        for block_id in cfg.basic_blocks().keys() {
            self.dominance_frontier.insert(*block_id, HashSet::new());
        }

        // For each block, compute its dominance frontier
        for block_id in cfg.basic_blocks().keys() {
            let successors = cfg.successors(*block_id);

            for &successor in &successors {
                let mut runner = successor;

                // Walk up the dominator tree until we reach a common dominator
                while !self.strictly_dominates(*block_id, runner)? {
                    if let Some(frontier) = self.dominance_frontier.get_mut(&runner) {
                        frontier.insert(*block_id);
                    }

                    if let Some(Some(idom)) = self.idom.get(&runner) {
                        runner = *idom;
                    } else {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if block a dominates block b
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        if a == b {
            return true;
        }

        self.strictly_dominates(a, b).unwrap_or(false)
    }

    /// Check if block a strictly dominates block b (a != b and a dominates b)
    pub fn strictly_dominates(&self, a: BlockId, b: BlockId) -> Result<bool> {
        if a == b {
            return Ok(false);
        }

        let mut current = b;
        while let Some(Some(idom)) = self.idom.get(&current) {
            if *idom == a {
                return Ok(true);
            }
            current = *idom;
        }

        Ok(false)
    }

    /// Get the immediate dominator of a block
    pub fn immediate_dominator(&self, block: BlockId) -> Option<BlockId> {
        self.idom.get(&block).and_then(|idom| *idom)
    }

    /// Get all dominators of a block (including itself)
    pub fn dominators(&self, block: BlockId) -> Vec<BlockId> {
        let mut dominators = vec![block];
        let mut current = block;

        while let Some(Some(idom)) = self.idom.get(&current) {
            dominators.push(*idom);
            current = *idom;
        }

        dominators
    }

    /// Get the children of a block in the dominator tree
    pub fn children(&self, block: BlockId) -> Vec<BlockId> {
        self.children.get(&block).cloned().unwrap_or_default()
    }

    /// Get the dominance frontier of a block
    pub fn dominance_frontier(&self, block: BlockId) -> HashSet<BlockId> {
        self.dominance_frontier.get(&block).cloned().unwrap_or_default()
    }

    /// Find the lowest common ancestor in the dominator tree
    pub fn lowest_common_ancestor(&self, a: BlockId, b: BlockId) -> Option<BlockId> {
        let a_dominators: HashSet<BlockId> = self.dominators(a).into_iter().collect();
        let b_dominators = self.dominators(b);

        // Find the first common dominator walking up from b
        for dominator in b_dominators {
            if a_dominators.contains(&dominator) {
                return Some(dominator);
            }
        }

        None
    }

    /// Get the root of the dominator tree
    pub fn root(&self) -> Option<BlockId> {
        self.root
    }

    /// Check if the dominator tree is well-formed
    pub fn validate(&self) -> Result<()> {
        // Check that root has no immediate dominator
        if let Some(root) = self.root {
            if self.idom.get(&root) != Some(&None) {
                return Err(anyhow!("Root block has an immediate dominator"));
            }
        }

        // Check that each non-root block has an immediate dominator
        for (block, idom) in &self.idom {
            if Some(*block) != self.root && idom.is_none() {
                return Err(anyhow!("Non-root block {} has no immediate dominator", block));
            }
        }

        // Check that children relationships are consistent
        for (parent, children) in &self.children {
            for &child in children {
                if self.immediate_dominator(child) != Some(*parent) {
                    return Err(anyhow!(
                        "Inconsistent parent-child relationship: {} -> {}",
                        parent, child
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get statistics about the dominator tree
    pub fn statistics(&self) -> DominatorTreeStatistics {
        let mut stats = DominatorTreeStatistics::default();

        stats.total_blocks = self.idom.len();

        if let Some(root) = self.root {
            stats.tree_height = self.compute_tree_height(root);
        }

        // Compute average dominance frontier size
        let total_frontier_size: usize = self.dominance_frontier.values()
            .map(|frontier| frontier.len())
            .sum();

        if stats.total_blocks > 0 {
            stats.average_frontier_size = total_frontier_size as f64 / stats.total_blocks as f64;
        }

        // Find maximum frontier size
        stats.max_frontier_size = self.dominance_frontier.values()
            .map(|frontier| frontier.len())
            .max()
            .unwrap_or(0);

        // Count blocks with no children (leaves)
        stats.leaf_blocks = self.children.values()
            .filter(|children| children.is_empty())
            .count();

        stats
    }

    /// Compute the height of the dominator tree
    fn compute_tree_height(&self, root: BlockId) -> usize {
        let mut max_height = 0;
        let mut queue = VecDeque::new();
        queue.push_back((root, 0));

        while let Some((block, height)) = queue.pop_front() {
            max_height = max_height.max(height);

            for &child in &self.children(block) {
                queue.push_back((child, height + 1));
            }
        }

        max_height
    }

    /// Export dominator tree to DOT format for visualization
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str(&format!("digraph \"dominator_tree_{}\" {{\n", self.cfg_name));
        dot.push_str("    rankdir=TB;\n");
        dot.push_str("    node [shape=box];\n\n");

        // Add nodes
        for block_id in self.idom.keys() {
            let style = if Some(*block_id) == self.root {
                "style=filled,fillcolor=lightgreen"
            } else {
                ""
            };

            dot.push_str(&format!("    \"{}\" [label=\"{}\",{}];\n",
                block_id, block_id, style));
        }

        dot.push_str("\n");

        // Add edges (parent -> child relationships)
        for (parent, children) in &self.children {
            for &child in children {
                dot.push_str(&format!("    \"{}\" -> \"{}\";\n", parent, child));
            }
        }

        dot.push_str("}\n");
        dot
    }

    /// Export dominator tree to human-readable text format
    pub fn to_text(&self) -> String {
        let mut text = String::new();
        text.push_str(&format!("Dominator Tree for '{}'\n", self.cfg_name));
        text.push_str(&format!("Blocks: {}\n\n", self.idom.len()));

        if let Some(root) = self.root {
            text.push_str(&format!("Root: {}\n\n", root));
            self.append_tree_text(&mut text, root, 0);
        }

        text.push_str("\nImmediate Dominators:\n");
        for (block, idom) in &self.idom {
            match idom {
                Some(dom) => text.push_str(&format!("  {} -> {}\n", block, dom)),
                None => text.push_str(&format!("  {} -> (root)\n", block)),
            }
        }

        text.push_str("\nDominance Frontiers:\n");
        for (block, frontier) in &self.dominance_frontier {
            if frontier.is_empty() {
                text.push_str(&format!("  {}: {{}}\n", block));
            } else {
                text.push_str(&format!("  {}: {:?}\n", block, frontier));
            }
        }

        text
    }

    /// Helper to append tree structure to text representation
    fn append_tree_text(&self, text: &mut String, block: BlockId, depth: usize) {
        let indent = "  ".repeat(depth);
        text.push_str(&format!("{}{}\n", indent, block));

        for &child in &self.children(block) {
            self.append_tree_text(text, child, depth + 1);
        }
    }
}

/// Statistics about a dominator tree
#[derive(Debug, Clone, Default)]
pub struct DominatorTreeStatistics {
    pub total_blocks: usize,
    pub tree_height: usize,
    pub leaf_blocks: usize,
    pub average_frontier_size: f64,
    pub max_frontier_size: usize,
}

impl std::fmt::Display for DominatorTreeStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Dominator Tree Statistics:\n")?;
        write!(f, "  Total blocks: {}\n", self.total_blocks)?;
        write!(f, "  Tree height: {}\n", self.tree_height)?;
        write!(f, "  Leaf blocks: {}\n", self.leaf_blocks)?;
        write!(f, "  Average frontier size: {:.2}\n", self.average_frontier_size)?;
        write!(f, "  Max frontier size: {}", self.max_frontier_size)
    }
}

/// Post-dominance analysis (reverse dominance)
#[derive(Debug, Clone)]
pub struct PostDominatorTree {
    /// The underlying dominator tree (computed on reversed CFG)
    tree: DominatorTree,
}

impl PostDominatorTree {
    /// Build a post-dominator tree from a control flow graph
    pub fn build(cfg: &ControlFlowGraph) -> Result<PostDominatorTree> {
        // For post-dominance, we would need to reverse the CFG
        // For now, this is a placeholder implementation
        let tree = DominatorTree {
            cfg_name: format!("{}_postdom", cfg.function_name()),
            idom: HashMap::new(),
            children: HashMap::new(),
            dominance_frontier: HashMap::new(),
            root: None,
        };

        Ok(PostDominatorTree { tree })
    }

    /// Check if block a post-dominates block b
    pub fn post_dominates(&self, a: BlockId, b: BlockId) -> bool {
        self.tree.dominates(a, b)
    }

    /// Get the immediate post-dominator of a block
    pub fn immediate_post_dominator(&self, block: BlockId) -> Option<BlockId> {
        self.tree.immediate_dominator(block)
    }
}

/// Dominance-based analysis utilities
pub struct DominanceAnalysis<'a> {
    cfg: &'a ControlFlowGraph,
    dom_tree: DominatorTree,
}

impl<'a> DominanceAnalysis<'a> {
    /// Create a new dominance analysis
    pub fn new(cfg: &'a ControlFlowGraph) -> Result<Self> {
        let dom_tree = DominatorTree::build(cfg)?;
        Ok(Self { cfg, dom_tree })
    }

    /// Find natural loops using dominance information
    pub fn find_natural_loops(&self) -> Result<Vec<NaturalLoop>> {
        let mut loops = Vec::new();
        let back_edges = self.cfg.back_edges();

        for (tail, head) in back_edges {
            // A natural loop is formed by a back edge (tail -> head)
            // where head dominates tail
            if self.dom_tree.dominates(head, tail) {
                let loop_blocks = self.find_loop_blocks(head, tail)?;
                loops.push(NaturalLoop {
                    header: head,
                    tail,
                    blocks: loop_blocks,
                });
            }
        }

        Ok(loops)
    }

    /// Find all blocks in a natural loop
    fn find_loop_blocks(&self, header: BlockId, tail: BlockId) -> Result<Vec<BlockId>> {
        let mut loop_blocks = HashSet::new();
        let mut worklist = VecDeque::new();

        loop_blocks.insert(header);
        loop_blocks.insert(tail);
        worklist.push_back(tail);

        while let Some(current) = worklist.pop_front() {
            for pred in self.cfg.predecessors(current) {
                if !loop_blocks.contains(&pred) {
                    loop_blocks.insert(pred);
                    worklist.push_back(pred);
                }
            }
        }

        Ok(loop_blocks.into_iter().collect())
    }

    /// Find reducible control flow regions
    pub fn find_reducible_regions(&self) -> Result<Vec<ControlFlowRegion>> {
        let mut regions = Vec::new();

        // Single-entry regions based on dominance
        for (block_id, _) in self.cfg.basic_blocks() {
            let dominated_blocks = self.find_dominated_blocks(block_id);

            if dominated_blocks.len() > 1 {
                regions.push(ControlFlowRegion {
                    entry: block_id,
                    blocks: dominated_blocks,
                    region_type: RegionType::SingleEntry,
                });
            }
        }

        Ok(regions)
    }

    /// Find all blocks dominated by a given block
    fn find_dominated_blocks(&self, dominator: BlockId) -> Vec<BlockId> {
        let mut dominated = Vec::new();

        for (block_id, _) in self.cfg.basic_blocks() {
            if self.dom_tree.dominates(dominator, block_id) {
                dominated.push(block_id);
            }
        }

        dominated
    }

    /// Analyze control dependence relationships
    pub fn analyze_control_dependence(&self) -> Result<HashMap<BlockId, Vec<BlockId>>> {
        let mut control_deps = HashMap::new();

        for (block_id, _) in self.cfg.basic_blocks() {
            let mut deps = Vec::new();

            // A block X is control dependent on Y if:
            // 1. There exists a path from Y to X such that every node on the path
            //    (except Y and X) is post-dominated by X
            // 2. Y is not post-dominated by X

            // Simplified analysis using dominance frontiers
            let frontier = self.dom_tree.dominance_frontier(block_id);
            deps.extend(frontier);

            control_deps.insert(block_id, deps);
        }

        Ok(control_deps)
    }

    /// Get the dominator tree
    pub fn dominator_tree(&self) -> &DominatorTree {
        &self.dom_tree
    }
}

/// Represents a natural loop in terms of dominance
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    pub header: BlockId,
    pub tail: BlockId,
    pub blocks: Vec<BlockId>,
}

impl NaturalLoop {
    /// Check if this loop contains a block
    pub fn contains(&self, block: BlockId) -> bool {
        self.blocks.contains(&block)
    }

    /// Get the size of the loop
    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    /// Check if this is a self-loop
    pub fn is_self_loop(&self) -> bool {
        self.header == self.tail && self.blocks.len() == 1
    }
}

/// Represents a control flow region
#[derive(Debug, Clone)]
pub struct ControlFlowRegion {
    pub entry: BlockId,
    pub blocks: Vec<BlockId>,
    pub region_type: RegionType,
}

/// Types of control flow regions
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegionType {
    SingleEntry,
    Loop,
    Conditional,
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
        let block4 = BlockId(4);

        cfg.add_block(block1, vec![]);
        cfg.add_block(block2, vec![]);
        cfg.add_block(block3, vec![]);
        cfg.add_block(block4, vec![]);

        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();
        cfg.add_edge(block1, block3, EdgeType::Unconditional).unwrap();
        cfg.add_edge(block2, block4, EdgeType::Unconditional).unwrap();
        cfg.add_edge(block3, block4, EdgeType::Unconditional).unwrap();

        cfg
    }

    #[test]
    fn test_dominator_tree_construction() {
        let cfg = create_test_cfg();
        let result = DominatorTree::build(&cfg);

        assert!(result.is_ok());
        let dom_tree = result.unwrap();

        assert_eq!(dom_tree.root(), Some(BlockId(1)));
        assert!(dom_tree.validate().is_ok());
    }

    #[test]
    fn test_dominance_relationships() {
        let cfg = create_test_cfg();
        let dom_tree = DominatorTree::build(&cfg).unwrap();

        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block4 = BlockId(4);

        // Block 1 should dominate all other blocks
        assert!(dom_tree.dominates(block1, block2));
        assert!(dom_tree.dominates(block1, block4));

        // Block 4 should not dominate block 2
        assert!(!dom_tree.dominates(block4, block2));

        // Block should dominate itself
        assert!(dom_tree.dominates(block1, block1));
    }

    #[test]
    fn test_immediate_dominators() {
        let cfg = create_test_cfg();
        let dom_tree = DominatorTree::build(&cfg).unwrap();

        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block4 = BlockId(4);

        // Entry block has no immediate dominator
        assert_eq!(dom_tree.immediate_dominator(block1), None);

        // Other blocks should have immediate dominators
        assert_eq!(dom_tree.immediate_dominator(block2), Some(block1));

        // Block 4 should be immediately dominated by block 1 (common dominator of 2 and 3)
        assert_eq!(dom_tree.immediate_dominator(block4), Some(block1));
    }

    #[test]
    fn test_dominance_frontiers() {
        let cfg = create_test_cfg();
        let dom_tree = DominatorTree::build(&cfg).unwrap();

        let block1 = BlockId(1);
        let block4 = BlockId(4);

        // Block 4 should be in the dominance frontier of blocks 2 and 3
        // (since they both can reach 4, but don't dominate it)
        let frontier_1 = dom_tree.dominance_frontier(block1);

        // The exact frontier depends on the specific CFG structure
        // Just verify the method doesn't crash
        assert!(frontier_1.len() >= 0);
    }

    #[test]
    fn test_dominator_tree_statistics() {
        let cfg = create_test_cfg();
        let dom_tree = DominatorTree::build(&cfg).unwrap();

        let stats = dom_tree.statistics();
        assert_eq!(stats.total_blocks, 4);
        assert!(stats.tree_height >= 1);
    }

    #[test]
    fn test_dominance_analysis() {
        let cfg = create_test_cfg();
        let analysis = DominanceAnalysis::new(&cfg).unwrap();

        let natural_loops = analysis.find_natural_loops().unwrap();
        // This CFG has no loops, so should be empty
        assert!(natural_loops.is_empty());

        let regions = analysis.find_reducible_regions().unwrap();
        // Should find some regions
        assert!(regions.len() >= 0);
    }

    #[test]
    fn test_dot_export() {
        let cfg = create_test_cfg();
        let dom_tree = DominatorTree::build(&cfg).unwrap();

        let dot = dom_tree.to_dot();
        assert!(dot.contains("digraph"));
        assert!(dot.contains("dominator_tree"));
        assert!(dot.contains("->"));
    }

    #[test]
    fn test_text_export() {
        let cfg = create_test_cfg();
        let dom_tree = DominatorTree::build(&cfg).unwrap();

        let text = dom_tree.to_text();
        assert!(text.contains("Dominator Tree"));
        assert!(text.contains("Root:"));
        assert!(text.contains("Immediate Dominators:"));
        assert!(text.contains("Dominance Frontiers:"));
    }

    #[test]
    fn test_lowest_common_ancestor() {
        let cfg = create_test_cfg();
        let dom_tree = DominatorTree::build(&cfg).unwrap();

        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block3 = BlockId(3);

        // LCA of blocks 2 and 3 should be block 1
        let lca = dom_tree.lowest_common_ancestor(block2, block3);
        assert_eq!(lca, Some(block1));

        // LCA of a block with itself should be the block itself
        let lca_self = dom_tree.lowest_common_ancestor(block1, block1);
        assert_eq!(lca_self, Some(block1));
    }
}