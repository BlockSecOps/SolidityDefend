use std::collections::{HashMap, HashSet};
use std::fmt;
use petgraph::{Graph, Directed, Direction};
use petgraph::graph::{NodeIndex, EdgeIndex};
use petgraph::visit::EdgeRef;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};

use ir::{BlockId, BasicBlock, IrFunction, Instruction};

/// Control Flow Graph using petgraph for efficient graph operations
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// The underlying directed graph
    graph: Graph<CfgNode, CfgEdge, Directed>,
    /// Mapping from BlockId to NodeIndex in the graph
    block_to_node: HashMap<BlockId, NodeIndex>,
    /// Mapping from NodeIndex to BlockId
    node_to_block: HashMap<NodeIndex, BlockId>,
    /// Entry block of the CFG
    entry_block: Option<NodeIndex>,
    /// Exit block(s) of the CFG
    exit_blocks: Vec<NodeIndex>,
    /// Function name this CFG represents
    function_name: String,
}

/// Node data in the CFG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgNode {
    /// Block ID from the IR
    pub block_id: BlockId,
    /// Instructions in this basic block
    pub instructions: Vec<Instruction>,
    /// Predecessors in the CFG
    pub predecessors: Vec<BlockId>,
    /// Successors in the CFG
    pub successors: Vec<BlockId>,
    /// Whether this is an entry block
    pub is_entry: bool,
    /// Whether this is an exit block
    pub is_exit: bool,
}

impl CfgNode {
    pub fn new(block_id: BlockId, instructions: Vec<Instruction>) -> Self {
        Self {
            block_id,
            instructions,
            predecessors: Vec::new(),
            successors: Vec::new(),
            is_entry: false,
            is_exit: false,
        }
    }

    /// Check if this block ends with a terminator instruction
    pub fn has_terminator(&self) -> bool {
        if let Some(last_instruction) = self.instructions.last() {
            matches!(last_instruction,
                Instruction::Branch(_) |
                Instruction::ConditionalBranch(_, _, _) |
                Instruction::Return(_) |
                Instruction::Revert(_) |
                Instruction::SelfDestruct(_)
            )
        } else {
            false
        }
    }

    /// Get the terminator instruction if present
    pub fn terminator(&self) -> Option<&Instruction> {
        self.instructions.last().filter(|_| self.has_terminator())
    }

    /// Check if this block is empty (no instructions)
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Get the number of instructions in this block
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}

/// Edge data in the CFG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    /// Type of control flow edge
    pub edge_type: EdgeType,
    /// Condition for conditional branches (if applicable)
    pub condition: Option<String>,
}

impl CfgEdge {
    pub fn new(edge_type: EdgeType) -> Self {
        Self {
            edge_type,
            condition: None,
        }
    }

    pub fn conditional(condition: String, is_true_branch: bool) -> Self {
        Self {
            edge_type: if is_true_branch { EdgeType::True } else { EdgeType::False },
            condition: Some(condition),
        }
    }
}

/// Types of control flow edges
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeType {
    /// Unconditional flow (fall-through or jump)
    Unconditional,
    /// True branch of conditional
    True,
    /// False branch of conditional
    False,
    /// Back edge (loop)
    Back,
    /// Exception edge
    Exception,
}

impl fmt::Display for EdgeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdgeType::Unconditional => write!(f, "unconditional"),
            EdgeType::True => write!(f, "true"),
            EdgeType::False => write!(f, "false"),
            EdgeType::Back => write!(f, "back"),
            EdgeType::Exception => write!(f, "exception"),
        }
    }
}

impl ControlFlowGraph {
    /// Create a new empty CFG
    pub fn new(function_name: String) -> Self {
        Self {
            graph: Graph::new(),
            block_to_node: HashMap::new(),
            node_to_block: HashMap::new(),
            entry_block: None,
            exit_blocks: Vec::new(),
            function_name,
        }
    }

    /// Get the function name this CFG represents
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// Add a basic block to the CFG
    pub fn add_block(&mut self, block_id: BlockId, instructions: Vec<Instruction>) -> NodeIndex {
        let mut node = CfgNode::new(block_id, instructions);

        // Check if this is an exit block based on terminator
        if let Some(terminator) = node.terminator() {
            node.is_exit = matches!(terminator,
                Instruction::Return(_) |
                Instruction::Revert(_) |
                Instruction::SelfDestruct(_)
            );
            if node.is_exit {
                self.exit_blocks.push(petgraph::graph::NodeIndex::new(self.graph.node_count()));
            }
        }

        let node_index = self.graph.add_node(node);
        self.block_to_node.insert(block_id, node_index);
        self.node_to_block.insert(node_index, block_id);

        node_index
    }

    /// Add an edge between two blocks
    pub fn add_edge(&mut self, from: BlockId, to: BlockId, edge_type: EdgeType) -> Result<EdgeIndex> {
        let from_node = self.block_to_node.get(&from)
            .ok_or_else(|| anyhow!("Source block {} not found", from))?;
        let to_node = self.block_to_node.get(&to)
            .ok_or_else(|| anyhow!("Target block {} not found", to))?;

        let edge = CfgEdge::new(edge_type);
        let edge_index = self.graph.add_edge(*from_node, *to_node, edge);

        // Update predecessor/successor lists
        if let Some(from_node_data) = self.graph.node_weight_mut(*from_node) {
            if !from_node_data.successors.contains(&to) {
                from_node_data.successors.push(to);
            }
        }

        if let Some(to_node_data) = self.graph.node_weight_mut(*to_node) {
            if !to_node_data.predecessors.contains(&from) {
                to_node_data.predecessors.push(from);
            }
        }

        Ok(edge_index)
    }

    /// Set the entry block
    pub fn set_entry_block(&mut self, block_id: BlockId) -> Result<()> {
        let node_index = self.block_to_node.get(&block_id)
            .ok_or_else(|| anyhow!("Entry block {} not found", block_id))?;

        self.entry_block = Some(*node_index);

        if let Some(node_data) = self.graph.node_weight_mut(*node_index) {
            node_data.is_entry = true;
        }

        Ok(())
    }

    /// Get the entry block ID
    pub fn entry_block_id(&self) -> Option<BlockId> {
        self.entry_block.and_then(|node| self.node_to_block.get(&node)).copied()
    }

    /// Get all exit block IDs
    pub fn exit_block_ids(&self) -> Vec<BlockId> {
        self.exit_blocks.iter()
            .filter_map(|node| self.node_to_block.get(node).copied())
            .collect()
    }

    /// Get basic blocks as a map
    pub fn basic_blocks(&self) -> HashMap<BlockId, &CfgNode> {
        self.block_to_node.iter()
            .filter_map(|(block_id, node_index)| {
                self.graph.node_weight(*node_index).map(|node| (*block_id, node))
            })
            .collect()
    }

    /// Get predecessors of a block
    pub fn predecessors(&self, block_id: BlockId) -> Vec<BlockId> {
        if let Some(node_index) = self.block_to_node.get(&block_id) {
            self.graph.neighbors_directed(*node_index, Direction::Incoming)
                .filter_map(|pred_node| self.node_to_block.get(&pred_node).copied())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get successors of a block
    pub fn successors(&self, block_id: BlockId) -> Vec<BlockId> {
        if let Some(node_index) = self.block_to_node.get(&block_id) {
            self.graph.neighbors_directed(*node_index, Direction::Outgoing)
                .filter_map(|succ_node| self.node_to_block.get(&succ_node).copied())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Check if there's an edge between two blocks
    pub fn has_edge(&self, from: BlockId, to: BlockId) -> bool {
        if let (Some(from_node), Some(to_node)) =
            (self.block_to_node.get(&from), self.block_to_node.get(&to)) {
            self.graph.find_edge(*from_node, *to_node).is_some()
        } else {
            false
        }
    }

    /// Check if a block is reachable from the entry block
    pub fn is_reachable_from_entry(&self, block_id: BlockId) -> bool {
        if let (Some(entry_node), Some(target_node)) =
            (self.entry_block, self.block_to_node.get(&block_id)) {

            if entry_node == *target_node {
                return true;
            }

            // Use DFS to check reachability
            let mut visited = HashSet::new();
            let mut stack = vec![entry_node];

            while let Some(current) = stack.pop() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current);

                if current == *target_node {
                    return true;
                }

                for neighbor in self.graph.neighbors_directed(current, Direction::Outgoing) {
                    if !visited.contains(&neighbor) {
                        stack.push(neighbor);
                    }
                }
            }
            false
        } else {
            false
        }
    }

    /// Check if target is reachable from source
    pub fn can_reach(&self, from: BlockId, to: BlockId) -> bool {
        if let (Some(from_node), Some(to_node)) =
            (self.block_to_node.get(&from), self.block_to_node.get(&to)) {

            if from_node == to_node {
                return true;
            }

            // Use DFS to check reachability
            let mut visited = HashSet::new();
            let mut stack = vec![*from_node];

            while let Some(current) = stack.pop() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current);

                if current == *to_node {
                    return true;
                }

                for neighbor in self.graph.neighbors_directed(current, Direction::Outgoing) {
                    if !visited.contains(&neighbor) {
                        stack.push(neighbor);
                    }
                }
            }
            false
        } else {
            false
        }
    }

    /// Find back edges (indicating loops)
    pub fn back_edges(&self) -> Vec<(BlockId, BlockId)> {
        let mut back_edges = Vec::new();

        if let Some(entry_node) = self.entry_block {
            let mut visited = HashSet::new();
            let mut in_stack = HashSet::new();

            self.dfs_back_edges(entry_node, &mut visited, &mut in_stack, &mut back_edges);
        }

        back_edges
    }

    /// Helper for DFS-based back edge detection
    fn dfs_back_edges(
        &self,
        node: NodeIndex,
        visited: &mut HashSet<NodeIndex>,
        in_stack: &mut HashSet<NodeIndex>,
        back_edges: &mut Vec<(BlockId, BlockId)>
    ) {
        visited.insert(node);
        in_stack.insert(node);

        for neighbor in self.graph.neighbors_directed(node, Direction::Outgoing) {
            if !visited.contains(&neighbor) {
                self.dfs_back_edges(neighbor, visited, in_stack, back_edges);
            } else if in_stack.contains(&neighbor) {
                // Found a back edge
                if let (Some(from_block), Some(to_block)) =
                    (self.node_to_block.get(&node), self.node_to_block.get(&neighbor)) {
                    back_edges.push((*from_block, *to_block));
                }
            }
        }

        in_stack.remove(&node);
    }

    /// Find unreachable blocks
    pub fn find_unreachable_blocks(&self) -> Vec<BlockId> {
        let mut unreachable = Vec::new();

        for (block_id, _) in &self.block_to_node {
            if !self.is_reachable_from_entry(*block_id) {
                unreachable.push(*block_id);
            }
        }

        unreachable
    }

    /// Find blocks that can be merged (empty blocks with single predecessor/successor)
    pub fn find_mergeable_blocks(&self) -> Vec<BlockId> {
        let mut mergeable = Vec::new();

        for (block_id, node) in self.basic_blocks() {
            // A block is mergeable if:
            // 1. It's not the entry block
            // 2. It has exactly one predecessor
            // 3. The predecessor has exactly one successor (this block)
            // 4. It doesn't start with a label that might be a jump target
            if self.entry_block_id() != Some(block_id) &&
               node.predecessors.len() == 1 &&
               node.successors.len() <= 1 {

                let pred_id = node.predecessors[0];
                let pred_successors = self.successors(pred_id);

                if pred_successors.len() == 1 && pred_successors[0] == block_id {
                    mergeable.push(block_id);
                }
            }
        }

        mergeable
    }

    /// Suggest optimizations for the CFG
    pub fn suggest_optimizations(&self) -> Vec<String> {
        let mut suggestions = Vec::new();

        let unreachable = self.find_unreachable_blocks();
        if !unreachable.is_empty() {
            suggestions.push(format!(
                "Remove {} unreachable blocks: {:?}",
                unreachable.len(),
                unreachable
            ));
        }

        let mergeable = self.find_mergeable_blocks();
        if !mergeable.is_empty() {
            suggestions.push(format!(
                "Merge {} unnecessary blocks: {:?}",
                mergeable.len(),
                mergeable
            ));
        }

        let back_edges = self.back_edges();
        if !back_edges.is_empty() {
            suggestions.push(format!(
                "Consider loop optimizations for {} loops",
                back_edges.len()
            ));
        }

        if suggestions.is_empty() {
            suggestions.push("CFG is well-optimized".to_string());
        }

        suggestions
    }

    /// Validate CFG well-formedness
    pub fn validate(&self) -> Result<()> {
        // Check that entry block exists and is reachable
        if self.entry_block.is_none() {
            return Err(anyhow!("CFG has no entry block"));
        }

        // Check that all blocks except entry have at least one predecessor
        for (block_id, _) in &self.block_to_node {
            if self.entry_block_id() != Some(*block_id) {
                let preds = self.predecessors(*block_id);
                if preds.is_empty() {
                    return Err(anyhow!("Block {} has no predecessors", block_id));
                }
            }
        }

        // Check that all non-exit blocks have at least one successor
        for (block_id, node) in self.basic_blocks() {
            if !node.is_exit {
                let succs = self.successors(block_id);
                if succs.is_empty() && !node.has_terminator() {
                    return Err(anyhow!("Non-exit block {} has no successors", block_id));
                }
            }
        }

        // Check that terminator instructions match edge structure
        for (block_id, node) in self.basic_blocks() {
            let successors = self.successors(block_id);

            if let Some(terminator) = node.terminator() {
                match terminator {
                    Instruction::Branch(_) => {
                        if successors.len() != 1 {
                            return Err(anyhow!(
                                "Block {} has branch instruction but {} successors",
                                block_id, successors.len()
                            ));
                        }
                    }
                    Instruction::ConditionalBranch(_, _, _) => {
                        if successors.len() != 2 {
                            return Err(anyhow!(
                                "Block {} has conditional branch but {} successors",
                                block_id, successors.len()
                            ));
                        }
                    }
                    Instruction::Return(_) | Instruction::Revert(_) | Instruction::SelfDestruct(_) => {
                        if !successors.is_empty() {
                            return Err(anyhow!(
                                "Block {} has terminating instruction but has successors",
                                block_id
                            ));
                        }
                    }
                    _ => {} // Other instructions are not terminators
                }
            }
        }

        Ok(())
    }

    /// Export CFG to DOT format for visualization
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str(&format!("digraph \"{}\" {{\n", self.function_name));
        dot.push_str("    rankdir=TB;\n");
        dot.push_str("    node [shape=box];\n\n");

        // Add nodes
        for (block_id, node) in self.basic_blocks() {
            let label = format!("{}\\l{} instructions",
                block_id,
                node.instructions.len()
            );

            let style = if node.is_entry {
                "style=filled,fillcolor=lightgreen"
            } else if node.is_exit {
                "style=filled,fillcolor=lightcoral"
            } else {
                ""
            };

            dot.push_str(&format!("    \"{}\" [label=\"{}\",{}];\n",
                block_id, label, style));
        }

        dot.push_str("\n");

        // Add edges
        for edge_ref in self.graph.edge_references() {
            let source_node = edge_ref.source();
            let target_node = edge_ref.target();
            let source = self.node_to_block[&source_node];
            let target = self.node_to_block[&target_node];
            let edge_data = edge_ref.weight();

            let label = match edge_data.edge_type {
                EdgeType::True => "T",
                EdgeType::False => "F",
                EdgeType::Back => "back",
                EdgeType::Exception => "exception",
                EdgeType::Unconditional => "",
            };

            let style = match edge_data.edge_type {
                EdgeType::Back => "color=red,style=dashed",
                EdgeType::Exception => "color=orange",
                EdgeType::True => "color=green",
                EdgeType::False => "color=red",
                EdgeType::Unconditional => "",
            };

            dot.push_str(&format!("    \"{}\" -> \"{}\" [label=\"{}\",{}];\n",
                source, target, label, style));
        }

        dot.push_str("}\n");
        dot
    }

    /// Export CFG to human-readable text format
    pub fn to_text(&self) -> String {
        let mut text = String::new();
        text.push_str(&format!("Control Flow Graph for function '{}'\n", self.function_name));
        text.push_str(&format!("Blocks: {}, Edges: {}\n\n",
            self.graph.node_count(), self.graph.edge_count()));

        if let Some(entry_id) = self.entry_block_id() {
            text.push_str(&format!("Entry Block: {}\n", entry_id));
        }

        let exit_ids = self.exit_block_ids();
        if !exit_ids.is_empty() {
            text.push_str(&format!("Exit Blocks: {:?}\n", exit_ids));
        }

        text.push_str("\nBlocks:\n");
        for (block_id, node) in self.basic_blocks() {
            text.push_str(&format!("  Block {}:\n", block_id));
            text.push_str(&format!("    Instructions: {}\n", node.instructions.len()));
            text.push_str(&format!("    Predecessors: {:?}\n", node.predecessors));
            text.push_str(&format!("    Successors: {:?}\n", node.successors));

            if node.is_entry {
                text.push_str("    [ENTRY]\n");
            }
            if node.is_exit {
                text.push_str("    [EXIT]\n");
            }
            text.push('\n');
        }

        let back_edges = self.back_edges();
        if !back_edges.is_empty() {
            text.push_str(&format!("Back Edges (Loops): {:?}\n", back_edges));
        }

        text
    }

    /// Get graph statistics
    pub fn statistics(&self) -> CfgStatistics {
        let back_edges = self.back_edges();
        let unreachable = self.find_unreachable_blocks();

        CfgStatistics {
            block_count: self.graph.node_count(),
            edge_count: self.graph.edge_count(),
            entry_blocks: if self.entry_block.is_some() { 1 } else { 0 },
            exit_blocks: self.exit_blocks.len(),
            back_edges: back_edges.len(),
            unreachable_blocks: unreachable.len(),
            has_loops: !back_edges.is_empty(),
        }
    }
}

/// Statistics about a CFG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgStatistics {
    pub block_count: usize,
    pub edge_count: usize,
    pub entry_blocks: usize,
    pub exit_blocks: usize,
    pub back_edges: usize,
    pub unreachable_blocks: usize,
    pub has_loops: bool,
}

impl fmt::Display for CfgStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CFG Statistics: {} blocks, {} edges, {} exit blocks, {} loops, {} unreachable",
            self.block_count, self.edge_count, self.exit_blocks,
            self.back_edges, self.unreachable_blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::{Instruction, IrValue, ValueId};

    #[test]
    fn test_cfg_creation() {
        let cfg = ControlFlowGraph::new("test_function".to_string());
        assert_eq!(cfg.function_name, "test_function");
        assert_eq!(cfg.graph.node_count(), 0);
        assert_eq!(cfg.graph.edge_count(), 0);
        assert!(cfg.entry_block.is_none());
    }

    #[test]
    fn test_add_block() {
        let mut cfg = ControlFlowGraph::new("test".to_string());
        let block_id = BlockId(0);
        let instructions = vec![
            Instruction::Add(ValueId(0), IrValue::ConstantInt(1), IrValue::ConstantInt(2))
        ];

        let node_index = cfg.add_block(block_id, instructions);
        assert_eq!(cfg.graph.node_count(), 1);
        assert!(cfg.block_to_node.contains_key(&block_id));
        assert!(cfg.node_to_block.contains_key(&node_index));
    }

    #[test]
    fn test_add_edge() {
        let mut cfg = ControlFlowGraph::new("test".to_string());
        let block1 = BlockId(1);
        let block2 = BlockId(2);

        cfg.add_block(block1, vec![]);
        cfg.add_block(block2, vec![]);

        let result = cfg.add_edge(block1, block2, EdgeType::Unconditional);
        assert!(result.is_ok());
        assert_eq!(cfg.graph.edge_count(), 1);
        assert!(cfg.has_edge(block1, block2));
    }

    #[test]
    fn test_entry_block() {
        let mut cfg = ControlFlowGraph::new("test".to_string());
        let entry_block = BlockId(0);

        cfg.add_block(entry_block, vec![]);
        cfg.set_entry_block(entry_block).unwrap();

        assert_eq!(cfg.entry_block_id(), Some(entry_block));
    }

    #[test]
    fn test_reachability() {
        let mut cfg = ControlFlowGraph::new("test".to_string());
        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block3 = BlockId(3);

        cfg.add_block(block1, vec![]);
        cfg.add_block(block2, vec![]);
        cfg.add_block(block3, vec![]);

        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();

        assert!(cfg.is_reachable_from_entry(block1));
        assert!(cfg.is_reachable_from_entry(block2));
        assert!(!cfg.is_reachable_from_entry(block3));

        assert!(cfg.can_reach(block1, block2));
        assert!(!cfg.can_reach(block2, block1));
    }

    #[test]
    fn test_back_edge_detection() {
        let mut cfg = ControlFlowGraph::new("test".to_string());
        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block3 = BlockId(3);

        cfg.add_block(block1, vec![]);
        cfg.add_block(block2, vec![]);
        cfg.add_block(block3, vec![]);

        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();
        cfg.add_edge(block2, block3, EdgeType::Unconditional).unwrap();
        cfg.add_edge(block3, block2, EdgeType::Back).unwrap(); // Back edge creating loop

        let back_edges = cfg.back_edges();
        assert_eq!(back_edges.len(), 1);
        assert!(back_edges.contains(&(block3, block2)));
    }

    #[test]
    fn test_cfg_validation() {
        let mut cfg = ControlFlowGraph::new("test".to_string());
        let entry_block = BlockId(0);
        let exit_block = BlockId(1);

        cfg.add_block(entry_block, vec![]);
        cfg.add_block(exit_block, vec![Instruction::Return(None)]);

        cfg.set_entry_block(entry_block).unwrap();
        cfg.add_edge(entry_block, exit_block, EdgeType::Unconditional).unwrap();

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_dot_export() {
        let mut cfg = ControlFlowGraph::new("test_function".to_string());
        let block1 = BlockId(1);
        let block2 = BlockId(2);

        cfg.add_block(block1, vec![]);
        cfg.add_block(block2, vec![]);
        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();

        let dot = cfg.to_dot();
        assert!(dot.contains("digraph"));
        assert!(dot.contains("test_function"));
        assert!(dot.contains("1"));
        assert!(dot.contains("2"));
        assert!(dot.contains("->"));
    }

    #[test]
    fn test_cfg_statistics() {
        let mut cfg = ControlFlowGraph::new("test".to_string());
        let block1 = BlockId(1);
        let block2 = BlockId(2);

        cfg.add_block(block1, vec![]);
        cfg.add_block(block2, vec![]);
        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();

        let stats = cfg.statistics();
        assert_eq!(stats.block_count, 2);
        assert_eq!(stats.edge_count, 1);
        assert_eq!(stats.entry_blocks, 1);
        assert!(!stats.has_loops);
    }
}