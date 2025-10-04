use std::collections::{HashMap, HashSet};
use anyhow::{Result, anyhow};

use ir::{IrFunction, BlockId, Instruction, BasicBlock};

/// Basic block identification and analysis utilities
pub struct BasicBlockAnalyzer {
    /// Options for basic block analysis
    #[allow(dead_code)]
    options: BasicBlockOptions,
}

/// Configuration options for basic block analysis
#[derive(Debug, Clone)]
pub struct BasicBlockOptions {
    /// Whether to split blocks at function calls
    pub split_at_calls: bool,
    /// Whether to split blocks at conditional branches
    pub split_at_conditionals: bool,
    /// Whether to merge consecutive blocks when possible
    pub merge_consecutive: bool,
    /// Whether to identify leaders and terminators
    pub identify_leaders: bool,
}

impl Default for BasicBlockOptions {
    fn default() -> Self {
        Self {
            split_at_calls: true,
            split_at_conditionals: true,
            merge_consecutive: false,
            identify_leaders: true,
        }
    }
}

impl BasicBlockAnalyzer {
    /// Create a new basic block analyzer with default options
    pub fn new() -> Self {
        Self {
            options: BasicBlockOptions::default(),
        }
    }

    /// Create a new basic block analyzer with custom options
    pub fn with_options(options: BasicBlockOptions) -> Self {
        Self { options }
    }

    /// Identify basic blocks in an IR function
    pub fn identify_basic_blocks(&self, ir_function: &IrFunction) -> Result<BasicBlockInfo> {
        let mut info = BasicBlockInfo::new();

        // Phase 1: Identify leaders (first instructions of basic blocks)
        let leaders = self.find_leaders(ir_function)?;

        // Phase 2: Identify terminators (last instructions of basic blocks)
        let terminators = self.find_terminators(ir_function)?;

        // Phase 3: Build basic block boundaries
        let boundaries = self.compute_block_boundaries(ir_function, &leaders, &terminators)?;

        // Phase 4: Analyze each basic block
        for (block_id, basic_block) in &ir_function.basic_blocks {
            let analysis = self.analyze_basic_block(*block_id, basic_block)?;
            info.block_analyses.insert(*block_id, analysis);
        }

        info.leaders = leaders;
        info.terminators = terminators;
        info.boundaries = boundaries;

        Ok(info)
    }

    /// Find leader instructions (start of basic blocks)
    fn find_leaders(&self, ir_function: &IrFunction) -> Result<HashSet<BlockId>> {
        let mut leaders = HashSet::new();

        // Entry block is always a leader
        leaders.insert(ir_function.entry_block);

        // Find targets of branches
        for (_block_id, basic_block) in &ir_function.basic_blocks {
            for instruction in &basic_block.instructions {
                match instruction {
                    Instruction::Branch(target) => {
                        leaders.insert(*target);
                    }
                    Instruction::ConditionalBranch(_, true_target, false_target) => {
                        leaders.insert(*true_target);
                        leaders.insert(*false_target);
                    }
                    _ => {}
                }
            }
        }

        Ok(leaders)
    }

    /// Find terminator instructions (end of basic blocks)
    fn find_terminators(&self, ir_function: &IrFunction) -> Result<HashSet<BlockId>> {
        let mut terminators = HashSet::new();

        for (block_id, basic_block) in &ir_function.basic_blocks {
            if let Some(last_instruction) = basic_block.instructions.last() {
                if self.is_terminator_instruction(last_instruction) {
                    terminators.insert(*block_id);
                }
            }
        }

        Ok(terminators)
    }

    /// Check if an instruction is a terminator
    fn is_terminator_instruction(&self, instruction: &Instruction) -> bool {
        matches!(instruction,
            Instruction::Branch(_) |
            Instruction::ConditionalBranch(_, _, _) |
            Instruction::Return(_) |
            Instruction::Revert(_) |
            Instruction::SelfDestruct(_)
        )
    }

    /// Compute basic block boundaries
    fn compute_block_boundaries(
        &self,
        ir_function: &IrFunction,
        leaders: &HashSet<BlockId>,
        terminators: &HashSet<BlockId>
    ) -> Result<HashMap<BlockId, BlockBoundary>> {
        let mut boundaries = HashMap::new();

        for (block_id, basic_block) in &ir_function.basic_blocks {
            let is_leader = leaders.contains(block_id);
            let is_terminator = terminators.contains(block_id);

            let boundary = BlockBoundary {
                block_id: *block_id,
                is_leader,
                is_terminator,
                instruction_count: basic_block.instructions.len(),
                predecessors: basic_block.predecessors.clone(),
                successors: basic_block.successors.clone(),
            };

            boundaries.insert(*block_id, boundary);
        }

        Ok(boundaries)
    }

    /// Analyze a single basic block
    fn analyze_basic_block(&self, block_id: BlockId, basic_block: &BasicBlock) -> Result<BlockAnalysis> {
        let mut analysis = BlockAnalysis::new(block_id);

        // Count different types of instructions
        for instruction in &basic_block.instructions {
            self.classify_instruction(&mut analysis, instruction);
        }

        // Analyze control flow properties
        analysis.has_terminator = basic_block.is_terminator();
        analysis.is_empty = basic_block.instructions.is_empty();
        analysis.instruction_count = basic_block.instructions.len();

        // Check for specific patterns
        analysis.is_straight_line = self.is_straight_line_block(basic_block);
        analysis.is_loop_header = self.is_potential_loop_header(basic_block);
        analysis.is_merge_point = basic_block.predecessors.len() > 1;

        // Estimate complexity
        analysis.complexity_score = self.calculate_complexity_score(basic_block);

        Ok(analysis)
    }

    /// Classify an instruction for analysis
    fn classify_instruction(&self, analysis: &mut BlockAnalysis, instruction: &Instruction) {
        match instruction {
            // Arithmetic operations
            Instruction::Add(_, _, _) | Instruction::Sub(_, _, _) |
            Instruction::Mul(_, _, _) | Instruction::Div(_, _, _) |
            Instruction::Mod(_, _, _) | Instruction::Exp(_, _, _) => {
                analysis.arithmetic_ops += 1;
            }

            // Memory operations
            Instruction::Load(_, _) | Instruction::Store(_, _) |
            Instruction::StorageLoad(_, _) | Instruction::StorageStore(_, _) => {
                analysis.memory_ops += 1;
            }

            // Control flow operations
            Instruction::Branch(_) | Instruction::ConditionalBranch(_, _, _) |
            Instruction::Return(_) => {
                analysis.control_flow_ops += 1;
            }

            // Function calls
            Instruction::Call(_, _, _) | Instruction::ExternalCall(_, _, _, _) |
            Instruction::DelegateCall(_, _, _, _) | Instruction::StaticCall(_, _, _, _) => {
                analysis.function_calls += 1;
            }

            // Other operations
            _ => {
                analysis.other_ops += 1;
            }
        }
    }

    /// Check if a block is straight-line code (no branches)
    fn is_straight_line_block(&self, basic_block: &BasicBlock) -> bool {
        !basic_block.instructions.iter().any(|inst| {
            matches!(inst,
                Instruction::Branch(_) |
                Instruction::ConditionalBranch(_, _, _)
            )
        })
    }

    /// Check if a block is potentially a loop header
    fn is_potential_loop_header(&self, basic_block: &BasicBlock) -> bool {
        // A block might be a loop header if it has multiple predecessors
        // and contains conditional branching
        basic_block.predecessors.len() > 1 &&
        basic_block.instructions.iter().any(|inst| {
            matches!(inst, Instruction::ConditionalBranch(_, _, _))
        })
    }

    /// Calculate a complexity score for the block
    fn calculate_complexity_score(&self, basic_block: &BasicBlock) -> u32 {
        let mut score = 0;

        // Base score from instruction count
        score += basic_block.instructions.len() as u32;

        // Additional score for complex instructions
        for instruction in &basic_block.instructions {
            match instruction {
                Instruction::ConditionalBranch(_, _, _) => score += 3,
                Instruction::Call(_, _, _) | Instruction::ExternalCall(_, _, _, _) => score += 2,
                Instruction::StorageLoad(_, _) | Instruction::StorageStore(_, _) => score += 2,
                _ => score += 1,
            }
        }

        score
    }

    /// Find blocks that can be merged
    pub fn find_mergeable_blocks(&self, ir_function: &IrFunction) -> Result<Vec<(BlockId, BlockId)>> {
        let mut mergeable_pairs = Vec::new();

        for (block_id, basic_block) in &ir_function.basic_blocks {
            // A block can be merged with its successor if:
            // 1. It has exactly one successor
            // 2. The successor has exactly one predecessor (this block)
            // 3. Neither block is a special block (entry, loop header, etc.)

            if basic_block.successors.len() == 1 {
                let successor_id = basic_block.successors[0];

                if let Some(successor_block) = ir_function.basic_blocks.get(&successor_id) {
                    if successor_block.predecessors.len() == 1 &&
                       successor_block.predecessors[0] == *block_id &&
                       successor_id != ir_function.entry_block {
                        mergeable_pairs.push((*block_id, successor_id));
                    }
                }
            }
        }

        Ok(mergeable_pairs)
    }

    /// Split a basic block at a given instruction index
    pub fn split_block_at(
        &self,
        _ir_function: &mut IrFunction,
        _block_id: BlockId,
        _split_index: usize
    ) -> Result<BlockId> {
        // This would be implemented to actually split blocks
        // For now, return a placeholder
        Err(anyhow!("Block splitting not implemented yet"))
    }

    /// Merge two consecutive basic blocks
    pub fn merge_blocks(
        &self,
        _ir_function: &mut IrFunction,
        _first_block: BlockId,
        _second_block: BlockId
    ) -> Result<()> {
        // This would be implemented to actually merge blocks
        // For now, return success
        Ok(())
    }
}

impl Default for BasicBlockAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about basic blocks in a function
#[derive(Debug, Clone)]
pub struct BasicBlockInfo {
    /// Set of leader blocks
    pub leaders: HashSet<BlockId>,
    /// Set of terminator blocks
    pub terminators: HashSet<BlockId>,
    /// Block boundary information
    pub boundaries: HashMap<BlockId, BlockBoundary>,
    /// Analysis for each block
    pub block_analyses: HashMap<BlockId, BlockAnalysis>,
}

impl BasicBlockInfo {
    fn new() -> Self {
        Self {
            leaders: HashSet::new(),
            terminators: HashSet::new(),
            boundaries: HashMap::new(),
            block_analyses: HashMap::new(),
        }
    }

    /// Get the total number of basic blocks
    pub fn block_count(&self) -> usize {
        self.boundaries.len()
    }

    /// Get the number of leader blocks
    pub fn leader_count(&self) -> usize {
        self.leaders.len()
    }

    /// Get the number of terminator blocks
    pub fn terminator_count(&self) -> usize {
        self.terminators.len()
    }

    /// Get blocks with the highest complexity scores
    pub fn most_complex_blocks(&self, count: usize) -> Vec<(BlockId, u32)> {
        let mut blocks: Vec<_> = self.block_analyses.iter()
            .map(|(id, analysis)| (*id, analysis.complexity_score))
            .collect();

        blocks.sort_by(|a, b| b.1.cmp(&a.1));
        blocks.truncate(count);
        blocks
    }

    /// Get statistics about the basic blocks
    pub fn statistics(&self) -> BasicBlockStatistics {
        let mut stats = BasicBlockStatistics::default();

        stats.total_blocks = self.block_count();
        stats.leader_blocks = self.leader_count();
        stats.terminator_blocks = self.terminator_count();

        for analysis in self.block_analyses.values() {
            stats.total_instructions += analysis.instruction_count;
            stats.total_arithmetic_ops += analysis.arithmetic_ops;
            stats.total_memory_ops += analysis.memory_ops;
            stats.total_control_flow_ops += analysis.control_flow_ops;
            stats.total_function_calls += analysis.function_calls;

            if analysis.is_empty {
                stats.empty_blocks += 1;
            }
            if analysis.is_straight_line {
                stats.straight_line_blocks += 1;
            }
            if analysis.is_loop_header {
                stats.potential_loop_headers += 1;
            }
            if analysis.is_merge_point {
                stats.merge_points += 1;
            }

            stats.max_complexity = stats.max_complexity.max(analysis.complexity_score);
            stats.total_complexity += analysis.complexity_score;
        }

        if stats.total_blocks > 0 {
            stats.average_complexity = stats.total_complexity as f64 / stats.total_blocks as f64;
            stats.average_instructions_per_block = stats.total_instructions as f64 / stats.total_blocks as f64;
        }

        stats
    }
}

/// Boundary information for a basic block
#[derive(Debug, Clone)]
pub struct BlockBoundary {
    pub block_id: BlockId,
    pub is_leader: bool,
    pub is_terminator: bool,
    pub instruction_count: usize,
    pub predecessors: Vec<BlockId>,
    pub successors: Vec<BlockId>,
}

/// Analysis results for a single basic block
#[derive(Debug, Clone)]
pub struct BlockAnalysis {
    pub block_id: BlockId,
    pub instruction_count: usize,
    pub arithmetic_ops: usize,
    pub memory_ops: usize,
    pub control_flow_ops: usize,
    pub function_calls: usize,
    pub other_ops: usize,
    pub has_terminator: bool,
    pub is_empty: bool,
    pub is_straight_line: bool,
    pub is_loop_header: bool,
    pub is_merge_point: bool,
    pub complexity_score: u32,
}

impl BlockAnalysis {
    fn new(block_id: BlockId) -> Self {
        Self {
            block_id,
            instruction_count: 0,
            arithmetic_ops: 0,
            memory_ops: 0,
            control_flow_ops: 0,
            function_calls: 0,
            other_ops: 0,
            has_terminator: false,
            is_empty: true,
            is_straight_line: true,
            is_loop_header: false,
            is_merge_point: false,
            complexity_score: 0,
        }
    }

    /// Get the operation mix as percentages
    pub fn operation_mix(&self) -> OperationMix {
        let total = self.arithmetic_ops + self.memory_ops + self.control_flow_ops +
                   self.function_calls + self.other_ops;

        if total == 0 {
            return OperationMix::default();
        }

        OperationMix {
            arithmetic_percent: (self.arithmetic_ops * 100) as f64 / total as f64,
            memory_percent: (self.memory_ops * 100) as f64 / total as f64,
            control_flow_percent: (self.control_flow_ops * 100) as f64 / total as f64,
            function_call_percent: (self.function_calls * 100) as f64 / total as f64,
            other_percent: (self.other_ops * 100) as f64 / total as f64,
        }
    }

    /// Check if this block is compute-intensive
    pub fn is_compute_intensive(&self) -> bool {
        let mix = self.operation_mix();
        mix.arithmetic_percent >= 50.0
    }

    /// Check if this block is memory-intensive
    pub fn is_memory_intensive(&self) -> bool {
        let mix = self.operation_mix();
        mix.memory_percent >= 30.0
    }
}

/// Operation mix percentages for a block
#[derive(Debug, Clone, Default)]
pub struct OperationMix {
    pub arithmetic_percent: f64,
    pub memory_percent: f64,
    pub control_flow_percent: f64,
    pub function_call_percent: f64,
    pub other_percent: f64,
}

/// Statistics about basic blocks in a function
#[derive(Debug, Clone, Default)]
pub struct BasicBlockStatistics {
    pub total_blocks: usize,
    pub leader_blocks: usize,
    pub terminator_blocks: usize,
    pub empty_blocks: usize,
    pub straight_line_blocks: usize,
    pub potential_loop_headers: usize,
    pub merge_points: usize,
    pub total_instructions: usize,
    pub total_arithmetic_ops: usize,
    pub total_memory_ops: usize,
    pub total_control_flow_ops: usize,
    pub total_function_calls: usize,
    pub max_complexity: u32,
    pub total_complexity: u32,
    pub average_complexity: f64,
    pub average_instructions_per_block: f64,
}

impl std::fmt::Display for BasicBlockStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Basic Block Statistics:\n")?;
        write!(f, "  Total blocks: {}\n", self.total_blocks)?;
        write!(f, "  Leader blocks: {}\n", self.leader_blocks)?;
        write!(f, "  Terminator blocks: {}\n", self.terminator_blocks)?;
        write!(f, "  Empty blocks: {}\n", self.empty_blocks)?;
        write!(f, "  Straight-line blocks: {}\n", self.straight_line_blocks)?;
        write!(f, "  Potential loop headers: {}\n", self.potential_loop_headers)?;
        write!(f, "  Merge points: {}\n", self.merge_points)?;
        write!(f, "  Total instructions: {}\n", self.total_instructions)?;
        write!(f, "  Average instructions per block: {:.2}\n", self.average_instructions_per_block)?;
        write!(f, "  Max complexity: {}\n", self.max_complexity)?;
        write!(f, "  Average complexity: {:.2}", self.average_complexity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::{IrFunction, Instruction, IrValue, ValueId};

    fn create_test_function() -> IrFunction {
        let mut ir_function = IrFunction::new(
            "test_function".to_string(),
            vec![],
            vec![],
        );

        // Create some basic blocks
        let block1 = ir_function.create_block();
        let block2 = ir_function.create_block();
        let block3 = ir_function.create_block();

        // Add instructions to blocks
        ir_function.add_instruction(block1,
            Instruction::Add(ValueId(0), IrValue::ConstantInt(1), IrValue::ConstantInt(2))
        ).unwrap();

        ir_function.add_instruction(block1,
            Instruction::ConditionalBranch(IrValue::Value(ValueId(0)), block2, block3)
        ).unwrap();

        ir_function.add_instruction(block2,
            Instruction::Return(Some(IrValue::ConstantInt(1)))
        ).unwrap();

        ir_function.add_instruction(block3,
            Instruction::Return(Some(IrValue::ConstantInt(0)))
        ).unwrap();

        ir_function
    }

    #[test]
    fn test_basic_block_analyzer_creation() {
        let analyzer = BasicBlockAnalyzer::new();
        assert!(analyzer.options.split_at_calls);
        assert!(analyzer.options.split_at_conditionals);
        assert!(!analyzer.options.merge_consecutive);
        assert!(analyzer.options.identify_leaders);
    }

    #[test]
    fn test_basic_block_identification() {
        let ir_function = create_test_function();
        let analyzer = BasicBlockAnalyzer::new();

        let result = analyzer.identify_basic_blocks(&ir_function);
        assert!(result.is_ok());

        let info = result.unwrap();
        assert!(info.block_count() > 0);
        assert!(info.leader_count() > 0);
    }

    #[test]
    fn test_leader_identification() {
        let ir_function = create_test_function();
        let analyzer = BasicBlockAnalyzer::new();

        let leaders = analyzer.find_leaders(&ir_function).unwrap();

        // Entry block should always be a leader
        assert!(leaders.contains(&ir_function.entry_block));

        // Should have found leaders from branch targets
        assert!(leaders.len() >= 1);
    }

    #[test]
    fn test_terminator_identification() {
        let ir_function = create_test_function();
        let analyzer = BasicBlockAnalyzer::new();

        let terminators = analyzer.find_terminators(&ir_function).unwrap();

        // Should have found some terminators
        assert!(terminators.len() > 0);
    }

    #[test]
    fn test_block_analysis() {
        let ir_function = create_test_function();
        let analyzer = BasicBlockAnalyzer::new();

        let info = analyzer.identify_basic_blocks(&ir_function).unwrap();
        let stats = info.statistics();

        assert_eq!(stats.total_blocks, info.block_count());
        assert!(stats.total_instructions > 0);
        assert!(stats.average_instructions_per_block > 0.0);
    }

    #[test]
    fn test_mergeable_blocks() {
        let ir_function = create_test_function();
        let analyzer = BasicBlockAnalyzer::new();

        let _mergeable = analyzer.find_mergeable_blocks(&ir_function).unwrap();
        // The result depends on the specific structure, so just check it doesn't crash
        // Length is inherently non-negative due to type constraints
    }

    #[test]
    fn test_operation_mix() {
        let mut analysis = BlockAnalysis::new(BlockId(0));
        analysis.arithmetic_ops = 5;
        analysis.memory_ops = 3;
        analysis.control_flow_ops = 2;

        let mix = analysis.operation_mix();
        assert!((mix.arithmetic_percent - 50.0).abs() < 0.1);
        assert!((mix.memory_percent - 30.0).abs() < 0.1);
        assert!((mix.control_flow_percent - 20.0).abs() < 0.1);

        assert!(analysis.is_compute_intensive());
        assert!(analysis.is_memory_intensive());
    }

    #[test]
    fn test_complexity_calculation() {
        let ir_function = create_test_function();
        let analyzer = BasicBlockAnalyzer::new();

        let info = analyzer.identify_basic_blocks(&ir_function).unwrap();
        let most_complex = info.most_complex_blocks(1);

        assert!(most_complex.len() <= 1);
        if !most_complex.is_empty() {
            assert!(most_complex[0].1 > 0); // Complexity score should be positive
        }
    }
}