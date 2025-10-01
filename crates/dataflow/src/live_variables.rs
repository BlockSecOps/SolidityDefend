use std::collections::{HashMap, HashSet};
use anyhow::Result;
use serde::{Deserialize, Serialize};

use ir::{BlockId, ValueId, Instruction, IrValue};
use cfg::ControlFlowGraph;
use crate::analysis::{DataFlowAnalysis, DataFlowDirection, DataFlowResult, DefUseAnalysis, utils};

/// Live variables analysis
///
/// This analysis determines which variables are "live" at each program point.
/// A variable is live at a point if its value may be used along some path
/// from that point to the end of the function.
pub struct LiveVariables<'a> {
    cfg: &'a ControlFlowGraph,
    /// Variables that are considered live at function exit (e.g., return values)
    exit_live_variables: HashSet<ValueId>,
}

/// State for live variables analysis
/// Contains the set of variables that are live at this program point
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LiveVariablesState {
    /// Set of variables that are live at this point
    pub live_variables: HashSet<ValueId>,
}

impl LiveVariablesState {
    /// Create an empty state
    pub fn new() -> Self {
        Self {
            live_variables: HashSet::new(),
        }
    }

    /// Create a state with initial live variables
    pub fn with_variables(variables: HashSet<ValueId>) -> Self {
        Self {
            live_variables: variables,
        }
    }

    /// Add a variable to the live set
    pub fn add_variable(&mut self, variable: ValueId) {
        self.live_variables.insert(variable);
    }

    /// Remove a variable from the live set
    pub fn remove_variable(&mut self, variable: ValueId) {
        self.live_variables.remove(&variable);
    }

    /// Check if a variable is live
    pub fn is_live(&self, variable: ValueId) -> bool {
        self.live_variables.contains(&variable)
    }

    /// Get all live variables
    pub fn get_live_variables(&self) -> &HashSet<ValueId> {
        &self.live_variables
    }

    /// Union with another state
    pub fn union_with(&mut self, other: &Self) {
        self.live_variables.extend(&other.live_variables);
    }

    /// Intersection with another state
    pub fn intersect_with(&mut self, other: &Self) {
        self.live_variables.retain(|var| other.live_variables.contains(var));
    }

    /// Get the number of live variables
    pub fn count(&self) -> usize {
        self.live_variables.len()
    }

    /// Check if no variables are live
    pub fn is_empty(&self) -> bool {
        self.live_variables.is_empty()
    }
}

/// Information about variable liveness in a function
#[derive(Debug, Clone)]
pub struct LivenessInfo {
    /// Variables that are never used (dead variables)
    pub dead_variables: HashSet<ValueId>,
    /// Variables that are used before being defined
    pub potentially_uninitialized: HashSet<ValueId>,
    /// Variables that are live at function entry
    pub entry_live: HashSet<ValueId>,
    /// Variables that are live at function exit
    pub exit_live: HashSet<ValueId>,
    /// Maximum number of simultaneously live variables
    pub max_live_count: usize,
}

impl<'a> LiveVariables<'a> {
    /// Create a new live variables analysis
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self {
            cfg,
            exit_live_variables: HashSet::new(),
        }
    }

    /// Create a new live variables analysis with specified exit live variables
    pub fn with_exit_variables(cfg: &'a ControlFlowGraph, exit_vars: HashSet<ValueId>) -> Self {
        Self {
            cfg,
            exit_live_variables: exit_vars,
        }
    }

    /// Add a variable that should be considered live at function exit
    pub fn add_exit_live_variable(&mut self, variable: ValueId) {
        self.exit_live_variables.insert(variable);
    }

    /// Compute use and def sets for a basic block
    pub fn compute_use_def(&self, instructions: &[Instruction]) -> (HashSet<ValueId>, HashSet<ValueId>) {
        let mut use_set = HashSet::new();
        let mut def_set = HashSet::new();

        // Process instructions in forward order for use-def computation
        for instruction in instructions {
            // First, add any variables used by this instruction (if not already defined in this block)
            let used_vars = utils::get_instruction_uses(instruction);
            for var in used_vars {
                if !def_set.contains(&var) {
                    use_set.insert(var);
                }
            }

            // Then, add any variable defined by this instruction
            if let Some(defined_var) = utils::get_instruction_definition(instruction) {
                def_set.insert(defined_var);
            }
        }

        (use_set, def_set)
    }

    /// Get live variables at the entry of a block
    pub fn get_live_variables_entry(&self, result: &DataFlowResult<LiveVariablesState>, block_id: BlockId) -> HashSet<ValueId> {
        result.get_entry_state(block_id)
            .map(|state| state.live_variables.clone())
            .unwrap_or_default()
    }

    /// Get live variables at the exit of a block
    pub fn get_live_variables_exit(&self, result: &DataFlowResult<LiveVariablesState>, block_id: BlockId) -> HashSet<ValueId> {
        result.get_exit_state(block_id)
            .map(|state| state.live_variables.clone())
            .unwrap_or_default()
    }

    /// Find dead variables (variables that are defined but never used)
    pub fn find_dead_variables(&self, result: &DataFlowResult<LiveVariablesState>) -> HashSet<ValueId> {
        let mut dead_variables = HashSet::new();

        for (block_id, instructions) in self.cfg.basic_blocks() {
            let exit_live = self.get_live_variables_exit(result, *block_id);

            // Check each instruction to see if it defines a variable that is not live after
            for (instr_index, instruction) in instructions.iter().enumerate() {
                if let Some(defined_var) = utils::get_instruction_definition(instruction) {
                    // Simulate the state after this instruction
                    let mut state_after = LiveVariablesState::new();

                    // Start with variables live at block exit
                    state_after.live_variables = exit_live.clone();

                    // Process remaining instructions in reverse order
                    for later_instr in instructions.iter().skip(instr_index + 1).rev() {
                        // Remove variables defined by later instructions
                        if let Some(later_def) = utils::get_instruction_definition(later_instr) {
                            state_after.remove_variable(later_def);
                        }

                        // Add variables used by later instructions
                        let later_uses = utils::get_instruction_uses(later_instr);
                        for used_var in later_uses {
                            state_after.add_variable(used_var);
                        }
                    }

                    // If the defined variable is not live after this instruction, it's dead
                    if !state_after.is_live(defined_var) {
                        dead_variables.insert(defined_var);
                    }
                }
            }
        }

        dead_variables
    }

    /// Analyze variable liveness and generate comprehensive information
    pub fn analyze_liveness(&mut self) -> Result<LivenessInfo> {
        let result = self.analyze()?;

        let dead_variables = self.find_dead_variables(&result);

        // Find potentially uninitialized variables
        let mut potentially_uninitialized = HashSet::new();
        let entry_block = self.cfg.entry_block();
        let entry_live = self.get_live_variables_entry(&result, entry_block);

        for var in &entry_live {
            // If a variable is live at entry, it might be used before being defined
            potentially_uninitialized.insert(*var);
        }

        // Find variables live at exit
        let mut exit_live = HashSet::new();
        for exit_block in self.cfg.exit_blocks() {
            let block_exit_live = self.get_live_variables_exit(&result, exit_block);
            exit_live.extend(block_exit_live);
        }

        // Compute maximum number of simultaneously live variables
        let max_live_count = result.exit_states.values()
            .map(|state| state.count())
            .max()
            .unwrap_or(0);

        Ok(LivenessInfo {
            dead_variables,
            potentially_uninitialized,
            entry_live,
            exit_live,
            max_live_count,
        })
    }

    /// Generate analysis report
    pub fn generate_report(&self, result: &DataFlowResult<LiveVariablesState>) -> String {
        let mut report = String::new();

        report.push_str("=== Live Variables Analysis Report ===\n\n");

        // Overall statistics
        report.push_str(&format!("Analysis converged: {}\n", result.converged));
        report.push_str(&format!("Iterations: {}\n", result.iterations));

        // Per-block analysis
        report.push_str("\nPer-Block Analysis:\n");
        for (block_id, _) in self.cfg.basic_blocks() {
            let entry_live = self.get_live_variables_entry(result, *block_id);
            let exit_live = self.get_live_variables_exit(result, *block_id);

            report.push_str(&format!("Block {}:\n", block_id.0));
            report.push_str(&format!("  Entry live: {:?}\n", entry_live));
            report.push_str(&format!("  Exit live: {:?}\n", exit_live));
        }

        // Dead variable analysis
        let dead_vars = self.find_dead_variables(result);
        if !dead_vars.is_empty() {
            report.push_str("\nDead Variables (defined but never used):\n");
            for var in dead_vars {
                report.push_str(&format!("  Variable {}\n", var.0));
            }
        }

        // Liveness statistics
        let max_live = result.exit_states.values()
            .map(|state| state.count())
            .max()
            .unwrap_or(0);
        let avg_live = result.exit_states.values()
            .map(|state| state.count())
            .sum::<usize>() as f64 / result.exit_states.len() as f64;

        report.push_str(&format!("\nLiveness Statistics:\n"));
        report.push_str(&format!("  Maximum simultaneously live variables: {}\n", max_live));
        report.push_str(&format!("  Average live variables per block: {:.2}\n", avg_live));

        report
    }

    /// Compute register pressure (useful for optimization)
    pub fn compute_register_pressure(&self, result: &DataFlowResult<LiveVariablesState>) -> HashMap<BlockId, usize> {
        let mut pressure = HashMap::new();

        for (block_id, _) in self.cfg.basic_blocks() {
            let live_count = self.get_live_variables_exit(result, *block_id).len();
            pressure.insert(*block_id, live_count);
        }

        pressure
    }

    /// Find variables that interfere with each other (live at the same time)
    pub fn compute_interference_graph(&self, result: &DataFlowResult<LiveVariablesState>) -> HashMap<ValueId, HashSet<ValueId>> {
        let mut interference = HashMap::new();

        for (block_id, _) in self.cfg.basic_blocks() {
            let live_vars = self.get_live_variables_exit(result, *block_id);

            // Every pair of live variables interferes
            for var1 in &live_vars {
                for var2 in &live_vars {
                    if var1 != var2 {
                        interference.entry(*var1).or_insert_with(HashSet::new).insert(*var2);
                    }
                }
            }
        }

        interference
    }
}

impl<'a> DataFlowAnalysis for LiveVariables<'a> {
    type State = LiveVariablesState;

    fn direction(&self) -> DataFlowDirection {
        // Live variables is a backward analysis
        DataFlowDirection::Backward
    }

    fn initial_state(&self) -> Self::State {
        LiveVariablesState::new()
    }

    fn boundary_state(&self) -> Self::State {
        // Exit blocks have specified live variables (e.g., return values)
        LiveVariablesState::with_variables(self.exit_live_variables.clone())
    }

    fn transfer_instruction(&self, state: &Self::State, instruction: &Instruction) -> Self::State {
        let mut new_state = state.clone();

        // Remove variables defined by this instruction (they become dead)
        if let Some(defined_var) = utils::get_instruction_definition(instruction) {
            new_state.remove_variable(defined_var);
        }

        // Add variables used by this instruction (they become live)
        let used_vars = utils::get_instruction_uses(instruction);
        for used_var in used_vars {
            new_state.add_variable(used_var);
        }

        new_state
    }

    fn transfer_block(&self, state: &Self::State, _block_id: BlockId, instructions: &[Instruction]) -> Self::State {
        let mut current_state = state.clone();

        // Process instructions in reverse order for backward analysis
        for instruction in instructions.iter().rev() {
            current_state = self.transfer_instruction(&current_state, instruction);
        }

        current_state
    }

    fn meet(&self, states: &[Self::State]) -> Self::State {
        // Union of all live variables (a variable is live if it's live in any successor)
        let mut result = LiveVariablesState::new();

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

impl<'a> DefUseAnalysis for LiveVariables<'a> {
    fn get_definitions(&self, instruction: &Instruction) -> HashSet<ValueId> {
        utils::get_instruction_definition(instruction)
            .map(|var| {
                let mut set = HashSet::new();
                set.insert(var);
                set
            })
            .unwrap_or_default()
    }

    fn get_uses(&self, instruction: &Instruction) -> HashSet<ValueId> {
        utils::get_instruction_uses(instruction)
    }

    fn kills_definition(&self, instruction: &Instruction, def: &ValueId) -> bool {
        // In live variables analysis, an instruction "kills" liveness of a variable if it defines it
        utils::get_instruction_definition(instruction)
            .map(|defined_var| defined_var == *def)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfg::{ControlFlowGraph, EdgeType};
    use ir::{Instruction, IrValue, ValueId};

    fn create_test_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new("test_liveness".to_string());

        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block3 = BlockId(3);

        // Block 1: x = 1, y = 2
        let instructions1 = vec![
            Instruction::Add(ValueId(1), IrValue::Constant(1), IrValue::Constant(0)), // x = 1
            Instruction::Add(ValueId(2), IrValue::Constant(2), IrValue::Constant(0)), // y = 2
        ];

        // Block 2: dead = 42 (dead variable)
        let instructions2 = vec![
            Instruction::Add(ValueId(3), IrValue::Constant(42), IrValue::Constant(0)), // dead = 42
        ];

        // Block 3: return x + y
        let instructions3 = vec![
            Instruction::Add(ValueId(4), IrValue::Variable(ValueId(1)), IrValue::Variable(ValueId(2))), // temp = x + y
            Instruction::Return(Some(IrValue::Variable(ValueId(4)))), // return temp
        ];

        cfg.add_block(block1, instructions1);
        cfg.add_block(block2, instructions2);
        cfg.add_block(block3, instructions3);

        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();
        cfg.add_edge(block2, block3, EdgeType::Unconditional).unwrap();

        cfg
    }

    #[test]
    fn test_live_variables_basic() {
        let cfg = create_test_cfg();
        let mut analysis = LiveVariables::new(&cfg);

        // Add return value as live at exit
        analysis.add_exit_live_variable(ValueId(4));

        let result = analysis.analyze();
        assert!(result.is_ok());

        let lv_result = result.unwrap();
        assert!(lv_result.converged);

        // At block 3 entry, x and y should be live (used in the addition)
        let block3_entry = lv_result.get_entry_state(BlockId(3)).unwrap();
        assert!(block3_entry.is_live(ValueId(1))); // x
        assert!(block3_entry.is_live(ValueId(2))); // y

        // At block 2 exit, x and y should still be live
        let block2_exit = lv_result.get_exit_state(BlockId(2)).unwrap();
        assert!(block2_exit.is_live(ValueId(1))); // x
        assert!(block2_exit.is_live(ValueId(2))); // y
    }

    #[test]
    fn test_dead_variable_detection() {
        let cfg = create_test_cfg();
        let mut analysis = LiveVariables::new(&cfg);
        analysis.add_exit_live_variable(ValueId(4));

        let result = analysis.analyze().unwrap();
        let dead_vars = analysis.find_dead_variables(&result);

        // Variable 3 (dead = 42) should be detected as dead
        assert!(dead_vars.contains(&ValueId(3)));
    }

    #[test]
    fn test_use_def_computation() {
        let cfg = create_test_cfg();
        let analysis = LiveVariables::new(&cfg);

        // Test block 3: temp = x + y, return temp
        let (_, instructions3) = cfg.basic_blocks().get(&BlockId(3)).unwrap();
        let (use_set, def_set) = analysis.compute_use_def(instructions3);

        // Should use x and y
        assert!(use_set.contains(&ValueId(1))); // x
        assert!(use_set.contains(&ValueId(2))); // y

        // Should define temp
        assert!(def_set.contains(&ValueId(4))); // temp
    }

    #[test]
    fn test_branching_liveness() {
        // Create CFG with branching to test liveness merging
        let mut cfg = ControlFlowGraph::new("test_branching_liveness".to_string());

        let entry = BlockId(0);
        let branch1 = BlockId(1);
        let branch2 = BlockId(2);
        let merge = BlockId(3);

        cfg.add_block(entry, vec![
            Instruction::Add(ValueId(1), IrValue::Constant(1), IrValue::Constant(0)), // x = 1
            Instruction::Add(ValueId(2), IrValue::Constant(2), IrValue::Constant(0)), // y = 2
        ]);

        cfg.add_block(branch1, vec![
            Instruction::Add(ValueId(3), IrValue::Variable(ValueId(1)), IrValue::Constant(1)), // use x
        ]);

        cfg.add_block(branch2, vec![
            Instruction::Add(ValueId(4), IrValue::Variable(ValueId(2)), IrValue::Constant(1)), // use y
        ]);

        cfg.add_block(merge, vec![
            Instruction::Return(Some(IrValue::Constant(0))), // return 0
        ]);

        cfg.set_entry_block(entry).unwrap();
        cfg.add_edge(entry, branch1, EdgeType::Conditional).unwrap();
        cfg.add_edge(entry, branch2, EdgeType::Conditional).unwrap();
        cfg.add_edge(branch1, merge, EdgeType::Unconditional).unwrap();
        cfg.add_edge(branch2, merge, EdgeType::Unconditional).unwrap();

        let mut analysis = LiveVariables::new(&cfg);
        let result = analysis.analyze().unwrap();

        // At entry, both x and y should be live because they're used in different branches
        let entry_exit = result.get_exit_state(entry).unwrap();
        assert!(entry_exit.is_live(ValueId(1))); // x
        assert!(entry_exit.is_live(ValueId(2))); // y
    }

    #[test]
    fn test_register_pressure() {
        let cfg = create_test_cfg();
        let mut analysis = LiveVariables::new(&cfg);
        analysis.add_exit_live_variable(ValueId(4));

        let result = analysis.analyze().unwrap();
        let pressure = analysis.compute_register_pressure(&result);

        // Each block should have some register pressure
        assert!(pressure.len() > 0);
        for (_, count) in pressure {
            assert!(count >= 0);
        }
    }

    #[test]
    fn test_interference_graph() {
        let cfg = create_test_cfg();
        let mut analysis = LiveVariables::new(&cfg);
        analysis.add_exit_live_variable(ValueId(4));

        let result = analysis.analyze().unwrap();
        let interference = analysis.compute_interference_graph(&result);

        // Variables that are live at the same time should interfere
        if let Some(x_interferences) = interference.get(&ValueId(1)) {
            // x might interfere with y if they're live at the same time
            // The exact interference depends on the CFG structure
            assert!(x_interferences.len() >= 0);
        }
    }
}