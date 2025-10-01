use std::collections::{HashMap, HashSet};
use anyhow::Result;
use serde::{Deserialize, Serialize};

use ir::{BlockId, ValueId, Instruction, IrValue};
use cfg::ControlFlowGraph;

/// Core trait for all data flow analyses
pub trait DataFlowAnalysis {
    /// The type representing the analysis state at each program point
    type State: Clone + PartialEq + Default;

    /// The direction of data flow for this analysis
    fn direction(&self) -> DataFlowDirection;

    /// The initial state for the analysis
    fn initial_state(&self) -> Self::State;

    /// The boundary condition (entry/exit state)
    fn boundary_state(&self) -> Self::State;

    /// Transfer function for a single instruction
    fn transfer_instruction(&self, state: &Self::State, instruction: &Instruction) -> Self::State;

    /// Transfer function for an entire basic block
    fn transfer_block(&self, state: &Self::State, block_id: BlockId, instructions: &[Instruction]) -> Self::State {
        let mut current_state = state.clone();

        for instruction in instructions {
            current_state = self.transfer_instruction(&current_state, instruction);
        }

        current_state
    }

    /// Meet (join/union) operation to combine states from multiple predecessors/successors
    fn meet(&self, states: &[Self::State]) -> Self::State;

    /// Check if two states are equal (for convergence detection)
    fn states_equal(&self, state1: &Self::State, state2: &Self::State) -> bool {
        state1 == state2
    }

    /// Run the complete data flow analysis
    fn analyze(&mut self) -> Result<DataFlowResult<Self::State>>;

    /// Get the CFG being analyzed
    fn cfg(&self) -> &ControlFlowGraph;

    /// Optional: Custom convergence check
    fn has_converged(&self, old_states: &HashMap<BlockId, Self::State>, new_states: &HashMap<BlockId, Self::State>) -> bool {
        old_states.len() == new_states.len() &&
        old_states.iter().all(|(block_id, old_state)| {
            new_states.get(block_id)
                .map(|new_state| self.states_equal(old_state, new_state))
                .unwrap_or(false)
        })
    }

    /// Optional: Maximum number of iterations before giving up
    fn max_iterations(&self) -> usize {
        1000
    }
}

/// Direction of data flow analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFlowDirection {
    Forward,
    Backward,
}

/// Result of a data flow analysis
#[derive(Debug, Clone)]
pub struct DataFlowResult<State> {
    /// Entry states for each basic block
    pub entry_states: HashMap<BlockId, State>,
    /// Exit states for each basic block
    pub exit_states: HashMap<BlockId, State>,
    /// Whether the analysis converged
    pub converged: bool,
    /// Number of iterations required
    pub iterations: usize,
    /// Analysis direction
    pub direction: DataFlowDirection,
}

impl<State> DataFlowResult<State> {
    /// Get the entry state for a block
    pub fn get_entry_state(&self, block_id: BlockId) -> Option<&State> {
        self.entry_states.get(&block_id)
    }

    /// Get the exit state for a block
    pub fn get_exit_state(&self, block_id: BlockId) -> Option<&State> {
        self.exit_states.get(&block_id)
    }

    /// Get the state at the beginning of analysis (entry block for forward, exit blocks for backward)
    pub fn get_initial_state(&self) -> Option<&State> {
        match self.direction {
            DataFlowDirection::Forward => {
                // Find entry block and return its entry state
                self.entry_states.values().next()
            },
            DataFlowDirection::Backward => {
                // Find exit blocks and return one of their exit states
                self.exit_states.values().next()
            }
        }
    }

    /// Get the final states (exit blocks for forward, entry block for backward)
    pub fn get_final_states(&self) -> Vec<&State> {
        match self.direction {
            DataFlowDirection::Forward => {
                self.exit_states.values().collect()
            },
            DataFlowDirection::Backward => {
                self.entry_states.values().collect()
            }
        }
    }
}

/// Generic implementation of the iterative data flow algorithm
pub struct DataFlowEngine;

impl DataFlowEngine {
    /// Run iterative data flow analysis using worklist algorithm
    pub fn analyze<A: DataFlowAnalysis>(analysis: &A) -> Result<DataFlowResult<A::State>> {
        let cfg = analysis.cfg();
        let direction = analysis.direction();

        // Initialize states
        let mut entry_states: HashMap<BlockId, A::State> = HashMap::new();
        let mut exit_states: HashMap<BlockId, A::State> = HashMap::new();

        // Set boundary conditions
        match direction {
            DataFlowDirection::Forward => {
                let entry_block = cfg.entry_block();
                entry_states.insert(entry_block, analysis.boundary_state());

                // Initialize all other blocks with initial state
                for (block_id, _) in cfg.basic_blocks() {
                    if *block_id != entry_block {
                        entry_states.insert(*block_id, analysis.initial_state());
                    }
                    exit_states.insert(*block_id, analysis.initial_state());
                }
            },
            DataFlowDirection::Backward => {
                for exit_block in cfg.exit_blocks() {
                    exit_states.insert(exit_block, analysis.boundary_state());
                }

                // Initialize all other blocks with initial state
                for (block_id, _) in cfg.basic_blocks() {
                    if !cfg.exit_blocks().contains(block_id) {
                        exit_states.insert(*block_id, analysis.initial_state());
                    }
                    entry_states.insert(*block_id, analysis.initial_state());
                }
            }
        }

        // Worklist algorithm
        let mut worklist: Vec<BlockId> = cfg.basic_blocks().keys().cloned().collect();
        let mut iterations = 0;
        let max_iterations = analysis.max_iterations();

        while !worklist.is_empty() && iterations < max_iterations {
            iterations += 1;

            let block_id = worklist.pop().unwrap();
            let block_node = cfg.basic_blocks().get(&block_id)
                .ok_or_else(|| anyhow::anyhow!("Block {} not found", block_id.0))?;
            let instructions = &block_node.instructions;

            let old_entry = entry_states.get(&block_id).cloned().unwrap_or_else(|| analysis.initial_state());
            let old_exit = exit_states.get(&block_id).cloned().unwrap_or_else(|| analysis.initial_state());

            match direction {
                DataFlowDirection::Forward => {
                    // Compute new entry state from predecessors
                    let predecessors = cfg.predecessors(block_id);
                    if !predecessors.is_empty() {
                        let pred_states: Vec<A::State> = predecessors.iter()
                            .filter_map(|pred_id| exit_states.get(pred_id).cloned())
                            .collect();

                        if !pred_states.is_empty() {
                            let new_entry = analysis.meet(&pred_states);
                            entry_states.insert(block_id, new_entry);
                        }
                    }

                    // Compute new exit state using transfer function
                    let current_entry = entry_states.get(&block_id).cloned().unwrap_or_else(|| analysis.initial_state());
                    let new_exit = analysis.transfer_block(&current_entry, block_id, &instructions);

                    // Check if exit state changed
                    if !analysis.states_equal(&old_exit, &new_exit) {
                        exit_states.insert(block_id, new_exit);

                        // Add successors to worklist
                        for successor in cfg.successors(block_id) {
                            if !worklist.contains(&successor) {
                                worklist.push(successor);
                            }
                        }
                    }
                },
                DataFlowDirection::Backward => {
                    // Compute new exit state from successors
                    let successors = cfg.successors(block_id);
                    if !successors.is_empty() {
                        let succ_states: Vec<A::State> = successors.iter()
                            .filter_map(|succ_id| entry_states.get(succ_id).cloned())
                            .collect();

                        if !succ_states.is_empty() {
                            let new_exit = analysis.meet(&succ_states);
                            exit_states.insert(block_id, new_exit);
                        }
                    }

                    // Compute new entry state using transfer function
                    let current_exit = exit_states.get(&block_id).cloned().unwrap_or_else(|| analysis.initial_state());
                    let new_entry = analysis.transfer_block(&current_exit, block_id, &instructions);

                    // Check if entry state changed
                    if !analysis.states_equal(&old_entry, &new_entry) {
                        entry_states.insert(block_id, new_entry);

                        // Add predecessors to worklist
                        for predecessor in cfg.predecessors(block_id) {
                            if !worklist.contains(&predecessor) {
                                worklist.push(predecessor);
                            }
                        }
                    }
                }
            }
        }

        let converged = iterations < max_iterations;

        Ok(DataFlowResult {
            entry_states,
            exit_states,
            converged,
            iterations,
            direction,
        })
    }
}

/// Trait for analyses that track variable definitions and uses
pub trait DefUseAnalysis: DataFlowAnalysis {
    /// Get all variables defined by an instruction
    fn get_definitions(&self, instruction: &Instruction) -> HashSet<ValueId>;

    /// Get all variables used by an instruction
    fn get_uses(&self, instruction: &Instruction) -> HashSet<ValueId>;

    /// Check if an instruction kills (overwrites) a definition
    fn kills_definition(&self, instruction: &Instruction, def: &ValueId) -> bool;
}

/// Trait for analyses that need to track data flow across function calls
pub trait InterproceduralAnalysis: DataFlowAnalysis {
    /// Handle function call transfer
    fn transfer_call(&self, state: &Self::State, call_instruction: &Instruction) -> Self::State;

    /// Handle function return transfer
    fn transfer_return(&self, state: &Self::State, return_instruction: &Instruction) -> Self::State;

    /// Get the call graph for interprocedural analysis
    fn call_graph(&self) -> Option<&CallGraph>;
}

/// Simple call graph representation
#[derive(Debug, Clone)]
pub struct CallGraph {
    /// Map from function to the functions it calls
    pub calls: HashMap<String, HashSet<String>>,
    /// Map from function to the functions that call it
    pub callers: HashMap<String, HashSet<String>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            calls: HashMap::new(),
            callers: HashMap::new(),
        }
    }

    pub fn add_call(&mut self, caller: String, callee: String) {
        self.calls.entry(caller.clone()).or_default().insert(callee.clone());
        self.callers.entry(callee).or_default().insert(caller);
    }
}

/// Utility functions for common data flow operations
pub mod utils {
    use super::*;

    /// Extract variable ID from an IR value if it's a variable
    pub fn extract_variable_id(value: &IrValue) -> Option<ValueId> {
        match value {
            IrValue::Value(id) => Some(*id),
            _ => None,
        }
    }

    /// Get all variable IDs used in an instruction
    pub fn get_instruction_uses(instruction: &Instruction) -> HashSet<ValueId> {
        let mut uses = HashSet::new();

        match instruction {
            Instruction::Add(_, lhs, rhs) |
            Instruction::Sub(_, lhs, rhs) |
            Instruction::Mul(_, lhs, rhs) |
            Instruction::Div(_, lhs, rhs) => {
                if let Some(id) = extract_variable_id(lhs) {
                    uses.insert(id);
                }
                if let Some(id) = extract_variable_id(rhs) {
                    uses.insert(id);
                }
            },
            Instruction::Load(_, address) => {
                if let Some(id) = extract_variable_id(address) {
                    uses.insert(id);
                }
            },
            Instruction::Store(address, value) => {
                if let Some(id) = extract_variable_id(address) {
                    uses.insert(id);
                }
                if let Some(id) = extract_variable_id(value) {
                    uses.insert(id);
                }
            },
            Instruction::Branch(condition, _, _) => {
                if let Some(id) = extract_variable_id(condition) {
                    uses.insert(id);
                }
            },
            Instruction::Return(Some(value)) => {
                if let Some(id) = extract_variable_id(value) {
                    uses.insert(id);
                }
            },
            Instruction::Phi(_, phi_args) => {
                for (value, _) in phi_args {
                    if let Some(id) = extract_variable_id(value) {
                        uses.insert(id);
                    }
                }
            },
            _ => {
                // Handle other instruction types as needed
            }
        }

        uses
    }

    /// Get the variable ID defined by an instruction, if any
    pub fn get_instruction_definition(instruction: &Instruction) -> Option<ValueId> {
        match instruction {
            Instruction::Add(target, _, _) |
            Instruction::Sub(target, _, _) |
            Instruction::Mul(target, _, _) |
            Instruction::Div(target, _, _) |
            Instruction::Load(target, _) |
            Instruction::Phi(target, _) => Some(*target),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfg::ControlFlowGraph;

    // Simple test analysis that counts the number of definitions
    struct TestAnalysis<'a> {
        cfg: &'a ControlFlowGraph,
    }

    impl<'a> TestAnalysis<'a> {
        fn new(cfg: &'a ControlFlowGraph) -> Self {
            Self { cfg }
        }
    }

    impl<'a> DataFlowAnalysis for TestAnalysis<'a> {
        type State = usize; // Count of definitions

        fn direction(&self) -> DataFlowDirection {
            DataFlowDirection::Forward
        }

        fn initial_state(&self) -> Self::State {
            0
        }

        fn boundary_state(&self) -> Self::State {
            0
        }

        fn transfer_instruction(&self, state: &Self::State, instruction: &Instruction) -> Self::State {
            // Increment count if instruction defines a variable
            if utils::get_instruction_definition(instruction).is_some() {
                state + 1
            } else {
                *state
            }
        }

        fn meet(&self, states: &[Self::State]) -> Self::State {
            // Take maximum for this test
            states.iter().cloned().max().unwrap_or(0)
        }

        fn analyze(&mut self) -> Result<DataFlowResult<Self::State>> {
            DataFlowEngine::analyze(self)
        }

        fn cfg(&self) -> &ControlFlowGraph {
            self.cfg
        }
    }

    #[test]
    fn test_dataflow_framework() {
        // Create a simple CFG for testing
        use ir::{Instruction, IrValue, ValueId};
        use cfg::{ControlFlowGraph, EdgeType};

        let mut cfg = ControlFlowGraph::new("test_function".to_string());
        let block1 = BlockId(1);
        let block2 = BlockId(2);

        let instructions1 = vec![
            Instruction::Add(ValueId(1), IrValue::ConstantInt(1), IrValue::ConstantInt(2)),
            Instruction::Sub(ValueId(2), IrValue::Value(ValueId(1)), IrValue::ConstantInt(1)),
        ];

        let instructions2 = vec![
            Instruction::Mul(ValueId(3), IrValue::Value(ValueId(2)), IrValue::ConstantInt(2)),
        ];

        cfg.add_block(block1, instructions1);
        cfg.add_block(block2, instructions2);
        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional).unwrap();

        let mut analysis = TestAnalysis::new(&cfg);
        let result = analysis.analyze();

        assert!(result.is_ok());
        let dataflow_result = result.unwrap();
        assert!(dataflow_result.converged);

        // Block 1 should have 2 definitions (ValueId(1) and ValueId(2))
        let block1_exit = dataflow_result.get_exit_state(block1).unwrap();
        assert_eq!(*block1_exit, 2);

        // Block 2 should have 3 definitions total (2 from block1 + 1 new)
        let block2_exit = dataflow_result.get_exit_state(block2).unwrap();
        assert_eq!(*block2_exit, 3);
    }
}