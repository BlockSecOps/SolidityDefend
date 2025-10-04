use std::collections::{HashMap, HashSet};
use anyhow::Result;
use serde::{Deserialize, Serialize};

use ir::{BlockId, ValueId, Instruction};
use cfg::ControlFlowGraph;
use crate::analysis::{DataFlowAnalysis, DataFlowDirection, DataFlowResult, DefUseAnalysis, utils};

/// Reaching definitions analysis
///
/// This analysis determines which definitions of variables may reach each program point.
/// A definition d of variable x reaches a point p if there is a path from d to p
/// such that d is not killed (overwritten) along that path.
pub struct ReachingDefinitions<'a> {
    cfg: &'a ControlFlowGraph,
    /// Map from variable to all its definition points
    variable_definitions: HashMap<ValueId, HashSet<DefinitionSite>>,
}

/// A specific definition site for a variable
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefinitionSite {
    /// The block where the definition occurs
    pub block_id: BlockId,
    /// The instruction index within the block
    pub instruction_index: usize,
    /// The variable being defined
    pub variable: ValueId,
    /// Optional: the instruction that defines the variable
    pub instruction_type: DefinitionType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DefinitionType {
    /// Assignment operation (Add, Sub, etc.)
    Assignment,
    /// Load from memory
    Load,
    /// Function parameter
    Parameter,
    /// Phi node in SSA form
    Phi,
    /// Function call result
    Call,
    /// Unknown/other
    Other,
}

/// State for reaching definitions analysis
/// Contains the set of definitions that reach this program point
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReachingDefinitionsState {
    /// Set of definition sites that reach this point
    pub definitions: HashSet<DefinitionSite>,
}

impl ReachingDefinitionsState {
    /// Create an empty state
    pub fn new() -> Self {
        Self {
            definitions: HashSet::new(),
        }
    }

    /// Add a definition to the state
    pub fn add_definition(&mut self, def: DefinitionSite) {
        self.definitions.insert(def);
    }

    /// Remove all definitions of a specific variable (kill)
    pub fn kill_variable(&mut self, variable: ValueId) {
        self.definitions.retain(|def| def.variable != variable);
    }

    /// Get all definitions of a specific variable
    pub fn get_definitions(&self, variable: ValueId) -> HashSet<&DefinitionSite> {
        self.definitions.iter()
            .filter(|def| def.variable == variable)
            .collect()
    }

    /// Get all variables that have reaching definitions
    pub fn get_defined_variables(&self) -> HashSet<ValueId> {
        self.definitions.iter()
            .map(|def| def.variable)
            .collect()
    }

    /// Union with another state
    pub fn union_with(&mut self, other: &Self) {
        self.definitions.extend(other.definitions.iter().cloned());
    }

    /// Check if a specific definition reaches this point
    pub fn has_definition(&self, def: &DefinitionSite) -> bool {
        self.definitions.contains(def)
    }

    /// Get the number of reaching definitions
    pub fn count(&self) -> usize {
        self.definitions.len()
    }
}

impl<'a> ReachingDefinitions<'a> {
    /// Create a new reaching definitions analysis
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        let mut analysis = Self {
            cfg,
            variable_definitions: HashMap::new(),
        };

        // Pre-compute all definition sites in the CFG
        analysis.collect_definitions();
        analysis
    }

    /// Collect all definition sites in the CFG
    fn collect_definitions(&mut self) {
        for (block_id, block_node) in self.cfg.basic_blocks() {
            let instructions = &block_node.instructions;
            for (instr_index, instruction) in instructions.iter().enumerate() {
                if let Some(defined_var) = utils::get_instruction_definition(instruction) {
                    let def_site = DefinitionSite {
                        block_id: block_id,
                        instruction_index: instr_index,
                        variable: defined_var,
                        instruction_type: self.classify_definition(instruction),
                    };

                    self.variable_definitions
                        .entry(defined_var)
                        .or_default()
                        .insert(def_site);
                }
            }
        }
    }

    /// Classify the type of definition
    fn classify_definition(&self, instruction: &Instruction) -> DefinitionType {
        match instruction {
            Instruction::Add(_, _, _) |
            Instruction::Sub(_, _, _) |
            Instruction::Mul(_, _, _) |
            Instruction::Div(_, _, _) => DefinitionType::Assignment,
            Instruction::Load(_, _) => DefinitionType::Load,
            Instruction::Phi(_, _) => DefinitionType::Phi,
            _ => DefinitionType::Other,
        }
    }

    /// Generate a definition for the current instruction
    fn gen_definition(&self, block_id: BlockId, instr_index: usize, instruction: &Instruction) -> Option<DefinitionSite> {
        utils::get_instruction_definition(instruction).map(|var| {
            DefinitionSite {
                block_id,
                instruction_index: instr_index,
                variable: var,
                instruction_type: self.classify_definition(instruction),
            }
        })
    }

    /// Get all definitions killed by an instruction
    fn kill_definitions(&self, variable: ValueId) -> HashSet<DefinitionSite> {
        self.variable_definitions
            .get(&variable)
            .cloned()
            .unwrap_or_default()
    }

    /// Compute gen and kill sets for a basic block
    pub fn compute_gen_kill(&self, block_id: BlockId, instructions: &[Instruction]) -> (HashSet<DefinitionSite>, HashSet<DefinitionSite>) {
        let mut gen = HashSet::new();
        let mut kill = HashSet::new();

        for (instr_index, instruction) in instructions.iter().enumerate() {
            if let Some(defined_var) = utils::get_instruction_definition(instruction) {
                // Kill all previous definitions of this variable from OTHER blocks
                let all_defs = self.kill_definitions(defined_var);
                let killed_defs: HashSet<DefinitionSite> = all_defs.into_iter()
                    .filter(|def| def.block_id != block_id)
                    .collect();
                kill.extend(killed_defs);

                // Remove any definitions of this variable from gen set
                gen.retain(|def: &DefinitionSite| def.variable != defined_var);

                // Generate new definition
                if let Some(new_def) = self.gen_definition(block_id, instr_index, instruction) {
                    gen.insert(new_def);
                }
            }
        }

        (gen, kill)
    }

    /// Get all reaching definitions at the entry of a block
    pub fn get_reaching_definitions(&self, result: &DataFlowResult<ReachingDefinitionsState>, block_id: BlockId) -> HashSet<DefinitionSite> {
        result.get_entry_state(block_id)
            .map(|state| state.definitions.clone())
            .unwrap_or_default()
    }

    /// Get reaching definitions for a specific variable at a program point
    pub fn get_variable_reaching_definitions(
        &self,
        result: &DataFlowResult<ReachingDefinitionsState>,
        block_id: BlockId,
        variable: ValueId
    ) -> HashSet<DefinitionSite> {
        self.get_reaching_definitions(result, block_id)
            .into_iter()
            .filter(|def| def.variable == variable)
            .collect()
    }

    /// Check if there are multiple definitions reaching a use point
    pub fn has_multiple_reaching_definitions(
        &self,
        result: &DataFlowResult<ReachingDefinitionsState>,
        block_id: BlockId,
        variable: ValueId
    ) -> bool {
        self.get_variable_reaching_definitions(result, block_id, variable).len() > 1
    }

    /// Find uninitialized variable uses
    pub fn find_uninitialized_uses(&self, result: &DataFlowResult<ReachingDefinitionsState>) -> Vec<(BlockId, ValueId)> {
        let mut uninitialized = Vec::new();

        for (block_id, block_node) in self.cfg.basic_blocks() {
            let instructions = &block_node.instructions;
            let reaching_defs = self.get_reaching_definitions(result, block_id);

            for instruction in instructions {
                let used_vars = utils::get_instruction_uses(instruction);
                for var in used_vars {
                    // Check if any definition of this variable reaches this point
                    let has_reaching_def = reaching_defs.iter()
                        .any(|def| def.variable == var);

                    if !has_reaching_def {
                        uninitialized.push((block_id, var));
                    }
                }
            }
        }

        uninitialized
    }

    /// Generate analysis report
    pub fn generate_report(&self, result: &DataFlowResult<ReachingDefinitionsState>) -> String {
        let mut report = String::new();

        report.push_str("=== Reaching Definitions Analysis Report ===\n\n");

        // Overall statistics
        report.push_str(&format!("Analysis converged: {}\n", result.converged));
        report.push_str(&format!("Iterations: {}\n", result.iterations));
        report.push_str(&format!("Total variables: {}\n", self.variable_definitions.len()));
        report.push_str(&format!("Total definitions: {}\n",
            self.variable_definitions.values().map(|defs| defs.len()).sum::<usize>()));

        // Per-block analysis
        report.push_str("\nPer-Block Analysis:\n");
        for (block_id, _) in self.cfg.basic_blocks() {
            let reaching_defs = self.get_reaching_definitions(result, block_id);
            report.push_str(&format!("Block {}: {} reaching definitions\n",
                block_id.0, reaching_defs.len()));

            // Group by variable
            let mut vars_to_defs: HashMap<ValueId, Vec<&DefinitionSite>> = HashMap::new();
            for def in &reaching_defs {
                vars_to_defs.entry(def.variable).or_default().push(def);
            }

            for (var, defs) in vars_to_defs {
                report.push_str(&format!("  Variable {}: {} definitions\n", var.0, defs.len()));
                if defs.len() > 1 {
                    report.push_str("    (Multiple definitions - potential φ-node needed)\n");
                }
            }
        }

        // Uninitialized variable uses
        let uninitialized = self.find_uninitialized_uses(result);
        if !uninitialized.is_empty() {
            report.push_str("\nPotential Uninitialized Variable Uses:\n");
            for (block_id, var) in uninitialized {
                report.push_str(&format!("  Block {}: Variable {} used without reaching definition\n",
                    block_id.0, var.0));
            }
        }

        report
    }
}

impl<'a> DataFlowAnalysis for ReachingDefinitions<'a> {
    type State = ReachingDefinitionsState;

    fn direction(&self) -> DataFlowDirection {
        DataFlowDirection::Forward
    }

    fn initial_state(&self) -> Self::State {
        ReachingDefinitionsState::new()
    }

    fn boundary_state(&self) -> Self::State {
        // Entry point has no reaching definitions initially
        ReachingDefinitionsState::new()
    }

    fn transfer_instruction(&self, state: &Self::State, instruction: &Instruction) -> Self::State {
        let mut new_state = state.clone();

        // If this instruction defines a variable, kill all previous definitions and add new one
        if let Some(defined_var) = utils::get_instruction_definition(instruction) {
            // Kill all definitions of this variable
            new_state.kill_variable(defined_var);

            // Add this definition (we need block_id and instruction_index for this)
            // This is a simplified version - in practice, we'd need the full context
        }

        new_state
    }

    fn transfer_block(&self, state: &Self::State, block_id: BlockId, instructions: &[Instruction]) -> Self::State {
        let mut current_state = state.clone();

        for (instr_index, instruction) in instructions.iter().enumerate() {
            if let Some(defined_var) = utils::get_instruction_definition(instruction) {
                // Kill all definitions of this variable
                current_state.kill_variable(defined_var);

                // Add new definition
                let new_def = DefinitionSite {
                    block_id,
                    instruction_index: instr_index,
                    variable: defined_var,
                    instruction_type: self.classify_definition(instruction),
                };
                current_state.add_definition(new_def);
            }
        }

        current_state
    }

    fn meet(&self, states: &[Self::State]) -> Self::State {
        // Union of all reaching definitions
        let mut result = ReachingDefinitionsState::new();

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

impl<'a> DefUseAnalysis for ReachingDefinitions<'a> {
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
        // An instruction kills a definition if it defines the same variable
        utils::get_instruction_definition(instruction)
            .map(|defined_var| defined_var == *def)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{DataFlowEngine};
    use cfg::{ControlFlowGraph, EdgeType};
    use ir::{Instruction, IrValue, ValueId};

    fn create_test_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new("test_reaching_defs".to_string());

        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block3 = BlockId(3);

        // Block 1: x = 1, y = 2
        let instructions1 = vec![
            Instruction::Add(ValueId(1), IrValue::ConstantInt(1), IrValue::ConstantInt(0)), // x = 1
            Instruction::Add(ValueId(2), IrValue::ConstantInt(2), IrValue::ConstantInt(0)), // y = 2
        ];

        // Block 2: x = x + 1
        let instructions2 = vec![
            Instruction::Add(ValueId(3), IrValue::Value(ValueId(1)), IrValue::ConstantInt(1)), // x = x + 1
        ];

        // Block 3: z = x + y
        let instructions3 = vec![
            Instruction::Add(ValueId(4), IrValue::Value(ValueId(1)), IrValue::Value(ValueId(2))), // z = x + y
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
    fn test_reaching_definitions_basic() {
        let cfg = create_test_cfg();
        let mut analysis = ReachingDefinitions::new(&cfg);

        let result = analysis.analyze();
        assert!(result.is_ok());

        let rd_result = result.unwrap();
        assert!(rd_result.converged);

        // Check that definitions are properly tracked
        let block3_entry = rd_result.get_entry_state(BlockId(3)).unwrap();

        // At block 3 entry, we should have:
        // - Definition of ValueId(3) from block 2 (latest x)
        // - Definition of ValueId(2) from block 1 (y)
        assert!(block3_entry.definitions.len() >= 2);
    }

    #[test]
    fn test_definition_killing() {
        let cfg = create_test_cfg();
        let analysis = ReachingDefinitions::new(&cfg);

        // Test that new definitions kill old ones
        let mut state = ReachingDefinitionsState::new();

        // Add initial definition of x
        state.add_definition(DefinitionSite {
            block_id: BlockId(1),
            instruction_index: 0,
            variable: ValueId(1),
            instruction_type: DefinitionType::Assignment,
        });

        // Kill all definitions of ValueId(1)
        state.kill_variable(ValueId(1));

        // Should have no definitions now
        assert_eq!(state.definitions.len(), 0);
    }

    #[test]
    fn test_gen_kill_computation() {
        let cfg = create_test_cfg();
        let analysis = ReachingDefinitions::new(&cfg);

        let binding = cfg.basic_blocks();
        let block1_node = binding.get(&BlockId(1)).unwrap();
        let (gen, kill) = analysis.compute_gen_kill(BlockId(1), &block1_node.instructions);

        // Block 1 should generate 2 definitions
        assert_eq!(gen.len(), 2);

        // Initially no definitions to kill
        assert_eq!(kill.len(), 0);
    }

    #[test]
    fn test_multiple_definitions() {
        // Create CFG with branching to test multiple reaching definitions
        let mut cfg = ControlFlowGraph::new("test_multiple_defs".to_string());

        let entry = BlockId(0);
        let branch1 = BlockId(1);
        let branch2 = BlockId(2);
        let merge = BlockId(3);

        cfg.add_block(entry, vec![]);
        cfg.add_block(branch1, vec![
            Instruction::Add(ValueId(1), IrValue::ConstantInt(1), IrValue::ConstantInt(0)), // x = 1
        ]);
        cfg.add_block(branch2, vec![
            Instruction::Add(ValueId(2), IrValue::ConstantInt(2), IrValue::ConstantInt(0)), // x = 2
        ]);
        cfg.add_block(merge, vec![
            Instruction::Add(ValueId(3), IrValue::Value(ValueId(1)), IrValue::ConstantInt(0)), // use x
        ]);

        cfg.set_entry_block(entry).unwrap();
        cfg.add_edge(entry, branch1, EdgeType::True).unwrap();
        cfg.add_edge(entry, branch2, EdgeType::False).unwrap();
        cfg.add_edge(branch1, merge, EdgeType::Unconditional).unwrap();
        cfg.add_edge(branch2, merge, EdgeType::Unconditional).unwrap();

        let mut analysis = ReachingDefinitions::new(&cfg);
        let result = analysis.analyze().unwrap();

        // At merge point, should have multiple definitions of x reaching
        let merge_entry = result.get_entry_state(merge).unwrap();
        assert!(merge_entry.definitions.len() >= 2);
    }
}