use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::analysis::{DataFlowResult, utils};
use crate::reaching_definitions::{DefinitionSite, ReachingDefinitionsState};
use cfg::ControlFlowGraph;
use ir::{BlockId, Instruction, ValueId};

/// Def-Use chain analysis
///
/// This analysis constructs chains that connect each definition of a variable
/// to all its uses. These chains are fundamental for many optimization and
/// analysis passes.
pub struct DefUseChain {
    /// Map from definition sites to their uses
    def_to_uses: HashMap<DefinitionSite, Vec<UseSite>>,
    /// Map from use sites to their reaching definitions
    use_to_defs: HashMap<UseSite, Vec<DefinitionSite>>,
    /// Map from variables to all their definition sites
    variable_definitions: HashMap<ValueId, Vec<DefinitionSite>>,
    /// Map from variables to all their use sites
    variable_uses: HashMap<ValueId, Vec<UseSite>>,
}

/// A specific use site for a variable
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UseSite {
    /// The block where the use occurs
    pub block_id: BlockId,
    /// The instruction index within the block
    pub instruction_index: usize,
    /// The variable being used
    pub variable: ValueId,
    /// Type of use
    pub use_type: UseType,
}

/// Different types of variable uses
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UseType {
    /// Variable used in arithmetic operation
    Arithmetic,
    /// Variable used as memory address
    MemoryAddress,
    /// Variable used as memory value
    MemoryValue,
    /// Variable used in conditional
    Conditional,
    /// Variable used in function call
    FunctionCall,
    /// Variable used in return statement
    Return,
    /// Variable used in phi node
    Phi,
    /// Other use type
    Other,
}

/// A single def-use chain
#[derive(Debug, Clone)]
pub struct Chain {
    /// The definition that starts this chain
    pub definition: DefinitionSite,
    /// All uses that this definition reaches
    pub uses: Vec<UseSite>,
    /// The variable this chain is for
    pub variable: ValueId,
}

/// Statistics about def-use chains
#[derive(Debug, Clone)]
pub struct DefUseStatistics {
    /// Total number of definitions
    pub total_definitions: usize,
    /// Total number of uses
    pub total_uses: usize,
    /// Total number of chains
    pub total_chains: usize,
    /// Average chain length
    pub average_chain_length: f64,
    /// Variables with multiple definitions
    pub multi_def_variables: usize,
    /// Variables with no uses (dead variables)
    pub unused_variables: usize,
    /// Variables with no definitions (potentially uninitialized)
    pub undefined_variables: usize,
}

impl DefUseChain {
    /// Build def-use chains for a control flow graph
    pub fn build(cfg: &ControlFlowGraph) -> Self {
        let builder = DefUseChainBuilder::new(cfg);
        builder.build()
    }

    /// Build def-use chains using reaching definitions analysis
    pub fn build_with_reaching_definitions(
        cfg: &ControlFlowGraph,
        reaching_defs: &DataFlowResult<ReachingDefinitionsState>,
    ) -> Self {
        let builder = DefUseChainBuilder::new(cfg);
        builder.build_with_reaching_definitions(reaching_defs)
    }

    /// Get all chains for a specific variable
    pub fn get_chains(&self, variable: ValueId) -> Vec<Chain> {
        let mut chains = Vec::new();

        if let Some(definitions) = self.variable_definitions.get(&variable) {
            for def in definitions {
                let uses = self.def_to_uses.get(def).cloned().unwrap_or_default();
                chains.push(Chain {
                    definition: def.clone(),
                    uses,
                    variable,
                });
            }
        }

        chains
    }

    /// Get all definitions that reach a specific use
    pub fn get_reaching_definitions(&self, use_site: &UseSite) -> Vec<DefinitionSite> {
        self.use_to_defs.get(use_site).cloned().unwrap_or_default()
    }

    /// Get all uses that a definition reaches
    pub fn get_uses(&self, definition: &DefinitionSite) -> Vec<UseSite> {
        self.def_to_uses
            .get(definition)
            .cloned()
            .unwrap_or_default()
    }

    /// Check if a definition has any uses
    pub fn has_uses(&self, definition: &DefinitionSite) -> bool {
        self.def_to_uses
            .get(definition)
            .map(|uses| !uses.is_empty())
            .unwrap_or(false)
    }

    /// Find dead definitions (definitions with no uses)
    pub fn find_dead_definitions(&self) -> Vec<DefinitionSite> {
        self.def_to_uses
            .iter()
            .filter(|(_, uses)| uses.is_empty())
            .map(|(def, _)| def.clone())
            .collect()
    }

    /// Find variables with multiple definitions reaching a single use
    pub fn find_multi_def_uses(&self) -> Vec<(UseSite, Vec<DefinitionSite>)> {
        self.use_to_defs
            .iter()
            .filter(|(_, defs)| defs.len() > 1)
            .map(|(use_site, defs)| (use_site.clone(), defs.clone()))
            .collect()
    }

    /// Get all variables that have definitions
    pub fn get_defined_variables(&self) -> HashSet<ValueId> {
        self.variable_definitions.keys().cloned().collect()
    }

    /// Get all variables that have uses
    pub fn get_used_variables(&self) -> HashSet<ValueId> {
        self.variable_uses.keys().cloned().collect()
    }

    /// Find variables that are used but never defined
    pub fn find_undefined_variables(&self) -> HashSet<ValueId> {
        let defined = self.get_defined_variables();
        let used = self.get_used_variables();
        used.difference(&defined).cloned().collect()
    }

    /// Find variables that are defined but never used
    pub fn find_unused_variables(&self) -> HashSet<ValueId> {
        let defined = self.get_defined_variables();
        let used = self.get_used_variables();
        defined.difference(&used).cloned().collect()
    }

    /// Compute statistics about the def-use chains
    pub fn compute_statistics(&self) -> DefUseStatistics {
        let total_definitions = self.def_to_uses.len();
        let total_uses = self.use_to_defs.len();
        let total_chains = self
            .variable_definitions
            .values()
            .map(|defs| defs.len())
            .sum();

        let total_chain_length: usize = self.def_to_uses.values().map(|uses| uses.len()).sum();

        let average_chain_length = if total_chains > 0 {
            total_chain_length as f64 / total_chains as f64
        } else {
            0.0
        };

        let multi_def_variables = self
            .variable_definitions
            .values()
            .filter(|defs| defs.len() > 1)
            .count();

        let unused_variables = self.find_unused_variables().len();
        let undefined_variables = self.find_undefined_variables().len();

        DefUseStatistics {
            total_definitions,
            total_uses,
            total_chains,
            average_chain_length,
            multi_def_variables,
            unused_variables,
            undefined_variables,
        }
    }

    /// Generate a detailed report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        let stats = self.compute_statistics();

        report.push_str("=== Def-Use Chain Analysis Report ===\n\n");

        // Overall statistics
        report.push_str("Statistics:\n");
        report.push_str(&format!(
            "  Total definitions: {}\n",
            stats.total_definitions
        ));
        report.push_str(&format!("  Total uses: {}\n", stats.total_uses));
        report.push_str(&format!("  Total chains: {}\n", stats.total_chains));
        report.push_str(&format!(
            "  Average chain length: {:.2}\n",
            stats.average_chain_length
        ));
        report.push_str(&format!(
            "  Variables with multiple definitions: {}\n",
            stats.multi_def_variables
        ));
        report.push_str(&format!("  Unused variables: {}\n", stats.unused_variables));
        report.push_str(&format!(
            "  Undefined variables: {}\n",
            stats.undefined_variables
        ));

        // Dead definitions
        let dead_defs = self.find_dead_definitions();
        if !dead_defs.is_empty() {
            report.push_str("\nDead Definitions (no uses):\n");
            for dead_def in dead_defs {
                report.push_str(&format!(
                    "  Variable {} at Block {}, Instruction {}\n",
                    dead_def.variable.0, dead_def.block_id.0, dead_def.instruction_index
                ));
            }
        }

        // Multiple definition uses
        let multi_def_uses = self.find_multi_def_uses();
        if !multi_def_uses.is_empty() {
            report.push_str("\nUses with Multiple Reaching Definitions:\n");
            for (use_site, defs) in multi_def_uses {
                report.push_str(&format!(
                    "  Variable {} used at Block {}, Instruction {} has {} reaching definitions\n",
                    use_site.variable.0,
                    use_site.block_id.0,
                    use_site.instruction_index,
                    defs.len()
                ));
            }
        }

        // Undefined variables
        let undefined_vars = self.find_undefined_variables();
        if !undefined_vars.is_empty() {
            report.push_str("\nPotentially Undefined Variables:\n");
            for var in undefined_vars {
                report.push_str(&format!("  Variable {} is used but never defined\n", var.0));
            }
        }

        // Unused variables
        let unused_vars = self.find_unused_variables();
        if !unused_vars.is_empty() {
            report.push_str("\nUnused Variables:\n");
            for var in unused_vars {
                report.push_str(&format!("  Variable {} is defined but never used\n", var.0));
            }
        }

        report
    }

    /// Get the chain starting from a specific definition
    pub fn get_chain_from_definition(&self, definition: &DefinitionSite) -> Option<Chain> {
        let uses = self.def_to_uses.get(definition)?;
        Some(Chain {
            definition: definition.clone(),
            uses: uses.clone(),
            variable: definition.variable,
        })
    }

    /// Check if two variables interfere (one is live when the other is defined)
    pub fn variables_interfere(&self, var1: ValueId, var2: ValueId) -> bool {
        // Check if any definition of var1 has a use that conflicts with definitions of var2
        if let Some(var1_defs) = self.variable_definitions.get(&var1) {
            if let Some(var2_defs) = self.variable_definitions.get(&var2) {
                for var1_def in var1_defs {
                    if let Some(var1_uses) = self.def_to_uses.get(var1_def) {
                        for var1_use in var1_uses {
                            // Check if any definition of var2 is in the same block and could interfere
                            for var2_def in var2_defs {
                                if var1_use.block_id == var2_def.block_id {
                                    // Simplified interference check - in practice, this would be more sophisticated
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Find the shortest path between a definition and a use
    pub fn find_def_use_path(
        &self,
        definition: &DefinitionSite,
        use_site: &UseSite,
        cfg: &ControlFlowGraph,
    ) -> Option<Vec<BlockId>> {
        if definition.variable != use_site.variable {
            return None;
        }

        // Use BFS to find shortest path
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<BlockId, BlockId> = HashMap::new();

        queue.push_back(definition.block_id);
        visited.insert(definition.block_id);

        while let Some(current_block) = queue.pop_front() {
            if current_block == use_site.block_id {
                // Reconstruct path
                let mut path = Vec::new();
                let mut block = use_site.block_id;

                while block != definition.block_id {
                    path.push(block);
                    block = parent[&block];
                }
                path.push(definition.block_id);
                path.reverse();
                return Some(path);
            }

            // Add successors to queue
            for successor in cfg.successors(current_block) {
                if !visited.contains(&successor) {
                    visited.insert(successor);
                    parent.insert(successor, current_block);
                    queue.push_back(successor);
                }
            }
        }

        None // No path found
    }
}

/// Builder for constructing def-use chains
struct DefUseChainBuilder<'a> {
    cfg: &'a ControlFlowGraph,
    def_to_uses: HashMap<DefinitionSite, Vec<UseSite>>,
    use_to_defs: HashMap<UseSite, Vec<DefinitionSite>>,
    variable_definitions: HashMap<ValueId, Vec<DefinitionSite>>,
    variable_uses: HashMap<ValueId, Vec<UseSite>>,
}

impl<'a> DefUseChainBuilder<'a> {
    fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self {
            cfg,
            def_to_uses: HashMap::new(),
            use_to_defs: HashMap::new(),
            variable_definitions: HashMap::new(),
            variable_uses: HashMap::new(),
        }
    }

    fn build(mut self) -> DefUseChain {
        // First pass: collect all definitions and uses
        self.collect_definitions_and_uses();

        // Second pass: build def-use chains using simple reachability
        self.build_simple_chains();

        DefUseChain {
            def_to_uses: self.def_to_uses,
            use_to_defs: self.use_to_defs,
            variable_definitions: self.variable_definitions,
            variable_uses: self.variable_uses,
        }
    }

    fn build_with_reaching_definitions(
        mut self,
        reaching_defs: &DataFlowResult<ReachingDefinitionsState>,
    ) -> DefUseChain {
        // First pass: collect all definitions and uses
        self.collect_definitions_and_uses();

        // Second pass: build chains using reaching definitions analysis
        self.build_chains_with_reaching_definitions(reaching_defs);

        DefUseChain {
            def_to_uses: self.def_to_uses,
            use_to_defs: self.use_to_defs,
            variable_definitions: self.variable_definitions,
            variable_uses: self.variable_uses,
        }
    }

    fn collect_definitions_and_uses(&mut self) {
        for (block_id, block_node) in self.cfg.basic_blocks() {
            let instructions = &block_node.instructions;
            for (instr_index, instruction) in instructions.iter().enumerate() {
                // Collect definitions
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
                        .push(def_site.clone());

                    self.def_to_uses.insert(def_site, Vec::new());
                }

                // Collect uses
                let used_vars = utils::get_instruction_uses(instruction);
                for used_var in used_vars {
                    let use_site = UseSite {
                        block_id: block_id,
                        instruction_index: instr_index,
                        variable: used_var,
                        use_type: self.classify_use(instruction, used_var),
                    };

                    self.variable_uses
                        .entry(used_var)
                        .or_default()
                        .push(use_site.clone());

                    self.use_to_defs.insert(use_site, Vec::new());
                }
            }
        }
    }

    fn classify_definition(
        &self,
        instruction: &Instruction,
    ) -> crate::reaching_definitions::DefinitionType {
        match instruction {
            Instruction::Add(_, _, _)
            | Instruction::Sub(_, _, _)
            | Instruction::Mul(_, _, _)
            | Instruction::Div(_, _, _) => crate::reaching_definitions::DefinitionType::Assignment,
            Instruction::Load(_, _) => crate::reaching_definitions::DefinitionType::Load,
            Instruction::Phi(_, _) => crate::reaching_definitions::DefinitionType::Phi,
            _ => crate::reaching_definitions::DefinitionType::Other,
        }
    }

    fn classify_use(&self, instruction: &Instruction, variable: ValueId) -> UseType {
        match instruction {
            Instruction::Add(_, lhs, rhs)
            | Instruction::Sub(_, lhs, rhs)
            | Instruction::Mul(_, lhs, rhs)
            | Instruction::Div(_, lhs, rhs) => {
                if utils::extract_variable_id(lhs) == Some(variable)
                    || utils::extract_variable_id(rhs) == Some(variable)
                {
                    UseType::Arithmetic
                } else {
                    UseType::Other
                }
            }
            Instruction::Load(_, address) => {
                if utils::extract_variable_id(address) == Some(variable) {
                    UseType::MemoryAddress
                } else {
                    UseType::Other
                }
            }
            Instruction::Store(address, value) => {
                if utils::extract_variable_id(address) == Some(variable) {
                    UseType::MemoryAddress
                } else if utils::extract_variable_id(value) == Some(variable) {
                    UseType::MemoryValue
                } else {
                    UseType::Other
                }
            }
            Instruction::ConditionalBranch(condition, _, _) => {
                if utils::extract_variable_id(condition) == Some(variable) {
                    UseType::Conditional
                } else {
                    UseType::Other
                }
            }
            Instruction::Return(Some(value)) => {
                if utils::extract_variable_id(value) == Some(variable) {
                    UseType::Return
                } else {
                    UseType::Other
                }
            }
            Instruction::Phi(_, phi_args) => {
                for (value, _) in phi_args {
                    if utils::extract_variable_id(value) == Some(variable) {
                        return UseType::Phi;
                    }
                }
                UseType::Other
            }
            _ => UseType::Other,
        }
    }

    fn build_simple_chains(&mut self) {
        // Simple approach: connect each definition to all uses of the same variable
        // This is imprecise but functional without reaching definitions analysis

        for (variable, definitions) in &self.variable_definitions {
            if let Some(uses) = self.variable_uses.get(variable) {
                // For simplicity, connect all definitions to all uses
                // In practice, you'd want to use reaching definitions for precision
                for definition in definitions {
                    if let Some(def_uses) = self.def_to_uses.get_mut(definition) {
                        def_uses.extend(uses.iter().cloned());
                    }
                }

                for use_site in uses {
                    if let Some(use_defs) = self.use_to_defs.get_mut(use_site) {
                        use_defs.extend(definitions.iter().cloned());
                    }
                }
            }
        }
    }

    fn build_chains_with_reaching_definitions(
        &mut self,
        reaching_defs: &DataFlowResult<ReachingDefinitionsState>,
    ) {
        // Use reaching definitions to build precise def-use chains
        for (use_site, _) in self.use_to_defs.clone() {
            if let Some(entry_state) = reaching_defs.get_entry_state(use_site.block_id) {
                let reaching_definitions: Vec<DefinitionSite> = entry_state
                    .definitions
                    .iter()
                    .filter(|def| def.variable == use_site.variable)
                    .cloned()
                    .collect();

                // Update use_to_defs with precise reaching definitions
                if let Some(use_defs) = self.use_to_defs.get_mut(&use_site) {
                    *use_defs = reaching_definitions.clone();
                }

                // Update def_to_uses for each reaching definition
                for def in reaching_definitions {
                    if let Some(def_uses) = self.def_to_uses.get_mut(&def) {
                        if !def_uses.contains(&use_site) {
                            def_uses.push(use_site.clone());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfg::{ControlFlowGraph, EdgeType};
    use ir::{Instruction, IrValue, ValueId};

    fn create_def_use_test_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new("test_def_use".to_string());

        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block3 = BlockId(3);

        // Block 1: x = 1, y = 2
        let instructions1 = vec![
            Instruction::Add(ValueId(1), IrValue::ConstantInt(1), IrValue::ConstantInt(0)), // x = 1
            Instruction::Add(ValueId(2), IrValue::ConstantInt(2), IrValue::ConstantInt(0)), // y = 2
        ];

        // Block 2: z = x + y
        let instructions2 = vec![
            Instruction::Add(
                ValueId(3),
                IrValue::Value(ValueId(1)),
                IrValue::Value(ValueId(2)),
            ), // z = x + y
        ];

        // Block 3: return z
        let instructions3 = vec![
            Instruction::Return(Some(IrValue::Value(ValueId(3)))), // return z
        ];

        cfg.add_block(block1, instructions1);
        cfg.add_block(block2, instructions2);
        cfg.add_block(block3, instructions3);

        cfg.set_entry_block(block1).unwrap();
        cfg.add_edge(block1, block2, EdgeType::Unconditional)
            .unwrap();
        cfg.add_edge(block2, block3, EdgeType::Unconditional)
            .unwrap();

        cfg
    }

    #[test]
    fn test_def_use_chain_construction() {
        let cfg = create_def_use_test_cfg();
        let def_use_chain = DefUseChain::build(&cfg);

        // Check that we have the expected definitions and uses
        let stats = def_use_chain.compute_statistics();
        assert!(stats.total_definitions > 0);
        assert!(stats.total_uses > 0);

        // Check chains for variable x (ValueId(1))
        let x_chains = def_use_chain.get_chains(ValueId(1));
        assert_eq!(x_chains.len(), 1); // One definition of x

        let x_chain = &x_chains[0];
        assert!(!x_chain.uses.is_empty()); // x should be used
    }

    #[test]
    fn test_use_classification() {
        let cfg = create_def_use_test_cfg();
        let def_use_chain = DefUseChain::build(&cfg);

        // Find uses of x in arithmetic operations
        if let Some(x_uses) = def_use_chain.variable_uses.get(&ValueId(1)) {
            let arithmetic_uses: Vec<_> = x_uses
                .iter()
                .filter(|use_site| use_site.use_type == UseType::Arithmetic)
                .collect();
            assert!(!arithmetic_uses.is_empty());
        }
    }

    #[test]
    fn test_dead_definition_detection() {
        // Create a CFG with a dead definition
        let mut cfg = ControlFlowGraph::new("test_dead_def".to_string());
        let block1 = BlockId(1);

        let instructions = vec![
            Instruction::Add(ValueId(1), IrValue::ConstantInt(1), IrValue::ConstantInt(0)), // x = 1 (used)
            Instruction::Add(ValueId(2), IrValue::ConstantInt(2), IrValue::ConstantInt(0)), // y = 2 (dead)
            Instruction::Return(Some(IrValue::Value(ValueId(1)))), // return x
        ];

        cfg.add_block(block1, instructions);
        cfg.set_entry_block(block1).unwrap();

        let def_use_chain = DefUseChain::build(&cfg);
        let dead_defs = def_use_chain.find_dead_definitions();

        // Variable y should be identified as dead
        let dead_y: Vec<_> = dead_defs
            .iter()
            .filter(|def| def.variable == ValueId(2))
            .collect();
        assert!(!dead_y.is_empty());
    }

    #[test]
    fn test_undefined_variable_detection() {
        // Create a CFG that uses a variable without defining it
        let mut cfg = ControlFlowGraph::new("test_undefined_var".to_string());
        let block1 = BlockId(1);

        let instructions = vec![
            // Use ValueId(1) without defining it first
            Instruction::Add(
                ValueId(2),
                IrValue::Value(ValueId(1)),
                IrValue::ConstantInt(1),
            ),
        ];

        cfg.add_block(block1, instructions);
        cfg.set_entry_block(block1).unwrap();

        let def_use_chain = DefUseChain::build(&cfg);
        let undefined_vars = def_use_chain.find_undefined_variables();

        assert!(undefined_vars.contains(&ValueId(1)));
    }

    #[test]
    fn test_statistics_computation() {
        let cfg = create_def_use_test_cfg();
        let def_use_chain = DefUseChain::build(&cfg);
        let stats = def_use_chain.compute_statistics();

        assert!(stats.total_definitions > 0);
        assert!(stats.total_uses > 0);
        assert!(stats.total_chains > 0);
        assert!(stats.average_chain_length >= 0.0);
    }

    #[test]
    fn test_multi_definition_detection() {
        // Create CFG with multiple definitions of the same variable
        let mut cfg = ControlFlowGraph::new("test_multi_def".to_string());

        let entry = BlockId(0);
        let branch1 = BlockId(1);
        let branch2 = BlockId(2);
        let merge = BlockId(3);

        cfg.add_block(entry, vec![]);
        cfg.add_block(
            branch1,
            vec![
                Instruction::Add(ValueId(1), IrValue::ConstantInt(1), IrValue::ConstantInt(0)), // x = 1
            ],
        );
        cfg.add_block(
            branch2,
            vec![
                Instruction::Add(ValueId(2), IrValue::ConstantInt(2), IrValue::ConstantInt(0)), // x = 2 (different ValueId but same logical variable)
            ],
        );
        cfg.add_block(
            merge,
            vec![
                Instruction::Add(
                    ValueId(3),
                    IrValue::Value(ValueId(1)),
                    IrValue::ConstantInt(0),
                ), // use x
            ],
        );

        cfg.set_entry_block(entry).unwrap();
        cfg.add_edge(entry, branch1, EdgeType::True).unwrap();
        cfg.add_edge(entry, branch2, EdgeType::False).unwrap();
        cfg.add_edge(branch1, merge, EdgeType::Unconditional)
            .unwrap();
        cfg.add_edge(branch2, merge, EdgeType::Unconditional)
            .unwrap();

        let def_use_chain = DefUseChain::build(&cfg);
        let stats = def_use_chain.compute_statistics();

        // Should have multiple definitions and chains
        assert!(stats.total_definitions >= 2);
        assert!(stats.total_chains >= 2);
    }
}
