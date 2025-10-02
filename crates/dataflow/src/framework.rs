use std::collections::{HashMap, HashSet};
use anyhow::Result;

use ir::{BlockId, ValueId, Instruction, IrValue, IrFunction};
use cfg::ControlFlowGraph;
use crate::analysis::{DataFlowAnalysis, DataFlowDirection, DataFlowResult, DataFlowEngine};

/// Generic dataflow analysis framework that provides common functionality
pub struct DataFlowFramework<'a> {
    /// The control flow graph being analyzed
    cfg: &'a ControlFlowGraph,
    /// The IR function being analyzed
    ir_function: &'a IrFunction,
}

impl<'a> DataFlowFramework<'a> {
    /// Create a new dataflow framework
    pub fn new(cfg: &'a ControlFlowGraph, ir_function: &'a IrFunction) -> Self {
        Self { cfg, ir_function }
    }

    /// Run reaching definitions analysis
    pub fn reaching_definitions(&self) -> Result<DataFlowResult<ReachingDefinitionsState>> {
        let mut analysis = ReachingDefinitionsAnalysis::new(self.cfg, self.ir_function);
        analysis.analyze()
    }

    /// Run live variables analysis
    pub fn live_variables(&self) -> Result<DataFlowResult<LiveVariablesState>> {
        let mut analysis = LiveVariablesAnalysis::new(self.cfg, self.ir_function);
        analysis.analyze()
    }

    /// Run def-use chain analysis
    pub fn def_use_chains(&self) -> Result<DefUseChains> {
        let reaching_defs = self.reaching_definitions()?;
        let live_vars = self.live_variables()?;

        DefUseChainBuilder::new(self.cfg, self.ir_function)
            .build(&reaching_defs, &live_vars)
    }

    /// Get the CFG
    pub fn cfg(&self) -> &ControlFlowGraph {
        self.cfg
    }

    /// Get the IR function
    pub fn ir_function(&self) -> &IrFunction {
        self.ir_function
    }
}

/// State for reaching definitions analysis
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReachingDefinitionsState {
    /// Set of (variable, definition_point) pairs that reach this point
    pub definitions: HashMap<ValueId, HashSet<BlockId>>,
}

impl ReachingDefinitionsState {
    pub fn new() -> Self {
        Self {
            definitions: HashMap::new(),
        }
    }

    pub fn add_definition(&mut self, var: ValueId, def_point: BlockId) {
        self.definitions.entry(var).or_default().insert(def_point);
    }

    pub fn kill_definitions(&mut self, var: ValueId) {
        self.definitions.remove(&var);
    }

    pub fn merge(&mut self, other: &Self) {
        for (var, def_points) in &other.definitions {
            let entry = self.definitions.entry(*var).or_default();
            entry.extend(def_points);
        }
    }

    pub fn get_definitions(&self, var: ValueId) -> Option<&HashSet<BlockId>> {
        self.definitions.get(&var)
    }
}

/// Reaching definitions analysis implementation
pub struct ReachingDefinitionsAnalysis<'a> {
    cfg: &'a ControlFlowGraph,
    ir_function: &'a IrFunction,
}

impl<'a> ReachingDefinitionsAnalysis<'a> {
    pub fn new(cfg: &'a ControlFlowGraph, ir_function: &'a IrFunction) -> Self {
        Self { cfg, ir_function }
    }
}

impl<'a> DataFlowAnalysis for ReachingDefinitionsAnalysis<'a> {
    type State = ReachingDefinitionsState;

    fn direction(&self) -> DataFlowDirection {
        DataFlowDirection::Forward
    }

    fn initial_state(&self) -> Self::State {
        ReachingDefinitionsState::new()
    }

    fn boundary_state(&self) -> Self::State {
        ReachingDefinitionsState::new()
    }

    fn transfer_instruction(&self, state: &Self::State, instruction: &Instruction) -> Self::State {
        let mut new_state = state.clone();

        // Get definition and uses for this instruction
        if let Some(def_var) = get_instruction_definition(instruction) {
            // Kill previous definitions of this variable
            new_state.kill_definitions(def_var);
            // Add new definition (we need the block ID - simplified for now)
            new_state.add_definition(def_var, BlockId(0)); // TODO: Pass current block ID
        }

        new_state
    }

    fn meet(&self, states: &[Self::State]) -> Self::State {
        let mut result = ReachingDefinitionsState::new();
        for state in states {
            result.merge(state);
        }
        result
    }

    fn analyze(&mut self) -> Result<DataFlowResult<Self::State>> {
        DataFlowEngine::analyze(self)
    }

    fn cfg(&self) -> &ControlFlowGraph {
        self.cfg
    }
}

/// State for live variables analysis
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LiveVariablesState {
    /// Set of variables that are live at this point
    pub live_vars: HashSet<ValueId>,
}

impl LiveVariablesState {
    pub fn new() -> Self {
        Self {
            live_vars: HashSet::new(),
        }
    }

    pub fn add_live_var(&mut self, var: ValueId) {
        self.live_vars.insert(var);
    }

    pub fn remove_live_var(&mut self, var: ValueId) {
        self.live_vars.remove(&var);
    }

    pub fn merge(&mut self, other: &Self) {
        self.live_vars.extend(&other.live_vars);
    }

    pub fn is_live(&self, var: ValueId) -> bool {
        self.live_vars.contains(&var)
    }
}

/// Live variables analysis implementation
pub struct LiveVariablesAnalysis<'a> {
    cfg: &'a ControlFlowGraph,
    ir_function: &'a IrFunction,
}

impl<'a> LiveVariablesAnalysis<'a> {
    pub fn new(cfg: &'a ControlFlowGraph, ir_function: &'a IrFunction) -> Self {
        Self { cfg, ir_function }
    }
}

impl<'a> DataFlowAnalysis for LiveVariablesAnalysis<'a> {
    type State = LiveVariablesState;

    fn direction(&self) -> DataFlowDirection {
        DataFlowDirection::Backward
    }

    fn initial_state(&self) -> Self::State {
        LiveVariablesState::new()
    }

    fn boundary_state(&self) -> Self::State {
        LiveVariablesState::new()
    }

    fn transfer_instruction(&self, state: &Self::State, instruction: &Instruction) -> Self::State {
        let mut new_state = state.clone();

        // Remove variables that are defined (killed) by this instruction
        if let Some(def_var) = get_instruction_definition(instruction) {
            new_state.remove_live_var(def_var);
        }

        // Add variables that are used by this instruction
        for used_var in get_instruction_uses(instruction) {
            new_state.add_live_var(used_var);
        }

        new_state
    }

    fn meet(&self, states: &[Self::State]) -> Self::State {
        let mut result = LiveVariablesState::new();
        for state in states {
            result.merge(state);
        }
        result
    }

    fn analyze(&mut self) -> Result<DataFlowResult<Self::State>> {
        DataFlowEngine::analyze(self)
    }

    fn cfg(&self) -> &ControlFlowGraph {
        self.cfg
    }
}

/// Def-use chains data structure
#[derive(Debug, Clone)]
pub struct DefUseChains {
    /// Map from definition points to use points
    pub def_to_uses: HashMap<(ValueId, BlockId), HashSet<(ValueId, BlockId)>>,
    /// Map from use points to definition points
    pub use_to_defs: HashMap<(ValueId, BlockId), HashSet<(ValueId, BlockId)>>,
}

impl DefUseChains {
    pub fn new() -> Self {
        Self {
            def_to_uses: HashMap::new(),
            use_to_defs: HashMap::new(),
        }
    }

    pub fn add_def_use_edge(&mut self, def: (ValueId, BlockId), use_point: (ValueId, BlockId)) {
        self.def_to_uses.entry(def).or_default().insert(use_point);
        self.use_to_defs.entry(use_point).or_default().insert(def);
    }

    pub fn get_uses(&self, def: (ValueId, BlockId)) -> Option<&HashSet<(ValueId, BlockId)>> {
        self.def_to_uses.get(&def)
    }

    pub fn get_defs(&self, use_point: (ValueId, BlockId)) -> Option<&HashSet<(ValueId, BlockId)>> {
        self.use_to_defs.get(&use_point)
    }
}

/// Builder for def-use chains
pub struct DefUseChainBuilder<'a> {
    cfg: &'a ControlFlowGraph,
    ir_function: &'a IrFunction,
}

impl<'a> DefUseChainBuilder<'a> {
    pub fn new(cfg: &'a ControlFlowGraph, ir_function: &'a IrFunction) -> Self {
        Self { cfg, ir_function }
    }

    pub fn build(
        &self,
        reaching_defs: &DataFlowResult<ReachingDefinitionsState>,
        _live_vars: &DataFlowResult<LiveVariablesState>,
    ) -> Result<DefUseChains> {
        let mut chains = DefUseChains::new();

        // For each block and instruction, build def-use relationships
        for (block_id, _) in self.cfg.basic_blocks() {
            if let Some(entry_state) = reaching_defs.get_entry_state(block_id) {
                // Process instructions in this block
                // This is a simplified implementation
                for (var_id, def_blocks) in &entry_state.definitions {
                    for def_block in def_blocks {
                        chains.add_def_use_edge((*var_id, *def_block), (*var_id, block_id));
                    }
                }
            }
        }

        Ok(chains)
    }
}

/// Utility functions for instruction analysis
pub fn get_instruction_definition(instruction: &Instruction) -> Option<ValueId> {
    match instruction {
        Instruction::Add(target, _, _) |
        Instruction::Sub(target, _, _) |
        Instruction::Mul(target, _, _) |
        Instruction::Div(target, _, _) |
        Instruction::Mod(target, _, _) |
        Instruction::Exp(target, _, _) |
        Instruction::And(target, _, _) |
        Instruction::Or(target, _, _) |
        Instruction::Xor(target, _, _) |
        Instruction::Not(target, _) |
        Instruction::Shl(target, _, _) |
        Instruction::Shr(target, _, _) |
        Instruction::Sar(target, _, _) |
        Instruction::Compare(target, _, _, _) |
        Instruction::LogicalAnd(target, _, _) |
        Instruction::LogicalOr(target, _, _) |
        Instruction::LogicalNot(target, _) |
        Instruction::Cast(target, _, _, _) |
        Instruction::Load(target, _) |
        Instruction::StorageLoad(target, _) |
        Instruction::ArrayAccess(target, _, _) |
        Instruction::ArrayLength(target, _) |
        Instruction::ArrayPop(target, _) |
        Instruction::MappingAccess(target, _, _) |
        Instruction::StructAccess(target, _, _) |
        Instruction::Call(target, _, _) |
        Instruction::ExternalCall(target, _, _, _) |
        Instruction::DelegateCall(target, _, _, _) |
        Instruction::StaticCall(target, _, _, _) |
        Instruction::Create(target, _, _) |
        Instruction::Create2(target, _, _, _) |
        Instruction::Keccak256(target, _) |
        Instruction::Ecrecover(target, _, _, _, _) |
        Instruction::BlockHash(target, _) |
        Instruction::Balance(target, _) |
        Instruction::Send(target, _, _) |
        Instruction::Phi(target, _) |
        Instruction::Assign(target, _) |
        Instruction::CodeSize(target, _) |
        Instruction::ExtCodeSize(target, _) |
        Instruction::Gas(target) |
        Instruction::GasLimit(target) |
        Instruction::GasPrice(target) => Some(*target),
        _ => None,
    }
}

pub fn get_instruction_uses(instruction: &Instruction) -> HashSet<ValueId> {
    let mut uses = HashSet::new();

    match instruction {
        Instruction::Add(_, lhs, rhs) |
        Instruction::Sub(_, lhs, rhs) |
        Instruction::Mul(_, lhs, rhs) |
        Instruction::Div(_, lhs, rhs) |
        Instruction::Mod(_, lhs, rhs) |
        Instruction::Exp(_, lhs, rhs) => {
            if let IrValue::Value(id) = lhs {
                uses.insert(*id);
            }
            if let IrValue::Value(id) = rhs {
                uses.insert(*id);
            }
        },
        Instruction::Load(_, address) |
        Instruction::StorageLoad(_, address) => {
            if let IrValue::Value(id) = address {
                uses.insert(*id);
            }
        },
        Instruction::Store(address, value) |
        Instruction::StorageStore(address, value) => {
            if let IrValue::Value(id) = address {
                uses.insert(*id);
            }
            if let IrValue::Value(id) = value {
                uses.insert(*id);
            }
        },
        Instruction::ConditionalBranch(condition, _, _) => {
            if let IrValue::Value(id) = condition {
                uses.insert(*id);
            }
        },
        Instruction::Return(Some(value)) => {
            if let IrValue::Value(id) = value {
                uses.insert(*id);
            }
        },
        Instruction::Phi(_, phi_args) => {
            for (value, _) in phi_args {
                if let IrValue::Value(id) = value {
                    uses.insert(*id);
                }
            }
        },
        Instruction::Assign(_, value) => {
            if let IrValue::Value(id) = value {
                uses.insert(*id);
            }
        },
        _ => {
            // Handle other instruction types as needed
        }
    }

    uses
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::{IrFunction, IrType, Instruction, IrValue, ValueId};
    use cfg::{ControlFlowGraph, EdgeType};

    #[test]
    fn test_reaching_definitions_state() {
        let mut state = ReachingDefinitionsState::new();
        let var_id = ValueId(1);
        let block_id = BlockId(1);

        state.add_definition(var_id, block_id);
        assert!(state.get_definitions(var_id).unwrap().contains(&block_id));

        state.kill_definitions(var_id);
        assert!(state.get_definitions(var_id).is_none());
    }

    #[test]
    fn test_live_variables_state() {
        let mut state = LiveVariablesState::new();
        let var_id = ValueId(1);

        state.add_live_var(var_id);
        assert!(state.is_live(var_id));

        state.remove_live_var(var_id);
        assert!(!state.is_live(var_id));
    }

    #[test]
    fn test_def_use_chains() {
        let mut chains = DefUseChains::new();
        let def = (ValueId(1), BlockId(1));
        let use_point = (ValueId(1), BlockId(2));

        chains.add_def_use_edge(def, use_point);
        assert!(chains.get_uses(def).unwrap().contains(&use_point));
        assert!(chains.get_defs(use_point).unwrap().contains(&def));
    }

    #[test]
    fn test_instruction_analysis() {
        let instruction = Instruction::Add(
            ValueId(1),
            IrValue::Value(ValueId(2)),
            IrValue::Value(ValueId(3)),
        );

        assert_eq!(get_instruction_definition(&instruction), Some(ValueId(1)));

        let uses = get_instruction_uses(&instruction);
        assert!(uses.contains(&ValueId(2)));
        assert!(uses.contains(&ValueId(3)));
        assert_eq!(uses.len(), 2);
    }
}
