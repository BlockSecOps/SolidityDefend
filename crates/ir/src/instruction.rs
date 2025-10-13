use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Unique identifier for IR values in SSA form
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueId(pub u32);

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "%{}", self.0)
    }
}

/// Unique identifier for basic blocks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId(pub u32);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// IR type system for Solidity
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrType {
    /// Boolean type
    Bool,
    /// Unsigned integer with bit width
    Uint(u16),
    /// Signed integer with bit width
    Int(u16),
    /// Fixed-size byte array
    FixedBytes(u8),
    /// Dynamic byte array
    Bytes,
    /// String type
    String,
    /// Address type (20 bytes)
    Address,
    /// Array type with element type and optional length
    Array {
        element_type: Box<IrType>,
        length: Option<u64>,
    },
    /// Mapping type
    Mapping {
        key_type: Box<IrType>,
        value_type: Box<IrType>,
    },
    /// Struct type with field types
    Struct {
        name: String,
        fields: Vec<(String, IrType)>,
    },
    /// Contract type
    Contract(String),
    /// Function type
    Function {
        parameters: Vec<IrType>,
        returns: Vec<IrType>,
    },
    /// Void type for operations that don't return values
    Void,
    /// Error type for type resolution failures
    Error,
}

impl fmt::Display for IrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrType::Bool => write!(f, "bool"),
            IrType::Uint(bits) => write!(f, "uint{}", bits),
            IrType::Int(bits) => write!(f, "int{}", bits),
            IrType::FixedBytes(size) => write!(f, "bytes{}", size),
            IrType::Bytes => write!(f, "bytes"),
            IrType::String => write!(f, "string"),
            IrType::Address => write!(f, "address"),
            IrType::Array {
                element_type,
                length,
            } => match length {
                Some(len) => write!(f, "{}[{}]", element_type, len),
                None => write!(f, "{}[]", element_type),
            },
            IrType::Mapping {
                key_type,
                value_type,
            } => {
                write!(f, "mapping({} => {})", key_type, value_type)
            }
            IrType::Struct { name, .. } => write!(f, "struct {}", name),
            IrType::Contract(name) => write!(f, "contract {}", name),
            IrType::Function {
                parameters,
                returns,
            } => {
                write!(
                    f,
                    "function({}) returns ({})",
                    parameters
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    returns
                        .iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            IrType::Void => write!(f, "void"),
            IrType::Error => write!(f, "error"),
        }
    }
}

/// IR value representation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IrValue {
    /// SSA value reference
    Value(ValueId),
    /// Constant integer literal
    ConstantInt(u64),
    /// Constant boolean literal
    ConstantBool(bool),
    /// Constant string literal
    ConstantString(String),
    /// Constant address literal
    ConstantAddress([u8; 20]),
    /// Constant bytes literal
    ConstantBytes(Vec<u8>),
    /// Undefined value (for uninitialized variables)
    Undefined,
}

impl fmt::Display for IrValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrValue::Value(id) => write!(f, "{}", id),
            IrValue::ConstantInt(val) => write!(f, "{}", val),
            IrValue::ConstantBool(val) => write!(f, "{}", val),
            IrValue::ConstantString(val) => write!(f, "\"{}\"", val),
            IrValue::ConstantAddress(addr) => {
                write!(f, "0x{}", hex::encode(addr))
            }
            IrValue::ConstantBytes(bytes) => {
                write!(f, "0x{}", hex::encode(bytes))
            }
            IrValue::Undefined => write!(f, "undef"),
        }
    }
}

/// Comparison operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareOp {
    Equal,
    NotEqual,
    LessThan,
    LessEqual,
    GreaterThan,
    GreaterEqual,
}

impl fmt::Display for CompareOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompareOp::Equal => write!(f, "eq"),
            CompareOp::NotEqual => write!(f, "ne"),
            CompareOp::LessThan => write!(f, "lt"),
            CompareOp::LessEqual => write!(f, "le"),
            CompareOp::GreaterThan => write!(f, "gt"),
            CompareOp::GreaterEqual => write!(f, "ge"),
        }
    }
}

/// Cast types for type conversions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CastType {
    /// Truncate to smaller type
    Truncate,
    /// Zero-extend to larger type
    ZeroExtend,
    /// Sign-extend to larger type
    SignExtend,
    /// Bitcast (reinterpret bits)
    Bitcast,
}

/// IR instruction set for Solidity analysis
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Instruction {
    // Arithmetic operations
    Add(ValueId, IrValue, IrValue),
    Sub(ValueId, IrValue, IrValue),
    Mul(ValueId, IrValue, IrValue),
    Div(ValueId, IrValue, IrValue),
    Mod(ValueId, IrValue, IrValue),
    Exp(ValueId, IrValue, IrValue),

    // Bitwise operations
    And(ValueId, IrValue, IrValue),
    Or(ValueId, IrValue, IrValue),
    Xor(ValueId, IrValue, IrValue),
    Not(ValueId, IrValue),
    Shl(ValueId, IrValue, IrValue), // Left shift
    Shr(ValueId, IrValue, IrValue), // Right shift
    Sar(ValueId, IrValue, IrValue), // Arithmetic right shift

    // Comparison operations
    Compare(ValueId, CompareOp, IrValue, IrValue),

    // Logical operations
    LogicalAnd(ValueId, IrValue, IrValue),
    LogicalOr(ValueId, IrValue, IrValue),
    LogicalNot(ValueId, IrValue),

    // Type casting
    Cast(ValueId, CastType, IrValue, IrType),

    // Memory operations
    Load(ValueId, IrValue),  // Load from memory address
    Store(IrValue, IrValue), // Store value to memory address

    // Storage operations (Solidity-specific)
    StorageLoad(ValueId, IrValue),  // Load from storage slot
    StorageStore(IrValue, IrValue), // Store to storage slot

    // Array operations
    ArrayAccess(ValueId, IrValue, IrValue), // array[index]
    ArrayLength(ValueId, IrValue),          // array.length
    ArrayPush(IrValue, IrValue),            // array.push(value)
    ArrayPop(ValueId, IrValue),             // array.pop()

    // Mapping operations
    MappingAccess(ValueId, IrValue, IrValue), // mapping[key]
    MappingStore(IrValue, IrValue, IrValue),  // mapping[key] = value

    // Struct operations
    StructAccess(ValueId, IrValue, String), // struct.field
    StructStore(IrValue, String, IrValue),  // struct.field = value

    // Control flow
    Branch(BlockId),                              // Unconditional branch
    ConditionalBranch(IrValue, BlockId, BlockId), // Branch on condition
    Return(Option<IrValue>),                      // Return with optional value

    // Function calls
    Call(ValueId, String, Vec<IrValue>), // Function call
    ExternalCall(ValueId, IrValue, String, Vec<IrValue>), // External contract call
    DelegateCall(ValueId, IrValue, String, Vec<IrValue>), // Delegate call
    StaticCall(ValueId, IrValue, String, Vec<IrValue>), // Static call

    // Contract operations
    Create(ValueId, String, Vec<IrValue>), // Contract creation
    Create2(ValueId, IrValue, String, Vec<IrValue>), // CREATE2
    SelfDestruct(IrValue),                 // selfdestruct(address)

    // Built-in operations
    Keccak256(ValueId, IrValue), // keccak256 hash
    Ecrecover(ValueId, IrValue, IrValue, IrValue, IrValue), // ecrecover

    // Blockchain operations
    BlockHash(ValueId, IrValue),     // blockhash(blockNumber)
    Balance(ValueId, IrValue),       // address.balance
    Transfer(IrValue, IrValue),      // address.transfer(amount)
    Send(ValueId, IrValue, IrValue), // address.send(amount)

    // Assembly operations
    Asm(String, Vec<IrValue>, Vec<ValueId>), // Inline assembly

    // SSA operations
    Phi(ValueId, Vec<(IrValue, BlockId)>), // Phi node for SSA form

    // Variable assignment
    Assign(ValueId, IrValue), // Variable assignment in SSA form

    // Error handling
    Revert(Option<IrValue>),           // revert with optional message
    Require(IrValue, Option<IrValue>), // require(condition, message)
    Assert(IrValue),                   // assert(condition)

    // Events
    EmitEvent(String, Vec<IrValue>), // Emit event

    // Low-level operations
    CodeSize(ValueId, IrValue),                      // address.code.length
    CodeCopy(IrValue, IrValue, IrValue),             // codecopy
    ExtCodeSize(ValueId, IrValue),                   // external code size
    ExtCodeCopy(IrValue, IrValue, IrValue, IrValue), // external code copy

    // Gas operations
    Gas(ValueId),      // gasleft()
    GasLimit(ValueId), // block.gaslimit
    GasPrice(ValueId), // tx.gasprice
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Add(dest, lhs, rhs) => write!(f, "{} = add {}, {}", dest, lhs, rhs),
            Instruction::Sub(dest, lhs, rhs) => write!(f, "{} = sub {}, {}", dest, lhs, rhs),
            Instruction::Mul(dest, lhs, rhs) => write!(f, "{} = mul {}, {}", dest, lhs, rhs),
            Instruction::Div(dest, lhs, rhs) => write!(f, "{} = div {}, {}", dest, lhs, rhs),
            Instruction::Mod(dest, lhs, rhs) => write!(f, "{} = mod {}, {}", dest, lhs, rhs),
            Instruction::Exp(dest, lhs, rhs) => write!(f, "{} = exp {}, {}", dest, lhs, rhs),

            Instruction::And(dest, lhs, rhs) => write!(f, "{} = and {}, {}", dest, lhs, rhs),
            Instruction::Or(dest, lhs, rhs) => write!(f, "{} = or {}, {}", dest, lhs, rhs),
            Instruction::Xor(dest, lhs, rhs) => write!(f, "{} = xor {}, {}", dest, lhs, rhs),
            Instruction::Not(dest, operand) => write!(f, "{} = not {}", dest, operand),
            Instruction::Shl(dest, lhs, rhs) => write!(f, "{} = shl {}, {}", dest, lhs, rhs),
            Instruction::Shr(dest, lhs, rhs) => write!(f, "{} = shr {}, {}", dest, lhs, rhs),
            Instruction::Sar(dest, lhs, rhs) => write!(f, "{} = sar {}, {}", dest, lhs, rhs),

            Instruction::Compare(dest, op, lhs, rhs) => {
                write!(f, "{} = {} {}, {}", dest, op, lhs, rhs)
            }

            Instruction::LogicalAnd(dest, lhs, rhs) => {
                write!(f, "{} = land {}, {}", dest, lhs, rhs)
            }
            Instruction::LogicalOr(dest, lhs, rhs) => write!(f, "{} = lor {}, {}", dest, lhs, rhs),
            Instruction::LogicalNot(dest, operand) => write!(f, "{} = lnot {}", dest, operand),

            Instruction::Cast(dest, cast_type, value, target_type) => {
                write!(f, "{} = {:?} {} to {}", dest, cast_type, value, target_type)
            }

            Instruction::Load(dest, addr) => write!(f, "{} = load {}", dest, addr),
            Instruction::Store(addr, value) => write!(f, "store {}, {}", addr, value),

            Instruction::StorageLoad(dest, slot) => write!(f, "{} = sload {}", dest, slot),
            Instruction::StorageStore(slot, value) => write!(f, "sstore {}, {}", slot, value),

            Instruction::ArrayAccess(dest, array, index) => {
                write!(f, "{} = array_access {}, {}", dest, array, index)
            }
            Instruction::ArrayLength(dest, array) => write!(f, "{} = array_length {}", dest, array),
            Instruction::ArrayPush(array, value) => write!(f, "array_push {}, {}", array, value),
            Instruction::ArrayPop(dest, array) => write!(f, "{} = array_pop {}", dest, array),

            Instruction::MappingAccess(dest, mapping, key) => {
                write!(f, "{} = mapping_access {}, {}", dest, mapping, key)
            }
            Instruction::MappingStore(mapping, key, value) => {
                write!(f, "mapping_store {}, {}, {}", mapping, key, value)
            }

            Instruction::StructAccess(dest, struct_val, field) => {
                write!(f, "{} = struct_access {}, {}", dest, struct_val, field)
            }
            Instruction::StructStore(struct_val, field, value) => {
                write!(f, "struct_store {}, {}, {}", struct_val, field, value)
            }

            Instruction::Branch(block) => write!(f, "br {}", block),
            Instruction::ConditionalBranch(cond, then_block, else_block) => {
                write!(f, "br {}, {}, {}", cond, then_block, else_block)
            }
            Instruction::Return(value) => match value {
                Some(val) => write!(f, "ret {}", val),
                None => write!(f, "ret"),
            },

            Instruction::Call(dest, func_name, args) => {
                write!(
                    f,
                    "{} = call {}({})",
                    dest,
                    func_name,
                    args.iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Instruction::ExternalCall(dest, contract, func_name, args) => {
                write!(
                    f,
                    "{} = external_call {}.{}({})",
                    dest,
                    contract,
                    func_name,
                    args.iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }

            Instruction::Phi(dest, incoming) => {
                let incoming_str = incoming
                    .iter()
                    .map(|(val, block)| format!("[{}, {}]", val, block))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "{} = phi {}", dest, incoming_str)
            }

            Instruction::Assign(dest, value) => write!(f, "{} = {}", dest, value),

            Instruction::Revert(msg) => match msg {
                Some(message) => write!(f, "revert {}", message),
                None => write!(f, "revert"),
            },
            Instruction::Require(cond, msg) => match msg {
                Some(message) => write!(f, "require {}, {}", cond, message),
                None => write!(f, "require {}", cond),
            },
            Instruction::Assert(cond) => write!(f, "assert {}", cond),

            // Simplified display for other instructions
            _ => write!(f, "{:?}", self),
        }
    }
}

/// Basic block in the IR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub instructions: Vec<Instruction>,
    pub predecessors: Vec<BlockId>,
    pub successors: Vec<BlockId>,
}

impl BasicBlock {
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            instructions: Vec::new(),
            predecessors: Vec::new(),
            successors: Vec::new(),
        }
    }

    pub fn add_instruction(&mut self, instruction: Instruction) {
        self.instructions.push(instruction);
    }

    pub fn add_predecessor(&mut self, block_id: BlockId) {
        if !self.predecessors.contains(&block_id) {
            self.predecessors.push(block_id);
        }
    }

    pub fn add_successor(&mut self, block_id: BlockId) {
        if !self.successors.contains(&block_id) {
            self.successors.push(block_id);
        }
    }

    pub fn is_terminator(&self) -> bool {
        if let Some(last_instruction) = self.instructions.last() {
            matches!(
                last_instruction,
                Instruction::Branch(_)
                    | Instruction::ConditionalBranch(_, _, _)
                    | Instruction::Return(_)
                    | Instruction::Revert(_)
                    | Instruction::SelfDestruct(_)
            )
        } else {
            false
        }
    }
}

/// IR function representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFunction {
    pub name: String,
    pub parameters: Vec<(String, IrType)>,
    pub return_types: Vec<IrType>,
    pub basic_blocks: HashMap<BlockId, BasicBlock>,
    pub entry_block: BlockId,
    pub value_types: HashMap<ValueId, IrType>,
    pub next_value_id: u32,
    pub next_block_id: u32,
}

impl IrFunction {
    pub fn new(name: String, parameters: Vec<(String, IrType)>, return_types: Vec<IrType>) -> Self {
        let entry_block = BlockId(0);
        let mut basic_blocks = HashMap::new();
        basic_blocks.insert(entry_block, BasicBlock::new(entry_block));

        Self {
            name,
            parameters,
            return_types,
            basic_blocks,
            entry_block,
            value_types: HashMap::new(),
            next_value_id: 0,
            next_block_id: 1,
        }
    }

    pub fn create_value(&mut self, ir_type: IrType) -> ValueId {
        let value_id = ValueId(self.next_value_id);
        self.next_value_id += 1;
        self.value_types.insert(value_id, ir_type);
        value_id
    }

    pub fn create_block(&mut self) -> BlockId {
        let block_id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        self.basic_blocks
            .insert(block_id, BasicBlock::new(block_id));
        block_id
    }

    pub fn get_block_mut(&mut self, block_id: BlockId) -> Option<&mut BasicBlock> {
        self.basic_blocks.get_mut(&block_id)
    }

    pub fn get_block(&self, block_id: BlockId) -> Option<&BasicBlock> {
        self.basic_blocks.get(&block_id)
    }

    pub fn add_instruction(&mut self, block_id: BlockId, instruction: Instruction) -> Result<()> {
        if let Some(block) = self.basic_blocks.get_mut(&block_id) {
            block.add_instruction(instruction);
            Ok(())
        } else {
            Err(anyhow!("Block {} not found", block_id))
        }
    }

    pub fn get_value_type(&self, value_id: ValueId) -> Option<&IrType> {
        self.value_types.get(&value_id)
    }

    pub fn get_instructions(&self) -> Vec<&Instruction> {
        let mut instructions = Vec::new();
        for block in self.basic_blocks.values() {
            instructions.extend(&block.instructions);
        }
        instructions
    }

    pub fn is_ssa_form(&self) -> bool {
        // Basic SSA validation: each value is defined exactly once
        let mut defined_values = std::collections::HashSet::new();

        for block in self.basic_blocks.values() {
            for instruction in &block.instructions {
                if let Some(def_value) = self.get_defined_value(instruction) {
                    if defined_values.contains(&def_value) {
                        return false; // Value defined multiple times
                    }
                    defined_values.insert(def_value);
                }
            }
        }
        true
    }

    fn get_defined_value(&self, instruction: &Instruction) -> Option<ValueId> {
        match instruction {
            Instruction::Add(dest, _, _)
            | Instruction::Sub(dest, _, _)
            | Instruction::Mul(dest, _, _)
            | Instruction::Div(dest, _, _)
            | Instruction::Mod(dest, _, _)
            | Instruction::Exp(dest, _, _)
            | Instruction::And(dest, _, _)
            | Instruction::Or(dest, _, _)
            | Instruction::Xor(dest, _, _)
            | Instruction::Not(dest, _)
            | Instruction::Shl(dest, _, _)
            | Instruction::Shr(dest, _, _)
            | Instruction::Sar(dest, _, _)
            | Instruction::Compare(dest, _, _, _)
            | Instruction::LogicalAnd(dest, _, _)
            | Instruction::LogicalOr(dest, _, _)
            | Instruction::LogicalNot(dest, _)
            | Instruction::Cast(dest, _, _, _)
            | Instruction::Load(dest, _)
            | Instruction::StorageLoad(dest, _)
            | Instruction::ArrayAccess(dest, _, _)
            | Instruction::ArrayLength(dest, _)
            | Instruction::ArrayPop(dest, _)
            | Instruction::MappingAccess(dest, _, _)
            | Instruction::StructAccess(dest, _, _)
            | Instruction::Call(dest, _, _)
            | Instruction::ExternalCall(dest, _, _, _)
            | Instruction::DelegateCall(dest, _, _, _)
            | Instruction::StaticCall(dest, _, _, _)
            | Instruction::Create(dest, _, _)
            | Instruction::Create2(dest, _, _, _)
            | Instruction::Keccak256(dest, _)
            | Instruction::Ecrecover(dest, _, _, _, _)
            | Instruction::BlockHash(dest, _)
            | Instruction::Balance(dest, _)
            | Instruction::Send(dest, _, _)
            | Instruction::Phi(dest, _)
            | Instruction::Assign(dest, _)
            | Instruction::CodeSize(dest, _)
            | Instruction::ExtCodeSize(dest, _)
            | Instruction::Gas(dest)
            | Instruction::GasLimit(dest)
            | Instruction::GasPrice(dest) => Some(*dest),
            _ => None,
        }
    }

    pub fn to_ssa_form(&self) -> IrFunction {
        // For now, return a clone as the IR is already designed for SSA
        // TODO: Implement proper SSA construction with phi node insertion
        self.clone()
    }
}

impl fmt::Display for IrFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "function {}({}) -> ({}) {{",
            self.name,
            self.parameters
                .iter()
                .map(|(name, ty)| format!("{}: {}", name, ty))
                .collect::<Vec<_>>()
                .join(", "),
            self.return_types
                .iter()
                .map(|ty| ty.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )?;

        // Print blocks in order starting with entry block
        if let Some(entry_block) = self.basic_blocks.get(&self.entry_block) {
            writeln!(f, "{}:", entry_block.id)?;
            for instruction in &entry_block.instructions {
                writeln!(f, "    {}", instruction)?;
            }
        }

        // Print other blocks
        for (block_id, block) in &self.basic_blocks {
            if *block_id != self.entry_block {
                writeln!(f, "{}:", block.id)?;
                for instruction in &block.instructions {
                    writeln!(f, "    {}", instruction)?;
                }
            }
        }

        writeln!(f, "}}")
    }
}

/// AST to IR lowering context
pub struct Lowering {
    current_function: Option<IrFunction>,
    value_counter: u32,
    block_counter: u32,
}

impl Lowering {
    pub fn new() -> Self {
        Self {
            current_function: None,
            value_counter: 0,
            block_counter: 0,
        }
    }

    /// Create a new value with the given type
    pub fn create_value(&mut self, ir_type: IrType) -> ValueId {
        let value_id = ValueId(self.value_counter);
        self.value_counter += 1;

        if let Some(ref mut function) = self.current_function {
            function.value_types.insert(value_id, ir_type);
        }

        value_id
    }

    /// Create a new basic block
    pub fn create_block(&mut self) -> BlockId {
        let block_id = BlockId(self.block_counter);
        self.block_counter += 1;

        if let Some(ref mut function) = self.current_function {
            function
                .basic_blocks
                .insert(block_id, BasicBlock::new(block_id));
        }

        block_id
    }
}

impl Default for Lowering {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_id_display() {
        let value = ValueId(42);
        assert_eq!(format!("{}", value), "%42");
    }

    #[test]
    fn test_block_id_display() {
        let block = BlockId(5);
        assert_eq!(format!("{}", block), "bb5");
    }

    #[test]
    fn test_ir_type_display() {
        assert_eq!(format!("{}", IrType::Uint(256)), "uint256");
        assert_eq!(format!("{}", IrType::Address), "address");
        assert_eq!(format!("{}", IrType::Bool), "bool");
    }

    #[test]
    fn test_instruction_display() {
        let add_inst = Instruction::Add(
            ValueId(1),
            IrValue::Value(ValueId(2)),
            IrValue::ConstantInt(42),
        );
        assert_eq!(format!("{}", add_inst), "%1 = add %2, 42");
    }

    #[test]
    fn test_basic_block_creation() {
        let mut block = BasicBlock::new(BlockId(0));
        assert_eq!(block.id, BlockId(0));
        assert!(block.instructions.is_empty());
        assert!(block.predecessors.is_empty());
        assert!(block.successors.is_empty());

        block.add_instruction(Instruction::Add(
            ValueId(0),
            IrValue::ConstantInt(1),
            IrValue::ConstantInt(2),
        ));
        assert_eq!(block.instructions.len(), 1);
    }

    #[test]
    fn test_ir_function_creation() {
        let params = vec![("a".to_string(), IrType::Uint(256))];
        let returns = vec![IrType::Uint(256)];
        let mut function = IrFunction::new("test".to_string(), params, returns);

        assert_eq!(function.name, "test");
        assert_eq!(function.parameters.len(), 1);
        assert_eq!(function.return_types.len(), 1);
        assert_eq!(function.basic_blocks.len(), 1);

        let value_id = function.create_value(IrType::Uint(256));
        assert_eq!(value_id, ValueId(0));

        let block_id = function.create_block();
        assert_eq!(block_id, BlockId(1));
        assert_eq!(function.basic_blocks.len(), 2);
    }

    #[test]
    fn test_ssa_form_validation() {
        let params = vec![];
        let returns = vec![];
        let mut function = IrFunction::new("test".to_string(), params, returns);

        // Add valid SSA instructions
        let val1 = function.create_value(IrType::Uint(256));
        let val2 = function.create_value(IrType::Uint(256));

        function
            .add_instruction(
                function.entry_block,
                Instruction::Add(val1, IrValue::ConstantInt(1), IrValue::ConstantInt(2)),
            )
            .unwrap();

        function
            .add_instruction(
                function.entry_block,
                Instruction::Mul(val2, IrValue::Value(val1), IrValue::ConstantInt(3)),
            )
            .unwrap();

        assert!(function.is_ssa_form());
    }

    #[test]
    fn test_lowering_creation() {
        let lowering = Lowering::new();
        assert!(lowering.current_function.is_none());
        assert_eq!(lowering.value_counter, 0);
        assert_eq!(lowering.block_counter, 0);
    }
}
