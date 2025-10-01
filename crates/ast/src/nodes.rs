use bumpalo::collections::Vec as BumpVec;
use crate::location::{SourceLocation, Located};
use crate::arena::AstArena;

/// Identifier with source location
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identifier<'arena> {
    pub name: &'arena str,
    pub location: SourceLocation,
}

impl<'arena> Identifier<'arena> {
    pub fn new(name: &'arena str, location: SourceLocation) -> Self {
        Self { name, location }
    }
}

impl<'arena> Located for Identifier<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Source file containing multiple contracts and imports
#[derive(Debug, Clone)]
pub struct SourceFile<'arena> {
    pub path: &'arena str,
    pub content: &'arena str,
    pub pragma_directives: BumpVec<'arena, PragmaDirective<'arena>>,
    pub import_directives: BumpVec<'arena, ImportDirective<'arena>>,
    pub contracts: BumpVec<'arena, Contract<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> SourceFile<'arena> {
    pub fn new(arena: &'arena AstArena, path: &'arena str, content: &'arena str, location: SourceLocation) -> Self {
        Self {
            path,
            content,
            pragma_directives: BumpVec::new_in(&arena.bump),
            import_directives: BumpVec::new_in(&arena.bump),
            contracts: BumpVec::new_in(&arena.bump),
            location,
        }
    }
}

impl<'arena> Located for SourceFile<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Pragma directive (e.g., pragma solidity ^0.8.0;)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PragmaDirective<'arena> {
    pub name: Identifier<'arena>,
    pub value: &'arena str,
    pub location: SourceLocation,
}

impl<'arena> Located for PragmaDirective<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Import directive
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDirective<'arena> {
    pub path: &'arena str,
    pub symbols: Option<BumpVec<'arena, Identifier<'arena>>>,
    pub alias: Option<Identifier<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Located for ImportDirective<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Contract definition
#[derive(Debug, Clone)]
pub struct Contract<'arena> {
    pub name: Identifier<'arena>,
    pub contract_type: ContractType,
    pub inheritance: BumpVec<'arena, InheritanceSpecifier<'arena>>,
    pub using_for_directives: BumpVec<'arena, UsingForDirective<'arena>>,
    pub state_variables: BumpVec<'arena, StateVariable<'arena>>,
    pub functions: BumpVec<'arena, Function<'arena>>,
    pub modifiers: BumpVec<'arena, Modifier<'arena>>,
    pub events: BumpVec<'arena, Event<'arena>>,
    pub errors: BumpVec<'arena, ErrorDefinition<'arena>>,
    pub structs: BumpVec<'arena, StructDefinition<'arena>>,
    pub enums: BumpVec<'arena, EnumDefinition<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Contract<'arena> {
    pub fn new(arena: &'arena AstArena, name: Identifier<'arena>, contract_type: ContractType, location: SourceLocation) -> Self {
        Self {
            name,
            contract_type,
            inheritance: BumpVec::new_in(&arena.bump),
            using_for_directives: BumpVec::new_in(&arena.bump),
            state_variables: BumpVec::new_in(&arena.bump),
            functions: BumpVec::new_in(&arena.bump),
            modifiers: BumpVec::new_in(&arena.bump),
            events: BumpVec::new_in(&arena.bump),
            errors: BumpVec::new_in(&arena.bump),
            structs: BumpVec::new_in(&arena.bump),
            enums: BumpVec::new_in(&arena.bump),
            location,
        }
    }
}

impl<'arena> Located for Contract<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Contract type (contract, interface, library)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractType {
    Contract,
    Interface,
    Library,
}

/// Inheritance specifier
#[derive(Debug, Clone, PartialEq)]
pub struct InheritanceSpecifier<'arena> {
    pub base: Identifier<'arena>,
    pub arguments: Option<BumpVec<'arena, Expression<'arena>>>,
    pub location: SourceLocation,
}

impl<'arena> Located for InheritanceSpecifier<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Using for directive
#[derive(Debug, Clone, PartialEq)]
pub struct UsingForDirective<'arena> {
    pub library: Identifier<'arena>,
    pub type_name: Option<TypeName<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Located for UsingForDirective<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// State variable declaration
#[derive(Debug, Clone)]
pub struct StateVariable<'arena> {
    pub name: Identifier<'arena>,
    pub type_name: TypeName<'arena>,
    pub visibility: Visibility,
    pub mutability: StateMutability,
    pub initial_value: Option<Expression<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Located for StateVariable<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Function definition
#[derive(Debug, Clone)]
pub struct Function<'arena> {
    pub name: Identifier<'arena>,
    pub function_type: FunctionType,
    pub parameters: BumpVec<'arena, Parameter<'arena>>,
    pub return_parameters: BumpVec<'arena, Parameter<'arena>>,
    pub modifiers: BumpVec<'arena, ModifierInvocation<'arena>>,
    pub visibility: Visibility,
    pub mutability: StateMutability,
    pub body: Option<Block<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Function<'arena> {
    pub fn new(arena: &'arena AstArena, name: Identifier<'arena>, location: SourceLocation) -> Self {
        Self {
            name,
            function_type: FunctionType::Function,
            parameters: BumpVec::new_in(&arena.bump),
            return_parameters: BumpVec::new_in(&arena.bump),
            modifiers: BumpVec::new_in(&arena.bump),
            visibility: Visibility::Internal,
            mutability: StateMutability::NonPayable,
            body: None,
            location,
        }
    }
}

impl<'arena> Located for Function<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Function type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionType {
    Function,
    Constructor,
    Fallback,
    Receive,
}

/// Parameter definition
#[derive(Debug, Clone, PartialEq)]
pub struct Parameter<'arena> {
    pub name: Option<Identifier<'arena>>,
    pub type_name: TypeName<'arena>,
    pub storage_location: Option<StorageLocation>,
    pub location: SourceLocation,
}

impl<'arena> Located for Parameter<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Modifier definition
#[derive(Debug, Clone)]
pub struct Modifier<'arena> {
    pub name: Identifier<'arena>,
    pub parameters: BumpVec<'arena, Parameter<'arena>>,
    pub body: Block<'arena>,
    pub location: SourceLocation,
}

impl<'arena> Located for Modifier<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Modifier invocation in function
#[derive(Debug, Clone)]
pub struct ModifierInvocation<'arena> {
    pub name: Identifier<'arena>,
    pub arguments: BumpVec<'arena, Expression<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Located for ModifierInvocation<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Event definition
#[derive(Debug, Clone)]
pub struct Event<'arena> {
    pub name: Identifier<'arena>,
    pub parameters: BumpVec<'arena, EventParameter<'arena>>,
    pub anonymous: bool,
    pub location: SourceLocation,
}

impl<'arena> Located for Event<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Event parameter
#[derive(Debug, Clone, PartialEq)]
pub struct EventParameter<'arena> {
    pub name: Option<Identifier<'arena>>,
    pub type_name: TypeName<'arena>,
    pub indexed: bool,
    pub location: SourceLocation,
}

impl<'arena> Located for EventParameter<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Error definition
#[derive(Debug, Clone)]
pub struct ErrorDefinition<'arena> {
    pub name: Identifier<'arena>,
    pub parameters: BumpVec<'arena, Parameter<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Located for ErrorDefinition<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Struct definition
#[derive(Debug, Clone)]
pub struct StructDefinition<'arena> {
    pub name: Identifier<'arena>,
    pub members: BumpVec<'arena, StructMember<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Located for StructDefinition<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Struct member
#[derive(Debug, Clone, PartialEq)]
pub struct StructMember<'arena> {
    pub name: Identifier<'arena>,
    pub type_name: TypeName<'arena>,
    pub location: SourceLocation,
}

impl<'arena> Located for StructMember<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Enum definition
#[derive(Debug, Clone)]
pub struct EnumDefinition<'arena> {
    pub name: Identifier<'arena>,
    pub values: BumpVec<'arena, Identifier<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Located for EnumDefinition<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Type name
#[derive(Debug, Clone, PartialEq)]
pub enum TypeName<'arena> {
    Elementary(ElementaryType),
    UserDefined(Identifier<'arena>),
    Array {
        base_type: &'arena TypeName<'arena>,
        length: Option<&'arena Expression<'arena>>,
    },
    Mapping {
        key_type: &'arena TypeName<'arena>,
        value_type: &'arena TypeName<'arena>,
    },
    Function {
        parameters: BumpVec<'arena, TypeName<'arena>>,
        return_types: BumpVec<'arena, TypeName<'arena>>,
        visibility: Visibility,
        mutability: StateMutability,
    },
}

/// Elementary type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElementaryType {
    Bool,
    String,
    Bytes,
    FixedBytes(u8),
    Address,
    Uint(u16),
    Int(u16),
    Fixed(u16, u8),
    Ufixed(u16, u8),
}

/// Statement block
#[derive(Debug, Clone)]
pub struct Block<'arena> {
    pub statements: BumpVec<'arena, Statement<'arena>>,
    pub location: SourceLocation,
}

impl<'arena> Block<'arena> {
    pub fn new(arena: &'arena AstArena, location: SourceLocation) -> Self {
        Self {
            statements: BumpVec::new_in(&arena.bump),
            location,
        }
    }
}

impl<'arena> Located for Block<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Statement types
#[derive(Debug, Clone)]
pub enum Statement<'arena> {
    Block(Block<'arena>),
    Expression(Expression<'arena>),
    VariableDeclaration {
        declarations: BumpVec<'arena, VariableDeclaration<'arena>>,
        initial_value: Option<Expression<'arena>>,
        location: SourceLocation,
    },
    If {
        condition: Expression<'arena>,
        then_branch: &'arena Statement<'arena>,
        else_branch: Option<&'arena Statement<'arena>>,
        location: SourceLocation,
    },
    While {
        condition: Expression<'arena>,
        body: &'arena Statement<'arena>,
        location: SourceLocation,
    },
    For {
        init: Option<&'arena Statement<'arena>>,
        condition: Option<Expression<'arena>>,
        update: Option<Expression<'arena>>,
        body: &'arena Statement<'arena>,
        location: SourceLocation,
    },
    Return {
        value: Option<Expression<'arena>>,
        location: SourceLocation,
    },
    Break {
        location: SourceLocation,
    },
    Continue {
        location: SourceLocation,
    },
    Throw {
        location: SourceLocation,
    },
    EmitStatement {
        event_call: Expression<'arena>,
        location: SourceLocation,
    },
    RevertStatement {
        error_call: Option<Expression<'arena>>,
        location: SourceLocation,
    },
    TryStatement {
        expression: Expression<'arena>,
        returns: Option<BumpVec<'arena, Parameter<'arena>>>,
        body: Block<'arena>,
        catch_clauses: BumpVec<'arena, CatchClause<'arena>>,
        location: SourceLocation,
    },
}

impl<'arena> Located for Statement<'arena> {
    fn location(&self) -> &SourceLocation {
        match self {
            Statement::Block(block) => &block.location,
            Statement::Expression(expr) => expr.location(),
            Statement::VariableDeclaration { location, .. } => location,
            Statement::If { location, .. } => location,
            Statement::While { location, .. } => location,
            Statement::For { location, .. } => location,
            Statement::Return { location, .. } => location,
            Statement::Break { location } => location,
            Statement::Continue { location } => location,
            Statement::Throw { location } => location,
            Statement::EmitStatement { location, .. } => location,
            Statement::RevertStatement { location, .. } => location,
            Statement::TryStatement { location, .. } => location,
        }
    }
}

/// Variable declaration
#[derive(Debug, Clone, PartialEq)]
pub struct VariableDeclaration<'arena> {
    pub name: Identifier<'arena>,
    pub type_name: Option<TypeName<'arena>>,
    pub storage_location: Option<StorageLocation>,
    pub location: SourceLocation,
}

impl<'arena> Located for VariableDeclaration<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Catch clause for try/catch
#[derive(Debug, Clone)]
pub struct CatchClause<'arena> {
    pub identifier: Option<Identifier<'arena>>,
    pub parameters: BumpVec<'arena, Parameter<'arena>>,
    pub body: Block<'arena>,
    pub location: SourceLocation,
}

impl<'arena> Located for CatchClause<'arena> {
    fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Expression types
#[derive(Debug, Clone, PartialEq)]
pub enum Expression<'arena> {
    Identifier(Identifier<'arena>),
    Literal {
        value: LiteralValue<'arena>,
        location: SourceLocation,
    },
    BinaryOperation {
        left: &'arena Expression<'arena>,
        operator: BinaryOperator,
        right: &'arena Expression<'arena>,
        location: SourceLocation,
    },
    UnaryOperation {
        operator: UnaryOperator,
        operand: &'arena Expression<'arena>,
        prefix: bool,
        location: SourceLocation,
    },
    Assignment {
        left: &'arena Expression<'arena>,
        operator: AssignmentOperator,
        right: &'arena Expression<'arena>,
        location: SourceLocation,
    },
    MemberAccess {
        expression: &'arena Expression<'arena>,
        member: Identifier<'arena>,
        location: SourceLocation,
    },
    IndexAccess {
        base: &'arena Expression<'arena>,
        index: Option<&'arena Expression<'arena>>,
        location: SourceLocation,
    },
    FunctionCall {
        function: &'arena Expression<'arena>,
        arguments: BumpVec<'arena, Expression<'arena>>,
        names: BumpVec<'arena, Identifier<'arena>>,
        location: SourceLocation,
    },
    NewExpression {
        type_name: &'arena TypeName<'arena>,
        location: SourceLocation,
    },
    Conditional {
        condition: &'arena Expression<'arena>,
        true_expression: &'arena Expression<'arena>,
        false_expression: &'arena Expression<'arena>,
        location: SourceLocation,
    },
    TypeCast {
        type_name: &'arena TypeName<'arena>,
        expression: &'arena Expression<'arena>,
        location: SourceLocation,
    },
}

impl<'arena> Located for Expression<'arena> {
    fn location(&self) -> &SourceLocation {
        match self {
            Expression::Identifier(id) => &id.location,
            Expression::Literal { location, .. } => location,
            Expression::BinaryOperation { location, .. } => location,
            Expression::UnaryOperation { location, .. } => location,
            Expression::Assignment { location, .. } => location,
            Expression::MemberAccess { location, .. } => location,
            Expression::IndexAccess { location, .. } => location,
            Expression::FunctionCall { location, .. } => location,
            Expression::NewExpression { location, .. } => location,
            Expression::Conditional { location, .. } => location,
            Expression::TypeCast { location, .. } => location,
        }
    }
}

/// Literal values
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiteralValue<'arena> {
    Boolean(bool),
    Number(&'arena str),
    String(&'arena str),
    HexString(&'arena str),
    UnicodeString(&'arena str),
    Address(&'arena str),
}

/// Binary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOperator {
    Add, Sub, Mul, Div, Mod, Pow,
    Equal, NotEqual, Less, LessEqual, Greater, GreaterEqual,
    And, Or,
    BitwiseAnd, BitwiseOr, BitwiseXor,
    ShiftLeft, ShiftRight,
}

/// Unary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOperator {
    Plus, Minus, Not, BitwiseNot,
    Increment, Decrement,
    Delete,
}

/// Assignment operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssignmentOperator {
    Assign,
    AddAssign, SubAssign, MulAssign, DivAssign, ModAssign,
    AndAssign, OrAssign, XorAssign,
    ShiftLeftAssign, ShiftRightAssign,
}

/// Visibility modifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    Public,
    Internal,
    External,
    Private,
}

/// State mutability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StateMutability {
    Pure,
    View,
    NonPayable,
    Payable,
}

/// Storage location
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageLocation {
    Storage,
    Memory,
    Calldata,
}