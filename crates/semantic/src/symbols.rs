use std::collections::HashMap;
use std::fmt;
use anyhow::{Result, anyhow};

use ast::{Contract, Function, SourceLocation, ContractType};

/// Maximum depth for scope traversal to prevent infinite loops in circular parent relationships
const MAX_SCOPE_DEPTH: usize = 100;

/// Represents different kinds of symbols in the symbol table
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolKind {
    /// Built-in types (uint256, address, bool, etc.)
    Type,
    /// Contract definition
    Contract,
    /// Interface definition
    Interface,
    /// Library definition
    Library,
    /// Function definition
    Function,
    /// Modifier definition
    Modifier,
    /// Event definition
    Event,
    /// State variable
    StateVariable,
    /// Local variable
    LocalVariable,
    /// Function parameter
    Parameter,
    /// Struct definition
    Struct,
    /// Enum definition
    Enum,
    /// Error definition
    Error,
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolKind::Type => write!(f, "type"),
            SymbolKind::Contract => write!(f, "contract"),
            SymbolKind::Interface => write!(f, "interface"),
            SymbolKind::Library => write!(f, "library"),
            SymbolKind::Function => write!(f, "function"),
            SymbolKind::Modifier => write!(f, "modifier"),
            SymbolKind::Event => write!(f, "event"),
            SymbolKind::StateVariable => write!(f, "state variable"),
            SymbolKind::LocalVariable => write!(f, "local variable"),
            SymbolKind::Parameter => write!(f, "parameter"),
            SymbolKind::Struct => write!(f, "struct"),
            SymbolKind::Enum => write!(f, "enum"),
            SymbolKind::Error => write!(f, "error"),
        }
    }
}

/// Represents a symbol in the symbol table
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Name of the symbol
    pub name: String,
    /// Kind of symbol
    pub kind: SymbolKind,
    /// Source location where symbol is defined
    pub location: SourceLocation,
    /// Visibility of the symbol (for functions, variables)
    pub visibility: Option<String>,
    /// Type information (will be enhanced in T018)
    pub type_info: Option<String>,
    /// Function signature for overloaded functions
    pub signature: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Symbol {
    /// Create a new symbol
    pub fn new(name: String, kind: SymbolKind, location: SourceLocation) -> Self {
        Self {
            name,
            kind,
            location,
            visibility: None,
            type_info: None,
            signature: None,
            metadata: HashMap::new(),
        }
    }

    /// Set visibility for the symbol
    pub fn with_visibility(mut self, visibility: impl Into<String>) -> Self {
        self.visibility = Some(visibility.into());
        self
    }

    /// Set type information for the symbol
    pub fn with_type(mut self, type_info: impl Into<String>) -> Self {
        self.type_info = Some(type_info.into());
        self
    }

    /// Set function signature for the symbol
    pub fn with_signature(mut self, signature: impl Into<String>) -> Self {
        self.signature = Some(signature.into());
        self
    }

    /// Add metadata to the symbol
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Check if symbol is accessible from given context
    pub fn is_accessible(&self, context: &str) -> bool {
        match self.visibility.as_deref() {
            Some("public") => true,
            Some("external") => context == "external",
            Some("internal") => context == "internal" || context == "derived",
            Some("private") => context == "same_contract",
            Some(_) => false, // Unknown visibility
            None => true, // Default visibility depends on context
        }
    }
}

/// Represents a scope in the symbol table
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope(usize);

impl Scope {
    /// Create a new scope with given ID
    pub fn new(id: usize) -> Self {
        Scope(id)
    }

    /// Get the scope ID
    pub fn id(&self) -> usize {
        self.0
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scope({})", self.0)
    }
}

/// Scope information including parent relationships
#[derive(Debug, Clone)]
struct ScopeInfo {
    /// Parent scope (if any)
    parent: Option<Scope>,
    /// Kind of scope
    kind: ScopeKind,
    /// Symbols defined in this scope
    symbols: HashMap<String, Symbol>,
    /// Function overloads (function name -> list of symbols)
    overloads: HashMap<String, Vec<Symbol>>,
    /// Inheritance relationships (for contract scopes)
    inherited_scopes: Vec<Scope>,
}

/// Different kinds of scopes
#[derive(Debug, Clone, PartialEq)]
enum ScopeKind {
    Global,
    Contract,
    Function,
    Block,
    Modifier,
}

/// Multi-scope symbol table with contract inheritance support
pub struct SymbolTable {
    /// All scopes in the symbol table
    scopes: HashMap<Scope, ScopeInfo>,
    /// Global scope (always scope 0)
    global_scope: Scope,
    /// Counter for generating unique scope IDs
    scope_counter: usize,
}

impl SymbolTable {
    /// Create a new symbol table with global scope
    pub fn new() -> Self {
        let global_scope = Scope::new(0);
        let mut scopes = HashMap::new();

        scopes.insert(global_scope, ScopeInfo {
            parent: None,
            kind: ScopeKind::Global,
            symbols: HashMap::new(),
            overloads: HashMap::new(),
            inherited_scopes: Vec::new(),
        });

        let mut symbol_table = Self {
            scopes,
            global_scope,
            scope_counter: 1,
        };

        // Add built-in types to global scope
        symbol_table.add_builtin_types();

        symbol_table
    }

    /// Add built-in Solidity types to global scope
    fn add_builtin_types(&mut self) {
        // Generate all unsigned integer types from uint8 to uint256 in steps of 8 bits
        let mut uint_types = vec!["uint".to_string()];
        for bits in (8..=256).step_by(8) {
            uint_types.push(format!("uint{}", bits));
        }

        // Generate all signed integer types from int8 to int256 in steps of 8 bits
        let mut int_types = vec!["int".to_string()];
        for bits in (8..=256).step_by(8) {
            int_types.push(format!("int{}", bits));
        }

        // Generate all fixed-size byte types from bytes1 to bytes32
        let mut bytes_types = vec!["bytes".to_string()];
        for size in 1..=32 {
            bytes_types.push(format!("bytes{}", size));
        }

        // Other built-in types
        let other_types = [
            "address", "bool", "string", "mapping", "array", "function",
        ];

        // Add all types to symbol table
        for type_name in &uint_types {
            self.add_builtin_symbol(type_name, SymbolKind::Type);
        }
        for type_name in &int_types {
            self.add_builtin_symbol(type_name, SymbolKind::Type);
        }
        for type_name in &bytes_types {
            self.add_builtin_symbol(type_name, SymbolKind::Type);
        }
        for type_name in &other_types {
            self.add_builtin_symbol(type_name, SymbolKind::Type);
        }
    }

    /// Add a built-in symbol to global scope
    pub fn add_builtin_symbol(&mut self, name: &str, kind: SymbolKind) {
        let symbol = Symbol::new(
            name.to_string(),
            kind,
            SourceLocation::default(),
        );

        if let Some(global_info) = self.scopes.get_mut(&self.global_scope) {
            global_info.symbols.insert(name.to_string(), symbol);
        }
    }

    /// Create a new contract scope
    pub fn create_contract_scope(&mut self, contract: &Contract<'_>) -> Result<Scope> {
        let scope = Scope::new(self.scope_counter);
        self.scope_counter += 1;

        let scope_info = ScopeInfo {
            parent: Some(self.global_scope),
            kind: ScopeKind::Contract,
            symbols: HashMap::new(),
            overloads: HashMap::new(),
            inherited_scopes: Vec::new(),
        };

        self.scopes.insert(scope, scope_info);

        // Add the contract itself as a symbol in global scope
        let contract_symbol = Symbol::new(
            contract.name.name.to_string(),
            match contract.contract_type {
                ContractType::Contract => SymbolKind::Contract,
                ContractType::Interface => SymbolKind::Interface,
                ContractType::Library => SymbolKind::Library,
            },
            contract.location.clone(),
        );

        if let Some(global_info) = self.scopes.get_mut(&self.global_scope) {
            global_info.symbols.insert(contract.name.name.to_string(), contract_symbol);
        }

        Ok(scope)
    }

    /// Create a new function scope
    pub fn create_function_scope(&mut self, _function: &Function<'_>) -> Result<Scope> {
        let scope = Scope::new(self.scope_counter);
        self.scope_counter += 1;

        let scope_info = ScopeInfo {
            parent: None, // Will be set when adding to contract
            kind: ScopeKind::Function,
            symbols: HashMap::new(),
            overloads: HashMap::new(),
            inherited_scopes: Vec::new(),
        };

        self.scopes.insert(scope, scope_info);
        Ok(scope)
    }

    /// Create a new block scope
    pub fn create_block_scope(&mut self, parent: Scope) -> Result<Scope> {
        let scope = Scope::new(self.scope_counter);
        self.scope_counter += 1;

        let scope_info = ScopeInfo {
            parent: Some(parent),
            kind: ScopeKind::Block,
            symbols: HashMap::new(),
            overloads: HashMap::new(),
            inherited_scopes: Vec::new(),
        };

        self.scopes.insert(scope, scope_info);
        Ok(scope)
    }

    /// Add a contract symbol to global scope
    pub fn add_contract_symbol(&mut self, contract: &Contract<'_>) {
        let symbol = Symbol::new(
            contract.name.name.to_string(),
            match contract.contract_type {
                ContractType::Contract => SymbolKind::Contract,
                ContractType::Interface => SymbolKind::Interface,
                ContractType::Library => SymbolKind::Library,
            },
            contract.location.clone(),
        );

        if let Some(global_info) = self.scopes.get_mut(&self.global_scope) {
            global_info.symbols.insert(contract.name.name.to_string(), symbol);
        }
    }

    /// Add a function symbol to a scope
    pub fn add_function_symbol(&mut self, function: &Function<'_>) {
        let symbol = Symbol::new(
            function.name.name.to_string(),
            SymbolKind::Function,
            function.location.clone(),
        )
        .with_visibility("public") // Simplified for now
        .with_metadata("mutability", "nonpayable"); // Simplified for now

        // Add to global scope for now (would be contract scope in practice)
        if let Some(global_info) = self.scopes.get_mut(&self.global_scope) {
            global_info.symbols.insert(function.name.name.to_string(), symbol);
        }
    }

    /// Add a variable symbol to a scope
    pub fn add_variable_symbol(&mut self, scope: Scope, name: &str, kind: SymbolKind) {
        let symbol = Symbol::new(
            name.to_string(),
            kind,
            SourceLocation::default(),
        );

        if let Some(scope_info) = self.scopes.get_mut(&scope) {
            scope_info.symbols.insert(name.to_string(), symbol);
        }
    }

    /// Add a function symbol with signature for overloading
    pub fn add_function_symbol_with_signature(&mut self, scope: Scope, name: &str, signature: &str) {
        let symbol = Symbol::new(
            name.to_string(),
            SymbolKind::Function,
            SourceLocation::default(),
        ).with_signature(signature);

        if let Some(scope_info) = self.scopes.get_mut(&scope) {
            scope_info.overloads
                .entry(name.to_string())
                .or_insert_with(Vec::new)
                .push(symbol);
        }
    }

    /// Add a function symbol with visibility
    pub fn add_function_symbol_with_visibility(&mut self, scope: Scope, name: &str, kind: SymbolKind, visibility: &str) {
        let symbol = Symbol::new(
            name.to_string(),
            kind,
            SourceLocation::default(),
        ).with_visibility(visibility);

        if let Some(scope_info) = self.scopes.get_mut(&scope) {
            scope_info.symbols.insert(name.to_string(), symbol);
        }
    }

    /// Add a modifier symbol to a scope
    pub fn add_modifier_symbol(&mut self, scope: Scope, name: &str) {
        let symbol = Symbol::new(
            name.to_string(),
            SymbolKind::Modifier,
            SourceLocation::default(),
        );

        if let Some(scope_info) = self.scopes.get_mut(&scope) {
            scope_info.symbols.insert(name.to_string(), symbol);
        }
    }

    /// Add an event symbol to a scope
    pub fn add_event_symbol(&mut self, scope: Scope, name: &str) {
        let symbol = Symbol::new(
            name.to_string(),
            SymbolKind::Event,
            SourceLocation::default(),
        );

        if let Some(scope_info) = self.scopes.get_mut(&scope) {
            scope_info.symbols.insert(name.to_string(), symbol);
        }
    }

    /// Add a symbol to the symbol table
    pub fn add_symbol(&mut self, scope: Scope, symbol: Symbol) -> Result<()> {
        if let Some(scope_info) = self.scopes.get_mut(&scope) {
            scope_info.symbols.insert(symbol.name.clone(), symbol);
            Ok(())
        } else {
            Err(anyhow!("Scope {:?} not found", scope))
        }
    }

    /// Add inheritance relationship between scopes
    pub fn add_inheritance_relationship(&mut self, derived: Scope, base: Scope) {
        if let Some(derived_info) = self.scopes.get_mut(&derived) {
            derived_info.inherited_scopes.push(base);
        }
    }

    /// Lookup a symbol in global scope
    pub fn lookup_global(&self, name: &str) -> Option<&Symbol> {
        self.scopes.get(&self.global_scope)?.symbols.get(name)
    }

    /// Lookup a contract symbol
    pub fn lookup_contract(&self, name: &str) -> Option<&Symbol> {
        self.lookup_global(name).filter(|s| matches!(s.kind, SymbolKind::Contract | SymbolKind::Interface | SymbolKind::Library))
    }

    /// Lookup a function symbol
    pub fn lookup_function(&self, name: &str) -> Option<&Symbol> {
        self.lookup_global(name).filter(|s| s.kind == SymbolKind::Function)
    }

    /// Lookup a modifier symbol in a scope
    pub fn lookup_modifier(&self, scope: Scope, name: &str) -> Option<&Symbol> {
        self.scopes.get(&scope)?.symbols.get(name).filter(|s| s.kind == SymbolKind::Modifier)
    }

    /// Lookup an event symbol in a scope
    pub fn lookup_event(&self, scope: Scope, name: &str) -> Option<&Symbol> {
        self.scopes.get(&scope)?.symbols.get(name).filter(|s| s.kind == SymbolKind::Event)
    }

    /// Resolve a variable in a scope (with scope chain traversal)
    pub fn resolve_variable(&self, scope: Scope, name: &str) -> Option<&Symbol> {
        let mut current_scope = Some(scope);
        let mut depth = 0;

        while let Some(scope_id) = current_scope {
            if depth >= MAX_SCOPE_DEPTH {
                // Prevent infinite loop - likely circular parent relationship
                break;
            }

            if let Some(scope_info) = self.scopes.get(&scope_id) {
                if let Some(symbol) = scope_info.symbols.get(name) {
                    if matches!(symbol.kind, SymbolKind::StateVariable | SymbolKind::LocalVariable | SymbolKind::Parameter) {
                        return Some(symbol);
                    }
                }
                current_scope = scope_info.parent;
                depth += 1;
            } else {
                break;
            }
        }

        None
    }

    /// Resolve inherited symbol from base contracts
    pub fn resolve_inherited_symbol(&self, scope: Scope, name: &str) -> Option<&Symbol> {
        let mut visited = std::collections::HashSet::new();
        self.resolve_inherited_symbol_impl(scope, name, &mut visited)
    }

    /// Internal implementation with cycle detection
    fn resolve_inherited_symbol_impl(&self, scope: Scope, name: &str, visited: &mut std::collections::HashSet<Scope>) -> Option<&Symbol> {
        // Prevent infinite recursion in circular inheritance
        if visited.contains(&scope) {
            return None;
        }
        visited.insert(scope);

        if let Some(scope_info) = self.scopes.get(&scope) {
            for &inherited_scope in &scope_info.inherited_scopes {
                if let Some(inherited_info) = self.scopes.get(&inherited_scope) {
                    if let Some(symbol) = inherited_info.symbols.get(name) {
                        return Some(symbol);
                    }
                }
                // Recursively check inherited scopes with cycle detection
                if let Some(symbol) = self.resolve_inherited_symbol_impl(inherited_scope, name, visited) {
                    return Some(symbol);
                }
            }
        }
        None
    }

    /// Get function overloads
    pub fn get_function_overloads(&self, scope: Scope, name: &str) -> Vec<&Symbol> {
        self.scopes.get(&scope)
            .and_then(|info| info.overloads.get(name))
            .map(|overloads| overloads.iter().collect())
            .unwrap_or_else(Vec::new)
    }

    /// Resolve function by signature
    pub fn resolve_function_by_signature(&self, scope: Scope, signature: &str) -> Option<&Symbol> {
        if let Some(scope_info) = self.scopes.get(&scope) {
            for overloads in scope_info.overloads.values() {
                for symbol in overloads {
                    if symbol.signature.as_deref() == Some(signature) {
                        return Some(symbol);
                    }
                }
            }
        }
        None
    }

    /// Check for name collisions in a scope
    pub fn check_name_collision(&self, scope: Scope, name: &str, kind: SymbolKind) -> Result<()> {
        if let Some(scope_info) = self.scopes.get(&scope) {
            if let Some(existing) = scope_info.symbols.get(name) {
                // Allow function overloading
                if existing.kind == SymbolKind::Function && kind == SymbolKind::Function {
                    return Ok(());
                }
                return Err(anyhow!("Name collision: '{}' already defined as {} in this scope", name, existing.kind));
            }
        }
        Ok(())
    }

    /// Check if one scope is ancestor of another
    pub fn is_ancestor_scope(&self, ancestor: Scope, descendant: Scope) -> bool {
        let mut current = Some(descendant);
        let mut depth = 0;

        while let Some(scope_id) = current {
            if depth >= MAX_SCOPE_DEPTH {
                // Prevent infinite loop - likely circular parent relationship
                return false;
            }

            if scope_id == ancestor {
                return true;
            }
            current = self.scopes.get(&scope_id).and_then(|info| info.parent);
            depth += 1;
        }

        false
    }

    /// Check if symbol is accessible from given context
    pub fn is_symbol_accessible(&self, scope: Scope, name: &str, context: &str) -> bool {
        if let Some(scope_info) = self.scopes.get(&scope) {
            if let Some(symbol) = scope_info.symbols.get(name) {
                return symbol.is_accessible(context);
            }
        }
        false
    }

    /// Get number of scopes
    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }

    /// Check if symbol table is empty (only global scope with built-ins)
    pub fn is_empty(&self) -> bool {
        self.scopes.len() == 1 && self.global_symbol_count() > 0
    }

    /// Get number of symbols in global scope
    pub fn global_symbol_count(&self) -> usize {
        self.scopes.get(&self.global_scope)
            .map(|info| info.symbols.len())
            .unwrap_or(0)
    }

    /// Lookup symbol in a specific scope
    pub fn lookup_symbol(&self, scope: Scope, name: &str) -> Option<&Symbol> {
        self.scopes.get(&scope)?.symbols.get(name)
    }

    /// Get parent scope of a given scope
    pub fn get_parent_scope(&self, scope: Scope) -> Option<Scope> {
        self.scopes.get(&scope)?.parent
    }

    /// Get all symbols in a specific scope
    pub fn get_scope_symbols(&self, scope: Scope) -> Option<&HashMap<String, Symbol>> {
        Some(&self.scopes.get(&scope)?.symbols)
    }

    /// Get all symbols across all scopes
    pub fn get_all_symbols(&self) -> Vec<&Symbol> {
        let mut symbols = Vec::new();
        for scope_info in self.scopes.values() {
            symbols.extend(scope_info.symbols.values());
        }
        symbols
    }

    /// Get the global scope
    pub fn get_global_scope(&self) -> Scope {
        self.global_scope
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}
