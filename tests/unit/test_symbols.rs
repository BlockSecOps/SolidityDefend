use std::collections::HashMap;
use semantic::symbols::{SymbolTable, Symbol, SymbolKind, Scope};
use ast::{AstArena, SourceLocation, Position, Contract, Function, Identifier, ContractType};

/// Unit tests for symbol table construction and name resolution
/// These tests verify multi-scope symbol resolution with inheritance support

#[test]
fn test_symbol_table_creation() {
    let symbol_table = SymbolTable::new();
    assert_eq!(symbol_table.scope_count(), 1); // Global scope
    assert!(symbol_table.is_empty());
}

#[test]
fn test_global_scope_symbols() {
    let mut symbol_table = SymbolTable::new();

    // Add built-in types to global scope
    symbol_table.add_builtin_symbol("uint256", SymbolKind::Type);
    symbol_table.add_builtin_symbol("address", SymbolKind::Type);
    symbol_table.add_builtin_symbol("bool", SymbolKind::Type);

    assert_eq!(symbol_table.global_symbol_count(), 3);
    assert!(symbol_table.lookup_global("uint256").is_some());
    assert!(symbol_table.lookup_global("address").is_some());
    assert!(symbol_table.lookup_global("nonexistent").is_none());
}

#[test]
fn test_contract_scope() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let contract_name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let contract = Contract::new(&arena, contract_name, ContractType::Contract, location.clone());

    // Create contract scope
    let contract_scope = symbol_table.create_contract_scope(&contract);
    assert!(contract_scope.is_ok());

    // Add contract to symbol table
    symbol_table.add_contract_symbol(&contract);

    assert_eq!(symbol_table.scope_count(), 2); // Global + contract scope
    assert!(symbol_table.lookup_contract("TestContract").is_some());
}

#[test]
fn test_function_scope() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let function_name = Identifier::new(arena.alloc_str("testFunction"), location.clone());
    let function = Function::new(&arena, function_name, location.clone());

    // Create function scope
    let function_scope = symbol_table.create_function_scope(&function);
    assert!(function_scope.is_ok());

    // Add function symbol
    symbol_table.add_function_symbol(&function);

    assert!(symbol_table.lookup_function("testFunction").is_some());
}

#[test]
fn test_variable_resolution() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    // Create contract scope
    let contract_name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let contract = Contract::new(&arena, contract_name, ContractType::Contract, location.clone());
    let contract_scope = symbol_table.create_contract_scope(&contract).unwrap();

    // Add state variable
    symbol_table.add_variable_symbol(contract_scope, "stateVar", SymbolKind::StateVariable);

    // Create function scope
    let function_name = Identifier::new(arena.alloc_str("testFunction"), location.clone());
    let function = Function::new(&arena, function_name, location.clone());
    let function_scope = symbol_table.create_function_scope(&function).unwrap();

    // Add local variable
    symbol_table.add_variable_symbol(function_scope, "localVar", SymbolKind::LocalVariable);

    // Test resolution priority: local overrides state
    assert!(symbol_table.resolve_variable(function_scope, "localVar").is_some());
    assert!(symbol_table.resolve_variable(function_scope, "stateVar").is_some());
    assert!(symbol_table.resolve_variable(function_scope, "nonexistent").is_none());
}

#[test]
fn test_inheritance_resolution() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    // Create base contract
    let base_name = Identifier::new(arena.alloc_str("BaseContract"), location.clone());
    let base_contract = Contract::new(&arena, base_name, ContractType::Contract, location.clone());
    let base_scope = symbol_table.create_contract_scope(&base_contract).unwrap();

    symbol_table.add_contract_symbol(&base_contract);
    symbol_table.add_variable_symbol(base_scope, "baseVar", SymbolKind::StateVariable);

    // Create derived contract
    let derived_name = Identifier::new(arena.alloc_str("DerivedContract"), location.clone());
    let derived_contract = Contract::new(&arena, derived_name, ContractType::Contract, location.clone());
    let derived_scope = symbol_table.create_contract_scope(&derived_contract).unwrap();

    symbol_table.add_contract_symbol(&derived_contract);
    symbol_table.add_inheritance_relationship(derived_scope, base_scope);

    // Test inheritance resolution
    assert!(symbol_table.resolve_inherited_symbol(derived_scope, "baseVar").is_some());
    assert!(symbol_table.resolve_inherited_symbol(derived_scope, "nonexistent").is_none());
}

#[test]
fn test_function_overloading() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let contract_name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let contract = Contract::new(&arena, contract_name, ContractType::Contract, location.clone());
    let contract_scope = symbol_table.create_contract_scope(&contract).unwrap();

    // Add overloaded functions
    let signature1 = "transfer(address)";
    let signature2 = "transfer(address,uint256)";

    symbol_table.add_function_symbol_with_signature(contract_scope, "transfer", signature1);
    symbol_table.add_function_symbol_with_signature(contract_scope, "transfer", signature2);

    assert_eq!(symbol_table.get_function_overloads(contract_scope, "transfer").len(), 2);
    assert!(symbol_table.resolve_function_by_signature(contract_scope, signature1).is_some());
    assert!(symbol_table.resolve_function_by_signature(contract_scope, signature2).is_some());
}

#[test]
fn test_modifier_resolution() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let contract_name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let contract = Contract::new(&arena, contract_name, ContractType::Contract, location.clone());
    let contract_scope = symbol_table.create_contract_scope(&contract).unwrap();

    // Add modifier symbol
    symbol_table.add_modifier_symbol(contract_scope, "onlyOwner");

    assert!(symbol_table.lookup_modifier(contract_scope, "onlyOwner").is_some());
    assert!(symbol_table.lookup_modifier(contract_scope, "nonexistent").is_none());
}

#[test]
fn test_event_resolution() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let contract_name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let contract = Contract::new(&arena, contract_name, ContractType::Contract, location.clone());
    let contract_scope = symbol_table.create_contract_scope(&contract).unwrap();

    // Add event symbol
    symbol_table.add_event_symbol(contract_scope, "Transfer");

    assert!(symbol_table.lookup_event(contract_scope, "Transfer").is_some());
    assert!(symbol_table.lookup_event(contract_scope, "nonexistent").is_none());
}

#[test]
fn test_multi_level_inheritance() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    // Create inheritance chain: Grandparent -> Parent -> Child
    let grandparent_name = Identifier::new(arena.alloc_str("Grandparent"), location.clone());
    let grandparent = Contract::new(&arena, grandparent_name, ContractType::Contract, location.clone());
    let grandparent_scope = symbol_table.create_contract_scope(&grandparent).unwrap();
    symbol_table.add_variable_symbol(grandparent_scope, "grandparentVar", SymbolKind::StateVariable);

    let parent_name = Identifier::new(arena.alloc_str("Parent"), location.clone());
    let parent = Contract::new(&arena, parent_name, ContractType::Contract, location.clone());
    let parent_scope = symbol_table.create_contract_scope(&parent).unwrap();
    symbol_table.add_inheritance_relationship(parent_scope, grandparent_scope);
    symbol_table.add_variable_symbol(parent_scope, "parentVar", SymbolKind::StateVariable);

    let child_name = Identifier::new(arena.alloc_str("Child"), location.clone());
    let child = Contract::new(&arena, child_name, ContractType::Contract, location.clone());
    let child_scope = symbol_table.create_contract_scope(&child).unwrap();
    symbol_table.add_inheritance_relationship(child_scope, parent_scope);

    // Test multi-level resolution
    assert!(symbol_table.resolve_inherited_symbol(child_scope, "parentVar").is_some());
    assert!(symbol_table.resolve_inherited_symbol(child_scope, "grandparentVar").is_some());
}

#[test]
fn test_name_collision_detection() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let contract_name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let contract = Contract::new(&arena, contract_name, ContractType::Contract, location.clone());
    let contract_scope = symbol_table.create_contract_scope(&contract).unwrap();

    // Add variable
    symbol_table.add_variable_symbol(contract_scope, "name", SymbolKind::StateVariable);

    // Try to add function with same name - should detect collision
    let collision_result = symbol_table.check_name_collision(contract_scope, "name", SymbolKind::Function);
    assert!(collision_result.is_err());
}

#[test]
fn test_scope_hierarchy() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    // Create nested scopes: Global -> Contract -> Function -> Block
    let contract_name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let contract = Contract::new(&arena, contract_name, ContractType::Contract, location.clone());
    let contract_scope = symbol_table.create_contract_scope(&contract).unwrap();

    let function_name = Identifier::new(arena.alloc_str("testFunction"), location.clone());
    let function = Function::new(&arena, function_name, location.clone());
    let function_scope = symbol_table.create_function_scope(&function).unwrap();

    let block_scope = symbol_table.create_block_scope(function_scope).unwrap();

    // Test scope hierarchy
    assert!(symbol_table.is_ancestor_scope(contract_scope, function_scope));
    assert!(symbol_table.is_ancestor_scope(function_scope, block_scope));
    assert!(symbol_table.is_ancestor_scope(contract_scope, block_scope));
}

#[test]
fn test_symbol_visibility() {
    let arena = AstArena::new();
    let mut symbol_table = SymbolTable::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let contract_name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let contract = Contract::new(&arena, contract_name, ContractType::Contract, location.clone());
    let contract_scope = symbol_table.create_contract_scope(&contract).unwrap();

    // Add symbols with different visibility
    symbol_table.add_function_symbol_with_visibility(contract_scope, "publicFunc", SymbolKind::Function, "public");
    symbol_table.add_function_symbol_with_visibility(contract_scope, "privateFunc", SymbolKind::Function, "private");
    symbol_table.add_function_symbol_with_visibility(contract_scope, "internalFunc", SymbolKind::Function, "internal");

    // Test visibility-based resolution
    assert!(symbol_table.is_symbol_accessible(contract_scope, "publicFunc", "external"));
    assert!(!symbol_table.is_symbol_accessible(contract_scope, "privateFunc", "external"));
    assert!(symbol_table.is_symbol_accessible(contract_scope, "internalFunc", "internal"));
}