use std::collections::{HashMap, HashSet};
use anyhow::{Result, anyhow};

use ast::{Contract, Function, StateVariable, Expression, Identifier, SourceLocation};
use crate::symbols::{SymbolTable, Scope, Symbol, SymbolKind};
use crate::types::{TypeResolver, ResolvedType, TypeCompatibility};
use crate::inheritance::{InheritanceGraph, InheritanceNode};

/// Result of name resolution containing the resolved symbol and additional context
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    pub symbol: Symbol,
    pub resolution_scope: Scope,
    pub resolution_path: Vec<String>, // Path taken to resolve the name (for debugging)
    pub is_inherited: bool,
    pub inheritance_distance: usize, // How many levels up the inheritance chain
}

/// Context for name resolution containing scope and type information
pub struct NameResolver<'a> {
    symbol_table: &'a SymbolTable,
    type_resolver: TypeResolver<'a>,
    inheritance_graph: &'a InheritanceGraph,
    current_scope: Scope,
    /// Cache for resolved names to avoid repeated lookups
    resolution_cache: HashMap<(Scope, String), Option<ResolutionResult>>,
    /// Track resolution path to detect circular dependencies
    resolution_path: Vec<(Scope, String)>,
}

impl<'a> NameResolver<'a> {
    /// Create a new name resolver with full semantic context
    pub fn new(
        symbol_table: &'a SymbolTable,
        inheritance_graph: &'a InheritanceGraph,
        current_scope: Scope,
    ) -> Self {
        let type_resolver = TypeResolver::new(symbol_table, current_scope);

        Self {
            symbol_table,
            type_resolver,
            inheritance_graph,
            current_scope,
            resolution_cache: HashMap::new(),
            resolution_path: Vec::new(),
        }
    }

    /// Resolve a name in the current context, considering all scoping rules
    pub fn resolve_name(&mut self, name: &str) -> Result<Option<ResolutionResult>> {
        self.resolve_name_in_scope(name, self.current_scope)
    }

    /// Resolve a name starting from a specific scope
    pub fn resolve_name_in_scope(&mut self, name: &str, scope: Scope) -> Result<Option<ResolutionResult>> {
        let cache_key = (scope, name.to_string());

        // Check cache first
        if let Some(cached_result) = self.resolution_cache.get(&cache_key) {
            return Ok(cached_result.clone());
        }

        // Check for circular resolution
        if self.resolution_path.contains(&cache_key) {
            return Err(anyhow!("Circular name resolution detected for '{}' in scope {:?}", name, scope));
        }

        self.resolution_path.push(cache_key.clone());

        let result = self.resolve_name_internal(name, scope)?;

        // Cache the result
        self.resolution_cache.insert(cache_key, result.clone());

        self.resolution_path.pop();

        Ok(result)
    }

    /// Internal name resolution implementation
    fn resolve_name_internal(&mut self, name: &str, start_scope: Scope) -> Result<Option<ResolutionResult>> {
        let mut resolution_path = vec![format!("scope:{:?}", start_scope)];

        // 1. Look in the current scope
        if let Some(symbol) = self.symbol_table.lookup_symbol(start_scope, name) {
            return Ok(Some(ResolutionResult {
                symbol: symbol.clone(),
                resolution_scope: start_scope,
                resolution_path,
                is_inherited: false,
                inheritance_distance: 0,
            }));
        }

        // 2. Look in parent scopes (lexical scoping)
        if let Some(result) = self.resolve_in_parent_scopes(name, start_scope, &mut resolution_path)? {
            return Ok(Some(result));
        }

        // 3. Look in inherited contracts (for contract scopes)
        if let Some(result) = self.resolve_in_inherited_contracts(name, start_scope, &mut resolution_path)? {
            return Ok(Some(result));
        }

        // 4. Look in global scope (built-in types, global functions)
        let global_scope = self.symbol_table.get_global_scope();
        if start_scope != global_scope {
            if let Some(symbol) = self.symbol_table.lookup_symbol(global_scope, name) {
                resolution_path.push("global".to_string());
                return Ok(Some(ResolutionResult {
                    symbol: symbol.clone(),
                    resolution_scope: global_scope,
                    resolution_path,
                    is_inherited: false,
                    inheritance_distance: 0,
                }));
            }
        }

        // 5. Name not found
        Ok(None)
    }

    /// Resolve name in parent scopes (lexical scoping)
    fn resolve_in_parent_scopes(
        &self,
        name: &str,
        scope: Scope,
        resolution_path: &mut Vec<String>,
    ) -> Result<Option<ResolutionResult>> {
        let mut current_scope = scope;
        let mut depth = 0;
        const MAX_SCOPE_DEPTH: usize = 100; // Prevent infinite loops

        while depth < MAX_SCOPE_DEPTH {
            // Get parent scope
            if let Some(parent_scope) = self.symbol_table.get_parent_scope(current_scope) {
                resolution_path.push(format!("parent:{:?}", parent_scope));

                // Look for symbol in parent scope
                if let Some(symbol) = self.symbol_table.lookup_symbol(parent_scope, name) {
                    return Ok(Some(ResolutionResult {
                        symbol: symbol.clone(),
                        resolution_scope: parent_scope,
                        resolution_path: resolution_path.clone(),
                        is_inherited: false,
                        inheritance_distance: 0,
                    }));
                }

                current_scope = parent_scope;
                depth += 1;
            } else {
                break;
            }
        }

        Ok(None)
    }

    /// Resolve name in inherited contracts
    fn resolve_in_inherited_contracts(
        &self,
        name: &str,
        scope: Scope,
        resolution_path: &mut Vec<String>,
    ) -> Result<Option<ResolutionResult>> {
        // Check if this is a contract scope
        if let Some(contract_info) = self.get_contract_for_scope(scope) {
            resolution_path.push(format!("inheritance:{}", contract_info.name));

            // Get all ancestors in inheritance order
            if let Ok(ancestors) = self.inheritance_graph.get_all_ancestors(&contract_info.name) {
                for (distance, ancestor) in ancestors.iter().enumerate() {
                    resolution_path.push(format!("ancestor:{}", ancestor.name));

                    // Look for symbol in ancestor's scope
                    if let Some(symbol) = self.symbol_table.lookup_symbol(ancestor.scope, name) {
                        // Check if symbol is accessible (not private)
                        if self.is_symbol_accessible_from_inheritance(&symbol, distance) {
                            return Ok(Some(ResolutionResult {
                                symbol: symbol.clone(),
                                resolution_scope: ancestor.scope,
                                resolution_path: resolution_path.clone(),
                                is_inherited: true,
                                inheritance_distance: distance + 1,
                            }));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get contract information for a given scope
    fn get_contract_for_scope(&self, scope: Scope) -> Option<&InheritanceNode> {
        self.inheritance_graph
            .get_all_contracts()
            .iter()
            .find(|contract| contract.scope == scope)
            .copied()
    }

    /// Check if a symbol is accessible through inheritance based on Solidity visibility rules
    fn is_symbol_accessible_from_inheritance(&self, symbol: &Symbol, _inheritance_distance: usize) -> bool {
        match symbol.kind {
            // Functions and state variables: check actual visibility modifiers
            SymbolKind::StateVariable | SymbolKind::Function => {
                match symbol.visibility.as_deref() {
                    Some("private") => false,  // Private symbols are not accessible through inheritance
                    Some("internal") => true,  // Internal symbols are accessible through inheritance
                    Some("public") => true,    // Public symbols are accessible through inheritance
                    Some("external") => {      // External functions are callable but not accessible in derived contracts
                        // External functions can be called but not overridden in derived contracts
                        symbol.kind == SymbolKind::Function
                    }
                    None => {
                        // Default visibility in older Solidity versions:
                        // - Functions: public
                        // - State variables: internal
                        match symbol.kind {
                            SymbolKind::Function => true,      // Default public
                            SymbolKind::StateVariable => true, // Default internal
                            _ => true,
                        }
                    }
                    Some(_) => {
                        // Unknown visibility modifier - assume accessible for safety
                        // In a production system, this should log a warning
                        true
                    }
                }
            }
            // Types are generally accessible through inheritance
            SymbolKind::Struct | SymbolKind::Enum | SymbolKind::Type => true,
            // Events and modifiers are accessible through inheritance
            SymbolKind::Event | SymbolKind::Modifier => true,
            // Contracts, interfaces, libraries are accessible
            SymbolKind::Contract | SymbolKind::Interface | SymbolKind::Library => true,
            // Local variables and parameters are not accessible through inheritance
            SymbolKind::LocalVariable | SymbolKind::Parameter => false,
            // Error symbols are not accessible
            SymbolKind::Error => false,
        }
    }

    /// Resolve a qualified name (e.g., "ContractName.functionName")
    pub fn resolve_qualified_name(&mut self, qualified_name: &str) -> Result<Option<ResolutionResult>> {
        let parts: Vec<&str> = qualified_name.split('.').collect();

        if parts.len() < 2 {
            return self.resolve_name(qualified_name);
        }

        // First part should be a contract/library name
        let container_name = parts[0];
        let member_name = parts[1];

        // Resolve the container
        if let Some(container_result) = self.resolve_name(container_name)? {
            match container_result.symbol.kind {
                SymbolKind::Contract | SymbolKind::Interface | SymbolKind::Library => {
                    // Look for the member in the container's scope
                    // Since Symbol doesn't have scope, we'll look in current scope for now
                    return self.resolve_name(member_name);
                }
                _ => {
                    return Err(anyhow!("'{}' is not a contract, interface, or library", container_name));
                }
            }
        }

        Ok(None)
    }

    /// Resolve function overloads based on argument types
    pub fn resolve_function_overload(
        &mut self,
        function_name: &str,
        argument_types: &[ResolvedType],
    ) -> Result<Option<ResolutionResult>> {
        // Get all function overloads with the given name
        let overloads = self.symbol_table.get_function_overloads(self.current_scope, function_name);

        if overloads.is_empty() {
            return self.resolve_name(function_name);
        }

        // Find the best matching overload
        let mut best_match: Option<(&Symbol, TypeCompatibility)> = None;

        for overload in &overloads {
            // Resolve the function signature
            if let Some(signature) = &overload.signature {
                // Parse signature and check compatibility
                // This is simplified - in practice, we'd need full signature parsing
                let compatibility = self.check_function_signature_compatibility(signature, argument_types)?;

                match compatibility {
                    TypeCompatibility::Identical => {
                        // Exact match found
                        return Ok(Some(ResolutionResult {
                            symbol: (*overload).clone(),
                            resolution_scope: self.current_scope,
                            resolution_path: vec!["overload_exact".to_string()],
                            is_inherited: false,
                            inheritance_distance: 0,
                        }));
                    }
                    TypeCompatibility::ImplicitlyConvertible => {
                        // Better than explicit conversion
                        if best_match.is_none() || best_match.as_ref().unwrap().1 == TypeCompatibility::ExplicitlyConvertible {
                            best_match = Some((overload, compatibility));
                        }
                    }
                    TypeCompatibility::ExplicitlyConvertible => {
                        // Use as fallback
                        if best_match.is_none() {
                            best_match = Some((overload, compatibility));
                        }
                    }
                    TypeCompatibility::Incompatible => {
                        // Skip this overload
                    }
                }
            }
        }

        if let Some((symbol, _)) = best_match {
            Ok(Some(ResolutionResult {
                symbol: (*symbol).clone(),
                resolution_scope: self.current_scope,
                resolution_path: vec!["overload_compatible".to_string()],
                is_inherited: false,
                inheritance_distance: 0,
            }))
        } else {
            Ok(None)
        }
    }

    /// Check if function signature is compatible with given argument types
    fn check_function_signature_compatibility(
        &self,
        signature: &str,
        argument_types: &[ResolvedType],
    ) -> Result<TypeCompatibility> {
        // Parse the function signature to extract parameter types
        let param_count = self.parse_function_signature_parameters(signature)?;

        if param_count == argument_types.len() {
            // For now, only check parameter count
            // TODO: Implement full type compatibility checking
            Ok(TypeCompatibility::ImplicitlyConvertible)
        } else {
            Ok(TypeCompatibility::Incompatible)
        }
    }

    /// Parse function signature parameters accounting for nested types
    /// Examples:
    /// - "" -> 0 parameters
    /// - "uint256" -> 1 parameter
    /// - "uint256,address" -> 2 parameters
    /// - "mapping(address => uint256),uint256[]" -> 2 parameters
    /// - "mapping(address => mapping(uint256 => bool)),uint256" -> 2 parameters
    fn parse_function_signature_parameters(&self, signature: &str) -> Result<usize> {
        let trimmed = signature.trim();
        if trimmed.is_empty() {
            return Ok(0);
        }

        let mut param_count = 0;
        let mut depth = 0;
        let mut in_brackets = 0;
        let mut current_param_start = 0;
        let chars: Vec<char> = trimmed.chars().collect();

        for (i, &ch) in chars.iter().enumerate() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                '[' => in_brackets += 1,
                ']' => in_brackets -= 1,
                ',' if depth == 0 && in_brackets == 0 => {
                    // Found a top-level comma - this separates parameters
                    let param_str = chars[current_param_start..i].iter().collect::<String>();
                    let param = param_str.trim();
                    if !param.is_empty() {
                        param_count += 1;
                    }
                    current_param_start = i + 1;
                }
                _ => {}
            }
        }

        // Count the last parameter (after the last comma, or the only parameter)
        let last_param_str = chars[current_param_start..].iter().collect::<String>();
        let last_param = last_param_str.trim();
        if !last_param.is_empty() {
            param_count += 1;
        }

        Ok(param_count)
    }

    /// Resolve using directive (e.g., "using LibraryName for Type")
    pub fn resolve_using_directive(&mut self, type_name: &str, function_name: &str) -> Result<Option<ResolutionResult>> {
        // Look for using directives in current scope and parent scopes
        // This is a simplified implementation

        // Check if there's a library function available for the type
        let qualified_name = format!("{}.{}", type_name, function_name);
        self.resolve_qualified_name(&qualified_name)
    }

    /// Get all visible symbols in the current scope (for code completion)
    pub fn get_visible_symbols(&self) -> Result<Vec<Symbol>> {
        let mut visible_symbols = Vec::new();
        let mut visited_scopes = HashSet::new();

        // Collect symbols from current scope and parent scopes
        self.collect_symbols_from_scope_chain(self.current_scope, &mut visible_symbols, &mut visited_scopes)?;

        // Collect symbols from inherited contracts
        if let Some(contract_info) = self.get_contract_for_scope(self.current_scope) {
            if let Ok(ancestors) = self.inheritance_graph.get_all_ancestors(&contract_info.name) {
                for ancestor in ancestors {
                    if !visited_scopes.contains(&ancestor.scope) {
                        self.collect_accessible_inherited_symbols(ancestor.scope, &mut visible_symbols)?;
                        visited_scopes.insert(ancestor.scope);
                    }
                }
            }
        }

        // Add global symbols
        let global_scope = self.symbol_table.get_global_scope();
        if !visited_scopes.contains(&global_scope) {
            if let Some(global_symbols) = self.symbol_table.get_scope_symbols(global_scope) {
                visible_symbols.extend(global_symbols.values().cloned());
            }
        }

        Ok(visible_symbols)
    }

    /// Collect symbols from scope chain (current scope and parents)
    fn collect_symbols_from_scope_chain(
        &self,
        scope: Scope,
        visible_symbols: &mut Vec<Symbol>,
        visited_scopes: &mut HashSet<Scope>,
    ) -> Result<()> {
        let mut current_scope = scope;
        let mut depth = 0;
        const MAX_SCOPE_DEPTH: usize = 100;

        while depth < MAX_SCOPE_DEPTH && !visited_scopes.contains(&current_scope) {
            visited_scopes.insert(current_scope);

            // Add symbols from current scope
            if let Some(scope_symbols) = self.symbol_table.get_scope_symbols(current_scope) {
                visible_symbols.extend(scope_symbols.values().cloned());
            }

            // Move to parent scope
            if let Some(parent_scope) = self.symbol_table.get_parent_scope(current_scope) {
                current_scope = parent_scope;
                depth += 1;
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Collect accessible symbols from inherited contracts
    fn collect_accessible_inherited_symbols(&self, scope: Scope, visible_symbols: &mut Vec<Symbol>) -> Result<()> {
        if let Some(scope_symbols) = self.symbol_table.get_scope_symbols(scope) {
            for symbol in scope_symbols.values() {
                if self.is_symbol_accessible_from_inheritance(symbol, 1) {
                    visible_symbols.push(symbol.clone());
                }
            }
        }
        Ok(())
    }

    /// Check for name conflicts in the current resolution context
    pub fn check_name_conflicts(&self, name: &str, new_symbol_kind: SymbolKind) -> Result<Vec<Symbol>> {
        let mut conflicts = Vec::new();

        // Check for conflicts in current scope
        if let Some(existing_symbol) = self.symbol_table.lookup_symbol(self.current_scope, name) {
            // Allow function overloading
            if !(existing_symbol.kind == SymbolKind::Function && new_symbol_kind == SymbolKind::Function) {
                conflicts.push(existing_symbol.clone());
            }
        }

        // Check for conflicts with inherited symbols
        if let Some(contract_info) = self.get_contract_for_scope(self.current_scope) {
            if let Ok(ancestors) = self.inheritance_graph.get_all_ancestors(&contract_info.name) {
                for ancestor in ancestors {
                    if let Some(inherited_symbol) = self.symbol_table.lookup_symbol(ancestor.scope, name) {
                        if self.is_symbol_accessible_from_inheritance(&inherited_symbol, 1) {
                            conflicts.push(inherited_symbol.clone());
                        }
                    }
                }
            }
        }

        Ok(conflicts)
    }

    /// Get resolution statistics for debugging and optimization
    pub fn get_resolution_statistics(&self) -> ResolutionStatistics {
        ResolutionStatistics {
            cache_size: self.resolution_cache.len(),
            cache_hits: self.resolution_cache.values().filter(|v| v.is_some()).count(),
            cache_misses: self.resolution_cache.values().filter(|v| v.is_none()).count(),
            max_resolution_path_length: self.resolution_path.len(),
        }
    }

    /// Clear resolution cache (useful when symbol table changes)
    pub fn clear_cache(&mut self) {
        self.resolution_cache.clear();
    }

    /// Set current scope for resolution
    pub fn set_current_scope(&mut self, scope: Scope) {
        self.current_scope = scope;
        self.type_resolver = TypeResolver::new(self.symbol_table, scope);
    }
}

/// Statistics about name resolution performance
#[derive(Debug, Clone)]
pub struct ResolutionStatistics {
    pub cache_size: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub max_resolution_path_length: usize,
}

/// Utility for batch name resolution operations
pub struct BatchNameResolver<'a> {
    resolver: NameResolver<'a>,
    results: HashMap<String, Option<ResolutionResult>>,
}

impl<'a> BatchNameResolver<'a> {
    /// Create a new batch resolver
    pub fn new(
        symbol_table: &'a SymbolTable,
        inheritance_graph: &'a InheritanceGraph,
        scope: Scope,
    ) -> Self {
        Self {
            resolver: NameResolver::new(symbol_table, inheritance_graph, scope),
            results: HashMap::new(),
        }
    }

    /// Add a name to be resolved
    pub fn add_name(&mut self, name: String) {
        self.results.insert(name, None);
    }

    /// Resolve all added names
    pub fn resolve_all(&mut self) -> Result<()> {
        for name in self.results.keys().cloned().collect::<Vec<_>>() {
            let result = self.resolver.resolve_name(&name)?;
            self.results.insert(name, result);
        }
        Ok(())
    }

    /// Get resolution result for a name
    pub fn get_result(&self, name: &str) -> Option<&Option<ResolutionResult>> {
        self.results.get(name)
    }

    /// Get all resolved names
    pub fn get_resolved_names(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter_map(|(name, result)| if result.is_some() { Some(name.as_str()) } else { None })
            .collect()
    }

    /// Get all unresolved names
    pub fn get_unresolved_names(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter_map(|(name, result)| if result.is_none() { Some(name.as_str()) } else { None })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::SymbolTable;
    use ast::{SourceLocation, Position};

    #[test]
    fn test_basic_name_resolution() {
        let mut symbol_table = SymbolTable::new();
        let inheritance_graph = InheritanceGraph::new();
        let global_scope = symbol_table.get_global_scope();

        // Add a symbol to the global scope
        let symbol = Symbol::new(
            "testSymbol".to_string(),
            SymbolKind::Type,
            SourceLocation::new(
                std::path::PathBuf::from("test.sol"),
                Position::new(1, 1, 0),
                Position::new(1, 10, 9)
            ),
        );
        symbol_table.add_symbol(global_scope, symbol).unwrap();

        let mut resolver = NameResolver::new(&symbol_table, &inheritance_graph, global_scope);

        // Resolve the symbol
        let result = resolver.resolve_name("testSymbol").unwrap();
        assert!(result.is_some());

        let resolution = result.unwrap();
        assert_eq!(resolution.symbol.name, "testSymbol");
        assert_eq!(resolution.symbol.kind, SymbolKind::Type);
        assert!(!resolution.is_inherited);
    }

    #[test]
    fn test_qualified_name_resolution() {
        let mut symbol_table = SymbolTable::new();
        let inheritance_graph = InheritanceGraph::new();
        let global_scope = symbol_table.get_global_scope();

        // Create a contract scope
        let contract_scope = symbol_table.create_block_scope(global_scope).unwrap();

        // Add contract symbol
        let contract_symbol = Symbol::new(
            "TestContract".to_string(),
            SymbolKind::Contract,
            SourceLocation::new(
                std::path::PathBuf::from("test.sol"),
                Position::new(1, 1, 0),
                Position::new(5, 1, 50)
            ),
        );
        symbol_table.add_symbol(global_scope, contract_symbol).unwrap();

        // Add function to contract scope
        let function_symbol = Symbol::new(
            "testFunction".to_string(),
            SymbolKind::Function,
            SourceLocation::new(
                std::path::PathBuf::from("test.sol"),
                Position::new(2, 5, 20),
                Position::new(4, 5, 40)
            ),
        );
        symbol_table.add_symbol(contract_scope, function_symbol).unwrap();

        let mut resolver = NameResolver::new(&symbol_table, &inheritance_graph, global_scope);

        // Resolve qualified name
        let result = resolver.resolve_qualified_name("TestContract.testFunction").unwrap();
        assert!(result.is_some());

        let resolution = result.unwrap();
        assert_eq!(resolution.symbol.name, "testFunction");
        assert_eq!(resolution.symbol.kind, SymbolKind::Function);
    }

    #[test]
    fn test_resolution_caching() {
        let mut symbol_table = SymbolTable::new();
        let inheritance_graph = InheritanceGraph::new();
        let global_scope = symbol_table.get_global_scope();

        let symbol = Symbol::new(
            "cachedSymbol".to_string(),
            SymbolKind::Type,
            SourceLocation::new(
                std::path::PathBuf::from("test.sol"),
                Position::new(1, 1, 0),
                Position::new(1, 12, 11)
            ),
        );
        symbol_table.add_symbol(global_scope, symbol).unwrap();

        let mut resolver = NameResolver::new(&symbol_table, &inheritance_graph, global_scope);

        // First resolution
        let result1 = resolver.resolve_name("cachedSymbol").unwrap();
        assert!(result1.is_some());

        // Second resolution (should use cache)
        let result2 = resolver.resolve_name("cachedSymbol").unwrap();
        assert!(result2.is_some());

        let stats = resolver.get_resolution_statistics();
        assert!(stats.cache_size > 0);
    }

    #[test]
    fn test_batch_resolution() {
        let mut symbol_table = SymbolTable::new();
        let inheritance_graph = InheritanceGraph::new();
        let global_scope = symbol_table.get_global_scope();

        // Add multiple symbols
        for i in 0..5 {
            let symbol = Symbol::new(
                format!("symbol{}", i),
                SymbolKind::Type,
                SourceLocation::new(
                    std::path::PathBuf::from("test.sol"),
                    Position::new(i, 1, i * 10),
                    Position::new(i, 10, i * 10 + 10)
                ),
            );
            symbol_table.add_symbol(global_scope, symbol).unwrap();
        }

        let mut batch_resolver = BatchNameResolver::new(&symbol_table, &inheritance_graph, global_scope);

        // Add names to resolve
        for i in 0..5 {
            batch_resolver.add_name(format!("symbol{}", i));
        }
        batch_resolver.add_name("nonexistent".to_string());

        // Resolve all
        batch_resolver.resolve_all().unwrap();

        // Check results
        let resolved = batch_resolver.get_resolved_names();
        let unresolved = batch_resolver.get_unresolved_names();

        assert_eq!(resolved.len(), 5);
        assert_eq!(unresolved.len(), 1);
        assert!(unresolved.contains(&"nonexistent"));
    }

    #[test]
    fn test_function_signature_parameter_parsing() {
        let symbol_table = SymbolTable::new();
        let inheritance_graph = InheritanceGraph::new();
        let global_scope = symbol_table.get_global_scope();
        let resolver = NameResolver::new(&symbol_table, &inheritance_graph, global_scope);

        // Test cases for parameter counting
        let test_cases = vec![
            // (signature, expected_param_count, description)
            ("", 0, "empty signature"),
            ("   ", 0, "whitespace only signature"),
            ("uint256", 1, "single simple parameter"),
            ("uint256,address", 2, "two simple parameters"),
            ("uint256, address", 2, "two simple parameters with space"),
            ("uint256 , address", 2, "two simple parameters with spaces"),

            // Complex types with commas inside
            ("mapping(address => uint256)", 1, "mapping type"),
            ("mapping(address => uint256),uint256", 2, "mapping and simple type"),
            ("uint256[],mapping(address => uint256)", 2, "array and mapping"),
            ("mapping(address => mapping(uint256 => bool))", 1, "nested mapping"),
            ("mapping(address => mapping(uint256 => bool)),uint256", 2, "nested mapping and simple type"),

            // Array types
            ("uint256[]", 1, "dynamic array"),
            ("uint256[10]", 1, "fixed array"),
            ("uint256[][],address", 2, "nested array and address"),
            ("mapping(address => uint256[])", 1, "mapping to array"),

            // Complex combinations
            ("mapping(address => uint256),uint256[],bool", 3, "mapping, array, and bool"),
            ("mapping(address => mapping(uint256 => bool)),uint256[],address", 3, "complex nested types"),
            ("uint256,mapping(address => uint256),bool", 3, "simple, mapping, simple"),

            // Edge cases
            ("mapping(address=>uint256)", 1, "mapping without spaces"),
            ("uint256  ,  address", 2, "multiple spaces around comma"),
            ("mapping(address => uint256)  ,  uint256[]", 2, "complex types with spaces"),
        ];

        for (signature, expected_count, description) in test_cases {
            let result = resolver.parse_function_signature_parameters(signature);
            assert!(result.is_ok(), "Failed to parse signature '{}': {:?}", signature, result.err());

            let actual_count = result.unwrap();
            assert_eq!(
                actual_count,
                expected_count,
                "Parameter count mismatch for '{}' ({}): expected {}, got {}",
                signature, description, expected_count, actual_count
            );
        }
    }

    #[test]
    fn test_function_signature_compatibility() {
        let symbol_table = SymbolTable::new();
        let inheritance_graph = InheritanceGraph::new();
        let global_scope = symbol_table.get_global_scope();
        let resolver = NameResolver::new(&symbol_table, &inheritance_graph, global_scope);

        use crate::types::ResolvedType;
        use ast::ElementaryType;

        // Test compatibility checking
        let single_arg = vec![ResolvedType::Elementary(ElementaryType::Uint(256))];
        let two_args = vec![
            ResolvedType::Elementary(ElementaryType::Uint(256)),
            ResolvedType::Elementary(ElementaryType::Address),
        ];

        // Compatible cases
        let result = resolver.check_function_signature_compatibility("uint256", &single_arg);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TypeCompatibility::ImplicitlyConvertible);

        let result = resolver.check_function_signature_compatibility("uint256,address", &two_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TypeCompatibility::ImplicitlyConvertible);

        let result = resolver.check_function_signature_compatibility("mapping(address => uint256),uint256", &two_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TypeCompatibility::ImplicitlyConvertible);

        // Incompatible cases (wrong parameter count)
        let result = resolver.check_function_signature_compatibility("uint256,address", &single_arg);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TypeCompatibility::Incompatible);

        let result = resolver.check_function_signature_compatibility("uint256", &two_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TypeCompatibility::Incompatible);

        // Empty signature with no arguments
        let empty_args: Vec<ResolvedType> = vec![];
        let result = resolver.check_function_signature_compatibility("", &empty_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TypeCompatibility::ImplicitlyConvertible);

        // Empty signature with arguments (incompatible)
        let result = resolver.check_function_signature_compatibility("", &single_arg);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TypeCompatibility::Incompatible);
    }
}