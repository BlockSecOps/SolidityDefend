use std::collections::HashMap;
use std::fmt;
use anyhow::{Result, anyhow};

use ast::{TypeName, ElementaryType, Function, StateVariable, SourceLocation};
use crate::symbols::{SymbolTable, Scope, SymbolKind};

/// Represents a resolved type in the Solidity type system
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedType {
    /// Elementary types (uint256, bool, address, etc.)
    Elementary(ElementaryType),
    /// User-defined types (contracts, structs, enums)
    UserDefined {
        name: String,
        definition_scope: Scope,
        location: SourceLocation,
    },
    /// Array types with resolved base type
    Array {
        base_type: Box<ResolvedType>,
        length: Option<u64>, // None for dynamic arrays
    },
    /// Mapping types with resolved key and value types
    Mapping {
        key_type: Box<ResolvedType>,
        value_type: Box<ResolvedType>,
    },
    /// Function types with parameter and return types
    Function {
        parameters: Vec<ResolvedType>,
        return_types: Vec<ResolvedType>,
        visibility: ast::Visibility,
        mutability: ast::StateMutability,
    },
    /// Error type for unresolved or invalid types
    Error(String),
}

impl fmt::Display for ResolvedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolvedType::Elementary(elem) => write!(f, "{:?}", elem),
            ResolvedType::UserDefined { name, .. } => write!(f, "{}", name),
            ResolvedType::Array { base_type, length } => {
                match length {
                    Some(len) => write!(f, "{}[{}]", base_type, len),
                    None => write!(f, "{}[]", base_type),
                }
            }
            ResolvedType::Mapping { key_type, value_type } => {
                write!(f, "mapping({} => {})", key_type, value_type)
            }
            ResolvedType::Function { parameters, return_types, .. } => {
                write!(f, "function({}) returns ({})",
                    parameters.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
                    return_types.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", ")
                )
            }
            ResolvedType::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Type compatibility levels for assignment and function call checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeCompatibility {
    /// Types are identical
    Identical,
    /// Types are compatible with implicit conversion
    ImplicitlyConvertible,
    /// Types are compatible with explicit conversion
    ExplicitlyConvertible,
    /// Types are incompatible
    Incompatible,
}

/// Type resolution context containing symbol information
pub struct TypeResolver<'a> {
    symbol_table: &'a SymbolTable,
    current_scope: Scope,
    /// Cache for resolved types to avoid recomputation
    type_cache: HashMap<String, ResolvedType>,
}

impl<'a> TypeResolver<'a> {
    /// Create a new type resolver with symbol table context
    pub fn new(symbol_table: &'a SymbolTable, current_scope: Scope) -> Self {
        Self {
            symbol_table,
            current_scope,
            type_cache: HashMap::new(),
        }
    }

    /// Resolve a TypeName from the AST to a ResolvedType
    pub fn resolve_type(&mut self, type_name: &TypeName) -> Result<ResolvedType> {
        match type_name {
            TypeName::Elementary(elem_type) => {
                Ok(ResolvedType::Elementary(*elem_type))
            }
            TypeName::UserDefined(identifier) => {
                self.resolve_user_defined_type(identifier.name)
            }
            TypeName::Array { base_type, length } => {
                let resolved_base = self.resolve_type(base_type)?;
                let resolved_length = if let Some(_length_expr) = length {
                    // TODO: Evaluate constant expressions for array length
                    // For now, assume dynamic array
                    None
                } else {
                    None
                };

                Ok(ResolvedType::Array {
                    base_type: Box::new(resolved_base),
                    length: resolved_length,
                })
            }
            TypeName::Mapping { key_type, value_type } => {
                let resolved_key = self.resolve_type(key_type)?;
                let resolved_value = self.resolve_type(value_type)?;

                Ok(ResolvedType::Mapping {
                    key_type: Box::new(resolved_key),
                    value_type: Box::new(resolved_value),
                })
            }
            TypeName::Function { parameters, return_types, visibility, mutability } => {
                // Resolve function type parameters and return types
                let mut param_types = Vec::new();
                for param_type_name in parameters {
                    let param_type = self.resolve_type(param_type_name)?;
                    param_types.push(param_type);
                }

                let mut ret_types = Vec::new();
                for ret_type_name in return_types {
                    let ret_type = self.resolve_type(ret_type_name)?;
                    ret_types.push(ret_type);
                }

                Ok(ResolvedType::Function {
                    parameters: param_types,
                    return_types: ret_types,
                    visibility: *visibility,
                    mutability: *mutability,
                })
            }
        }
    }

    /// Resolve a user-defined type by looking up in symbol table
    fn resolve_user_defined_type(&mut self, type_name: &str) -> Result<ResolvedType> {
        // Check cache first
        if let Some(cached_type) = self.type_cache.get(type_name) {
            return Ok(cached_type.clone());
        }

        // Look up the type in the symbol table
        if let Some(symbol) = self.symbol_table.lookup_symbol(self.current_scope, type_name) {
            let resolved_type = match symbol.kind {
                SymbolKind::Contract | SymbolKind::Interface | SymbolKind::Library => {
                    ResolvedType::UserDefined {
                        name: type_name.to_string(),
                        definition_scope: self.current_scope,
                        location: symbol.location.clone(),
                    }
                }
                SymbolKind::Struct => {
                    ResolvedType::UserDefined {
                        name: type_name.to_string(),
                        definition_scope: self.current_scope,
                        location: symbol.location.clone(),
                    }
                }
                SymbolKind::Enum => {
                    ResolvedType::UserDefined {
                        name: type_name.to_string(),
                        definition_scope: self.current_scope,
                        location: symbol.location.clone(),
                    }
                }
                SymbolKind::Type => {
                    ResolvedType::UserDefined {
                        name: type_name.to_string(),
                        definition_scope: self.current_scope,
                        location: symbol.location.clone(),
                    }
                }
                _ => {
                    return Err(anyhow!("Symbol '{}' is not a type", type_name));
                }
            };

            // Cache the resolved type
            self.type_cache.insert(type_name.to_string(), resolved_type.clone());
            Ok(resolved_type)
        } else {
            Err(anyhow!("Undefined type: {}", type_name))
        }
    }

    /// Check type compatibility for assignments and function calls
    pub fn check_compatibility(&self, from_type: &ResolvedType, to_type: &ResolvedType) -> TypeCompatibility {
        match (from_type, to_type) {
            // Identical types
            (a, b) if a == b => TypeCompatibility::Identical,

            // Elementary type conversions
            (ResolvedType::Elementary(from_elem), ResolvedType::Elementary(to_elem)) => {
                self.check_elementary_compatibility(from_elem, to_elem)
            }

            // Array type compatibility
            (ResolvedType::Array { base_type: from_base, length: from_len },
             ResolvedType::Array { base_type: to_base, length: to_len }) => {
                // Base types must be compatible
                let base_compat = self.check_compatibility(from_base, to_base);
                if base_compat == TypeCompatibility::Incompatible {
                    return TypeCompatibility::Incompatible;
                }

                // Length compatibility: fixed to dynamic is implicitly convertible
                match (from_len, to_len) {
                    (Some(_), None) => TypeCompatibility::ImplicitlyConvertible,
                    (Some(a), Some(b)) if a == b => base_compat,
                    (None, None) => base_compat,
                    _ => TypeCompatibility::Incompatible,
                }
            }

            // Mapping type compatibility (must be identical)
            (ResolvedType::Mapping { .. }, ResolvedType::Mapping { .. }) => {
                if from_type == to_type {
                    TypeCompatibility::Identical
                } else {
                    TypeCompatibility::Incompatible
                }
            }

            // User-defined type compatibility
            (ResolvedType::UserDefined { name: from_name, .. },
             ResolvedType::UserDefined { name: to_name, .. }) => {
                if from_name == to_name {
                    TypeCompatibility::Identical
                } else {
                    // TODO: Check inheritance relationships for contract types
                    TypeCompatibility::Incompatible
                }
            }

            // Different type categories are generally incompatible
            _ => TypeCompatibility::Incompatible,
        }
    }

    /// Check compatibility between elementary types
    fn check_elementary_compatibility(&self, from_type: &ElementaryType, to_type: &ElementaryType) -> TypeCompatibility {
        use ElementaryType::*;

        match (from_type, to_type) {
            // Identical types
            (a, b) if a == b => TypeCompatibility::Identical,

            // Integer size conversions
            (Uint(from_bits), Uint(to_bits)) => {
                if from_bits <= to_bits {
                    TypeCompatibility::ImplicitlyConvertible
                } else {
                    TypeCompatibility::ExplicitlyConvertible
                }
            }
            (Int(from_bits), Int(to_bits)) => {
                if from_bits <= to_bits {
                    TypeCompatibility::ImplicitlyConvertible
                } else {
                    TypeCompatibility::ExplicitlyConvertible
                }
            }

            // Signed to unsigned conversions (explicit only)
            (Int(_), Uint(_)) | (Uint(_), Int(_)) => TypeCompatibility::ExplicitlyConvertible,

            // Fixed bytes conversions
            (FixedBytes(from_size), FixedBytes(to_size)) => {
                if from_size <= to_size {
                    TypeCompatibility::ImplicitlyConvertible
                } else {
                    TypeCompatibility::ExplicitlyConvertible
                }
            }

            // Address and contract conversions
            (Address, Address) => TypeCompatibility::Identical,

            // String and bytes conversions
            (String, Bytes) | (Bytes, String) => TypeCompatibility::ExplicitlyConvertible,
            (FixedBytes(_), Bytes) => TypeCompatibility::ImplicitlyConvertible,
            (Bytes, FixedBytes(_)) => TypeCompatibility::ExplicitlyConvertible,

            // Boolean type (no implicit conversions)
            (Bool, _) | (_, Bool) => TypeCompatibility::Incompatible,

            // Fixed point types (limited support)
            (Fixed(_, _), Fixed(_, _)) | (Ufixed(_, _), Ufixed(_, _)) => {
                TypeCompatibility::ExplicitlyConvertible
            }

            // All other combinations are incompatible
            _ => TypeCompatibility::Incompatible,
        }
    }

    /// Resolve function signature including parameter and return types
    pub fn resolve_function_type(&mut self, function: &Function) -> Result<ResolvedType> {
        let mut parameter_types = Vec::new();

        // Resolve parameter types
        for param in &function.parameters {
            let param_type = self.resolve_type(&param.type_name)?;
            parameter_types.push(param_type);
        }

        let mut return_types = Vec::new();

        // Resolve return types
        for return_param in &function.return_parameters {
            let return_type = self.resolve_type(&return_param.type_name)?;
            return_types.push(return_type);
        }

        Ok(ResolvedType::Function {
            parameters: parameter_types,
            return_types,
            visibility: function.visibility,
            mutability: function.mutability,
        })
    }

    /// Resolve state variable type
    pub fn resolve_state_variable_type(&mut self, variable: &StateVariable) -> Result<ResolvedType> {
        self.resolve_type(&variable.type_name)
    }

    /// Find the common type for multiple expressions (for type inference)
    pub fn find_common_type(&self, types: &[ResolvedType]) -> Option<ResolvedType> {
        if types.is_empty() {
            return None;
        }

        if types.len() == 1 {
            return Some(types[0].clone());
        }

        let first_type = &types[0];

        // Check if all types are identical
        if types.iter().all(|t| t == first_type) {
            return Some(first_type.clone());
        }

        // For now, return None for different types
        // TODO: Implement more sophisticated common type finding
        None
    }

    /// Check if a type is a value type (copied by value)
    pub fn is_value_type(&self, resolved_type: &ResolvedType) -> bool {
        match resolved_type {
            ResolvedType::Elementary(_) => true,
            ResolvedType::UserDefined { .. } => false, // Contracts are reference types
            ResolvedType::Array { .. } => false, // Arrays are reference types
            ResolvedType::Mapping { .. } => false, // Mappings are reference types
            ResolvedType::Function { .. } => true, // Function types are value types
            ResolvedType::Error(_) => false,
        }
    }

    /// Get the size in bytes of a type (for value types)
    #[allow(clippy::only_used_in_recursion)]
    pub fn get_type_size(&self, resolved_type: &ResolvedType) -> Option<u32> {
        match resolved_type {
            ResolvedType::Elementary(elem_type) => {
                match elem_type {
                    ElementaryType::Bool => Some(1),
                    ElementaryType::Address => Some(20),
                    ElementaryType::Uint(bits) | ElementaryType::Int(bits) => Some(*bits as u32 / 8),
                    ElementaryType::FixedBytes(size) => Some(*size as u32),
                    ElementaryType::String | ElementaryType::Bytes => None, // Dynamic size
                    ElementaryType::Fixed(bits, _) | ElementaryType::Ufixed(bits, _) => Some(*bits as u32 / 8),
                }
            }
            ResolvedType::Array { length: Some(len), base_type } => {
                self.get_type_size(base_type).map(|base_size| base_size * (*len as u32))
            }
            _ => None, // Reference types or dynamic types don't have fixed size
        }
    }

    /// Clear the type resolution cache
    pub fn clear_cache(&mut self) {
        self.type_cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::SymbolTable;

    #[test]
    fn test_elementary_type_resolution() {
        let symbol_table = SymbolTable::new();
        let scope = symbol_table.get_global_scope();
        let mut resolver = TypeResolver::new(&symbol_table, scope);

        let uint256_type = TypeName::Elementary(ElementaryType::Uint(256));
        let resolved = resolver.resolve_type(&uint256_type).unwrap();

        assert_eq!(resolved, ResolvedType::Elementary(ElementaryType::Uint(256)));
    }

    #[test]
    fn test_type_compatibility() {
        let symbol_table = SymbolTable::new();
        let scope = symbol_table.get_global_scope();
        let resolver = TypeResolver::new(&symbol_table, scope);

        let uint8 = ResolvedType::Elementary(ElementaryType::Uint(8));
        let uint256 = ResolvedType::Elementary(ElementaryType::Uint(256));

        // uint8 -> uint256 should be implicitly convertible
        assert_eq!(
            resolver.check_compatibility(&uint8, &uint256),
            TypeCompatibility::ImplicitlyConvertible
        );

        // uint256 -> uint8 should be explicitly convertible
        assert_eq!(
            resolver.check_compatibility(&uint256, &uint8),
            TypeCompatibility::ExplicitlyConvertible
        );
    }

    #[test]
    fn test_array_type_resolution() {
        let symbol_table = SymbolTable::new();
        let scope = symbol_table.get_global_scope();
        let mut resolver = TypeResolver::new(&symbol_table, scope);

        // Use a proper arena for memory management instead of Box::leak
        let arena = ast::AstArena::new();
        let base_type = arena.alloc(TypeName::Elementary(ElementaryType::Uint(256)));
        let array_type = TypeName::Array {
            base_type,
            length: None,
        };

        let resolved = resolver.resolve_type(&array_type).unwrap();

        if let ResolvedType::Array { base_type, length } = resolved {
            assert_eq!(*base_type, ResolvedType::Elementary(ElementaryType::Uint(256)));
            assert_eq!(length, None);
        } else {
            panic!("Expected array type");
        }
    }

    #[test]
    fn test_type_size_calculation() {
        let symbol_table = SymbolTable::new();
        let scope = symbol_table.get_global_scope();
        let resolver = TypeResolver::new(&symbol_table, scope);

        let uint256 = ResolvedType::Elementary(ElementaryType::Uint(256));
        assert_eq!(resolver.get_type_size(&uint256), Some(32));

        let address = ResolvedType::Elementary(ElementaryType::Address);
        assert_eq!(resolver.get_type_size(&address), Some(20));

        let bool_type = ResolvedType::Elementary(ElementaryType::Bool);
        assert_eq!(resolver.get_type_size(&bool_type), Some(1));
    }
}