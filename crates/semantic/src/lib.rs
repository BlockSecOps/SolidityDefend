pub mod inheritance;
pub mod resolution;
pub mod symbols;
pub mod types;

pub use inheritance::{
    InheritanceGraph, InheritanceGraphBuilder, InheritanceGraphStats, InheritanceNode,
};
pub use resolution::{BatchNameResolver, NameResolver, ResolutionResult, ResolutionStatistics};
pub use symbols::{Scope, Symbol, SymbolKind, SymbolTable};
pub use types::{ResolvedType, TypeCompatibility, TypeResolver};
