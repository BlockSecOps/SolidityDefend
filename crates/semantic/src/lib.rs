pub mod inheritance;
pub mod resolution;
pub mod symbols;
pub mod types;

pub use symbols::{SymbolTable, Symbol, SymbolKind, Scope};
pub use types::{TypeResolver, ResolvedType, TypeCompatibility};
pub use inheritance::{InheritanceGraph, InheritanceNode, InheritanceGraphBuilder, InheritanceGraphStats};
pub use resolution::{NameResolver, ResolutionResult, BatchNameResolver, ResolutionStatistics};
