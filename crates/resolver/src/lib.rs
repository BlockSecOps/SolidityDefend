//! Import resolution for SolidityDefend
//!
//! This crate provides import resolution for Solidity projects, including:
//! - Import remapping (Foundry and Hardhat style)
//! - Path resolution (relative, absolute, and library paths)
//! - Import extraction from Solidity source files
//! - Dependency graph construction and topological sorting

pub mod extractor;
pub mod graph;
pub mod remapper;
pub mod resolver;

pub use extractor::ImportExtractor;
pub use graph::DependencyGraph;
pub use remapper::ImportRemapper;
pub use resolver::PathResolver;

use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during import resolution
#[derive(Error, Debug)]
pub enum ResolverError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to resolve import '{import}' from '{}'", from_file.display())]
    UnresolvedImport { import: String, from_file: PathBuf },

    #[error("Circular dependency detected: {0}")]
    CircularDependency(String),

    #[error("Invalid import path: {0}")]
    InvalidImportPath(String),

    #[error("Project error: {0}")]
    Project(#[from] project::ProjectError),
}

/// Result type for resolver operations
pub type ResolverResult<T> = Result<T, ResolverError>;

/// Represents a resolved import
#[derive(Debug, Clone)]
pub struct ResolvedImport {
    /// Original import path as written in source
    pub original: String,
    /// Resolved absolute file path
    pub resolved_path: PathBuf,
    /// Symbols imported (empty for wildcard imports)
    pub symbols: Vec<ImportedSymbol>,
    /// Import alias (for "import X as Y" or "import * as Y")
    pub alias: Option<String>,
}

/// Represents an imported symbol
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSymbol {
    /// Name of the symbol in the source file
    pub name: String,
    /// Alias for the symbol (for "import {X as Y}")
    pub alias: Option<String>,
}

/// Types of Solidity import statements
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportKind {
    /// Simple import: `import "path";`
    Simple,
    /// Named imports: `import {A, B} from "path";`
    Named(Vec<ImportedSymbol>),
    /// Aliased import: `import "path" as X;`
    Aliased(String),
    /// Wildcard import: `import * as X from "path";`
    Wildcard(String),
}

/// Represents a parsed import statement
#[derive(Debug, Clone)]
pub struct Import {
    /// The import path as written in source
    pub path: String,
    /// Type of import
    pub kind: ImportKind,
    /// Line number in source file
    pub line: usize,
}
