//! Dependency graph for Solidity projects
//!
//! Builds and traverses a dependency graph based on imports.

use crate::ResolverError;
use crate::extractor::ImportExtractor;
use crate::resolver::PathResolver;
use petgraph::algo::toposort;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Dependency graph for a Solidity project
pub struct DependencyGraph {
    /// The underlying directed graph
    graph: DiGraph<PathBuf, ()>,
    /// Map from file path to node index
    node_map: HashMap<PathBuf, NodeIndex>,
    /// Import extractor
    extractor: ImportExtractor,
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyGraph {
    /// Create a new empty dependency graph
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            extractor: ImportExtractor::new(),
        }
    }

    /// Build a dependency graph from a list of files
    pub fn build(
        &mut self,
        files: &[PathBuf],
        resolver: &PathResolver,
    ) -> Result<(), ResolverError> {
        // First pass: add all files as nodes
        for file in files {
            self.add_node(file);
        }

        // Second pass: add edges based on imports
        for file in files {
            self.process_file_imports(file, resolver)?;
        }

        Ok(())
    }

    /// Add a file node to the graph
    fn add_node(&mut self, path: &Path) -> NodeIndex {
        // Try to canonicalize the path for consistent comparisons
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        if let Some(&idx) = self.node_map.get(&canonical) {
            return idx;
        }

        let idx = self.graph.add_node(canonical.clone());
        self.node_map.insert(canonical, idx);
        idx
    }

    /// Process imports for a file and add edges
    fn process_file_imports(
        &mut self,
        file: &Path,
        resolver: &PathResolver,
    ) -> Result<(), ResolverError> {
        let content = std::fs::read_to_string(file)?;
        let imports = self.extractor.extract(&content);

        let from_idx = self.add_node(file);

        for import in imports {
            // Try to resolve the import
            match resolver.resolve(&import.path, file) {
                Ok(resolved) => {
                    let to_idx = self.add_node(&resolved);
                    // Add edge from importer to imported
                    self.graph.add_edge(from_idx, to_idx, ());
                }
                Err(e) => {
                    // Log warning but continue - some imports may be external
                    tracing::warn!(
                        "Could not resolve import '{}' in {}: {}",
                        import.path,
                        file.display(),
                        e
                    );
                }
            }
        }

        Ok(())
    }

    /// Get files in topological order (dependencies first)
    pub fn topological_order(&self) -> Result<Vec<PathBuf>, ResolverError> {
        // Reverse the graph for topological sort (we want dependencies first)
        let mut reversed = DiGraph::new();
        let mut reverse_map: HashMap<NodeIndex, NodeIndex> = HashMap::new();

        // Add nodes
        for node_idx in self.graph.node_indices() {
            let new_idx = reversed.add_node(self.graph[node_idx].clone());
            reverse_map.insert(node_idx, new_idx);
        }

        // Add reversed edges
        for edge in self.graph.edge_references() {
            let source = reverse_map[&edge.source()];
            let target = reverse_map[&edge.target()];
            reversed.add_edge(target, source, ());
        }

        match toposort(&reversed, None) {
            Ok(order) => Ok(order.into_iter().map(|idx| reversed[idx].clone()).collect()),
            Err(cycle) => {
                let cycle_node = &reversed[cycle.node_id()];
                Err(ResolverError::CircularDependency(format!(
                    "Circular dependency detected involving: {}",
                    cycle_node.display()
                )))
            }
        }
    }

    /// Get direct dependencies of a file
    pub fn dependencies(&self, file: &Path) -> Vec<PathBuf> {
        let canonical = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
        if let Some(&idx) = self.node_map.get(&canonical) {
            self.graph
                .neighbors(idx)
                .map(|n| self.graph[n].clone())
                .collect()
        } else {
            vec![]
        }
    }

    /// Get files that depend on the given file
    pub fn dependents(&self, file: &Path) -> Vec<PathBuf> {
        let canonical = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
        if let Some(&idx) = self.node_map.get(&canonical) {
            self.graph
                .neighbors_directed(idx, petgraph::Direction::Incoming)
                .map(|n| self.graph[n].clone())
                .collect()
        } else {
            vec![]
        }
    }

    /// Check if there are any circular dependencies
    pub fn has_cycles(&self) -> bool {
        toposort(&self.graph, None).is_err()
    }

    /// Get all files in the graph
    pub fn files(&self) -> Vec<PathBuf> {
        self.graph.node_weights().cloned().collect()
    }

    /// Get the number of files in the graph
    pub fn len(&self) -> usize {
        self.graph.node_count()
    }

    /// Check if the graph is empty
    pub fn is_empty(&self) -> bool {
        self.graph.node_count() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_project() -> TempDir {
        let temp = TempDir::new().unwrap();

        // Create files with imports
        let base_content = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Base {
    uint256 public value;
}
"#;

        let token_content = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Base.sol";

contract Token is Base {
    string public name;
}
"#;

        let vault_content = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Token.sol";
import "./Base.sol";

contract Vault {
    Token public token;
}
"#;

        std::fs::write(temp.path().join("Base.sol"), base_content).unwrap();
        std::fs::write(temp.path().join("Token.sol"), token_content).unwrap();
        std::fs::write(temp.path().join("Vault.sol"), vault_content).unwrap();

        temp
    }

    #[test]
    fn test_build_dependency_graph() {
        let temp = create_test_project();
        let resolver = PathResolver::new(temp.path(), vec![], vec![]);

        let files = vec![
            temp.path().join("Base.sol"),
            temp.path().join("Token.sol"),
            temp.path().join("Vault.sol"),
        ];

        let mut graph = DependencyGraph::new();
        graph.build(&files, &resolver).unwrap();

        // Graph should have 3 nodes (each file added plus resolved imports)
        // Since imports resolve to the same files, we have exactly 3 unique files
        assert!(graph.len() >= 3);
        assert!(!graph.has_cycles());
    }

    #[test]
    fn test_topological_order() {
        let temp = create_test_project();
        let resolver = PathResolver::new(temp.path(), vec![], vec![]);

        let files = vec![
            temp.path().join("Vault.sol"),
            temp.path().join("Token.sol"),
            temp.path().join("Base.sol"),
        ];

        let mut graph = DependencyGraph::new();
        graph.build(&files, &resolver).unwrap();

        let order = graph.topological_order().unwrap();

        // Base.sol should come before Token.sol
        // Token.sol should come before Vault.sol
        let base_pos = order.iter().position(|p| p.ends_with("Base.sol")).unwrap();
        let token_pos = order.iter().position(|p| p.ends_with("Token.sol")).unwrap();
        let vault_pos = order.iter().position(|p| p.ends_with("Vault.sol")).unwrap();

        assert!(
            base_pos < token_pos,
            "Base.sol should come before Token.sol"
        );
        assert!(
            token_pos < vault_pos,
            "Token.sol should come before Vault.sol"
        );
    }

    #[test]
    fn test_dependencies() {
        let temp = create_test_project();
        let resolver = PathResolver::new(temp.path(), vec![], vec![]);

        let files = vec![
            temp.path().join("Base.sol"),
            temp.path().join("Token.sol"),
            temp.path().join("Vault.sol"),
        ];

        let mut graph = DependencyGraph::new();
        graph.build(&files, &resolver).unwrap();

        // Token depends on Base
        let token_deps = graph.dependencies(&temp.path().join("Token.sol"));
        assert!(token_deps.iter().any(|p| p.ends_with("Base.sol")));

        // Vault depends on Token and Base
        let vault_deps = graph.dependencies(&temp.path().join("Vault.sol"));
        assert_eq!(vault_deps.len(), 2);
    }

    #[test]
    fn test_circular_dependency_detection() {
        let temp = TempDir::new().unwrap();

        // Create files with circular imports
        let a_content = r#"
pragma solidity ^0.8.0;
import "./B.sol";
contract A {}
"#;

        let b_content = r#"
pragma solidity ^0.8.0;
import "./A.sol";
contract B {}
"#;

        std::fs::write(temp.path().join("A.sol"), a_content).unwrap();
        std::fs::write(temp.path().join("B.sol"), b_content).unwrap();

        let resolver = PathResolver::new(temp.path(), vec![], vec![]);
        let files = vec![temp.path().join("A.sol"), temp.path().join("B.sol")];

        let mut graph = DependencyGraph::new();
        graph.build(&files, &resolver).unwrap();

        assert!(graph.has_cycles());

        let result = graph.topological_order();
        assert!(result.is_err());
    }
}
