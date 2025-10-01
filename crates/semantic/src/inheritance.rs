use std::collections::{HashMap, HashSet, VecDeque};
use petgraph::{Graph, Direction};
use petgraph::graph::{NodeIndex, EdgeIndex};
use petgraph::visit::{EdgeRef, IntoNodeReferences};
use anyhow::{Result, anyhow};

use ast::{Contract, InheritanceSpecifier, SourceLocation, ContractType};
use crate::symbols::{SymbolTable, Scope, Symbol, SymbolKind};

/// Node data for the inheritance graph
#[derive(Debug, Clone, PartialEq)]
pub struct InheritanceNode {
    pub name: String,
    pub contract_type: ContractType,
    pub scope: Scope,
    pub location: SourceLocation,
}

/// Edge data representing inheritance relationship
#[derive(Debug, Clone, PartialEq)]
pub struct InheritanceEdge {
    /// Information about constructor arguments passed to the base constructor
    /// - None: No constructor call (inheritance without explicit constructor invocation)
    /// - Some(count): Number of arguments passed to the constructor
    pub constructor_arg_count: Option<usize>,
    pub location: SourceLocation,
}

/// Contract inheritance graph using petgraph for efficient graph operations
pub struct InheritanceGraph {
    /// The underlying directed graph (child -> parent edges)
    graph: Graph<InheritanceNode, InheritanceEdge>,
    /// Map from contract name to node index for fast lookup
    name_to_node: HashMap<String, NodeIndex>,
    /// Map from scope to node index for symbol table integration
    scope_to_node: HashMap<Scope, NodeIndex>,
}

impl InheritanceGraph {
    /// Create a new empty inheritance graph
    pub fn new() -> Self {
        Self {
            graph: Graph::new(),
            name_to_node: HashMap::new(),
            scope_to_node: HashMap::new(),
        }
    }

    /// Add a contract to the inheritance graph
    pub fn add_contract(&mut self, contract: &Contract, scope: Scope) -> Result<NodeIndex> {
        let node_data = InheritanceNode {
            name: contract.name.name.to_string(),
            contract_type: contract.contract_type,
            scope,
            location: contract.location.clone(),
        };

        // Check for duplicate contracts
        if self.name_to_node.contains_key(&node_data.name) {
            return Err(anyhow!("Contract '{}' already exists in inheritance graph", node_data.name));
        }

        let node_index = self.graph.add_node(node_data.clone());

        // Update lookup maps
        self.name_to_node.insert(node_data.name.clone(), node_index);
        self.scope_to_node.insert(scope, node_index);

        Ok(node_index)
    }

    /// Add inheritance relationship between child and parent contracts
    pub fn add_inheritance(&mut self, child_name: &str, parent_spec: &InheritanceSpecifier) -> Result<EdgeIndex> {
        let parent_name = parent_spec.base.name;

        // Find child and parent nodes
        let child_node = self.name_to_node.get(child_name)
            .ok_or_else(|| anyhow!("Child contract '{}' not found in graph", child_name))?;

        let parent_node = self.name_to_node.get(parent_name)
            .ok_or_else(|| anyhow!("Parent contract '{}' not found in graph", parent_name))?;

        // Check for self-inheritance
        if child_node == parent_node {
            return Err(anyhow!("Contract '{}' cannot inherit from itself", child_name));
        }

        // Create edge data
        let edge_data = InheritanceEdge {
            constructor_arg_count: parent_spec.arguments.as_ref().map(|args| {
                // Store the actual number of constructor arguments
                args.len()
            }),
            location: parent_spec.base.location.clone(),
        };

        // Add edge from child to parent
        let edge_index = self.graph.add_edge(*child_node, *parent_node, edge_data);

        // Check for circular inheritance after adding the edge
        if self.has_circular_inheritance(*child_node)? {
            // Remove the edge and return error
            self.graph.remove_edge(edge_index);
            return Err(anyhow!("Adding inheritance from '{}' to '{}' would create circular inheritance",
                              child_name, parent_name));
        }

        Ok(edge_index)
    }

    /// Check if there is circular inheritance starting from a given node
    fn has_circular_inheritance(&self, start_node: NodeIndex) -> Result<bool> {
        let mut visited = HashSet::new();
        let mut path = HashSet::new();

        self.dfs_cycle_check(start_node, &mut visited, &mut path)
    }

    /// Depth-first search to detect cycles in inheritance
    fn dfs_cycle_check(&self, node: NodeIndex, visited: &mut HashSet<NodeIndex>, path: &mut HashSet<NodeIndex>) -> Result<bool> {
        if path.contains(&node) {
            return Ok(true); // Cycle detected
        }

        if visited.contains(&node) {
            return Ok(false); // Already processed, no cycle from this node
        }

        visited.insert(node);
        path.insert(node);

        // Check all parent contracts (outgoing edges)
        for edge in self.graph.edges_directed(node, Direction::Outgoing) {
            let parent_node = edge.target();
            if self.dfs_cycle_check(parent_node, visited, path)? {
                return Ok(true);
            }
        }

        path.remove(&node);
        Ok(false)
    }

    /// Get all direct parent contracts of a given contract
    pub fn get_direct_parents(&self, contract_name: &str) -> Result<Vec<&InheritanceNode>> {
        let node_index = self.name_to_node.get(contract_name)
            .ok_or_else(|| anyhow!("Contract '{}' not found", contract_name))?;

        let mut parents = Vec::new();
        for edge in self.graph.edges_directed(*node_index, Direction::Outgoing) {
            let parent_node = edge.target();
            if let Some(parent_data) = self.graph.node_weight(parent_node) {
                parents.push(parent_data);
            }
        }

        Ok(parents)
    }

    /// Get all ancestors (transitive closure of parents) of a given contract
    pub fn get_all_ancestors(&self, contract_name: &str) -> Result<Vec<&InheritanceNode>> {
        let node_index = self.name_to_node.get(contract_name)
            .ok_or_else(|| anyhow!("Contract '{}' not found", contract_name))?;

        let mut ancestors = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        // Start with direct parents
        for edge in self.graph.edges_directed(*node_index, Direction::Outgoing) {
            queue.push_back(edge.target());
        }

        while let Some(current_node) = queue.pop_front() {
            if visited.contains(&current_node) {
                continue;
            }
            visited.insert(current_node);

            if let Some(node_data) = self.graph.node_weight(current_node) {
                ancestors.push(node_data);
            }

            // Add parents of current node to queue
            for edge in self.graph.edges_directed(current_node, Direction::Outgoing) {
                queue.push_back(edge.target());
            }
        }

        Ok(ancestors)
    }

    /// Get all direct children of a given contract
    pub fn get_direct_children(&self, contract_name: &str) -> Result<Vec<&InheritanceNode>> {
        let node_index = self.name_to_node.get(contract_name)
            .ok_or_else(|| anyhow!("Contract '{}' not found", contract_name))?;

        let mut children = Vec::new();
        for edge in self.graph.edges_directed(*node_index, Direction::Incoming) {
            let child_node = edge.source();
            if let Some(child_data) = self.graph.node_weight(child_node) {
                children.push(child_data);
            }
        }

        Ok(children)
    }

    /// Get all descendants (transitive closure of children) of a given contract
    pub fn get_all_descendants(&self, contract_name: &str) -> Result<Vec<&InheritanceNode>> {
        let node_index = self.name_to_node.get(contract_name)
            .ok_or_else(|| anyhow!("Contract '{}' not found", contract_name))?;

        let mut descendants = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        // Start with direct children
        for edge in self.graph.edges_directed(*node_index, Direction::Incoming) {
            queue.push_back(edge.source());
        }

        while let Some(current_node) = queue.pop_front() {
            if visited.contains(&current_node) {
                continue;
            }
            visited.insert(current_node);

            if let Some(node_data) = self.graph.node_weight(current_node) {
                descendants.push(node_data);
            }

            // Add children of current node to queue
            for edge in self.graph.edges_directed(current_node, Direction::Incoming) {
                queue.push_back(edge.source());
            }
        }

        Ok(descendants)
    }

    /// Check if one contract inherits from another (directly or indirectly)
    pub fn inherits_from(&self, child_name: &str, ancestor_name: &str) -> Result<bool> {
        if child_name == ancestor_name {
            return Ok(false); // A contract doesn't inherit from itself
        }

        let ancestors = self.get_all_ancestors(child_name)?;
        Ok(ancestors.iter().any(|ancestor| ancestor.name == ancestor_name))
    }

    /// Get the linearized inheritance order (C3 linearization) for a contract
    /// This determines the order in which parent contracts are considered for method resolution
    pub fn get_linearized_inheritance(&self, contract_name: &str) -> Result<Vec<String>> {
        let node_index = self.name_to_node.get(contract_name)
            .ok_or_else(|| anyhow!("Contract '{}' not found", contract_name))?;

        // Simplified linearization - in practice, should implement C3 linearization
        // For now, use a topological sort of ancestors
        let mut linearized = vec![contract_name.to_string()];
        let ancestors = self.get_all_ancestors(contract_name)?;

        // Add ancestors in a deterministic order (by name for now)
        let mut ancestor_names: Vec<String> = ancestors.iter().map(|a| a.name.clone()).collect();
        ancestor_names.sort();
        linearized.extend(ancestor_names);

        Ok(linearized)
    }

    /// Find the lowest common ancestor of two contracts
    pub fn find_lowest_common_ancestor(&self, contract1: &str, contract2: &str) -> Result<Option<String>> {
        let ancestors1: HashSet<String> = self.get_all_ancestors(contract1)?
            .iter()
            .map(|a| a.name.clone())
            .collect();

        let ancestors2 = self.get_all_ancestors(contract2)?;

        // Find common ancestors
        for ancestor in ancestors2 {
            if ancestors1.contains(&ancestor.name) {
                return Ok(Some(ancestor.name.clone()));
            }
        }

        Ok(None)
    }

    /// Get contract information by name
    pub fn get_contract_info(&self, contract_name: &str) -> Option<&InheritanceNode> {
        self.name_to_node.get(contract_name)
            .and_then(|&node_index| self.graph.node_weight(node_index))
    }

    /// Get all contracts in the graph
    pub fn get_all_contracts(&self) -> Vec<&InheritanceNode> {
        self.graph.node_weights().collect()
    }

    /// Check if the inheritance graph is valid (no cycles)
    pub fn validate(&self) -> Result<()> {
        for node_index in self.graph.node_indices() {
            if self.has_circular_inheritance(node_index)? {
                if let Some(node_data) = self.graph.node_weight(node_index) {
                    return Err(anyhow!("Circular inheritance detected involving contract '{}'", node_data.name));
                }
            }
        }
        Ok(())
    }

    /// Get statistics about the inheritance graph
    pub fn get_statistics(&self) -> InheritanceGraphStats {
        let total_contracts = self.graph.node_count();
        let total_inheritance_relationships = self.graph.edge_count();

        let mut contracts_by_type = HashMap::new();
        let mut max_inheritance_depth = 0;

        for node in self.graph.node_weights() {
            *contracts_by_type.entry(node.contract_type).or_insert(0) += 1;

            // Calculate inheritance depth for this contract
            if let Ok(ancestors) = self.get_all_ancestors(&node.name) {
                max_inheritance_depth = max_inheritance_depth.max(ancestors.len());
            }
        }

        InheritanceGraphStats {
            total_contracts,
            total_inheritance_relationships,
            contracts_by_type,
            max_inheritance_depth,
        }
    }

    /// Export the graph structure for visualization or debugging
    pub fn export_dot_format(&self) -> String {
        let mut dot = String::from("digraph InheritanceGraph {\n");
        dot.push_str("  rankdir=BT;\n"); // Bottom to top (child to parent)

        // Add nodes
        for (node_index, node_data) in self.graph.node_references() {
            let shape = match node_data.contract_type {
                ContractType::Contract => "box",
                ContractType::Interface => "ellipse",
                ContractType::Library => "diamond",
            };
            dot.push_str(&format!("  {} [label=\"{}\" shape={}];\n",
                                 node_index.index(), node_data.name, shape));
        }

        // Add edges
        for edge in self.graph.edge_references() {
            dot.push_str(&format!("  {} -> {};\n",
                                 edge.source().index(), edge.target().index()));
        }

        dot.push_str("}\n");
        dot
    }
}

impl Default for InheritanceGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the inheritance graph
#[derive(Debug, Clone)]
pub struct InheritanceGraphStats {
    pub total_contracts: usize,
    pub total_inheritance_relationships: usize,
    pub contracts_by_type: HashMap<ContractType, usize>,
    pub max_inheritance_depth: usize,
}

/// Builder for constructing inheritance graphs from parsed contracts
pub struct InheritanceGraphBuilder<'a> {
    symbol_table: &'a SymbolTable,
    graph: InheritanceGraph,
}

impl<'a> InheritanceGraphBuilder<'a> {
    /// Create a new builder with symbol table context
    pub fn new(symbol_table: &'a SymbolTable) -> Self {
        Self {
            symbol_table,
            graph: InheritanceGraph::new(),
        }
    }

    /// Build the inheritance graph from all contracts in the symbol table
    /// Note: This method requires actual Contract AST nodes, not just symbols
    /// Use add_contract_with_inheritance for individual contracts
    pub fn build(self) -> Result<InheritanceGraph> {
        // For now, just return the graph as-is
        // Contracts should be added using add_contract_with_inheritance
        // which has access to the actual AST nodes

        // Validate the graph
        self.graph.validate()?;

        Ok(self.graph)
    }

    /// Add a specific contract and its inheritance relationships
    pub fn add_contract_with_inheritance(&mut self, contract: &Contract, scope: Scope) -> Result<()> {
        // Add the contract node
        self.graph.add_contract(contract, scope)?;

        // Add inheritance relationships
        for inheritance_spec in &contract.inheritance {
            self.graph.add_inheritance(contract.name.name, inheritance_spec)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast::{SourceLocation, Position};

    #[test]
    fn test_graph_creation() {
        let graph = InheritanceGraph::new();
        assert_eq!(graph.graph.node_count(), 0);
        assert_eq!(graph.graph.edge_count(), 0);
    }

    #[test]
    fn test_graph_statistics() {
        let graph = InheritanceGraph::new();
        let stats = graph.get_statistics();
        assert_eq!(stats.total_contracts, 0);
        assert_eq!(stats.total_inheritance_relationships, 0);
        assert_eq!(stats.max_inheritance_depth, 0);
    }

    #[test]
    fn test_dot_export() {
        let graph = InheritanceGraph::new();
        let dot = graph.export_dot_format();
        assert!(dot.contains("digraph InheritanceGraph"));
        assert!(dot.contains("rankdir=BT"));
    }

    #[test]
    fn test_inheritance_graph_builder() {
        let symbol_table = crate::symbols::SymbolTable::new();
        let inheritance_graph = InheritanceGraph::new();

        let builder = InheritanceGraphBuilder::new(&symbol_table);
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_graph_validation() {
        let graph = InheritanceGraph::new();
        assert!(graph.validate().is_ok());
    }
}