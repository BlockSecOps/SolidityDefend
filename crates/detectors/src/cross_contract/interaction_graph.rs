use crate::types::AnalysisContext;
use std::collections::{HashMap, HashSet, VecDeque};

/// Graph representing interactions between contracts
#[derive(Debug, Clone)]
pub struct InteractionGraph {
    nodes: HashMap<String, ContractNode>,
    edges: Vec<InteractionEdge>,
    adjacency_list: HashMap<String, Vec<String>>,
}

/// Node representing a contract in the interaction graph
#[derive(Debug, Clone)]
pub struct ContractNode {
    pub name: String,
    pub contract_type: ContractType,
    pub trust_level: TrustLevel,
    pub external_calls: Vec<String>,
    pub receives_calls: Vec<String>,
}

/// Edge representing an interaction between contracts
#[derive(Debug, Clone)]
pub struct InteractionEdge {
    pub from: String,
    pub to: String,
    pub interaction_type: InteractionType,
    pub functions: Vec<String>,
    pub data_flow: Vec<DataFlow>,
    pub risk_level: RiskLevel,
}

/// Type of contract based on its functionality
#[derive(Debug, Clone, PartialEq)]
pub enum ContractType {
    Token,
    DEX,
    LendingPool,
    Oracle,
    Governance,
    Vault,
    Factory,
    Proxy,
    Library,
    Standard,
    Unknown,
}

/// Trust level of a contract
#[derive(Debug, Clone, PartialEq)]
pub enum TrustLevel {
    Trusted,     // Well-known, audited contracts
    Verified,    // Verified source code
    Unverified,  // Unverified or unknown
    Malicious,   // Known malicious patterns
}

/// Type of interaction between contracts
#[derive(Debug, Clone, PartialEq)]
pub enum InteractionType {
    FunctionCall,
    DelegateCall,
    StaticCall,
    Transfer,
    Approve,
    Event,
    StateRead,
    StateWrite,
}

/// Data flow information
#[derive(Debug, Clone)]
pub struct DataFlow {
    pub parameter: String,
    pub data_type: String,
    pub is_tainted: bool,
    pub source_function: String,
    pub target_function: String,
}

/// Risk level of an interaction
#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl InteractionGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            adjacency_list: HashMap::new(),
        }
    }

    /// Build interaction graph from a set of contracts
    pub fn build_from_contracts(contracts: &HashMap<String, &AnalysisContext>) -> Self {
        let mut graph = Self::new();

        // Add nodes for each contract
        for (name, context) in contracts {
            let node = ContractNode::from_context(name.clone(), context);
            graph.add_node(node);
        }

        // Analyze interactions between contracts
        for (from_name, from_context) in contracts {
            for (to_name, to_context) in contracts {
                if from_name != to_name {
                    if let Some(interaction) = Self::detect_interaction(from_name, from_context, to_name, to_context) {
                        graph.add_edge(interaction);
                    }
                }
            }
        }

        graph
    }

    /// Add a contract node to the graph
    pub fn add_node(&mut self, node: ContractNode) {
        self.adjacency_list.insert(node.name.clone(), Vec::new());
        self.nodes.insert(node.name.clone(), node);
    }

    /// Add an interaction edge to the graph
    pub fn add_edge(&mut self, edge: InteractionEdge) {
        // Update adjacency list
        self.adjacency_list
            .entry(edge.from.clone())
            .or_insert_with(Vec::new)
            .push(edge.to.clone());

        self.edges.push(edge);
    }

    /// Get neighboring contracts
    pub fn get_neighbors(&self, contract: &str) -> Vec<String> {
        self.adjacency_list.get(contract).cloned().unwrap_or_default()
    }

    /// Check if there's a direct edge between contracts
    pub fn has_edge(&self, from: &str, to: &str) -> bool {
        self.adjacency_list
            .get(from)
            .map(|neighbors| neighbors.contains(&to.to_string()))
            .unwrap_or(false)
    }

    /// Find shortest path between two contracts
    pub fn shortest_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        if from == to {
            return Some(vec![from.to_string()]);
        }

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<String, String> = HashMap::new();

        queue.push_back(from.to_string());
        visited.insert(from.to_string());

        while let Some(current) = queue.pop_front() {
            if current == to {
                // Reconstruct path
                let mut path = Vec::new();
                let mut node = to.to_string();

                while let Some(p) = parent.get(&node) {
                    path.push(node.clone());
                    node = p.clone();
                }
                path.push(from.to_string());
                path.reverse();

                return Some(path);
            }

            if let Some(neighbors) = self.adjacency_list.get(&current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        parent.insert(neighbor.clone(), current.clone());
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }

        None
    }

    /// Find all cycles in the graph
    pub fn find_cycles(&self) -> Vec<Vec<String>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut path = Vec::new();

        for node in self.nodes.keys() {
            if !visited.contains(node) {
                self.dfs_cycles(
                    node,
                    &mut visited,
                    &mut rec_stack,
                    &mut path,
                    &mut cycles
                );
            }
        }

        cycles
    }

    /// Depth-first search for cycle detection
    fn dfs_cycles(
        &self,
        node: &str,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>
    ) {
        visited.insert(node.to_string());
        rec_stack.insert(node.to_string());
        path.push(node.to_string());

        if let Some(neighbors) = self.adjacency_list.get(node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    self.dfs_cycles(neighbor, visited, rec_stack, path, cycles);
                } else if rec_stack.contains(neighbor) {
                    // Found a cycle
                    if let Some(start_pos) = path.iter().position(|x| x == neighbor) {
                        let cycle = path[start_pos..].to_vec();
                        cycles.push(cycle);
                    }
                }
            }
        }

        rec_stack.remove(node);
        path.pop();
    }

    /// Get contract node by name
    pub fn get_node(&self, name: &str) -> Option<&ContractNode> {
        self.nodes.get(name)
    }

    /// Get all edges involving a contract
    pub fn get_edges_for_contract(&self, contract: &str) -> Vec<&InteractionEdge> {
        self.edges.iter()
            .filter(|edge| edge.from == contract || edge.to == contract)
            .collect()
    }

    /// Calculate graph metrics
    pub fn calculate_metrics(&self) -> GraphMetrics {
        let node_count = self.nodes.len();
        let edge_count = self.edges.len();

        let density = if node_count > 1 {
            (2.0 * edge_count as f64) / (node_count as f64 * (node_count - 1) as f64)
        } else {
            0.0
        };

        let cycles = self.find_cycles();
        let cycle_count = cycles.len();

        // Calculate average degree
        let total_degree: usize = self.adjacency_list.values()
            .map(|neighbors| neighbors.len())
            .sum();
        let average_degree = if node_count > 0 {
            total_degree as f64 / node_count as f64
        } else {
            0.0
        };

        GraphMetrics {
            node_count,
            edge_count,
            density,
            cycle_count,
            average_degree,
            max_path_length: self.calculate_max_path_length(),
        }
    }

    fn calculate_max_path_length(&self) -> usize {
        let mut max_length = 0;

        for from in self.nodes.keys() {
            for to in self.nodes.keys() {
                if from != to {
                    if let Some(path) = self.shortest_path(from, to) {
                        max_length = max_length.max(path.len() - 1);
                    }
                }
            }
        }

        max_length
    }

    /// Detect interaction between two contracts
    fn detect_interaction(
        from_name: &str,
        from_context: &AnalysisContext,
        to_name: &str,
        to_context: &AnalysisContext
    ) -> Option<InteractionEdge> {
        // Look for function calls to the target contract
        let calls_target = Self::calls_contract(from_context, to_name);

        if calls_target {
            let interaction_type = Self::determine_interaction_type(from_context, to_name);
            let functions = Self::extract_called_functions(from_context, to_name);
            let data_flow = Self::analyze_data_flow(from_context, to_context);
            let risk_level = Self::assess_risk_level(&interaction_type, &data_flow);

            Some(InteractionEdge {
                from: from_name.to_string(),
                to: to_name.to_string(),
                interaction_type,
                functions,
                data_flow,
                risk_level,
            })
        } else {
            None
        }
    }

    fn calls_contract(context: &AnalysisContext, target: &str) -> bool {
        // Simplified detection - would need AST analysis for precision
        context.source_code.contains(target) ||
        context.source_code.contains("call(") ||
        context.source_code.contains("delegatecall(")
    }

    fn determine_interaction_type(context: &AnalysisContext, target: &str) -> InteractionType {
        if context.source_code.contains("delegatecall") {
            InteractionType::DelegateCall
        } else if context.source_code.contains("staticcall") {
            InteractionType::StaticCall
        } else if context.source_code.contains("transfer") {
            InteractionType::Transfer
        } else if context.source_code.contains("approve") {
            InteractionType::Approve
        } else {
            InteractionType::FunctionCall
        }
    }

    fn extract_called_functions(context: &AnalysisContext, target: &str) -> Vec<String> {
        // Simplified extraction - would need proper AST parsing
        let mut functions = Vec::new();

        // Look for common function call patterns
        if context.source_code.contains("transfer") {
            functions.push("transfer".to_string());
        }
        if context.source_code.contains("approve") {
            functions.push("approve".to_string());
        }

        functions
    }

    fn analyze_data_flow(from_context: &AnalysisContext, to_context: &AnalysisContext) -> Vec<DataFlow> {
        // Simplified data flow analysis - would need more sophisticated implementation
        Vec::new()
    }

    fn assess_risk_level(interaction_type: &InteractionType, data_flow: &[DataFlow]) -> RiskLevel {
        match interaction_type {
            InteractionType::DelegateCall => RiskLevel::Critical,
            InteractionType::FunctionCall => RiskLevel::Medium,
            InteractionType::Transfer => RiskLevel::Low,
            InteractionType::StaticCall => RiskLevel::Low,
            _ => RiskLevel::Medium,
        }
    }
}

impl ContractNode {
    /// Create a contract node from analysis context
    pub fn from_context(name: String, context: &AnalysisContext) -> Self {
        let contract_type = Self::determine_contract_type(context);
        let trust_level = Self::determine_trust_level(context);
        let external_calls = Self::extract_external_calls(context);
        let receives_calls = Self::extract_received_calls(context);

        Self {
            name,
            contract_type,
            trust_level,
            external_calls,
            receives_calls,
        }
    }

    fn determine_contract_type(context: &AnalysisContext) -> ContractType {
        let source = &context.source_code.to_lowercase();

        if source.contains("erc20") || source.contains("token") {
            ContractType::Token
        } else if source.contains("swap") || source.contains("dex") || source.contains("uniswap") {
            ContractType::DEX
        } else if source.contains("lending") || source.contains("compound") || source.contains("aave") {
            ContractType::LendingPool
        } else if source.contains("oracle") || source.contains("chainlink") || source.contains("price") {
            ContractType::Oracle
        } else if source.contains("governance") || source.contains("voting") || source.contains("proposal") {
            ContractType::Governance
        } else if source.contains("vault") || source.contains("strategy") {
            ContractType::Vault
        } else if source.contains("factory") || source.contains("create") {
            ContractType::Factory
        } else if source.contains("proxy") || source.contains("delegatecall") {
            ContractType::Proxy
        } else if source.contains("library") {
            ContractType::Library
        } else {
            ContractType::Unknown
        }
    }

    fn determine_trust_level(context: &AnalysisContext) -> TrustLevel {
        let source = &context.source_code.to_lowercase();

        if source.contains("openzeppelin") || source.contains("@openzeppelin") {
            TrustLevel::Trusted
        } else if source.contains("selfdestruct") || source.contains("suicide") {
            TrustLevel::Malicious
        } else {
            TrustLevel::Unverified
        }
    }

    fn extract_external_calls(context: &AnalysisContext) -> Vec<String> {
        // Simplified extraction - would need AST analysis
        Vec::new()
    }

    fn extract_received_calls(context: &AnalysisContext) -> Vec<String> {
        // Simplified extraction - would need AST analysis
        Vec::new()
    }
}

/// Graph metrics for analysis
#[derive(Debug, Clone)]
pub struct GraphMetrics {
    pub node_count: usize,
    pub edge_count: usize,
    pub density: f64,
    pub cycle_count: usize,
    pub average_degree: f64,
    pub max_path_length: usize,
}

impl Default for InteractionGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::*;
    use ast::{AstArena, Visibility, StateMutability};
    use semantic::SymbolTable;

    #[test]
    fn test_graph_creation() {
        let graph = InteractionGraph::new();
        assert_eq!(graph.nodes.len(), 0);
        assert_eq!(graph.edges.len(), 0);
    }

    #[test]
    fn test_add_node() {
        let mut graph = InteractionGraph::new();
        let node = ContractNode {
            name: "TestContract".to_string(),
            contract_type: ContractType::Standard,
            trust_level: TrustLevel::Unverified,
            external_calls: Vec::new(),
            receives_calls: Vec::new(),
        };

        graph.add_node(node);
        assert_eq!(graph.nodes.len(), 1);
        assert!(graph.nodes.contains_key("TestContract"));
    }

    #[test]
    fn test_shortest_path() {
        let mut graph = InteractionGraph::new();

        // Add nodes
        let node1 = ContractNode {
            name: "A".to_string(),
            contract_type: ContractType::Standard,
            trust_level: TrustLevel::Unverified,
            external_calls: Vec::new(),
            receives_calls: Vec::new(),
        };
        let node2 = ContractNode {
            name: "B".to_string(),
            contract_type: ContractType::Standard,
            trust_level: TrustLevel::Unverified,
            external_calls: Vec::new(),
            receives_calls: Vec::new(),
        };

        graph.add_node(node1);
        graph.add_node(node2);

        // Add edge
        let edge = InteractionEdge {
            from: "A".to_string(),
            to: "B".to_string(),
            interaction_type: InteractionType::FunctionCall,
            functions: Vec::new(),
            data_flow: Vec::new(),
            risk_level: RiskLevel::Low,
        };
        graph.add_edge(edge);

        let path = graph.shortest_path("A", "B");
        assert_eq!(path, Some(vec!["A".to_string(), "B".to_string()]));
    }

    #[test]
    fn test_contract_type_detection() {
        let arena = AstArena::new();
        let function = create_mock_ast_function(
            &arena,
            "transfer",
            Visibility::External,
            StateMutability::NonPayable,
        );

        let contract = create_mock_ast_contract(&arena, "Token", vec![function]);

        let context = AnalysisContext {
            contract: &contract,
            symbols: SymbolTable::new(),
            source_code: "contract MyToken is ERC20 { }".to_string(),
            file_path: "test.sol".to_string(),
        };

        let node = ContractNode::from_context("Token".to_string(), &context);
        assert_eq!(node.contract_type, ContractType::Token);
    }
}
