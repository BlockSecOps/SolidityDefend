//! Cross-contract analysis for complex protocol interactions
//!
//! This module provides analysis capabilities for multi-contract protocols,
//! detecting vulnerabilities that span across contract boundaries.

pub mod analyzer;
pub mod interaction_graph;
// TODO: Implement missing modules
// pub mod protocol_detector;
// pub mod dependency_analyzer;

pub use analyzer::CrossContractAnalyzer;
pub use interaction_graph::{InteractionGraph, ContractNode, InteractionEdge};
// pub use protocol_detector::ProtocolDetector;
// pub use dependency_analyzer::DependencyAnalyzer;

use crate::types::{AnalysisContext, Severity};
use std::collections::HashMap;

/// Represents a cross-contract vulnerability finding
#[derive(Debug, Clone)]
pub struct CrossContractFinding {
    pub primary_contract: String,
    pub affected_contracts: Vec<String>,
    pub vulnerability_type: CrossContractVulnerabilityType,
    pub interaction_path: Vec<String>,
    pub severity: Severity,
    pub description: String,
    pub mitigation: String,
}

/// Types of cross-contract vulnerabilities
#[derive(Debug, Clone, PartialEq)]
pub enum CrossContractVulnerabilityType {
    CircularDependency,
    TrustBoundaryViolation,
    StateInconsistency,
    AtomicityViolation,
    CrossContractReentrancy,
    DelegateCallRisk,
    ProxyPatternVulnerability,
    UpgradeabilityRisk,
    CrossChainInteractionRisk,
    ComposabilityRisk,
}

/// Protocol interaction patterns
#[derive(Debug, Clone)]
pub struct ProtocolInteraction {
    pub pattern_type: InteractionPattern,
    pub contracts: Vec<String>,
    pub functions: Vec<String>,
    pub data_flow: Vec<DataFlowEdge>,
    pub risk_level: Severity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InteractionPattern {
    LendingProtocol,
    DEXAggregator,
    YieldFarming,
    Insurance,
    Derivatives,
    CrossChainBridge,
    GovernanceProtocol,
    OracleNetwork,
    LiquidityMining,
    FlashLoanProvider,
}

/// Represents data flow between contracts
#[derive(Debug, Clone)]
pub struct DataFlowEdge {
    pub from_contract: String,
    pub to_contract: String,
    pub from_function: String,
    pub to_function: String,
    pub data_type: String,
    pub is_trusted: bool,
}

/// Cross-contract analysis configuration
#[derive(Debug, Clone)]
pub struct CrossContractConfig {
    pub max_depth: usize,
    pub analyze_external_calls: bool,
    pub analyze_delegate_calls: bool,
    pub analyze_proxy_patterns: bool,
    pub track_state_changes: bool,
    pub detect_reentrancy_paths: bool,
}

impl Default for CrossContractConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            analyze_external_calls: true,
            analyze_delegate_calls: true,
            analyze_proxy_patterns: true,
            track_state_changes: true,
            detect_reentrancy_paths: true,
        }
    }
}

/// Context for cross-contract analysis
pub struct CrossContractContext<'a> {
    pub contracts: HashMap<String, &'a AnalysisContext<'a>>,
    pub interaction_graph: InteractionGraph,
    pub protocol_patterns: Vec<ProtocolInteraction>,
    pub config: CrossContractConfig,
}

impl<'a> CrossContractContext<'a> {
    pub fn new(contracts: HashMap<String, &'a AnalysisContext<'a>>) -> Self {
        Self {
            interaction_graph: InteractionGraph::new(),
            protocol_patterns: Vec::new(),
            config: CrossContractConfig::default(),
            contracts,
        }
    }

    pub fn with_config(mut self, config: CrossContractConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a contract to the analysis context
    pub fn add_contract(&mut self, name: String, context: &'a AnalysisContext<'a>) {
        self.contracts.insert(name, context);
    }

    /// Build the interaction graph from all contracts
    pub fn build_interaction_graph(&mut self) {
        self.interaction_graph = InteractionGraph::build_from_contracts(&self.contracts);
    }

    /// Detect protocol patterns across contracts
    pub fn detect_protocol_patterns(&mut self) {
        // TODO: Implement ProtocolDetector
        // let detector = ProtocolDetector::new();
        // self.protocol_patterns = detector.detect_patterns(&self.contracts, &self.interaction_graph);
        self.protocol_patterns = Vec::new();
    }

    /// Get contracts that interact with a specific contract
    pub fn get_interacting_contracts(&self, contract_name: &str) -> Vec<String> {
        self.interaction_graph.get_neighbors(contract_name)
    }

    /// Check if two contracts have a direct interaction
    pub fn has_direct_interaction(&self, from: &str, to: &str) -> bool {
        self.interaction_graph.has_edge(from, to)
    }

    /// Find the shortest interaction path between two contracts
    pub fn find_interaction_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        self.interaction_graph.shortest_path(from, to)
    }

    /// Get all contracts in the analysis
    pub fn get_all_contracts(&self) -> Vec<String> {
        self.contracts.keys().cloned().collect()
    }
}

/// Trait for cross-contract vulnerability detectors
pub trait CrossContractDetector {
    /// Detect cross-contract vulnerabilities
    fn detect_vulnerabilities(&self, context: &CrossContractContext) -> Vec<CrossContractFinding>;

    /// Get detector name
    fn name(&self) -> &'static str;

    /// Get detector description
    fn description(&self) -> &'static str;

    /// Check if detector applies to the given context
    fn applies_to(&self, context: &CrossContractContext) -> bool;
}

/// Utility functions for cross-contract analysis
pub struct CrossContractUtils;

impl CrossContractUtils {
    /// Check if a function makes external calls
    pub fn makes_external_calls(ctx: &AnalysisContext, function_name: &str) -> bool {
        let external_call_patterns = [
            ".call(", ".delegatecall(", ".staticcall(",
            ".transfer(", ".send(",
            "address(", "Contract("
        ];

        external_call_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }

    /// Extract external contract addresses from function calls
    pub fn extract_external_addresses(ctx: &AnalysisContext) -> Vec<String> {
        let mut addresses = Vec::new();

        // This would require AST parsing to extract actual addresses
        // For now, we'll look for common patterns
        if ctx.source.contains("0x") {
            // Extract potential addresses (simplified)
            let lines: Vec<&str> = ctx.source.lines().collect();
            for line in lines {
                if line.contains("0x") && line.len() >= 42 {
                    // This is a simplified extraction - real implementation would use regex
                    if let Some(start) = line.find("0x") {
                        if let Some(end) = line[start..].find(' ') {
                            addresses.push(line[start..start + end].to_string());
                        }
                    }
                }
            }
        }

        addresses
    }

    /// Check if a contract uses proxy patterns
    pub fn uses_proxy_pattern(ctx: &AnalysisContext) -> bool {
        let proxy_patterns = [
            "delegatecall", "implementation", "proxy", "upgrade",
            "fallback", "_delegate", "_implementation"
        ];

        proxy_patterns.iter().any(|&pattern|
            ctx.source.to_lowercase().contains(pattern)
        )
    }

    /// Check if a contract is upgradeable
    pub fn is_upgradeable(ctx: &AnalysisContext) -> bool {
        let upgrade_patterns = [
            "upgrade", "implementation", "initialize", "reinitializer",
            "UUPSUpgradeable", "TransparentUpgradeableProxy"
        ];

        upgrade_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }

    /// Detect circular dependencies in contract calls
    pub fn detect_circular_dependencies(graph: &InteractionGraph) -> Vec<Vec<String>> {
        graph.find_cycles()
    }

    /// Calculate trust score between contracts
    pub fn calculate_trust_score(from_ctx: &AnalysisContext, to_ctx: &AnalysisContext) -> f64 {
        let mut score: f64 = 0.5; // Base trust score

        // Increase trust for well-known patterns
        if Self::is_standard_interface(to_ctx) {
            score += 0.2;
        }

        // Decrease trust for complex interactions
        if Self::has_complex_state_changes(to_ctx) {
            score -= 0.3;
        }

        // Adjust for upgrade risks
        if Self::is_upgradeable(to_ctx) {
            score -= 0.1;
        }

        score.max(0.0).min(1.0)
    }

    fn is_standard_interface(ctx: &AnalysisContext) -> bool {
        let standard_patterns = [
            "ERC20", "ERC721", "ERC1155", "IERC", "OpenZeppelin"
        ];
        standard_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }

    fn has_complex_state_changes(ctx: &AnalysisContext) -> bool {
        let complexity_indicators = [
            "assembly", "delegatecall", "selfdestruct", "create2"
        ];
        complexity_indicators.iter().any(|&indicator|
            ctx.source.contains(indicator)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_contract_context_creation() {
        let contracts = HashMap::new();
        let context = CrossContractContext::new(contracts);
        assert_eq!(context.contracts.len(), 0);
        assert_eq!(context.protocol_patterns.len(), 0);
    }

    #[test]
    fn test_cross_contract_config_default() {
        let config = CrossContractConfig::default();
        assert_eq!(config.max_depth, 10);
        assert!(config.analyze_external_calls);
        assert!(config.track_state_changes);
    }

    #[test]
    fn test_vulnerability_type_enum() {
        let vuln = CrossContractVulnerabilityType::CircularDependency;
        assert_eq!(vuln, CrossContractVulnerabilityType::CircularDependency);
    }

    #[test]
    fn test_interaction_pattern_enum() {
        let pattern = InteractionPattern::LendingProtocol;
        assert_eq!(pattern, InteractionPattern::LendingProtocol);
    }
}