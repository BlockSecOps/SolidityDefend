use crate::cross_contract::{
    CrossContractContext, CrossContractFinding, CrossContractVulnerabilityType,
    CrossContractDetector, CrossContractUtils
};
use crate::types::{AnalysisContext, Severity};
use std::collections::HashSet;

/// Main analyzer for cross-contract vulnerabilities
pub struct CrossContractAnalyzer {
    detectors: Vec<Box<dyn CrossContractDetector>>,
}

impl CrossContractAnalyzer {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Add a detector to the analyzer
    pub fn add_detector(mut self, detector: Box<dyn CrossContractDetector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// Run comprehensive cross-contract analysis
    pub fn analyze(&self, context: &CrossContractContext) -> Vec<CrossContractFinding> {
        let mut findings = Vec::new();

        // Run all registered detectors
        for detector in &self.detectors {
            if detector.applies_to(context) {
                findings.extend(detector.detect_vulnerabilities(context));
            }
        }

        // Run built-in analysis
        findings.extend(self.detect_circular_dependencies(context));
        findings.extend(self.detect_trust_boundary_violations(context));
        findings.extend(self.detect_state_inconsistencies(context));
        findings.extend(self.detect_atomicity_violations(context));
        findings.extend(self.detect_cross_contract_reentrancy(context));

        // Sort findings by severity
        findings.sort_by(|a, b| {
            use Severity::*;
            let severity_order = |s: &Severity| match s {
                Critical => 0,
                High => 1,
                Medium => 2,
                Low => 3,
                Info => 4,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        findings
    }

    /// Detect circular dependencies between contracts
    fn detect_circular_dependencies(&self, context: &CrossContractContext) -> Vec<CrossContractFinding> {
        let mut findings = Vec::new();
        let cycles = context.interaction_graph.find_cycles();

        for cycle in cycles {
            if cycle.len() > 1 {
                findings.push(CrossContractFinding {
                    primary_contract: cycle[0].clone(),
                    affected_contracts: cycle.clone(),
                    vulnerability_type: CrossContractVulnerabilityType::CircularDependency,
                    interaction_path: cycle.clone(),
                    severity: Severity::High,
                    description: format!(
                        "Circular dependency detected between contracts: {}. \
                        This can lead to deployment issues, upgrade complications, \
                        and potential deadlock scenarios.",
                        cycle.join(" -> ")
                    ),
                    mitigation: "Refactor contract architecture to eliminate circular dependencies. \
                        Consider using interfaces, factory patterns, or dependency injection.".to_string(),
                });
            }
        }

        findings
    }

    /// Detect trust boundary violations
    fn detect_trust_boundary_violations(&self, context: &CrossContractContext) -> Vec<CrossContractFinding> {
        let mut findings = Vec::new();

        for (contract_name, contract_ctx) in &context.contracts {
            let interacting_contracts = context.get_interacting_contracts(contract_name);

            for target_contract in &interacting_contracts {
                if let Some(target_ctx) = context.contracts.get(target_contract) {
                    let trust_score = CrossContractUtils::calculate_trust_score(contract_ctx, target_ctx);

                    if trust_score < 0.3 && self.makes_privileged_calls(contract_ctx, target_contract) {
                        findings.push(CrossContractFinding {
                            primary_contract: contract_name.clone(),
                            affected_contracts: vec![target_contract.clone()],
                            vulnerability_type: CrossContractVulnerabilityType::TrustBoundaryViolation,
                            interaction_path: vec![contract_name.clone(), target_contract.clone()],
                            severity: Severity::High,
                            description: format!(
                                "Contract '{}' makes privileged calls to untrusted contract '{}'. \
                                This violates trust boundaries and could lead to privilege escalation \
                                or unauthorized access.",
                                contract_name, target_contract
                            ),
                            mitigation: "Implement proper access controls, input validation, and \
                                consider using a whitelist of trusted contracts.".to_string(),
                        });
                    }
                }
            }
        }

        findings
    }

    /// Detect state inconsistencies across contracts
    fn detect_state_inconsistencies(&self, context: &CrossContractContext) -> Vec<CrossContractFinding> {
        let mut findings = Vec::new();

        // Look for contracts that maintain synchronized state
        for (contract_name, contract_ctx) in &context.contracts {
            let shared_state_contracts = self.find_shared_state_contracts(context, contract_name);

            for shared_contract in shared_state_contracts {
                if !self.has_state_synchronization_mechanism(contract_ctx, &shared_contract) {
                    findings.push(CrossContractFinding {
                        primary_contract: contract_name.clone(),
                        affected_contracts: vec![shared_contract.clone()],
                        vulnerability_type: CrossContractVulnerabilityType::StateInconsistency,
                        interaction_path: vec![contract_name.clone(), shared_contract],
                        severity: Severity::Medium,
                        description: format!(
                            "Contract '{}' shares state with other contracts but lacks \
                            proper synchronization mechanisms. This can lead to state \
                            inconsistencies and race conditions.",
                            contract_name
                        ),
                        mitigation: "Implement state synchronization mechanisms such as events, \
                            callbacks, or atomic state updates across contracts.".to_string(),
                    });
                }
            }
        }

        findings
    }

    /// Detect atomicity violations in multi-contract operations
    fn detect_atomicity_violations(&self, context: &CrossContractContext) -> Vec<CrossContractFinding> {
        let mut findings = Vec::new();

        for (contract_name, _contract_ctx) in &context.contracts {
            let multi_contract_operations = self.find_multi_contract_operations(context, contract_name);

            for operation in multi_contract_operations {
                if !self.has_atomicity_guarantees(&operation) {
                    findings.push(CrossContractFinding {
                        primary_contract: contract_name.clone(),
                        affected_contracts: operation.contracts.clone(),
                        vulnerability_type: CrossContractVulnerabilityType::AtomicityViolation,
                        interaction_path: operation.contracts,
                        severity: Severity::High,
                        description: format!(
                            "Multi-contract operation in '{}' lacks atomicity guarantees. \
                            Partial failures could leave the system in an inconsistent state.",
                            contract_name
                        ),
                        mitigation: "Implement proper error handling, rollback mechanisms, \
                            or use atomic multi-contract transaction patterns.".to_string(),
                    });
                }
            }
        }

        findings
    }

    /// Detect cross-contract reentrancy vulnerabilities
    fn detect_cross_contract_reentrancy(&self, context: &CrossContractContext) -> Vec<CrossContractFinding> {
        let mut findings = Vec::new();

        for (contract_name, _contract_ctx) in &context.contracts {
            let reentrancy_paths = self.find_reentrancy_paths(context, contract_name);

            for path in reentrancy_paths {
                if path.len() > 2 { // Cross-contract reentrancy involves at least 3 contracts
                    findings.push(CrossContractFinding {
                        primary_contract: contract_name.clone(),
                        affected_contracts: path.clone(),
                        vulnerability_type: CrossContractVulnerabilityType::CrossContractReentrancy,
                        interaction_path: path.clone(),
                        severity: Severity::Critical,
                        description: format!(
                            "Cross-contract reentrancy vulnerability detected in path: {}. \
                            This allows attackers to manipulate contract state through \
                            complex interaction patterns.",
                            path.join(" -> ")
                        ),
                        mitigation: "Implement reentrancy guards across all contracts in the \
                            interaction path, use checks-effects-interactions pattern, \
                            and consider using pull-over-push patterns.".to_string(),
                    });
                }
            }
        }

        findings
    }

    // Helper methods

    fn makes_privileged_calls(&self, contract_ctx: &AnalysisContext, _target_contract: &str) -> bool {
        let privileged_patterns = [
            "onlyOwner", "onlyAdmin", "restricted", "authorized",
            "delegatecall", "selfdestruct", "upgrade"
        ];

        privileged_patterns.iter().any(|&pattern|
            contract_ctx.source_code.contains(pattern)
        )
    }

    fn find_shared_state_contracts(&self, context: &CrossContractContext, contract_name: &str) -> Vec<String> {
        let mut shared_contracts = Vec::new();

        if let Some(contract_ctx) = context.contracts.get(contract_name) {
            // Look for contracts that share storage variables or events
            for (other_name, other_ctx) in &context.contracts {
                if other_name != contract_name && self.shares_state(contract_ctx, other_ctx) {
                    shared_contracts.push(other_name.clone());
                }
            }
        }

        shared_contracts
    }

    fn shares_state(&self, ctx1: &AnalysisContext, ctx2: &AnalysisContext) -> bool {
        // Check for common state variable names (simplified)
        let state_vars1: HashSet<_> = ctx1.contract.state_variables.iter()
            .map(|var| &var.name)
            .collect();
        let state_vars2: HashSet<_> = ctx2.contract.state_variables.iter()
            .map(|var| &var.name)
            .collect();

        !state_vars1.intersection(&state_vars2).collect::<Vec<_>>().is_empty()
    }

    fn has_state_synchronization_mechanism(&self, contract_ctx: &AnalysisContext, _shared_contract: &str) -> bool {
        let sync_patterns = [
            "event", "emit", "callback", "sync", "notify", "update"
        ];

        sync_patterns.iter().any(|&pattern|
            contract_ctx.source_code.contains(pattern)
        )
    }

    fn find_multi_contract_operations(&self, context: &CrossContractContext, contract_name: &str) -> Vec<MultiContractOperation> {
        let mut operations = Vec::new();

        if let Some(contract_ctx) = context.contracts.get(contract_name) {
            // Find functions that call multiple external contracts
            for func in &contract_ctx.contract.functions {
                let called_contracts = self.extract_called_contracts(contract_ctx, func.name.as_str());
                if called_contracts.len() > 1 {
                    operations.push(MultiContractOperation {
                        contracts: called_contracts,
                        functions: vec![func.name.as_str().to_string()],
                        has_atomicity: false, // Will be determined later
                    });
                }
            }
        }

        operations
    }

    fn extract_called_contracts(&self, _contract_ctx: &AnalysisContext, _function_name: &str) -> Vec<String> {
        // This would require more sophisticated AST analysis
        // For now, return empty vector as placeholder
        Vec::new()
    }

    fn has_atomicity_guarantees(&self, _operation: &MultiContractOperation) -> bool {
        // Check for atomicity patterns like try-catch, rollback mechanisms
        false // Simplified for now
    }

    fn find_reentrancy_paths(&self, context: &CrossContractContext, start_contract: &str) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = Vec::new();

        self.dfs_reentrancy_search(
            context,
            start_contract,
            start_contract,
            &mut visited,
            &mut current_path,
            &mut paths,
            3 // Max depth for cross-contract reentrancy
        );

        paths
    }

    fn dfs_reentrancy_search(
        &self,
        context: &CrossContractContext,
        current: &str,
        target: &str,
        visited: &mut HashSet<String>,
        current_path: &mut Vec<String>,
        paths: &mut Vec<Vec<String>>,
        max_depth: usize
    ) {
        if current_path.len() > max_depth {
            return;
        }

        current_path.push(current.to_string());

        if current_path.len() > 1 && current == target {
            paths.push(current_path.clone());
            current_path.pop();
            return;
        }

        visited.insert(current.to_string());

        let neighbors = context.get_interacting_contracts(current);
        for neighbor in neighbors {
            if !visited.contains(&neighbor) || neighbor == target {
                self.dfs_reentrancy_search(
                    context,
                    &neighbor,
                    target,
                    visited,
                    current_path,
                    paths,
                    max_depth
                );
            }
        }

        visited.remove(current);
        current_path.pop();
    }
}

/// Represents a multi-contract operation
#[derive(Debug, Clone)]
struct MultiContractOperation {
    contracts: Vec<String>,
    functions: Vec<String>,
    has_atomicity: bool,
}

impl Default for CrossContractAnalyzer {
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
    fn test_analyzer_creation() {
        let analyzer = CrossContractAnalyzer::new();
        assert_eq!(analyzer.detectors.len(), 0);
    }

    #[test]
    fn test_privileged_calls_detection() {
        let analyzer = CrossContractAnalyzer::new();
        let arena = AstArena::new();

        let function = create_mock_ast_function(
            &arena,
            "admin",
            Visibility::External,
            StateMutability::NonPayable,
        );

        let contract = create_mock_ast_contract(&arena, "TestContract", vec![function]);

        let ctx = AnalysisContext {
            contract: &contract,
            symbols: SymbolTable::new(),
            source_code: "function admin() onlyOwner { target.call(); }".to_string(),
            file_path: "test.sol".to_string(),
        };

        assert!(analyzer.makes_privileged_calls(&ctx, "target"));
    }

    #[test]
    fn test_shared_state_detection() {
        let analyzer = CrossContractAnalyzer::new();
        let arena = AstArena::new();

        let function1 = create_mock_ast_function(
            &arena,
            "func1",
            Visibility::External,
            StateMutability::NonPayable,
        );

        let function2 = create_mock_ast_function(
            &arena,
            "func2",
            Visibility::External,
            StateMutability::NonPayable,
        );

        let contract1 = create_mock_ast_contract(&arena, "Contract1", vec![function1]);
        let contract2 = create_mock_ast_contract(&arena, "Contract2", vec![function2]);

        let ctx1 = AnalysisContext {
            contract: &contract1,
            symbols: SymbolTable::new(),
            source_code: "".to_string(),
            file_path: "test1.sol".to_string(),
        };

        let ctx2 = AnalysisContext {
            contract: &contract2,
            symbols: SymbolTable::new(),
            source_code: "".to_string(),
            file_path: "test2.sol".to_string(),
        };

        // This would need more sophisticated state variable comparison
        assert!(!analyzer.shares_state(&ctx1, &ctx2));
    }
}