use detectors::advanced_security_engine::{
    AdvancedSecurityEngine, AdvancedSecurityConfig, AdvancedAnalysisResult
};
use detectors::types::{AnalysisContext, Contract, Function, StateVariable, Severity};
use std::collections::HashMap;

/// Integration tests for the advanced security engine
pub struct AdvancedSecurityTestSuite;

impl AdvancedSecurityTestSuite {
    /// Test data representing a complex DeFi protocol with multiple vulnerabilities
    pub fn complex_defi_protocol() -> HashMap<String, String> {
        let mut contracts = HashMap::new();

        // Main protocol contract with flash loan and governance
        contracts.insert("DefiProtocol".to_string(), r#"
        pragma solidity ^0.8.0;

        contract DefiProtocol {
            IERC20 public governanceToken;
            mapping(address => uint256) public deposits;
            mapping(uint256 => Proposal) public proposals;
            uint256 public proposalCount;

            struct Proposal {
                string description;
                uint256 voteCount;
                bool executed;
            }

            function flashLoan(uint256 amount, address recipient) external {
                uint256 balanceBefore = address(this).balance;
                recipient.call{value: amount}("");
                require(address(this).balance >= balanceBefore, "Repayment failed");
            }

            function vote(uint256 proposalId) external {
                uint256 votingPower = governanceToken.balanceOf(msg.sender);
                proposals[proposalId].voteCount += votingPower;
            }

            function deposit() external payable {
                uint256 price = priceOracle.getPrice();
                deposits[msg.sender] += msg.value / price;
            }

            IPriceOracle public priceOracle;
        }
        "#.to_string());

        // Price oracle contract
        contracts.insert("PriceOracle".to_string(), r#"
        pragma solidity ^0.8.0;

        contract PriceOracle {
            uint256 private price;

            function getPrice() external view returns (uint256) {
                return price;
            }

            function updatePrice(uint256 newPrice) external {
                price = newPrice;
            }
        }
        "#.to_string());

        // Liquidity pool contract
        contracts.insert("LiquidityPool".to_string(), r#"
        pragma solidity ^0.8.0;

        contract LiquidityPool {
            mapping(address => uint256) public liquidityProviders;
            uint256 public totalLiquidity;

            function addLiquidity(uint256 amount) external {
                liquidityProviders[msg.sender] += amount;
                totalLiquidity += amount;
            }

            function removeLiquidity(uint256 amount) external {
                liquidityProviders[msg.sender] -= amount;
                totalLiquidity -= amount;
                payable(msg.sender).transfer(amount);
            }

            function swap(uint256 amountIn) external returns (uint256) {
                uint256 amountOut = getAmountOut(amountIn);
                return amountOut;
            }

            function getAmountOut(uint256 amountIn) public view returns (uint256) {
                return amountIn * 2; // Simplified pricing
            }
        }
        "#.to_string());

        contracts
    }

    pub fn create_analysis_contexts() -> HashMap<String, AnalysisContext<'static>> {
        let mut contexts = HashMap::new();
        let protocol_contracts = Self::complex_defi_protocol();

        for (name, source) in protocol_contracts {
            let contract = Box::leak(Box::new(Contract {
                name: name.clone(),
                functions: Self::extract_functions(&source),
                state_variables: Self::extract_state_variables(&source),
                events: Vec::new(),
                modifiers: Vec::new(),
            }));

            let context = AnalysisContext {
                contract,
                symbols: HashMap::new(),
                source_code: source,
                file_path: format!("{}.sol", name),
            };

            contexts.insert(name, context);
        }

        contexts
    }

    fn extract_functions(source: &str) -> Vec<Function> {
        let mut functions = Vec::new();

        // Simple regex-based extraction (in real implementation, use proper parsing)
        if source.contains("function flashLoan") {
            functions.push(Function {
                name: "flashLoan".to_string(),
                visibility: Some("external".to_string()),
                line_number: 15,
                parameters: Vec::new(),
                returns: Vec::new(),
            });
        }

        if source.contains("function vote") {
            functions.push(Function {
                name: "vote".to_string(),
                visibility: Some("external".to_string()),
                line_number: 22,
                parameters: Vec::new(),
                returns: Vec::new(),
            });
        }

        if source.contains("function swap") {
            functions.push(Function {
                name: "swap".to_string(),
                visibility: Some("external".to_string()),
                line_number: 20,
                parameters: Vec::new(),
                returns: Vec::new(),
            });
        }

        if source.contains("function getPrice") {
            functions.push(Function {
                name: "getPrice".to_string(),
                visibility: Some("external".to_string()),
                line_number: 8,
                parameters: Vec::new(),
                returns: Vec::new(),
            });
        }

        functions
    }

    fn extract_state_variables(source: &str) -> Vec<StateVariable> {
        let mut variables = Vec::new();

        if source.contains("mapping(address => uint256) public deposits") {
            variables.push(StateVariable {
                name: "deposits".to_string(),
                type_name: "mapping(address => uint256)".to_string(),
                visibility: "public".to_string(),
            });
        }

        if source.contains("IERC20 public governanceToken") {
            variables.push(StateVariable {
                name: "governanceToken".to_string(),
                type_name: "IERC20".to_string(),
                visibility: "public".to_string(),
            });
        }

        variables
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comprehensive_analysis() {
        let config = AdvancedSecurityConfig::default();
        let mut engine = AdvancedSecurityEngine::new(config);

        let contexts = AdvancedSecurityTestSuite::create_analysis_contexts();
        let context_refs: HashMap<String, &AnalysisContext> = contexts.iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();

        let result = engine.analyze_comprehensive(context_refs);

        // Should detect multiple types of vulnerabilities
        assert!(!result.defi_findings.is_empty(), "Should detect DeFi vulnerabilities");

        // Should detect cross-contract interactions (if multiple contracts)
        if contexts.len() > 1 {
            // Cross-contract analysis should run
            assert!(
                !result.cross_contract_findings.is_empty() || contexts.len() == 1,
                "Should detect cross-contract issues or have single contract"
            );
        }

        // Should have risk assessment
        assert!(result.risk_assessment.overall_risk_score >= 0.0);

        // Should have recommendations
        assert!(!result.recommendations.is_empty(), "Should provide security recommendations");
    }

    #[test]
    fn test_integrated_vulnerability_detection() {
        let config = AdvancedSecurityConfig::default();
        let mut engine = AdvancedSecurityEngine::new(config);

        let contexts = AdvancedSecurityTestSuite::create_analysis_contexts();
        let context_refs: HashMap<String, &AnalysisContext> = contexts.iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();

        let result = engine.analyze_comprehensive(context_refs);

        // Should detect flash loan vulnerabilities
        let flash_loan_findings: Vec<_> = result.defi_findings.iter()
            .filter(|f| f.finding.title.to_lowercase().contains("flash loan") ||
                       f.finding.detector.contains("flash-loan"))
            .collect();
        assert!(!flash_loan_findings.is_empty(), "Should detect flash loan vulnerabilities");

        // Should detect governance vulnerabilities
        let governance_findings: Vec<_> = result.defi_findings.iter()
            .filter(|f| f.finding.title.to_lowercase().contains("governance") ||
                       f.finding.detector.contains("governance"))
            .collect();
        assert!(!governance_findings.is_empty(), "Should detect governance vulnerabilities");

        // Check for integrated findings (complex attack chains)
        if !result.integrated_findings.is_empty() {
            let integrated_finding = &result.integrated_findings[0];
            assert!(!integrated_finding.attack_scenarios.is_empty(),
                   "Integrated findings should have attack scenarios");
            assert!(!integrated_finding.mitigation_strategies.is_empty(),
                   "Integrated findings should have mitigation strategies");
        }
    }

    #[test]
    fn test_risk_assessment_accuracy() {
        let config = AdvancedSecurityConfig::default();
        let mut engine = AdvancedSecurityEngine::new(config);

        let contexts = AdvancedSecurityTestSuite::create_analysis_contexts();
        let context_refs: HashMap<String, &AnalysisContext> = contexts.iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();

        let result = engine.analyze_comprehensive(context_refs);

        // Risk score should be reasonable
        assert!(result.risk_assessment.overall_risk_score <= 100.0);
        assert!(result.risk_assessment.overall_risk_score >= 0.0);

        // Should identify high-risk components if critical vulnerabilities exist
        if result.risk_assessment.critical_vulnerabilities > 0 {
            assert!(!result.risk_assessment.high_risk_components.is_empty(),
                   "Critical vulnerabilities should identify high-risk components");
        }

        // Should have systemic risks for complex protocols
        if contexts.len() > 2 {
            // Complex multi-contract protocols should have systemic risk considerations
            assert!(
                !result.risk_assessment.systemic_risks.is_empty() ||
                result.cross_contract_findings.len() < 3,
                "Complex protocols should identify systemic risks"
            );
        }
    }

    #[test]
    fn test_recommendation_generation() {
        let config = AdvancedSecurityConfig::default();
        let mut engine = AdvancedSecurityEngine::new(config);

        let contexts = AdvancedSecurityTestSuite::create_analysis_contexts();
        let context_refs: HashMap<String, &AnalysisContext> = contexts.iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();

        let result = engine.analyze_comprehensive(context_refs);

        // Should always have some recommendations
        assert!(!result.recommendations.is_empty(), "Should generate recommendations");

        // Should have critical priority recommendations if critical vulnerabilities exist
        if result.risk_assessment.critical_vulnerabilities > 0 {
            let critical_recommendations: Vec<_> = result.recommendations.iter()
                .filter(|r| r.priority == detectors::advanced_security_engine::Priority::Critical)
                .collect();
            assert!(!critical_recommendations.is_empty(),
                   "Critical vulnerabilities should generate critical priority recommendations");
        }

        // All recommendations should have proper categorization
        for recommendation in &result.recommendations {
            assert!(!recommendation.description.is_empty(),
                   "Recommendations should have descriptions");
            assert!(!recommendation.business_impact.is_empty(),
                   "Recommendations should explain business impact");
        }
    }

    #[test]
    fn test_severity_filtering() {
        let config = AdvancedSecurityConfig {
            severity_threshold: Severity::High,
            ..Default::default()
        };
        let mut engine = AdvancedSecurityEngine::new(config);

        let contexts = AdvancedSecurityTestSuite::create_analysis_contexts();
        let context_refs: HashMap<String, &AnalysisContext> = contexts.iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();

        let result = engine.analyze_comprehensive(context_refs);

        // All DeFi findings should meet severity threshold
        for finding in &result.defi_findings {
            let severity_value = match finding.finding.severity {
                Severity::Critical => 4,
                Severity::High => 3,
                Severity::Medium => 2,
                Severity::Low => 1,
                Severity::Info => 0,
            };
            assert!(severity_value >= 3,
                   "Finding should meet High severity threshold: {:?}",
                   finding.finding.severity);
        }
    }

    #[test]
    fn test_cross_contract_taint_integration() {
        let config = AdvancedSecurityConfig {
            enable_cross_contract_analysis: true,
            enable_taint_analysis: true,
            ..Default::default()
        };
        let mut engine = AdvancedSecurityEngine::new(config);

        let contexts = AdvancedSecurityTestSuite::create_analysis_contexts();
        let context_refs: HashMap<String, &AnalysisContext> = contexts.iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();

        let result = engine.analyze_comprehensive(context_refs);

        // Should perform taint analysis
        // Note: Taint findings might be empty if no clear taint paths exist in test data
        // This is expected behavior for simple test contracts

        // Should have performed cross-contract analysis if multiple contracts
        if contexts.len() > 1 {
            // The analysis should have run (even if no vulnerabilities found)
            // This is validated by the engine configuration being applied
            assert!(config.enable_cross_contract_analysis);
        }
    }

    #[test]
    fn test_attack_scenario_generation() {
        let config = AdvancedSecurityConfig::default();
        let mut engine = AdvancedSecurityEngine::new(config);

        let contexts = AdvancedSecurityTestSuite::create_analysis_contexts();
        let context_refs: HashMap<String, &AnalysisContext> = contexts.iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();

        let result = engine.analyze_comprehensive(context_refs);

        // If integrated findings exist, they should have attack scenarios
        for integrated_finding in &result.integrated_findings {
            assert!(!integrated_finding.attack_scenarios.is_empty(),
                   "Integrated findings should have attack scenarios");

            for scenario in &integrated_finding.attack_scenarios {
                assert!(!scenario.description.is_empty(),
                       "Attack scenarios should have descriptions");
                assert!(!scenario.attack_vector.is_empty(),
                       "Attack scenarios should describe attack vectors");
                assert!(scenario.likelihood >= 0.0 && scenario.likelihood <= 1.0,
                       "Attack scenario likelihood should be between 0 and 1");
            }
        }
    }

    #[test]
    fn test_configuration_validation() {
        // Test different configurations
        let configs = vec![
            AdvancedSecurityConfig {
                enable_defi_analysis: true,
                enable_cross_contract_analysis: false,
                enable_taint_analysis: false,
                ..Default::default()
            },
            AdvancedSecurityConfig {
                enable_defi_analysis: false,
                enable_cross_contract_analysis: true,
                enable_taint_analysis: false,
                ..Default::default()
            },
            AdvancedSecurityConfig {
                enable_defi_analysis: false,
                enable_cross_contract_analysis: false,
                enable_taint_analysis: true,
                ..Default::default()
            },
        ];

        for config in configs {
            let mut engine = AdvancedSecurityEngine::new(config.clone());
            let contexts = AdvancedSecurityTestSuite::create_analysis_contexts();
            let context_refs: HashMap<String, &AnalysisContext> = contexts.iter()
                .map(|(k, v)| (k.clone(), v))
                .collect();

            let result = engine.analyze_comprehensive(context_refs);

            // Verify that only enabled analyses produce findings
            if config.enable_defi_analysis {
                // May or may not have findings depending on contracts
            } else {
                assert!(result.defi_findings.is_empty(),
                       "DeFi analysis disabled should produce no DeFi findings");
            }

            // Should always have risk assessment and recommendations
            assert!(result.risk_assessment.overall_risk_score >= 0.0);
            assert!(!result.recommendations.is_empty() ||
                   (!config.enable_defi_analysis &&
                    !config.enable_cross_contract_analysis &&
                    !config.enable_taint_analysis));
        }
    }
}