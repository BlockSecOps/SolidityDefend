use detectors::defi::{
    FlashLoanDetector, MEVDetector, PriceManipulationDetector,
    LiquidityAttackDetector, GovernanceAttackDetector, DeFiDetector
};
use detectors::types::{AnalysisContext, Contract, Function, StateVariable, Severity};
use std::collections::HashMap;

/// Test data for DeFi vulnerability detection
pub struct DeFiTestData;

impl DeFiTestData {
    pub fn flash_loan_vulnerable_contract() -> String {
        r#"
        pragma solidity ^0.8.0;

        contract VulnerableFlashLoan {
            mapping(address => uint256) public balances;

            function flashLoan(uint256 amount, address recipient) external {
                // Vulnerable: No reentrancy protection
                uint256 balanceBefore = address(this).balance;
                recipient.call{value: amount}("");

                // No validation of repayment
                uint256 balanceAfter = address(this).balance;
                require(balanceAfter >= balanceBefore, "Repayment failed");
            }

            function onFlashLoan(bytes calldata data) external {
                // Vulnerable: No caller validation
                (bool success,) = msg.sender.call(data);
                require(success, "Callback failed");
            }
        }
        "#.to_string()
    }

    pub fn mev_vulnerable_contract() -> String {
        r#"
        pragma solidity ^0.8.0;

        contract MEVVulnerable {
            mapping(address => uint256) public balances;

            function swap(uint256 amountIn) external {
                // Vulnerable: No slippage protection
                uint256 amountOut = getAmountOut(amountIn);
                balances[msg.sender] -= amountIn;
                balances[msg.sender] += amountOut;
            }

            function approve(address spender, uint256 amount) external {
                // Vulnerable: Approval frontrunning
                allowances[msg.sender][spender] = amount;
            }

            function getAmountOut(uint256 amountIn) public view returns (uint256) {
                // Uses spot price - vulnerable to manipulation
                return amountIn * 2;
            }

            mapping(address => mapping(address => uint256)) public allowances;
        }
        "#.to_string()
    }

    pub fn price_manipulation_vulnerable_contract() -> String {
        r#"
        pragma solidity ^0.8.0;

        interface IPriceOracle {
            function getPrice() external view returns (uint256);
        }

        contract PriceManipulationVulnerable {
            IPriceOracle public oracle;
            mapping(address => uint256) public deposits;

            function deposit() external payable {
                uint256 price = oracle.getPrice(); // Single oracle dependency
                uint256 shares = msg.value / price;
                deposits[msg.sender] += shares;
            }

            function withdraw(uint256 shares) external {
                uint256 price = oracle.getPrice(); // Spot price usage
                uint256 amount = shares * price;

                // No price bounds validation
                deposits[msg.sender] -= shares;
                payable(msg.sender).transfer(amount);
            }
        }
        "#.to_string()
    }

    pub fn liquidity_attack_vulnerable_contract() -> String {
        r#"
        pragma solidity ^0.8.0;

        contract LiquidityVulnerable {
            mapping(address => uint256) public liquidityProviders;
            uint256 public totalLiquidity;

            function addLiquidity(uint256 amount) external {
                // Vulnerable: No frontrunning protection
                liquidityProviders[msg.sender] += amount;
                totalLiquidity += amount;
            }

            function removeLiquidity(uint256 amount) external {
                // Vulnerable: No withdrawal limits
                require(liquidityProviders[msg.sender] >= amount);
                liquidityProviders[msg.sender] -= amount;
                totalLiquidity -= amount;

                // No slippage protection
                payable(msg.sender).transfer(amount);
            }

            function distribute() external {
                // Vulnerable: JIT liquidity attacks
                uint256 snapshot = block.timestamp;
                for (address provider : liquidityProviders.keys()) {
                    // Reward based on current snapshot
                }
            }
        }
        "#.to_string()
    }

    pub fn governance_vulnerable_contract() -> String {
        r#"
        pragma solidity ^0.8.0;

        contract GovernanceVulnerable {
            mapping(address => uint256) public votes;
            mapping(uint256 => Proposal) public proposals;
            uint256 public proposalCount;

            struct Proposal {
                string description;
                uint256 voteCount;
                bool executed;
            }

            function propose(string memory description) external {
                // Vulnerable: No proposal threshold
                // Vulnerable: No cooldown period
                proposals[proposalCount] = Proposal(description, 0, false);
                proposalCount++;
            }

            function vote(uint256 proposalId) external {
                // Vulnerable: Flash loan voting
                uint256 votingPower = token.balanceOf(msg.sender);
                votes[proposalId] += votingPower;
            }

            function execute(uint256 proposalId) external {
                // Vulnerable: No execution protection
                require(votes[proposalId] > 100);
                proposals[proposalId].executed = true;
            }

            IERC20 public token;
        }
        "#.to_string()
    }

    pub fn create_context(contract_name: &str, source_code: String) -> AnalysisContext<'static> {
        let contract = Box::leak(Box::new(Contract {
            name: contract_name.to_string(),
            functions: vec![
                Function {
                    name: "flashLoan".to_string(),
                    visibility: Some("external".to_string()),
                    line_number: 6,
                    parameters: Vec::new(),
                    returns: Vec::new(),
                },
                Function {
                    name: "swap".to_string(),
                    visibility: Some("external".to_string()),
                    line_number: 10,
                    parameters: Vec::new(),
                    returns: Vec::new(),
                },
            ],
            state_variables: vec![
                StateVariable {
                    name: "balances".to_string(),
                    type_name: "mapping(address => uint256)".to_string(),
                    visibility: "public".to_string(),
                },
            ],
            events: Vec::new(),
            modifiers: Vec::new(),
        }));

        AnalysisContext {
            contract,
            symbols: HashMap::new(),
            source_code,
            file_path: format!("{}.sol", contract_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flash_loan_detector() {
        let detector = FlashLoanDetector;
        let context = DeFiTestData::create_context(
            "VulnerableFlashLoan",
            DeFiTestData::flash_loan_vulnerable_contract()
        );

        assert!(detector.applies_to_contract(&context));
        let findings = detector.detect_defi_vulnerabilities(&context);
        assert!(!findings.is_empty());

        // Should detect reentrancy vulnerability
        let reentrancy_finding = findings.iter()
            .find(|f| f.finding.title.contains("reentrancy"));
        assert!(reentrancy_finding.is_some());

        // Should detect callback validation issues
        let callback_finding = findings.iter()
            .find(|f| f.finding.title.contains("callback"));
        assert!(callback_finding.is_some());
    }

    #[test]
    fn test_mev_detector() {
        let detector = MEVDetector;
        let context = DeFiTestData::create_context(
            "MEVVulnerable",
            DeFiTestData::mev_vulnerable_contract()
        );

        assert!(detector.applies_to_contract(&context));
        let findings = detector.detect_defi_vulnerabilities(&context);
        assert!(!findings.is_empty());

        // Should detect sandwich attack vulnerability
        let sandwich_finding = findings.iter()
            .find(|f| f.finding.title.contains("sandwich"));
        assert!(sandwich_finding.is_some());

        // Should detect frontrunning vulnerability
        let frontrun_finding = findings.iter()
            .find(|f| f.finding.title.contains("frontrun"));
        assert!(frontrun_finding.is_some());
    }

    #[test]
    fn test_price_manipulation_detector() {
        let detector = PriceManipulationDetector;
        let context = DeFiTestData::create_context(
            "PriceManipulationVulnerable",
            DeFiTestData::price_manipulation_vulnerable_contract()
        );

        assert!(detector.applies_to_contract(&context));
        let findings = detector.detect_defi_vulnerabilities(&context);
        assert!(!findings.is_empty());

        // Should detect single oracle dependency
        let oracle_finding = findings.iter()
            .find(|f| f.finding.title.contains("oracle"));
        assert!(oracle_finding.is_some());

        // Should detect spot price usage
        let spot_price_finding = findings.iter()
            .find(|f| f.finding.title.contains("spot price"));
        assert!(spot_price_finding.is_some());
    }

    #[test]
    fn test_liquidity_attack_detector() {
        let detector = LiquidityAttackDetector;
        let context = DeFiTestData::create_context(
            "LiquidityVulnerable",
            DeFiTestData::liquidity_attack_vulnerable_contract()
        );

        assert!(detector.applies_to_contract(&context));
        let findings = detector.detect_defi_vulnerabilities(&context);
        assert!(!findings.is_empty());

        // Should detect JIT liquidity attacks
        let jit_finding = findings.iter()
            .find(|f| f.finding.title.contains("just-in-time") || f.finding.title.contains("JIT"));
        assert!(jit_finding.is_some());
    }

    #[test]
    fn test_governance_attack_detector() {
        let detector = GovernanceAttackDetector;
        let context = DeFiTestData::create_context(
            "GovernanceVulnerable",
            DeFiTestData::governance_vulnerable_contract()
        );

        assert!(detector.applies_to_contract(&context));
        let findings = detector.detect_defi_vulnerabilities(&context);
        assert!(!findings.is_empty());

        // Should detect flash loan voting vulnerability
        let flash_vote_finding = findings.iter()
            .find(|f| f.finding.title.contains("flash loan"));
        assert!(flash_vote_finding.is_some());

        // Should detect proposal spam vulnerability
        let spam_finding = findings.iter()
            .find(|f| f.finding.title.contains("spam"));
        assert!(spam_finding.is_some());
    }

    #[test]
    fn test_detector_severity_levels() {
        let detector = FlashLoanDetector;
        let context = DeFiTestData::create_context(
            "VulnerableFlashLoan",
            DeFiTestData::flash_loan_vulnerable_contract()
        );

        let findings = detector.detect_defi_vulnerabilities(&context);

        // Should have critical findings for reentrancy
        let critical_findings: Vec<_> = findings.iter()
            .filter(|f| f.finding.severity == Severity::Critical)
            .collect();
        assert!(!critical_findings.is_empty());

        // Should have high severity findings
        let high_findings: Vec<_> = findings.iter()
            .filter(|f| f.finding.severity == Severity::High)
            .collect();
        assert!(!high_findings.is_empty());
    }

    #[test]
    fn test_detector_confidence_levels() {
        let detector = MEVDetector;
        let context = DeFiTestData::create_context(
            "MEVVulnerable",
            DeFiTestData::mev_vulnerable_contract()
        );

        let findings = detector.detect_defi_vulnerabilities(&context);

        // All findings should have reasonable confidence levels
        for finding in &findings {
            assert!(finding.finding.confidence >= 0.5);
            assert!(finding.finding.confidence <= 1.0);
        }

        // High confidence findings should exist
        let high_confidence_findings: Vec<_> = findings.iter()
            .filter(|f| f.finding.confidence >= 0.8)
            .collect();
        assert!(!high_confidence_findings.is_empty());
    }

    #[test]
    fn test_detector_mitigation_suggestions() {
        let detector = PriceManipulationDetector;
        let context = DeFiTestData::create_context(
            "PriceManipulationVulnerable",
            DeFiTestData::price_manipulation_vulnerable_contract()
        );

        let findings = detector.detect_defi_vulnerabilities(&context);

        // All findings should have mitigation suggestions
        for finding in &findings {
            assert!(finding.suggested_fix.is_some());
            let fix = finding.suggested_fix.as_ref().unwrap();
            assert!(!fix.is_empty());
        }
    }

    #[test]
    fn test_false_positive_detection() {
        // Test with a secure contract
        let secure_contract = r#"
        pragma solidity ^0.8.0;

        contract SecureFlashLoan {
            bool private locked;

            modifier nonReentrant() {
                require(!locked, "ReentrancyGuard: reentrant call");
                locked = true;
                _;
                locked = false;
            }

            function flashLoan(uint256 amount, address recipient) external nonReentrant {
                require(amount > 0, "Invalid amount");
                require(recipient != address(0), "Invalid recipient");

                uint256 balanceBefore = address(this).balance;
                recipient.call{value: amount}("");

                uint256 balanceAfter = address(this).balance;
                require(balanceAfter >= balanceBefore + fee, "Insufficient repayment");
            }
        }
        "#;

        let detector = FlashLoanDetector;
        let context = DeFiTestData::create_context("SecureFlashLoan", secure_contract.to_string());

        let findings = detector.detect_defi_vulnerabilities(&context);

        // Should have fewer or no findings for secure contract
        let critical_findings: Vec<_> = findings.iter()
            .filter(|f| f.finding.severity == Severity::Critical)
            .collect();

        // Should not detect reentrancy in protected contract
        let reentrancy_findings: Vec<_> = findings.iter()
            .filter(|f| f.finding.title.contains("reentrancy"))
            .collect();
        assert!(reentrancy_findings.is_empty());
    }
}