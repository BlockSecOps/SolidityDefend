use anyhow::Result;

use detectors::{
    Detector, DetectorId, Finding, Severity, Confidence, AnalysisContext,
    reentrancy::{ClassicReentrancyDetector, ReadOnlyReentrancyDetector}
};
use ast::Contract;
use cfg::ControlFlowGraph;
use dataflow::{DataFlowAnalysis, TaintAnalysis};
use semantic::SymbolTable;

#[test]
fn test_classic_reentrancy_vulnerable() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableBank {
            mapping(address => uint256) public balances;

            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }

            // VULNERABILITY: Classic reentrancy - external call before state update
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                // External call before state update - VULNERABLE!
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");

                // State update after external call - TOO LATE!
                balances[msg.sender] -= amount;
            }

            // VULNERABILITY: Another classic reentrancy pattern
            function withdrawAll() public {
                uint256 balance = balances[msg.sender];
                require(balance > 0, "No balance");

                // External call before zeroing balance
                msg.sender.transfer(balance);
                balances[msg.sender] = 0; // Too late!
            }

            // VULNERABILITY: Reentrancy in emergency withdrawal
            function emergencyWithdraw() public {
                uint256 balance = balances[msg.sender];
                if (balance > 0) {
                    // External call before state change
                    payable(msg.sender).send(balance);
                    delete balances[msg.sender];
                }
            }

            function getBalance() public view returns (uint256) {
                return balances[msg.sender];
            }
        }
    "#;

    let detector = ClassicReentrancyDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect 3 reentrancy vulnerabilities
    assert!(findings.len() >= 3);

    // Verify withdraw function vulnerability
    let withdraw_finding = findings.iter()
        .find(|f| f.message.contains("withdraw") && !f.message.contains("withdrawAll"))
        .expect("Should detect withdraw reentrancy");
    assert_eq!(withdraw_finding.severity, Severity::Critical);
    assert!(withdraw_finding.confidence >= Confidence::High);
    assert!(withdraw_finding.message.contains("external call before state update"));

    // Verify withdrawAll function vulnerability
    let withdraw_all_finding = findings.iter()
        .find(|f| f.message.contains("withdrawAll"))
        .expect("Should detect withdrawAll reentrancy");
    assert_eq!(withdraw_all_finding.severity, Severity::Critical);

    // Verify emergencyWithdraw vulnerability
    let emergency_finding = findings.iter()
        .find(|f| f.message.contains("emergencyWithdraw"))
        .expect("Should detect emergencyWithdraw reentrancy");
    assert!(emergency_finding.severity >= Severity::High);
}

#[test]
fn test_classic_reentrancy_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

        contract SecureBank is ReentrancyGuard {
            mapping(address => uint256) public balances;

            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }

            // SECURE: Checks-Effects-Interactions pattern
            function withdraw(uint256 amount) public nonReentrant {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                // Effects: Update state first
                balances[msg.sender] -= amount;

                // Interactions: External call last
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
            }

            // SECURE: State updated before external call
            function withdrawAll() public nonReentrant {
                uint256 balance = balances[msg.sender];
                require(balance > 0, "No balance");

                // Update state first
                balances[msg.sender] = 0;

                // External call after state update
                msg.sender.transfer(balance);
            }

            // SECURE: Using pull pattern instead of push
            function requestWithdrawal(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                balances[msg.sender] -= amount;
                // User must call separate claimWithdrawal function
            }

            function getBalance() public view returns (uint256) {
                return balances[msg.sender];
            }
        }
    "#;

    let detector = ClassicReentrancyDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect any vulnerabilities in secure contract
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_cross_function_reentrancy() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract CrossFunctionReentrancy {
            mapping(address => uint256) public balances;
            mapping(address => uint256) public rewards;

            // VULNERABILITY: Cross-function reentrancy
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                // External call without state update
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");

                // Attacker can call claimReward() during external call
                balances[msg.sender] -= amount;
            }

            // VULNERABILITY: Can be called during reentrancy
            function claimReward() public {
                uint256 reward = rewards[msg.sender];
                require(reward > 0, "No reward");

                // Uses outdated balance from withdraw()
                if (balances[msg.sender] > 1000 ether) {
                    reward *= 2; // Double reward for large holders
                }

                rewards[msg.sender] = 0;
                payable(msg.sender).transfer(reward);
            }

            function addReward(address user, uint256 amount) external {
                rewards[user] += amount;
            }
        }
    "#;

    let detector = ClassicReentrancyDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect cross-function reentrancy vulnerability
    assert!(findings.len() >= 1);

    let cross_function_finding = findings.iter()
        .find(|f| f.message.contains("withdraw") || f.message.contains("cross-function"))
        .expect("Should detect cross-function reentrancy");
    assert!(cross_function_finding.severity >= Severity::High);
}

#[test]
fn test_read_only_reentrancy_vulnerable() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableOracle {
            mapping(address => uint256) public balances;
            uint256 public totalSupply;

            function deposit() public payable {
                balances[msg.sender] += msg.value;
                totalSupply += msg.value;
            }

            // VULNERABILITY: Read-only reentrancy - state inconsistent during external call
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                // External call before updating state
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");

                // State update after external call
                balances[msg.sender] -= amount;
                totalSupply -= amount;
            }

            // VULNERABILITY: View function can be called during reentrancy with stale state
            function getSharePrice() public view returns (uint256) {
                if (totalSupply == 0) return 1e18;
                return (address(this).balance * 1e18) / totalSupply;
            }

            // VULNERABILITY: Another view function with inconsistent state
            function getUserShare(address user) public view returns (uint256) {
                if (totalSupply == 0) return 0;
                return (balances[user] * 1e18) / totalSupply;
            }
        }

        // Contract that exploits read-only reentrancy
        contract ReentrancyExploit {
            VulnerableOracle public oracle;

            constructor(address _oracle) {
                oracle = VulnerableOracle(_oracle);
            }

            // Exploit function that demonstrates the vulnerability
            function exploit() external payable {
                oracle.deposit{value: msg.value}();
                oracle.withdraw(msg.value);
            }

            // This will be called during withdraw's external call
            receive() external payable {
                // Read inconsistent state - balance updated but totalSupply not yet
                uint256 manipulatedPrice = oracle.getSharePrice();
                // Attacker can use this manipulated price in other contracts
            }
        }
    "#;

    let detector = ReadOnlyReentrancyDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect read-only reentrancy vulnerabilities
    assert!(findings.len() >= 2);

    // Verify detection of vulnerable view functions
    let share_price_finding = findings.iter()
        .find(|f| f.message.contains("getSharePrice"))
        .expect("Should detect getSharePrice read-only reentrancy");
    assert!(share_price_finding.severity >= Severity::Medium);
    assert!(share_price_finding.message.contains("read-only reentrancy"));

    let user_share_finding = findings.iter()
        .find(|f| f.message.contains("getUserShare"))
        .expect("Should detect getUserShare read-only reentrancy");
    assert!(user_share_finding.severity >= Severity::Medium);
}

#[test]
fn test_read_only_reentrancy_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

        contract SecureOracle is ReentrancyGuard {
            mapping(address => uint256) public balances;
            uint256 public totalSupply;

            function deposit() public payable {
                balances[msg.sender] += msg.value;
                totalSupply += msg.value;
            }

            // SECURE: Uses reentrancy guard to prevent read-only reentrancy
            function withdraw(uint256 amount) public nonReentrant {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                // Update state first
                balances[msg.sender] -= amount;
                totalSupply -= amount;

                // External call after state update
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
            }

            // SECURE: View functions are safe when state is always consistent
            function getSharePrice() public view returns (uint256) {
                if (totalSupply == 0) return 1e18;
                return (address(this).balance * 1e18) / totalSupply;
            }

            function getUserShare(address user) public view returns (uint256) {
                if (totalSupply == 0) return 0;
                return (balances[user] * 1e18) / totalSupply;
            }

            // SECURE: Alternative pattern using internal state tracking
            function safeGetSharePrice() external view returns (uint256) {
                require(!_isInExternalCall(), "External call in progress");
                return getSharePrice();
            }

            bool private _externalCallFlag;

            function _isInExternalCall() internal view returns (bool) {
                return _externalCallFlag;
            }
        }
    "#;

    let detector = ReadOnlyReentrancyDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect vulnerabilities in secure contract
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_complex_reentrancy_patterns() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract ComplexReentrancy {
            mapping(address => uint256) public balances;
            mapping(address => uint256) public stakes;
            mapping(address => uint256) public lastAction;

            // VULNERABILITY: Multiple state variables affected
            function complexWithdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                require(block.timestamp > lastAction[msg.sender] + 1 days, "Too soon");

                // External call before updating multiple state variables
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");

                // Multiple state updates after external call - all vulnerable
                balances[msg.sender] -= amount;
                stakes[msg.sender] = stakes[msg.sender] * 90 / 100; // Reduce stake
                lastAction[msg.sender] = block.timestamp;
            }

            // VULNERABILITY: Reentrancy through callback pattern
            function withdrawWithCallback(uint256 amount, address callback) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                // Call external contract with callback
                IWithdrawCallback(callback).onWithdraw(msg.sender, amount);

                // State update after callback - vulnerable
                balances[msg.sender] -= amount;
            }

            // VULNERABILITY: Reentrancy through delegate call
            function delegateWithdraw(address delegate, bytes calldata data) public {
                require(balances[msg.sender] > 0, "No balance");

                // Delegate call before state update
                (bool success, ) = delegate.delegatecall(data);
                require(success, "Delegate call failed");

                // State update after delegate call
                balances[msg.sender] = 0;
            }

            // VULNERABILITY: Loop with external calls
            function batchWithdraw(address[] calldata recipients, uint256[] calldata amounts) public {
                require(recipients.length == amounts.length, "Length mismatch");

                for (uint i = 0; i < recipients.length; i++) {
                    require(balances[msg.sender] >= amounts[i], "Insufficient balance");

                    // External call in loop before state update
                    recipients[i].call{value: amounts[i]}("");

                    // State update after external call in loop
                    balances[msg.sender] -= amounts[i];
                }
            }
        }

        interface IWithdrawCallback {
            function onWithdraw(address user, uint256 amount) external;
        }
    "#;

    let detector = ClassicReentrancyDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect multiple complex reentrancy patterns
    assert!(findings.len() >= 4);

    // Verify detection of different reentrancy patterns
    let complex_finding = findings.iter()
        .find(|f| f.message.contains("complexWithdraw"))
        .expect("Should detect complex reentrancy");
    assert_eq!(complex_finding.severity, Severity::Critical);

    let callback_finding = findings.iter()
        .find(|f| f.message.contains("withdrawWithCallback"))
        .expect("Should detect callback reentrancy");
    assert!(callback_finding.severity >= Severity::High);

    let delegate_finding = findings.iter()
        .find(|f| f.message.contains("delegateWithdraw"))
        .expect("Should detect delegate call reentrancy");
    assert!(delegate_finding.severity >= Severity::High);

    let batch_finding = findings.iter()
        .find(|f| f.message.contains("batchWithdraw"))
        .expect("Should detect loop reentrancy");
    assert!(batch_finding.severity >= Severity::High);
}

#[test]
fn test_reentrancy_with_modifiers() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract ModifierReentrancy {
            mapping(address => uint256) public balances;
            bool private locked;

            modifier noReentrant() {
                require(!locked, "Reentrant call");
                locked = true;
                _;
                locked = false;
            }

            modifier checkBalance(uint256 amount) {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                _;
                // VULNERABILITY: State check in modifier after function execution
                require(balances[msg.sender] >= 0, "Invalid final balance");
            }

            // VULNERABILITY: External call in modifier
            modifier notifyExternal() {
                _;
                // External call after function execution - vulnerable to reentrancy
                INotifier(address(0x123)).notify(msg.sender);
            }

            // SECURE: Protected by custom reentrancy guard
            function secureWithdraw(uint256 amount) public noReentrant {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                balances[msg.sender] -= amount;
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
            }

            // VULNERABILITY: Modifier with external call
            function vulnerableWithdraw(uint256 amount) public notifyExternal {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");

                balances[msg.sender] -= amount;
            }
        }

        interface INotifier {
            function notify(address user) external;
        }
    "#;

    let detector = ClassicReentrancyDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect reentrancy in vulnerableWithdraw but not secureWithdraw
    assert!(findings.len() >= 1);

    let vulnerable_finding = findings.iter()
        .find(|f| f.message.contains("vulnerableWithdraw"))
        .expect("Should detect vulnerable function with modifier");
    assert!(vulnerable_finding.severity >= Severity::High);

    // Should not detect reentrancy in secureWithdraw
    let secure_findings: Vec<_> = findings.iter()
        .filter(|f| f.message.contains("secureWithdraw"))
        .collect();
    assert!(secure_findings.is_empty());
}

// Helper functions for test setup
fn parse_contract(solidity_code: &str) -> Result<Contract> {
    // This would use the actual parser implementation
    // For now, return a placeholder that will cause tests to fail
    unimplemented!("Contract parsing not yet implemented - tests should fail initially")
}

fn create_analysis_context(contract: &Contract) -> AnalysisContext {
    // This would create a real analysis context with CFG, data flow, etc.
    // For now, return a placeholder that will cause tests to fail
    unimplemented!("Analysis context creation not yet implemented - tests should fail initially")
}

// Additional test helper functions
fn assert_finding_mentions_function(finding: &Finding, function_name: &str) {
    assert!(finding.message.contains(function_name));
}

fn assert_finding_has_reentrancy_cwe(finding: &Finding) {
    // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
    assert!(finding.cwe_ids.contains(&362));
}

#[test]
fn test_reentrancy_in_constructor() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract ConstructorReentrancy {
            address public owner;
            mapping(address => uint256) public balances;

            // VULNERABILITY: External call in constructor
            constructor(address initialOwner) {
                owner = initialOwner;

                // External call during construction - vulnerable
                IInitializable(initialOwner).initialize();

                // State setting after external call
                balances[initialOwner] = 1000 ether;
            }

            function withdraw() public {
                uint256 balance = balances[msg.sender];
                require(balance > 0, "No balance");

                balances[msg.sender] = 0;
                payable(msg.sender).transfer(balance);
            }
        }

        interface IInitializable {
            function initialize() external;
        }
    "#;

    let detector = ClassicReentrancyDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect reentrancy vulnerability in constructor
    assert!(findings.len() >= 1);

    let constructor_finding = findings.iter()
        .find(|f| f.message.contains("constructor") || f.message.contains("initialize"))
        .expect("Should detect constructor reentrancy");
    assert!(constructor_finding.severity >= Severity::Medium);
}