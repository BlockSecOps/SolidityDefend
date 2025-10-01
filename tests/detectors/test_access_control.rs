use anyhow::Result;

use detectors::{
    Detector, DetectorId, Finding, Severity, Confidence, AnalysisContext,
    access_control::{MissingModifiersDetector, UnprotectedInitDetector, DefaultVisibilityDetector}
};
use ast::Contract;
use cfg::ControlFlowGraph;
use dataflow::{DataFlowAnalysis, TaintAnalysis};
use semantic::SymbolTable;

#[test]
fn test_missing_access_modifiers_vulnerable() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableContract {
            address public owner;
            uint256 private funds;

            constructor() {
                owner = msg.sender;
            }

            // VULNERABILITY: Missing onlyOwner modifier on critical function
            function withdrawFunds(uint256 amount) public {
                require(amount <= funds, "Insufficient funds");
                payable(msg.sender).transfer(amount);
                funds -= amount;
            }

            // VULNERABILITY: Administrative function without access control
            function setOwner(address newOwner) public {
                owner = newOwner;
            }

            // VULNERABILITY: Critical function exposed to anyone
            function emergencyShutdown() public {
                selfdestruct(payable(owner));
            }

            // Properly protected function (should not trigger)
            modifier onlyOwner() {
                require(msg.sender == owner, "Only owner");
                _;
            }

            function addFunds() public payable onlyOwner {
                funds += msg.value;
            }
        }
    "#;

    let detector = MissingModifiersDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect 3 vulnerable functions
    assert_eq!(findings.len(), 3);

    // Verify withdrawFunds vulnerability
    let withdraw_finding = findings.iter()
        .find(|f| f.message.contains("withdrawFunds"))
        .expect("Should detect withdrawFunds vulnerability");
    assert_eq!(withdraw_finding.severity, Severity::Critical);
    assert!(withdraw_finding.confidence >= Confidence::High);
    assert!(withdraw_finding.message.contains("missing access control"));

    // Verify setOwner vulnerability
    let set_owner_finding = findings.iter()
        .find(|f| f.message.contains("setOwner"))
        .expect("Should detect setOwner vulnerability");
    assert_eq!(set_owner_finding.severity, Severity::Critical);

    // Verify emergencyShutdown vulnerability
    let shutdown_finding = findings.iter()
        .find(|f| f.message.contains("emergencyShutdown"))
        .expect("Should detect emergencyShutdown vulnerability");
    assert_eq!(shutdown_finding.severity, Severity::Critical);
}

#[test]
fn test_missing_access_modifiers_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract SecureContract {
            address public owner;
            uint256 private funds;

            modifier onlyOwner() {
                require(msg.sender == owner, "Only owner");
                _;
            }

            modifier onlyAuthorized() {
                require(msg.sender == owner || authorized[msg.sender], "Not authorized");
                _;
            }

            mapping(address => bool) public authorized;

            constructor() {
                owner = msg.sender;
            }

            // Properly protected functions
            function withdrawFunds(uint256 amount) public onlyOwner {
                require(amount <= funds, "Insufficient funds");
                payable(msg.sender).transfer(amount);
                funds -= amount;
            }

            function setOwner(address newOwner) public onlyOwner {
                owner = newOwner;
            }

            function emergencyShutdown() public onlyOwner {
                selfdestruct(payable(owner));
            }

            function authorizeUser(address user) public onlyOwner {
                authorized[user] = true;
            }

            // Public functions that don't need protection
            function getBalance() public view returns (uint256) {
                return funds;
            }

            function publicInfo() public pure returns (string memory) {
                return "This is public information";
            }
        }
    "#;

    let detector = MissingModifiersDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect any vulnerabilities in properly protected contract
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_unprotected_initializer_vulnerable() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableProxy {
            address public implementation;
            address public owner;
            bool public initialized;

            // VULNERABILITY: Unprotected initializer - anyone can call
            function initialize(address _implementation, address _owner) public {
                require(!initialized, "Already initialized");
                implementation = _implementation;
                owner = _owner;
                initialized = true;
            }

            // VULNERABILITY: Re-initialization possible
            function reinitialize(address _newImplementation) public {
                implementation = _newImplementation;
            }

            // VULNERABILITY: Proxy implementation can be hijacked
            function setImplementation(address _implementation) public {
                implementation = _implementation;
            }

            fallback() external payable {
                address impl = implementation;
                assembly {
                    calldatacopy(0, 0, calldatasize())
                    let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                    returndatacopy(0, 0, returndatasize())
                    switch result
                    case 0 { revert(0, returndatasize()) }
                    default { return(0, returndatasize()) }
                }
            }
        }
    "#;

    let detector = UnprotectedInitDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect multiple initialization vulnerabilities
    assert!(findings.len() >= 2);

    // Verify unprotected initialize function
    let init_finding = findings.iter()
        .find(|f| f.message.contains("initialize"))
        .expect("Should detect unprotected initializer");
    assert_eq!(init_finding.severity, Severity::Critical);
    assert!(init_finding.message.contains("unprotected initializer"));

    // Verify reinitialize vulnerability
    let reinit_finding = findings.iter()
        .find(|f| f.message.contains("reinitialize") || f.message.contains("setImplementation"))
        .expect("Should detect reinitialization vulnerability");
    assert!(reinit_finding.severity >= Severity::High);
}

#[test]
fn test_unprotected_initializer_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

        contract SecureProxy is Initializable {
            address public implementation;
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "Only owner");
                _;
            }

            // Properly protected initializer
            function initialize(address _implementation, address _owner)
                public
                initializer
            {
                implementation = _implementation;
                owner = _owner;
            }

            // Properly protected admin functions
            function setImplementation(address _implementation) public onlyOwner {
                implementation = _implementation;
            }

            function transferOwnership(address newOwner) public onlyOwner {
                owner = newOwner;
            }

            fallback() external payable {
                address impl = implementation;
                assembly {
                    calldatacopy(0, 0, calldatasize())
                    let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                    returndatacopy(0, 0, returndatasize())
                    switch result
                    case 0 { revert(0, returndatasize()) }
                    default { return(0, returndatasize()) }
                }
            }
        }
    "#;

    let detector = UnprotectedInitDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect vulnerabilities in properly protected proxy
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_default_visibility_vulnerable() {
    let solidity_code = r#"
        pragma solidity ^0.4.24; // Old Solidity version

        contract VulnerableOldContract {
            address owner;
            uint256 balance;

            // VULNERABILITY: Default visibility is public in old Solidity
            function withdrawAll() {
                require(msg.sender == owner);
                msg.sender.transfer(balance);
            }

            // VULNERABILITY: State variable default visibility
            mapping(address => uint256) balances;

            // VULNERABILITY: Constructor with default visibility
            function VulnerableOldContract() {
                owner = msg.sender;
            }

            // VULNERABILITY: Default visibility function with sensitive operation
            function destroy() {
                selfdestruct(owner);
            }

            // Explicitly public (should not trigger)
            function publicFunction() public view returns (uint256) {
                return balance;
            }

            // Explicitly private (should not trigger)
            function privateFunction() private {
                balance += 1;
            }
        }
    "#;

    let detector = DefaultVisibilityDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect multiple default visibility issues
    assert!(findings.len() >= 3);

    // Verify function visibility issues
    let function_finding = findings.iter()
        .find(|f| f.message.contains("withdrawAll") || f.message.contains("destroy"))
        .expect("Should detect function visibility issues");
    assert!(function_finding.severity >= Severity::Medium);
    assert!(function_finding.message.contains("default visibility"));
}

#[test]
fn test_default_visibility_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract SecureModernContract {
            address private owner;
            uint256 private balance;

            mapping(address => uint256) private balances;

            modifier onlyOwner() {
                require(msg.sender == owner, "Only owner");
                _;
            }

            constructor() {
                owner = msg.sender;
            }

            // Explicitly declared visibility
            function withdrawAll() public onlyOwner {
                payable(msg.sender).transfer(balance);
            }

            function destroy() public onlyOwner {
                selfdestruct(payable(owner));
            }

            function getBalance() public view returns (uint256) {
                return balance;
            }

            function internalFunction() internal {
                balance += 1;
            }

            function privateFunction() private {
                balance -= 1;
            }
        }
    "#;

    let detector = DefaultVisibilityDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect issues in modern Solidity with explicit visibility
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_complex_access_control_patterns() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract ComplexAccessControl {
            address public owner;
            mapping(address => bool) public admins;
            mapping(address => uint256) public roles;

            modifier onlyOwner() {
                require(msg.sender == owner, "Only owner");
                _;
            }

            modifier onlyAdmin() {
                require(admins[msg.sender] || msg.sender == owner, "Only admin");
                _;
            }

            modifier hasRole(uint256 role) {
                require(roles[msg.sender] >= role, "Insufficient role");
                _;
            }

            constructor() {
                owner = msg.sender;
                admins[msg.sender] = true;
                roles[msg.sender] = 255; // Max role
            }

            // VULNERABILITY: Missing role check on sensitive function
            function sensitiveOperation(uint256 amount) public {
                // This should require hasRole(100) or similar
                // perform sensitive operation
            }

            // VULNERABILITY: Inconsistent access control
            function partiallyProtected(address user) public onlyAdmin {
                if (user == msg.sender) {
                    // This branch bypasses admin check effectively
                    roles[user] = 50;
                } else {
                    // This branch maintains protection
                    require(roles[user] < 10, "Role too high");
                    roles[user] = 10;
                }
            }

            // Properly protected functions
            function addAdmin(address admin) public onlyOwner {
                admins[admin] = true;
            }

            function setRole(address user, uint256 role) public onlyAdmin hasRole(100) {
                roles[user] = role;
            }

            function emergencyStop() public onlyOwner {
                selfdestruct(payable(owner));
            }
        }
    "#;

    let detector = MissingModifiersDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect complex access control issues
    assert!(findings.len() >= 1);

    let sensitive_finding = findings.iter()
        .find(|f| f.message.contains("sensitiveOperation"))
        .expect("Should detect unprotected sensitive operation");
    assert!(sensitive_finding.severity >= Severity::High);
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
fn assert_finding_location(finding: &Finding, expected_line: u32) {
    assert_eq!(finding.primary_location.line, expected_line);
}

fn assert_finding_contains_cwe(finding: &Finding, expected_cwe: u32) {
    assert!(finding.cwe_ids.contains(&expected_cwe));
}

#[test]
fn test_access_control_inheritance_issues() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract BaseContract {
            address internal owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "Only owner");
                _;
            }

            function setOwner(address newOwner) public onlyOwner {
                owner = newOwner;
            }
        }

        contract DerivedContract is BaseContract {
            uint256 public value;

            constructor() {
                owner = msg.sender;
            }

            // VULNERABILITY: Overrides access control without protection
            function setOwner(address newOwner) public override {
                // Missing onlyOwner modifier!
                owner = newOwner;
            }

            // VULNERABILITY: New function without inherited protection
            function criticalFunction() public {
                // Should require onlyOwner
                selfdestruct(payable(owner));
            }

            // Properly protected override
            function setValue(uint256 newValue) public onlyOwner {
                value = newValue;
            }
        }
    "#;

    let detector = MissingModifiersDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect inheritance-related access control issues
    assert!(findings.len() >= 2);

    // Verify override without proper protection
    let override_finding = findings.iter()
        .find(|f| f.message.contains("setOwner") && f.message.contains("override"))
        .expect("Should detect unsafe override");
    assert_eq!(override_finding.severity, Severity::Critical);
}

#[test]
fn test_access_control_with_assembly() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract AssemblyAccessControl {
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "Only owner");
                _;
            }

            constructor() {
                owner = msg.sender;
            }

            // VULNERABILITY: Assembly code bypassing Solidity access control
            function dangerousAssembly(address target, bytes calldata data) public {
                // Missing onlyOwner modifier!
                assembly {
                    let success := call(gas(), target, 0, add(data.offset, 0x20), data.length, 0, 0)
                    if iszero(success) { revert(0, 0) }
                }
            }

            // VULNERABILITY: Low-level call without protection
            function unsafeCall(address target, bytes calldata data) public returns (bool success) {
                // Missing access control
                (success, ) = target.call(data);
            }

            // Properly protected assembly
            function secureAssembly(address target, bytes calldata data) public onlyOwner {
                assembly {
                    let success := call(gas(), target, 0, add(data.offset, 0x20), data.length, 0, 0)
                    if iszero(success) { revert(0, 0) }
                }
            }
        }
    "#;

    let detector = MissingModifiersDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect assembly-related access control issues
    assert!(findings.len() >= 2);

    let assembly_finding = findings.iter()
        .find(|f| f.message.contains("dangerousAssembly"))
        .expect("Should detect unprotected assembly");
    assert_eq!(assembly_finding.severity, Severity::Critical);
}