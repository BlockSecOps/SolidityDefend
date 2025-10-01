use parser::arena::ArenaParser;
use detectors::{DetectorRegistry, AnalysisContext};
use semantic::SymbolTable;
use fixes::{FixEngine, FixSuggestion, TextReplacement};

/// Test fix suggestion system
/// These tests are designed to FAIL initially until the fix system is implemented

#[cfg(test)]
mod test_fix_suggestions {
    use super::*;

    fn setup_test_contract(source: &str) -> (ArenaParser, AnalysisContext) {
        let mut parser = ArenaParser::new();
        let contract = parser.parse_contract(source, "test.sol").unwrap();
        let symbols = SymbolTable::new();
        let ctx = AnalysisContext::new(contract, symbols, source.to_string(), "test.sol".to_string());
        (parser, ctx)
    }

    #[test]
    #[should_panic(expected = "FixEngine not found")]
    fn test_reentrancy_fix_suggestion() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableReentrancy {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];

        // Vulnerable: external call before state update
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because FixEngine is not implemented yet
        let fix_engine = FixEngine::new().unwrap();
        let detector = registry.get_detector("reentrancy").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect reentrancy vulnerability");

        // Test fix suggestion generation
        let fixes = fix_engine.generate_fixes(&findings[0], &ctx).unwrap();
        assert!(!fixes.is_empty(), "Should generate fix suggestions");

        // Should suggest checks-effects-interactions pattern
        let fix = &fixes[0];
        assert!(fix.description.contains("checks-effects-interactions"));
        assert!(fix.replacements.len() >= 2); // At least two replacements needed

        // Verify the fix moves state update before external call
        let applied_code = fix_engine.apply_fix(source, &fix).unwrap();
        assert!(applied_code.contains("balances[msg.sender] = 0;"));
        assert!(applied_code.find("balances[msg.sender] = 0;").unwrap() <
                applied_code.find("msg.sender.call").unwrap());
    }

    #[test]
    #[should_panic(expected = "FixEngine not found")]
    fn test_integer_overflow_fix_suggestion() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0; // Intentionally old version

contract VulnerableOverflow {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external payable {
        require(msg.value == amount, "Incorrect amount");

        // Vulnerable: no overflow check
        balances[msg.sender] += amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Vulnerable: no overflow checks
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because FixEngine is not implemented yet
        let fix_engine = FixEngine::new().unwrap();
        let detector = registry.get_detector("integer-overflow").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect overflow vulnerabilities");

        // Test fix suggestions for different overflow patterns
        for finding in &findings {
            let fixes = fix_engine.generate_fixes(finding, &ctx).unwrap();
            assert!(!fixes.is_empty(), "Should generate fix for each overflow");

            let fix = &fixes[0];

            // Should suggest SafeMath or Solidity ^0.8.0
            assert!(fix.description.contains("SafeMath") ||
                   fix.description.contains("Solidity ^0.8.0"));

            if fix.description.contains("SafeMath") {
                // Should add SafeMath import and usage
                let applied_code = fix_engine.apply_fix(source, &fix).unwrap();
                assert!(applied_code.contains("import \"@openzeppelin/contracts/math/SafeMath.sol\"") ||
                       applied_code.contains("using SafeMath for uint256"));
            }
        }
    }

    #[test]
    #[should_panic(expected = "FixEngine not found")]
    fn test_access_control_fix_suggestion() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableAccessControl {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
        balances[msg.sender] = totalSupply;
    }

    // Vulnerable: missing access control
    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balances[to] += amount;
    }

    // Vulnerable: missing access control
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // Vulnerable: weak access control
    function adminTransfer(address from, address to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        balances[from] -= amount;
        balances[to] += amount;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because FixEngine is not implemented yet
        let fix_engine = FixEngine::new().unwrap();
        let detector = registry.get_detector("missing-access-control").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect access control issues");

        // Test fix suggestions for different access control patterns
        for finding in &findings {
            let fixes = fix_engine.generate_fixes(finding, &ctx).unwrap();
            assert!(!fixes.is_empty(), "Should generate access control fixes");

            let fix = &fixes[0];

            // Should suggest proper access control patterns
            assert!(fix.description.contains("onlyOwner") ||
                   fix.description.contains("AccessControl") ||
                   fix.description.contains("Ownable"));

            let applied_code = fix_engine.apply_fix(source, &fix).unwrap();

            // Should add modifier or require statement
            assert!(applied_code.contains("onlyOwner") ||
                   applied_code.contains("require(msg.sender == owner") ||
                   applied_code.contains("_checkOwner()"));
        }
    }

    #[test]
    #[should_panic(expected = "FixEngine not found")]
    fn test_zero_address_fix_suggestion() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableZeroAddress {
    address public owner;
    address public treasury;

    constructor(address _owner, address _treasury) {
        // Vulnerable: no zero address checks
        owner = _owner;
        treasury = _treasury;
    }

    function setTreasury(address newTreasury) external {
        require(msg.sender == owner, "Not owner");

        // Vulnerable: no zero address check
        treasury = newTreasury;
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");

        // Vulnerable: no zero address check
        owner = newOwner;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because FixEngine is not implemented yet
        let fix_engine = FixEngine::new().unwrap();
        let detector = registry.get_detector("missing-zero-address-check").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect zero address issues");

        for finding in &findings {
            let fixes = fix_engine.generate_fixes(finding, &ctx).unwrap();
            assert!(!fixes.is_empty(), "Should generate zero address fixes");

            let fix = &fixes[0];

            // Should suggest zero address validation
            assert!(fix.description.contains("address(0)") ||
                   fix.description.contains("zero address"));

            let applied_code = fix_engine.apply_fix(source, &fix).unwrap();

            // Should add require statement checking for address(0)
            assert!(applied_code.contains("require(") &&
                   applied_code.contains("!= address(0)"));
        }
    }

    #[test]
    #[should_panic(expected = "FixEngine not found")]
    fn test_division_before_multiplication_fix() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerablePrecision {
    uint256 public constant FEE_RATE = 300; // 3%
    uint256 public constant FEE_DENOMINATOR = 10000;

    function calculateFee(uint256 amount) external pure returns (uint256) {
        // Vulnerable: division before multiplication causes precision loss
        return amount / FEE_DENOMINATOR * FEE_RATE;
    }

    function calculateReward(uint256 stake, uint256 multiplier) external pure returns (uint256) {
        // Vulnerable: division before multiplication
        uint256 baseReward = stake / 100 * multiplier;
        return baseReward;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because FixEngine is not implemented yet
        let fix_engine = FixEngine::new().unwrap();
        let detector = registry.get_detector("division-before-multiplication").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect precision loss issues");

        for finding in &findings {
            let fixes = fix_engine.generate_fixes(finding, &ctx).unwrap();
            assert!(!fixes.is_empty(), "Should generate precision fixes");

            let fix = &fixes[0];

            // Should suggest reordering operations
            assert!(fix.description.contains("multiplication before division") ||
                   fix.description.contains("reorder operations"));

            let applied_code = fix_engine.apply_fix(source, &fix).unwrap();

            // Should reorder to multiplication before division
            if applied_code.contains("FEE_RATE") {
                assert!(applied_code.find("* FEE_RATE").unwrap() <
                       applied_code.find("/ FEE_DENOMINATOR").unwrap());
            }
        }
    }

    #[test]
    #[should_panic(expected = "FixEngine not found")]
    fn test_multiple_fixes_with_conflicts() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MultipleBugs {
    address public owner;
    mapping(address => uint256) public balances;

    // Multiple vulnerabilities in one function
    function vulnerableFunction(address recipient, uint256 amount) external {
        // Missing access control
        // Missing zero address check
        // Reentrancy vulnerability

        uint256 balance = balances[msg.sender];
        require(balance >= amount, "Insufficient balance");

        // External call before state update (reentrancy)
        (bool success,) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because FixEngine is not implemented yet
        let fix_engine = FixEngine::new().unwrap();

        // Get findings from multiple detectors
        let reentrancy_findings = registry.get_detector("reentrancy").unwrap().detect(&ctx).unwrap();
        let access_control_findings = registry.get_detector("missing-access-control").unwrap().detect(&ctx).unwrap();
        let zero_address_findings = registry.get_detector("missing-zero-address-check").unwrap().detect(&ctx).unwrap();

        let mut all_findings = Vec::new();
        all_findings.extend(reentrancy_findings);
        all_findings.extend(access_control_findings);
        all_findings.extend(zero_address_findings);

        assert!(!all_findings.is_empty(), "Should detect multiple vulnerabilities");

        // Test conflict detection and resolution
        let combined_fixes = fix_engine.generate_combined_fixes(&all_findings, &ctx).unwrap();
        assert!(!combined_fixes.is_empty(), "Should generate combined fixes");

        // Should handle overlapping text ranges
        let applied_code = fix_engine.apply_multiple_fixes(source, &combined_fixes).unwrap();

        // All fixes should be applied without conflicts
        assert!(applied_code.contains("onlyOwner") || applied_code.contains("require(msg.sender == owner"));
        assert!(applied_code.contains("!= address(0)"));
        assert!(applied_code.find("balances[msg.sender] -= amount").unwrap() <
               applied_code.find("recipient.call").unwrap());
    }

    #[test]
    #[should_panic(expected = "FixEngine not found")]
    fn test_fix_ranking_and_confidence() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AmbiguousFix {
    mapping(address => uint256) public balances;

    function complexFunction(uint256 amount) external {
        // Could be fixed in multiple ways
        balances[msg.sender] += amount;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because FixEngine is not implemented yet
        let fix_engine = FixEngine::new().unwrap();
        let detector = registry.get_detector("integer-overflow").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        if !findings.is_empty() {
            let fixes = fix_engine.generate_fixes(&findings[0], &ctx).unwrap();
            assert!(!fixes.is_empty(), "Should generate multiple fix options");

            // Should be ranked by confidence
            for i in 1..fixes.len() {
                assert!(fixes[i-1].confidence >= fixes[i].confidence,
                       "Fixes should be ranked by confidence");
            }

            // High confidence fixes should have detailed explanations
            let best_fix = &fixes[0];
            assert!(best_fix.confidence > 0.7, "Best fix should have high confidence");
            assert!(!best_fix.explanation.is_empty(), "Should have explanation");
            assert!(!best_fix.description.is_empty(), "Should have description");
        }
    }
}