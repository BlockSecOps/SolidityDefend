use parser::arena::ArenaParser;
use detectors::{DetectorRegistry, AnalysisContext};
use semantic::SymbolTable;
use output::sarif::{SarifFormatter, SarifReport, SarifRun, SarifResult, SarifRule};

/// Test SARIF 2.1.0 output format implementation
/// These tests are designed to FAIL initially until the SARIF formatter is implemented

#[cfg(test)]
mod test_sarif_output {
    use super::*;
    use serde_json;

    fn setup_test_contract(source: &str) -> (ArenaParser, AnalysisContext) {
        let mut parser = ArenaParser::new();
        let contract = parser.parse_contract(source, "test.sol").unwrap();
        let symbols = SymbolTable::new();
        let ctx = AnalysisContext::new(contract, symbols, source.to_string(), "test.sol".to_string());
        (parser, ctx)
    }

    #[test]
    #[should_panic(expected = "SarifFormatter not found")]
    fn test_basic_sarif_structure() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    function unsafeFunction() external {
        // This will trigger a vulnerability
        selfdestruct(payable(msg.sender));
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because SarifFormatter is not implemented yet
        let sarif_formatter = SarifFormatter::new().unwrap();
        let detector = registry.get_detector("dangerous-selfdestruct").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect vulnerabilities");

        // Generate SARIF report
        let sarif_report = sarif_formatter.format_findings(&findings, &ctx).unwrap();

        // Validate SARIF 2.1.0 structure
        assert_eq!(sarif_report.version, "2.1.0");
        assert_eq!(sarif_report.schema, "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
        assert!(!sarif_report.runs.is_empty());

        let run = &sarif_report.runs[0];
        assert_eq!(run.tool.driver.name, "SolidityDefend");
        assert!(!run.tool.driver.version.is_empty());
        assert!(!run.results.is_empty());

        // Validate result structure
        let result = &run.results[0];
        assert!(!result.rule_id.is_empty());
        assert!(!result.message.text.is_empty());
        assert!(!result.locations.is_empty());

        let location = &result.locations[0];
        assert!(location.physical_location.artifact_location.uri.ends_with("test.sol"));
        assert!(location.physical_location.region.start_line > 0);
        assert!(location.physical_location.region.start_column > 0);
    }

    #[test]
    #[should_panic(expected = "SarifFormatter not found")]
    fn test_sarif_with_multiple_vulnerabilities() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MultipleVulnerabilities {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        // Missing zero address check
        owner = msg.sender;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];

        // Reentrancy vulnerability
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function adminFunction(address user) external {
        // Missing access control
        balances[user] = 1000;
    }

    function dangerousFunction() external {
        // Dangerous operation
        selfdestruct(payable(msg.sender));
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because SarifFormatter is not implemented yet
        let sarif_formatter = SarifFormatter::new().unwrap();

        // Collect findings from multiple detectors
        let mut all_findings = Vec::new();

        for detector_id in ["reentrancy", "missing-access-control", "dangerous-selfdestruct", "missing-zero-address-check"] {
            if let Ok(detector) = registry.get_detector(detector_id) {
                if let Ok(findings) = detector.detect(&ctx) {
                    all_findings.extend(findings);
                }
            }
        }

        assert!(!all_findings.is_empty(), "Should detect multiple vulnerabilities");

        // Generate comprehensive SARIF report
        let sarif_report = sarif_formatter.format_findings(&all_findings, &ctx).unwrap();

        // Validate multiple results
        let run = &sarif_report.runs[0];
        assert!(run.results.len() >= 2, "Should have multiple results");

        // Validate rule definitions
        assert!(!run.tool.driver.rules.is_empty());

        // Each rule should have proper metadata
        for rule in &run.tool.driver.rules {
            assert!(!rule.id.is_empty());
            assert!(!rule.name.is_empty());
            assert!(!rule.short_description.text.is_empty());
            assert!(!rule.full_description.text.is_empty());
            assert!(!rule.help.text.is_empty());
            assert!(!rule.properties.security_severity.is_empty());
        }

        // Validate results reference rules
        for result in &run.results {
            assert!(run.tool.driver.rules.iter().any(|rule| rule.id == result.rule_id));
        }
    }

    #[test]
    #[should_panic(expected = "SarifFormatter not found")]
    fn test_sarif_serialization() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleContract {
    function vulnerableFunction() external {
        // Simple vulnerability for testing
        require(tx.origin == msg.sender, "Invalid caller");
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because SarifFormatter is not implemented yet
        let sarif_formatter = SarifFormatter::new().unwrap();
        let detector = registry.get_detector("tx-origin-authentication").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect vulnerability");

        // Generate and serialize SARIF report
        let sarif_report = sarif_formatter.format_findings(&findings, &ctx).unwrap();
        let json_output = sarif_formatter.to_json(&sarif_report).unwrap();

        // Validate JSON structure
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["runs"].is_array());
        assert!(!parsed["runs"].as_array().unwrap().is_empty());

        let run = &parsed["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "SolidityDefend");
        assert!(run["results"].is_array());

        // Validate result structure in JSON
        let result = &run["results"][0];
        assert!(result["ruleId"].is_string());
        assert!(result["message"]["text"].is_string());
        assert!(result["locations"].is_array());

        let location = &result["locations"][0];
        assert!(location["physicalLocation"]["artifactLocation"]["uri"].is_string());
        assert!(location["physicalLocation"]["region"]["startLine"].is_number());
        assert!(location["physicalLocation"]["region"]["startColumn"].is_number());
    }

    #[test]
    #[should_panic(expected = "SarifFormatter not found")]
    fn test_sarif_with_fix_suggestions() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FixableContract {
    address public owner;

    function setOwner(address newOwner) external {
        // Missing access control and zero address check
        owner = newOwner;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because SarifFormatter is not implemented yet
        let sarif_formatter = SarifFormatter::new().unwrap();
        let detector = registry.get_detector("missing-access-control").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect vulnerability");

        // Generate SARIF with fix suggestions
        let sarif_report = sarif_formatter.format_findings_with_fixes(&findings, &ctx).unwrap();

        let run = &sarif_report.runs[0];
        let result = &run.results[0];

        // Should include fix suggestions
        assert!(result.fixes.is_some());
        let fixes = result.fixes.as_ref().unwrap();
        assert!(!fixes.is_empty());

        let fix = &fixes[0];
        assert!(!fix.description.text.is_empty());
        assert!(!fix.artifact_changes.is_empty());

        let artifact_change = &fix.artifact_changes[0];
        assert!(artifact_change.artifact_location.uri.ends_with("test.sol"));
        assert!(!artifact_change.replacements.is_empty());

        let replacement = &artifact_change.replacements[0];
        assert!(replacement.deleted_region.start_line > 0);
        assert!(!replacement.inserted_content.text.is_empty());
    }

    #[test]
    #[should_panic(expected = "SarifFormatter not found")]
    fn test_sarif_with_code_flows() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ComplexFlow {
    mapping(address => uint256) public balances;
    bool private locked;

    function complexFunction() external {
        require(!locked, "Locked");
        locked = true;

        uint256 amount = balances[msg.sender];

        // Complex call flow
        _processWithdrawal(amount);

        locked = false;
    }

    function _processWithdrawal(uint256 amount) internal {
        // Reentrancy vulnerability in call flow
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Failed");

        balances[msg.sender] = 0;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because SarifFormatter is not implemented yet
        let sarif_formatter = SarifFormatter::new().unwrap();
        let detector = registry.get_detector("reentrancy").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect reentrancy");

        // Generate SARIF with code flows
        let sarif_report = sarif_formatter.format_findings_with_flows(&findings, &ctx).unwrap();

        let run = &sarif_report.runs[0];
        let result = &run.results[0];

        // Should include code flows
        assert!(result.code_flows.is_some());
        let code_flows = result.code_flows.as_ref().unwrap();
        assert!(!code_flows.is_empty());

        let code_flow = &code_flows[0];
        assert!(!code_flow.thread_flows.is_empty());

        let thread_flow = &code_flow.thread_flows[0];
        assert!(!thread_flow.locations.is_empty());
        assert!(thread_flow.locations.len() >= 2); // At least entry and vulnerability points

        // Validate flow locations
        for location in &thread_flow.locations {
            assert!(location.location.physical_location.region.start_line > 0);
            assert!(!location.location.message.text.is_empty());
        }
    }

    #[test]
    #[should_panic(expected = "SarifFormatter not found")]
    fn test_sarif_taxonomies_and_tags() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    function vulnerableFunction() external {
        // CWE-476: NULL Pointer Dereference equivalent
        require(msg.sender != address(0), "Zero address");
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because SarifFormatter is not implemented yet
        let sarif_formatter = SarifFormatter::new().unwrap();
        let detector = registry.get_detector("missing-zero-address-check").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        if !findings.is_empty() {
            let sarif_report = sarif_formatter.format_findings(&findings, &ctx).unwrap();

            let run = &sarif_report.runs[0];

            // Should include taxonomies
            assert!(run.taxonomies.is_some());
            let taxonomies = run.taxonomies.as_ref().unwrap();
            assert!(!taxonomies.is_empty());

            // Should have CWE taxonomy
            let cwe_taxonomy = taxonomies.iter().find(|t| t.name == "CWE").unwrap();
            assert_eq!(cwe_taxonomy.organization, "MITRE");
            assert!(!cwe_taxonomy.taxa.is_empty());

            // Results should reference taxonomy
            let result = &run.results[0];
            assert!(result.taxa.is_some());
            let taxa = result.taxa.as_ref().unwrap();
            assert!(!taxa.is_empty());

            // Should have proper tags
            assert!(result.tags.is_some());
            let tags = result.tags.as_ref().unwrap();
            assert!(tags.contains(&"security".to_string()));
        }
    }

    #[test]
    #[should_panic(expected = "SarifFormatter not found")]
    fn test_sarif_baseline_comparison() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BaselineTest {
    function oldVulnerability() external {
        // Existing vulnerability
        selfdestruct(payable(msg.sender));
    }

    function newVulnerability() external {
        // New vulnerability
        require(tx.origin == msg.sender, "Invalid");
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because SarifFormatter is not implemented yet
        let sarif_formatter = SarifFormatter::new().unwrap();

        // Simulate baseline findings (would come from previous scan)
        let baseline_findings = Vec::new(); // Empty baseline for test

        // Get current findings
        let mut current_findings = Vec::new();
        for detector_id in ["dangerous-selfdestruct", "tx-origin-authentication"] {
            if let Ok(detector) = registry.get_detector(detector_id) {
                if let Ok(findings) = detector.detect(&ctx) {
                    current_findings.extend(findings);
                }
            }
        }

        assert!(!current_findings.is_empty(), "Should have current findings");

        // Generate SARIF with baseline comparison
        let sarif_report = sarif_formatter.format_with_baseline(
            &current_findings,
            &baseline_findings,
            &ctx
        ).unwrap();

        let run = &sarif_report.runs[0];

        // Should have baseline GUID
        assert!(run.baseline_guid.is_some());

        // Results should have baseline state
        for result in &run.results {
            assert!(result.baseline_state.is_some());
            // Since baseline is empty, all should be "new"
            assert_eq!(result.baseline_state.as_ref().unwrap(), "new");
        }
    }
}