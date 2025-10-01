use parser::arena::ArenaParser;
use detectors::{DetectorRegistry, AnalysisContext};
use semantic::SymbolTable;
use output::console::{ConsoleFormatter, ColorMode, OutputLevel, ConsoleConfig};

/// Test console output formatting with colors and different verbosity levels
/// These tests are designed to FAIL initially until the console formatter is implemented

#[cfg(test)]
mod test_console_output {
    use super::*;

    fn setup_test_contract(source: &str) -> (ArenaParser, AnalysisContext) {
        let mut parser = ArenaParser::new();
        let contract = parser.parse_contract(source, "test.sol").unwrap();
        let symbols = SymbolTable::new();
        let ctx = AnalysisContext::new(contract, symbols, source.to_string(), "test.sol".to_string());
        (parser, ctx)
    }

    #[test]
    #[should_panic(expected = "ConsoleFormatter not found")]
    fn test_basic_console_output() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    function unsafeFunction() external {
        selfdestruct(payable(msg.sender));
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because ConsoleFormatter is not implemented yet
        let console_formatter = ConsoleFormatter::new(ConsoleConfig::default()).unwrap();
        let detector = registry.get_detector("dangerous-selfdestruct").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect vulnerabilities");

        // Generate console output
        let output = console_formatter.format_findings(&findings, &ctx).unwrap();

        // Should contain basic information
        assert!(output.contains("dangerous-selfdestruct"));
        assert!(output.contains("test.sol"));
        assert!(output.contains("selfdestruct"));

        // Should have structured format
        assert!(output.contains("File:") || output.contains("Location:"));
        assert!(output.contains("Rule:") || output.contains("Detector:"));
        assert!(output.contains("Severity:"));
    }

    #[test]
    #[should_panic(expected = "ConsoleFormatter not found")]
    fn test_colored_output() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MultiSeverity {
    address public owner;

    function highSeverity() external {
        // High severity: dangerous operation
        selfdestruct(payable(msg.sender));
    }

    function mediumSeverity(address newOwner) external {
        // Medium severity: missing access control
        owner = newOwner;
    }

    function lowSeverity() external view returns (uint256) {
        // Low severity: unused variable
        uint256 unusedVar = 42;
        return block.timestamp;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because ConsoleFormatter is not implemented yet
        let config = ConsoleConfig {
            color_mode: ColorMode::Always,
            output_level: OutputLevel::All,
            show_code_snippets: true,
            show_fix_suggestions: false,
        };
        let console_formatter = ConsoleFormatter::new(config).unwrap();

        // Get findings of different severities
        let mut all_findings = Vec::new();
        for detector_id in ["dangerous-selfdestruct", "missing-access-control", "unused-variable"] {
            if let Ok(detector) = registry.get_detector(detector_id) {
                if let Ok(findings) = detector.detect(&ctx) {
                    all_findings.extend(findings);
                }
            }
        }

        assert!(!all_findings.is_empty(), "Should detect vulnerabilities");

        // Generate colored output
        let output = console_formatter.format_findings(&all_findings, &ctx).unwrap();

        // Should contain ANSI color codes for different severities
        assert!(output.contains("\x1b[31m") || output.contains("\x1b[91m")); // Red for high severity
        assert!(output.contains("\x1b[33m") || output.contains("\x1b[93m")); // Yellow for medium severity
        assert!(output.contains("\x1b[36m") || output.contains("\x1b[96m")); // Cyan for low severity
        assert!(output.contains("\x1b[0m")); // Reset color code

        // Should have proper formatting
        assert!(output.contains("●") || output.contains("■") || output.contains("▶")); // Bullet points
    }

    #[test]
    #[should_panic(expected = "ConsoleFormatter not found")]
    fn test_no_color_output() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleContract {
    function vulnerableFunction() external {
        require(tx.origin == msg.sender, "Invalid caller");
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because ConsoleFormatter is not implemented yet
        let config = ConsoleConfig {
            color_mode: ColorMode::Never,
            output_level: OutputLevel::All,
            show_code_snippets: false,
            show_fix_suggestions: false,
        };
        let console_formatter = ConsoleFormatter::new(config).unwrap();

        let detector = registry.get_detector("tx-origin-authentication").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect vulnerability");

        // Generate non-colored output
        let output = console_formatter.format_findings(&findings, &ctx).unwrap();

        // Should NOT contain ANSI color codes
        assert!(!output.contains("\x1b["));

        // Should still have structured information
        assert!(output.contains("tx-origin-authentication"));
        assert!(output.contains("test.sol"));
    }

    #[test]
    #[should_panic(expected = "ConsoleFormatter not found")]
    fn test_output_levels() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VerbosityTest {
    address public owner;

    function criticalBug() external {
        selfdestruct(payable(msg.sender));
    }

    function mediumBug(address newOwner) external {
        owner = newOwner;
    }

    function minorIssue() external view returns (uint256) {
        uint256 unused = 42;
        return block.timestamp;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // Test different output levels
        for level in [OutputLevel::Errors, OutputLevel::Warnings, OutputLevel::All] {
            let config = ConsoleConfig {
                color_mode: ColorMode::Never,
                output_level: level,
                show_code_snippets: false,
                show_fix_suggestions: false,
            };

            // This should fail because ConsoleFormatter is not implemented yet
            let console_formatter = ConsoleFormatter::new(config).unwrap();

            let mut all_findings = Vec::new();
            for detector_id in ["dangerous-selfdestruct", "missing-access-control", "unused-variable"] {
                if let Ok(detector) = registry.get_detector(detector_id) {
                    if let Ok(findings) = detector.detect(&ctx) {
                        all_findings.extend(findings);
                    }
                }
            }

            let output = console_formatter.format_findings(&all_findings, &ctx).unwrap();

            match level {
                OutputLevel::Errors => {
                    // Should only show high severity issues
                    assert!(output.contains("dangerous-selfdestruct"));
                    assert!(!output.contains("unused-variable"));
                }
                OutputLevel::Warnings => {
                    // Should show high and medium severity
                    assert!(output.contains("dangerous-selfdestruct"));
                    assert!(output.contains("missing-access-control"));
                    // May or may not include low severity depending on implementation
                }
                OutputLevel::All => {
                    // Should show all findings
                    assert!(output.contains("dangerous-selfdestruct"));
                    assert!(output.contains("missing-access-control"));
                    if all_findings.iter().any(|f| f.detector_id.as_str() == "unused-variable") {
                        assert!(output.contains("unused-variable"));
                    }
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "ConsoleFormatter not found")]
    fn test_code_snippets() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CodeSnippetTest {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];

        // This line has the vulnerability
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because ConsoleFormatter is not implemented yet
        let config = ConsoleConfig {
            color_mode: ColorMode::Always,
            output_level: OutputLevel::All,
            show_code_snippets: true,
            show_fix_suggestions: false,
        };
        let console_formatter = ConsoleFormatter::new(config).unwrap();

        let detector = registry.get_detector("reentrancy").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect reentrancy");

        let output = console_formatter.format_findings(&findings, &ctx).unwrap();

        // Should include code snippets
        assert!(output.contains("msg.sender.call"));
        assert!(output.contains("balances[msg.sender] = 0"));

        // Should have line numbers
        assert!(output.contains("11") || output.contains("12")); // Line numbers
        assert!(output.contains("|")); // Line separator

        // Should highlight vulnerable line
        assert!(output.contains("►") || output.contains(">") || output.contains("→"));
    }

    #[test]
    #[should_panic(expected = "ConsoleFormatter not found")]
    fn test_fix_suggestions_display() {
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

        // This should fail because ConsoleFormatter is not implemented yet
        let config = ConsoleConfig {
            color_mode: ColorMode::Always,
            output_level: OutputLevel::All,
            show_code_snippets: true,
            show_fix_suggestions: true,
        };
        let console_formatter = ConsoleFormatter::new(config).unwrap();

        let detector = registry.get_detector("missing-access-control").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect access control issue");

        let output = console_formatter.format_findings_with_fixes(&findings, &ctx).unwrap();

        // Should include fix suggestions
        assert!(output.contains("Fix:") || output.contains("Suggestion:"));
        assert!(output.contains("onlyOwner") || output.contains("require(msg.sender == owner"));

        // Should have proper formatting for fixes
        assert!(output.contains("💡") || output.contains("→") || output.contains("*"));
    }

    #[test]
    #[should_panic(expected = "ConsoleFormatter not found")]
    fn test_summary_statistics() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StatisticsTest {
    address public owner;
    mapping(address => uint256) public balances;

    function multipleIssues() external {
        // Multiple vulnerabilities for statistics
        selfdestruct(payable(msg.sender)); // High severity
        owner = msg.sender; // Medium severity (missing access control)

        uint256 amount = balances[msg.sender];
        (bool success,) = msg.sender.call{value: amount}(""); // High severity (reentrancy)
        require(success, "Failed");
        balances[msg.sender] = 0;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because ConsoleFormatter is not implemented yet
        let config = ConsoleConfig {
            color_mode: ColorMode::Never,
            output_level: OutputLevel::All,
            show_code_snippets: false,
            show_fix_suggestions: false,
        };
        let console_formatter = ConsoleFormatter::new(config).unwrap();

        let mut all_findings = Vec::new();
        for detector_id in ["dangerous-selfdestruct", "missing-access-control", "reentrancy"] {
            if let Ok(detector) = registry.get_detector(detector_id) {
                if let Ok(findings) = detector.detect(&ctx) {
                    all_findings.extend(findings);
                }
            }
        }

        assert!(!all_findings.is_empty(), "Should detect vulnerabilities");

        let output = console_formatter.format_with_summary(&all_findings, &ctx).unwrap();

        // Should include summary statistics
        assert!(output.contains("Summary:") || output.contains("Total:"));
        assert!(output.contains("High:") || output.contains("Critical:"));
        assert!(output.contains("Medium:"));

        // Should show counts
        let high_count = all_findings.iter()
            .filter(|f| matches!(f.severity, detectors::types::Severity::High))
            .count();
        let medium_count = all_findings.iter()
            .filter(|f| matches!(f.severity, detectors::types::Severity::Medium))
            .count();

        if high_count > 0 {
            assert!(output.contains(&high_count.to_string()));
        }
        if medium_count > 0 {
            assert!(output.contains(&medium_count.to_string()));
        }
    }

    #[test]
    #[should_panic(expected = "ConsoleFormatter not found")]
    fn test_auto_color_detection() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AutoColorTest {
    function test() external {
        selfdestruct(payable(msg.sender));
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because ConsoleFormatter is not implemented yet
        let config = ConsoleConfig {
            color_mode: ColorMode::Auto, // Should detect TTY capabilities
            output_level: OutputLevel::All,
            show_code_snippets: false,
            show_fix_suggestions: false,
        };
        let console_formatter = ConsoleFormatter::new(config).unwrap();

        let detector = registry.get_detector("dangerous-selfdestruct").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        assert!(!findings.is_empty(), "Should detect vulnerability");

        let output = console_formatter.format_findings(&findings, &ctx).unwrap();

        // Should contain structured output regardless of color support
        assert!(output.contains("dangerous-selfdestruct"));
        assert!(output.contains("test.sol"));

        // Color codes may or may not be present depending on TTY detection
        // This is implementation-dependent
    }

    #[test]
    #[should_panic(expected = "ConsoleFormatter not found")]
    fn test_wide_terminal_formatting() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract WideTerminalTest {
    function veryLongFunctionNameThatMightWrapInNarrowTerminals() external {
        // This is a very long line of code that might cause formatting issues in narrow terminals
        require(msg.sender == address(0x1234567890123456789012345678901234567890), "Very long address check");
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because ConsoleFormatter is not implemented yet
        let config = ConsoleConfig {
            color_mode: ColorMode::Never,
            output_level: OutputLevel::All,
            show_code_snippets: true,
            show_fix_suggestions: false,
        };
        let console_formatter = ConsoleFormatter::new(config).unwrap();

        let detector = registry.get_detector("missing-zero-address-check").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        if !findings.is_empty() {
            let output = console_formatter.format_findings(&findings, &ctx).unwrap();

            // Should handle long lines gracefully
            assert!(output.contains("veryLongFunctionName"));

            // Should not have extremely long lines (basic wrapping)
            let lines = output.lines();
            let max_line_length = lines.map(|line| line.len()).max().unwrap_or(0);
            assert!(max_line_length < 200, "Lines should not be excessively long");
        }
    }
}