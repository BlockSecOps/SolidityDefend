use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for reentrancy during initialization
///
/// Initialization functions are particularly vulnerable to reentrancy because
/// state is often partially set when external calls are made. An attacker can
/// exploit this to re-enter and manipulate the initialization process.
///
/// Vulnerable pattern:
/// ```solidity
/// function initialize(address token) public initializer {
///     IERC20(token).balanceOf(address(this)); // External call
///     owner = msg.sender; // State set AFTER external call
/// }
/// ```
pub struct InitializerReentrancyDetector {
    base: BaseDetector,
}

impl Default for InitializerReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl InitializerReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("initializer-reentrancy"),
                "Initializer Reentrancy".to_string(),
                "Detects external calls in initializer functions that could enable reentrancy \
                 attacks during contract initialization"
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::Upgradeable],
                Severity::High,
            ),
        }
    }

    /// Check if function is an initializer
    fn is_initializer_function(&self, source: &str, func_start: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();

        if func_start >= lines.len() {
            return false;
        }

        let line = lines[func_start];

        // Check for initializer modifier
        line.contains("initializer")
            || line.contains("onlyInitializing")
            || (line.contains("function initialize") && !line.contains("//"))
            || line.contains("function __") // OpenZeppelin internal initializers
    }

    /// Find external calls in function
    fn find_external_calls(&self, func_body: &str) -> Vec<(usize, &str)> {
        let mut calls = Vec::new();
        let patterns = [
            ".call(",
            ".delegatecall(",
            ".staticcall(",
            ".transfer(",
            ".send(",
            // Common interface calls that could have callbacks
            ".balanceOf(",
            ".approve(",
            ".transferFrom(",
            ".safeTransfer(",
            ".safeTransferFrom(",
            // Hook-enabled tokens
            ".tokensReceived(",
            ".onERC721Received(",
            ".onERC1155Received(",
        ];

        for (i, line) in func_body.lines().enumerate() {
            for pattern in &patterns {
                if line.contains(pattern) && !line.trim().starts_with("//") {
                    calls.push((i, *pattern));
                }
            }
        }

        calls
    }

    /// Find state changes after a given line
    fn has_state_changes_after(&self, func_body: &str, after_line: usize) -> bool {
        let lines: Vec<&str> = func_body.lines().collect();

        for line in lines.iter().skip(after_line + 1) {
            // Common state change patterns
            if (line.contains(" = ") && !line.contains("=="))
                || line.contains("+=")
                || line.contains("-=")
                || line.contains("*=")
                || line.contains("/=")
                || line.contains(".push(")
                || line.contains("delete ")
            {
                // Exclude local variable assignments
                if !line.contains("uint")
                    && !line.contains("address ")
                    && !line.contains("bool ")
                    && !line.contains("bytes ")
                    && !line.contains("string ")
                    && !line.contains("memory")
                {
                    return true;
                }
            }
        }
        false
    }

    /// Find initializer functions and check for issues
    fn analyze_initializers(&self, source: &str) -> Vec<(u32, String)> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains("function ") && self.is_initializer_function(source, i) {
                // Get function body
                let func_body = self.get_function_body(&lines, i);

                // Find external calls
                let external_calls = self.find_external_calls(&func_body);

                for (call_line_offset, call_pattern) in external_calls {
                    // Check if state changes happen after this call
                    if self.has_state_changes_after(&func_body, call_line_offset) {
                        let func_name = self.extract_function_name(line);
                        issues.push((
                            (i + call_line_offset + 1) as u32,
                            format!(
                                "External call '{}' in initializer '{}' before state changes complete - \
                                 potential reentrancy during initialization",
                                call_pattern.trim_end_matches('('),
                                func_name
                            ),
                        ));
                    }
                }
            }
        }

        issues
    }

    /// Get function body
    fn get_function_body(&self, lines: &[&str], start: usize) -> String {
        let mut body = String::new();
        let mut depth = 0;
        let mut started = false;

        for line in lines.iter().skip(start) {
            for c in line.chars() {
                if c == '{' {
                    depth += 1;
                    started = true;
                } else if c == '}' {
                    depth -= 1;
                }
            }

            body.push_str(line);
            body.push('\n');

            if started && depth == 0 {
                break;
            }
        }

        body
    }

    /// Extract function name
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(start) = line.find("function ") {
            let after_function = &line[start + 9..];
            if let Some(end) = after_function.find('(') {
                return after_function[..end].trim().to_string();
            }
        }
        "initialize".to_string()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for InitializerReentrancyDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        let issues = self.analyze_initializers(source);

        for (line, issue_desc) in issues {
            let message = format!("Contract '{}': {}", contract_name, issue_desc);

            let finding = self
                .base
                .create_finding(ctx, message, line, 0, 20)
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_cwe(696) // CWE-696: Incorrect Behavior Order
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Follow checks-effects-interactions pattern in initializers:\n\n\
                     function initialize(address token) public initializer {\n\
                         // 1. Checks\n\
                         require(token != address(0), \"Invalid token\");\n\
                         \n\
                         // 2. Effects (state changes)\n\
                         owner = msg.sender;\n\
                         _token = token;\n\
                         \n\
                         // 3. Interactions (external calls) - LAST\n\
                         IERC20(token).balanceOf(address(this));\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = InitializerReentrancyDetector::new();
        assert_eq!(detector.name(), "Initializer Reentrancy");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_is_initializer_function() {
        let detector = InitializerReentrancyDetector::new();
        let source = "function initialize() public initializer {";
        assert!(detector.is_initializer_function(source, 0));
    }

    #[test]
    fn test_find_external_calls() {
        let detector = InitializerReentrancyDetector::new();
        let body = r#"
            token.balanceOf(address(this));
            owner = msg.sender;
        "#;
        let calls = detector.find_external_calls(body);
        assert!(!calls.is_empty());
    }
}
