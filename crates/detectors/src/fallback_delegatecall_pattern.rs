use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for fallback function delegatecall patterns
///
/// Detects fallback functions that delegate all calls without selector filtering.
/// This pattern is dangerous as it allows arbitrary function execution.
///
/// Vulnerable pattern:
/// ```solidity
/// fallback() external payable {
///     address impl = implementation;
///     assembly {
///         calldatacopy(0, 0, calldatasize())
///         let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
///         // No selector filtering
///     }
/// }
/// ```
pub struct FallbackDelegatecallPatternDetector {
    base: BaseDetector,
}

impl Default for FallbackDelegatecallPatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FallbackDelegatecallPatternDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("fallback-delegatecall-pattern"),
                "Fallback Delegatecall Pattern".to_string(),
                "Detects fallback functions that delegate all calls without filtering. \
                 Unfiltered delegation can expose internal functions or allow \
                 unauthorized access to proxy storage."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find fallback with unfiltered delegatecall
    fn find_unfiltered_fallback_delegatecall(&self, source: &str) -> Option<(u32, bool)> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Find fallback function
            if trimmed.contains("fallback()") || trimmed.starts_with("fallback(") {
                // Get fallback body
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for delegatecall
                if func_body.contains("delegatecall") {
                    // Check for selector filtering
                    let has_filtering = func_body.contains("msg.sig")
                        || func_body.contains("selector")
                        || func_body.contains("bytes4(")
                        || func_body.contains("require(")
                        || func_body.contains("if (")
                        || func_body.contains("revert")
                        || func_body.contains("_beforeFallback");

                    let is_assembly = func_body.contains("assembly");

                    if !has_filtering {
                        return Some((line_num as u32 + 1, is_assembly));
                    }
                }
            }
        }

        None
    }

    /// Check for receive() function delegating
    fn has_receive_delegatecall(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("receive()") || trimmed.starts_with("receive(") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                if func_body.contains("delegatecall") {
                    return Some(line_num as u32 + 1);
                }
            }
        }

        None
    }

    /// Check for low-level delegatecall without msg.data validation
    fn has_raw_delegatecall(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for delegatecall with calldatacopy
            if trimmed.contains("calldatacopy") {
                // Check context for validation
                let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                let context_end = std::cmp::min(line_num + 10, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                if context.contains("delegatecall") {
                    // Check for any validation
                    if !context.contains("require")
                        && !context.contains("revert")
                        && !context.contains("if ")
                        && !context.contains("calldatasize() < 4")
                    {
                        let func_name = self.find_containing_function(&lines, line_num);
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find the end of a function
    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => {
                        depth -= 1;
                        if started && depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    /// Find the containing function for a line
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
            if trimmed.contains("fallback()") {
                return "fallback".to_string();
            }
            if trimmed.contains("receive()") {
                return "receive".to_string();
            }
        }
        "unknown".to_string()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for FallbackDelegatecallPatternDetector {
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
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Phase 53 FP Reduction: Skip standard proxy contracts
        // Proxies delegate ALL calls to implementation by design - that's their purpose
        let is_standard_proxy = source.contains("abstract contract Proxy")
            || source.contains("contract TransparentUpgradeableProxy")
            || source.contains("contract ERC1967Proxy")
            || source.contains("contract BeaconProxy")
            || source.contains("OpenZeppelin")
            || (source.contains("function _implementation(") && source.contains("function _delegate("));

        if is_standard_proxy {
            return Ok(findings);
        }

        // Check for unfiltered fallback delegatecall
        if let Some((line, is_assembly)) = self.find_unfiltered_fallback_delegatecall(source) {
            let assembly_note = if is_assembly {
                " using low-level assembly"
            } else {
                ""
            };
            let message = format!(
                "Fallback function in contract '{}'{}delegates all calls without selector \
                 filtering. Any function selector can be routed to the implementation, \
                 potentially exposing internal functions or allowing storage manipulation.",
                contract_name, assembly_note
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(749) // CWE-749: Exposed Dangerous Method
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add selector filtering or use transparent proxy pattern:\n\n\
                     fallback() external payable {\n\
                         // Option 1: Block admin functions\n\
                         require(msg.sig != bytes4(keccak256(\"upgrade(address)\")));\n\n\
                         // Option 2: Whitelist allowed selectors\n\
                         require(allowedSelectors[msg.sig], \"Selector not allowed\");\n\n\
                         // Option 3: Use transparent proxy pattern\n\
                         require(msg.sender != admin, \"Admin cannot call impl\");\n\n\
                         _delegate(implementation);\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for receive() with delegatecall
        if let Some(line) = self.has_receive_delegatecall(source) {
            let message = format!(
                "Contract '{}' has receive() function that delegates. This can cause \
                 unexpected behavior when receiving plain ETH transfers.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 20)
                .with_cwe(749) // CWE-749: Exposed Dangerous Method
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Separate receive() from fallback delegation:\n\n\
                     receive() external payable {\n\
                         // Just receive ETH, don't delegate\n\
                     }\n\n\
                     fallback() external payable {\n\
                         _delegate(implementation);\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for raw delegatecall without validation
        let raw_delegatecalls = self.has_raw_delegatecall(source);
        for (line, func_name) in raw_delegatecalls {
            let message = format!(
                "Function '{}' in contract '{}' copies calldata and delegates without \
                 validation. This allows arbitrary calldata to be forwarded.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(749) // CWE-749: Exposed Dangerous Method
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add minimum calldata length check:\n\n\
                     assembly {\n\
                         // Ensure calldata has at least selector\n\
                         if lt(calldatasize(), 4) { revert(0, 0) }\n\
                         calldatacopy(0, 0, calldatasize())\n\
                         // ...\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

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
        let detector = FallbackDelegatecallPatternDetector::new();
        assert_eq!(detector.name(), "Fallback Delegatecall Pattern");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_unfiltered_fallback() {
        let detector = FallbackDelegatecallPatternDetector::new();

        let vulnerable = r#"
            contract Proxy {
                fallback() external payable {
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        assert!(detector.find_unfiltered_fallback_delegatecall(vulnerable).is_some());

        let filtered = r#"
            contract Proxy {
                fallback() external payable {
                    require(msg.sig != UPGRADE_SELECTOR);
                    assembly {
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        assert!(detector.find_unfiltered_fallback_delegatecall(filtered).is_none());
    }

    #[test]
    fn test_receive_delegatecall() {
        let detector = FallbackDelegatecallPatternDetector::new();

        let vulnerable = r#"
            contract Proxy {
                receive() external payable {
                    address impl = implementation;
                    impl.delegatecall("");
                }
            }
        "#;
        assert!(detector.has_receive_delegatecall(vulnerable).is_some());
    }
}
