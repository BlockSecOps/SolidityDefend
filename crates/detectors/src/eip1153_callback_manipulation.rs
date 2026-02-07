use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-1153 callback manipulation vulnerabilities
///
/// Detects transient storage state that can be manipulated during callbacks,
/// leading to unexpected behavior when control returns to the caller.
///
/// Vulnerable pattern:
/// ```solidity
/// contract VulnerableCallback {
///     function process(address token) external {
///         assembly { tstore(0, 100) }  // Set transient state
///
///         // Callback to external contract
///         ICallback(msg.sender).onProcess();  // Can modify transient state!
///
///         assembly {
///             let value := tload(0)  // May not be 100 anymore!
///             // Use value assuming it's still 100
///         }
///     }
/// }
/// ```
pub struct Eip1153CallbackManipulationDetector {
    base: BaseDetector,
}

impl Default for Eip1153CallbackManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip1153CallbackManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip1153-callback-manipulation"),
                "EIP-1153 Callback Manipulation".to_string(),
                "Detects transient storage state that can be manipulated during external \
                 callbacks. When a contract stores state in transient storage and then \
                 makes an external call, the callee can manipulate that transient state."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find pattern: tstore -> external call -> tload
    fn find_tstore_call_tload(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Found function start
            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for the dangerous pattern
                if let Some(pattern) = self.check_tstore_call_tload_pattern(&func_body) {
                    findings.push((line_num as u32 + 1, func_name, pattern));
                }
            }
        }

        findings
    }

    /// Check if function has tstore -> call -> tload pattern
    fn check_tstore_call_tload_pattern(&self, func_body: &str) -> Option<String> {
        let lines: Vec<&str> = func_body.lines().collect();

        let mut tstore_line: Option<usize> = None;
        let mut call_line: Option<usize> = None;
        let mut tload_after_call = false;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("tstore(") {
                tstore_line = Some(i);
            }

            // External call patterns
            if tstore_line.is_some()
                && (line.contains(".call(")
                    || line.contains(".call{")
                    || line.contains(".delegatecall(")
                    || line.contains("safeTransfer")
                    || line.contains("onERC")
                    || line.contains("Callback")
                    || line.contains("callback"))
            {
                call_line = Some(i);
            }

            // tload after call
            if call_line.is_some() && line.contains("tload(") {
                tload_after_call = true;
            }
        }

        if tstore_line.is_some() && call_line.is_some() && tload_after_call {
            Some("tstore -> external call -> tload".to_string())
        } else {
            None
        }
    }

    /// Find transient state read after callback hooks
    fn find_read_after_callback(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Common callback function patterns
        let callback_patterns = [
            "onERC721Received",
            "onERC1155Received",
            "onERC1155BatchReceived",
            "onFlashLoan",
            "uniswapV3SwapCallback",
            "pancakeV3SwapCallback",
            "algebraSwapCallback",
            "hook(",
            "Callback(",
            "callback(",
        ];

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &callback_patterns {
                if line.contains(pattern) {
                    // Check if tload happens after this callback
                    let remaining = &lines[line_num..];
                    let remaining_str: String = remaining.join("\n");

                    if remaining_str.contains("tload(") {
                        let func_name = self.find_containing_function(&lines, line_num);
                        findings.push((line_num as u32 + 1, func_name));
                        break;
                    }
                }
            }
        }

        findings
    }

    /// Find unsafe transient state in reentrancy-prone functions
    fn find_reentrancy_unsafe_transient(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for functions that interact with external contracts
            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Has transient operations
                let has_transient = func_body.contains("tstore(") || func_body.contains("tload(");

                // Has external calls that could call back
                let has_callback_risk = func_body.contains("safeTransferFrom")
                    || func_body.contains("_safeMint")
                    || func_body.contains("flash")
                    || func_body.contains("swap");

                // Missing reentrancy guard
                let has_guard = func_body.contains("nonReentrant")
                    || func_body.contains("ReentrancyGuard")
                    || func_body.contains("_lock");

                if has_transient && has_callback_risk && !has_guard {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Extract function name
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    /// Find containing function name
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    /// Find end of function
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

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip1153CallbackManipulationDetector {
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

        // Find tstore -> call -> tload pattern
        let patterns = self.find_tstore_call_tload(source);
        for (line, func_name, pattern) in &patterns {
            let message = format!(
                "Function '{}' in contract '{}' exhibits dangerous pattern: {}. \
                 The external call can modify transient storage before tload reads it, \
                 leading to unexpected values.",
                func_name, contract_name, pattern
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 50)
                .with_cwe(367) // CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent callback manipulation of transient state:\n\n\
                     1. Read transient values BEFORE external calls:\n\
                     assembly { value := tload(slot) }\n\
                     externalContract.callback();  // Can't affect 'value'\n\n\
                     2. Use reentrancy guards:\n\
                     modifier nonReentrant() {\n\
                         assembly {\n\
                             if tload(LOCK_SLOT) { revert(0, 0) }\n\
                             tstore(LOCK_SLOT, 1)\n\
                         }\n\
                         _;\n\
                         assembly { tstore(LOCK_SLOT, 0) }\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Find reads after callbacks
        let callback_reads = self.find_read_after_callback(source);
        for (line, func_name) in callback_reads {
            if patterns.iter().any(|(l, _, _)| *l == line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' reads transient storage after a callback. \
                 The callback could have modified the transient state.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367) // CWE-367: TOCTOU Race Condition
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Cache transient values before callbacks:\n\n\
                     uint256 cachedValue;\n\
                     assembly { cachedValue := tload(slot) }\n\
                     // Callback happens here\n\
                     // Use cachedValue instead of tload"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find reentrancy-unsafe transient usage
        let unsafe_patterns = self.find_reentrancy_unsafe_transient(source);
        for (line, func_name) in unsafe_patterns {
            if patterns.iter().any(|(l, _, _)| *l == line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' uses transient storage with external \
                 calls that could trigger callbacks (safeTransfer, flash, swap) but \
                 lacks reentrancy protection.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367) // CWE-367: TOCTOU Race Condition
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add reentrancy guard when using transient storage with callbacks:\n\n\
                     function process() external nonReentrant {\n\
                         assembly { tstore(slot, value) }\n\
                         token.safeTransferFrom(...);  // Has callback\n\
                         assembly { result := tload(slot) }\n\
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
        let detector = Eip1153CallbackManipulationDetector::new();
        assert_eq!(detector.name(), "EIP-1153 Callback Manipulation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_tstore_call_tload() {
        let detector = Eip1153CallbackManipulationDetector::new();

        let vulnerable = r#"
            contract Vulnerable {
                function process() external {
                    assembly { tstore(0, 100) }
                    msg.sender.call("");
                    assembly {
                        let value := tload(0)
                    }
                }
            }
        "#;
        let findings = detector.find_tstore_call_tload(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_read_after_callback() {
        let detector = Eip1153CallbackManipulationDetector::new();

        // Test the tstore_call_tload pattern which is more reliable
        let vulnerable = r#"
            contract NFTMarket {
                function buy(uint256 tokenId) external {
                    assembly { tstore(0, tokenId) }
                    // onERC721Received callback happens here
                    onERC721Received(address(0), address(0), 0, "");
                    assembly {
                        let stored := tload(0)
                    }
                }
            }
        "#;
        let findings = detector.find_read_after_callback(vulnerable);
        assert!(!findings.is_empty());
    }
}
