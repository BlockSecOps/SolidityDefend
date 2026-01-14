use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for nested callback reentrancy vulnerabilities
///
/// Detects patterns where nested safe callbacks (like onERC721Received
/// calling another safeTransferFrom) can enable state corruption.
pub struct NestedCallbackReentrancyDetector {
    base: BaseDetector,
}

impl Default for NestedCallbackReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NestedCallbackReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("nested-callback-reentrancy"),
                "Nested Callback Reentrancy".to_string(),
                "Detects nested safe callbacks that can enable state corruption through \
                 chained reentrancy attacks."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Find nested callback patterns
    fn find_nested_callbacks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for callback functions that make external calls
            if trimmed.contains("function onERC721Received")
                || trimmed.contains("function onERC1155Received")
                || trimmed.contains("function onERC1155BatchReceived")
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if callback makes another safe transfer
                if func_body.contains("safeTransfer")
                    || func_body.contains("safeMint")
                    || func_body.contains("safeTransferFrom")
                {
                    findings.push((line_num as u32 + 1, "onERC*Received".to_string()));
                }
            }
        }

        findings
    }

    /// Find callback chains in flash loans
    fn find_flash_callback_chains(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for flash loan callbacks
            if trimmed.contains("function executeOperation")
                || trimmed.contains("function onFlashLoan")
                || trimmed.contains("function uniswapV2Call")
                || trimmed.contains("function uniswapV3FlashCallback")
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for nested external calls in callback
                let external_call_count = func_body.matches(".call").count()
                    + func_body.matches("transfer(").count()
                    + func_body.matches("safeTransfer").count();

                if external_call_count > 1 {
                    let func_name = self.extract_function_name(trimmed);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find state changes in callbacks
    fn find_callback_state_changes(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function on") && trimmed.contains("Received") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for state changes in callback
                let has_state_change = func_body.contains(" = ")
                    && !func_body.contains("==")
                    && (func_body.contains("balance")
                        || func_body.contains("total")
                        || func_body.contains("count")
                        || func_body.contains("owner"));

                if has_state_change {
                    let func_name = self.extract_function_name(trimmed);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for NestedCallbackReentrancyDetector {
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

        for (line, func_name) in self.find_nested_callbacks(source) {
            let message = format!(
                "Function '{}' in contract '{}' contains nested safe callbacks. \
                 This can enable chained reentrancy through multiple callback invocations.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent nested callback reentrancy:\n\n\
                     1. Use reentrancy guards in callback functions\n\
                     2. Avoid making safe transfers from within callbacks\n\
                     3. Use pull pattern instead of push in callbacks\n\
                     4. Complete all state changes before callback returns"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_flash_callback_chains(source) {
            let message = format!(
                "Function '{}' in contract '{}' has multiple external calls in flash callback. \
                 Nested calls can enable complex reentrancy attacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect flash loan callbacks:\n\n\
                     1. Use reentrancy guards\n\
                     2. Validate callback source\n\
                     3. Minimize external calls in callback\n\
                     4. Follow checks-effects-interactions"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_callback_state_changes(source) {
            let message = format!(
                "Function '{}' in contract '{}' modifies state in callback. \
                 State changes in callbacks can be exploited through reentrancy.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Avoid state changes in callbacks:\n\n\
                     1. Use a separate function for state updates\n\
                     2. Apply reentrancy guards\n\
                     3. Use commit-reveal pattern\n\
                     4. Validate caller and context"
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
        let detector = NestedCallbackReentrancyDetector::new();
        assert_eq!(detector.name(), "Nested Callback Reentrancy");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
