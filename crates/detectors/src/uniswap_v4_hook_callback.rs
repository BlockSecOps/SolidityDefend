use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for Uniswap V4 hook callback vulnerabilities
///
/// Detects patterns where Uniswap V4 hooks can be exploited through
/// improper callback handling and state manipulation.
pub struct UniswapV4HookCallbackDetector {
    base: BaseDetector,
}

impl Default for UniswapV4HookCallbackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UniswapV4HookCallbackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("uniswap-v4-hook-callback"),
                "Uniswap V4 Hook Callback".to_string(),
                "Detects Uniswap V4 hook patterns vulnerable to callback exploitation, \
                 state manipulation, and reentrancy attacks."
                    .to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Reentrancy],
                Severity::High,
            ),
        }
    }

    /// Find hooks with state modification before completion
    fn find_hook_state_modification(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for Uniswap V4 hook functions
            if trimmed.contains("function before") || trimmed.contains("function after") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for hook patterns
                if func_body.contains("beforeSwap")
                    || func_body.contains("afterSwap")
                    || func_body.contains("beforeModify")
                    || func_body.contains("afterModify")
                {
                    // Check for state modification
                    let modifies_state = func_body.contains(" = ")
                        && !func_body.contains("==")
                        && (func_body.contains("balance")
                            || func_body.contains("reserve")
                            || func_body.contains("position")
                            || func_body.contains("fee"));

                    if modifies_state && !func_body.contains("lock") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find hooks without proper pool validation
    fn find_unvalidated_pool_hooks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if (trimmed.contains("function before") || trimmed.contains("function after"))
                && (trimmed.contains("Swap") || trimmed.contains("Modify"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for pool validation
                let validates_pool = func_body.contains("require(msg.sender")
                    || func_body.contains("poolManager")
                    || func_body.contains("onlyPool")
                    || func_body.contains("validatePool");

                if !validates_pool {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find hooks with external calls
    fn find_hook_external_calls(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function before") || trimmed.contains("function after") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for external calls in hooks
                let has_external_call = func_body.contains(".call")
                    || func_body.contains(".transfer(")
                    || func_body.contains("safeTransfer")
                    || func_body.contains(".swap(");

                if has_external_call && !func_body.contains("nonReentrant") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find dynamic fee hooks with manipulation risk
    fn find_dynamic_fee_manipulation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") && (trimmed.contains("Fee") || trimmed.contains("fee"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for dynamic fee calculation
                if func_body.contains("return")
                    && (func_body.contains("fee") || func_body.contains("Fee"))
                {
                    // Check for manipulation vectors
                    let manipulation_risk = func_body.contains("block.timestamp")
                        || func_body.contains("block.number")
                        || func_body.contains("tx.origin")
                        || func_body.contains("balanceOf");

                    if manipulation_risk {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find hooks returning delta with improper calculation
    fn find_improper_delta_return(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function before") || trimmed.contains("function after") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for delta returns
                if func_body.contains("BalanceDelta") || func_body.contains("toBalanceDelta") {
                    // Check for potential manipulation
                    let has_external_input = func_body.contains("calldata")
                        || func_body.contains("msg.sender")
                        || func_body.contains("params.");

                    if has_external_input && !func_body.contains("require(") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
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

impl Detector for UniswapV4HookCallbackDetector {
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

        for (line, func_name) in self.find_hook_state_modification(source) {
            let message = format!(
                "Function '{}' in contract '{}' modifies state in Uniswap V4 hook. \
                 State changes in hooks can be exploited through callback manipulation.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect state in V4 hooks:\n\n\
                     1. Use transient storage for hook state\n\
                     2. Validate state changes match expected delta\n\
                     3. Lock critical state during hook execution\n\
                     4. Complete all checks before state modification"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_unvalidated_pool_hooks(source) {
            let message = format!(
                "Function '{}' in contract '{}' is a V4 hook without pool validation. \
                 Unauthorized callers can invoke hook with malicious parameters.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Validate hook caller:\n\n\
                     function beforeSwap(...) external returns (...) {\n\
                         require(msg.sender == address(poolManager));\n\
                         // ... hook logic\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_hook_external_calls(source) {
            let message = format!(
                "Function '{}' in contract '{}' makes external calls in V4 hook. \
                 External calls can enable reentrancy and state manipulation.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Minimize external calls in hooks:\n\n\
                     1. Use PoolManager's settlement functions\n\
                     2. Add reentrancy protection\n\
                     3. Validate all external call results\n\
                     4. Follow checks-effects-interactions"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_dynamic_fee_manipulation(source) {
            let message = format!(
                "Function '{}' in contract '{}' calculates dynamic fees with manipulable inputs. \
                 Fee can be manipulated through block variables or balances.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect dynamic fee calculation:\n\n\
                     1. Use TWAP for price-based fees\n\
                     2. Bound fee within safe range\n\
                     3. Avoid manipulable block variables\n\
                     4. Add fee change limits"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_improper_delta_return(source) {
            let message = format!(
                "Function '{}' in contract '{}' returns BalanceDelta from external input. \
                 Unvalidated delta can cause accounting errors.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Validate BalanceDelta returns:\n\n\
                     1. Verify delta matches expected calculation\n\
                     2. Bound delta within safe limits\n\
                     3. Validate external input before using\n\
                     4. Use SafeCast for conversions"
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
        let detector = UniswapV4HookCallbackDetector::new();
        assert_eq!(detector.name(), "Uniswap V4 Hook Callback");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
