use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for flash callback manipulation vulnerabilities
///
/// Detects patterns where flash loan callbacks can be exploited to
/// manipulate state or steal funds through TOCTOU attacks.
pub struct FlashCallbackManipulationDetector {
    base: BaseDetector,
}

impl Default for FlashCallbackManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FlashCallbackManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("flash-callback-manipulation"),
                "Flash Callback Manipulation".to_string(),
                "Detects flash loan callback patterns vulnerable to state manipulation \
                 through time-of-check-to-time-of-use (TOCTOU) attacks."
                    .to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find flash loan functions with state read before callback
    fn find_state_read_before_callback(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function flash")
                || trimmed.contains("function flashLoan")
                || trimmed.contains("function executeFlash")
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if state is read before callback and used after
                let has_balance_read = func_body.contains("balanceOf")
                    || func_body.contains("getReserves")
                    || func_body.contains("totalSupply");

                let has_callback = func_body.contains("Callback")
                    || func_body.contains("onFlashLoan")
                    || func_body.contains("executeOperation");

                if has_balance_read && has_callback {
                    // Check if same value used after callback
                    if func_body.contains("require(") && func_body.contains("+ fee") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find callback receiver with state modification
    fn find_callback_state_modification(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function onFlashLoan")
                || trimmed.contains("function executeOperation")
                || trimmed.contains("function uniswapV2Call")
                || trimmed.contains("function uniswapV3FlashCallback")
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for price-impacting operations
                let has_swap = func_body.contains("swap(")
                    || func_body.contains("exactInput")
                    || func_body.contains("exactOutput");

                let has_liquidity = func_body.contains("addLiquidity")
                    || func_body.contains("removeLiquidity")
                    || func_body.contains("mint(")
                    || func_body.contains("burn(");

                if has_swap || has_liquidity {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find oracle reads in flash context
    fn find_oracle_in_flash(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function onFlashLoan")
                || trimmed.contains("function executeOperation")
                || (trimmed.contains("function ") && trimmed.contains("Callback"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for oracle reads
                if func_body.contains("getPrice")
                    || func_body.contains("latestAnswer")
                    || func_body.contains("latestRoundData")
                    || func_body.contains("consult")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find flash functions without proper validation
    fn find_unvalidated_flash_callback(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function flash") || trimmed.contains("function flashLoan") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if callback is called without validation
                if func_body.contains(".call")
                    || func_body.contains("Callback(")
                    || func_body.contains("onFlashLoan(")
                {
                    // Check for missing validation
                    if !func_body.contains("require(msg.sender")
                        && !func_body.contains("onlyPool")
                        && !func_body.contains("onlyFlashLoaner")
                    {
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

impl Detector for FlashCallbackManipulationDetector {
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

        for (line, func_name) in self.find_state_read_before_callback(source) {
            let message = format!(
                "Function '{}' in contract '{}' reads state before flash callback. \
                 Callback can manipulate state causing TOCTOU vulnerability.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent flash callback manipulation:\n\n\
                     1. Read state AFTER callback completes:\n\
                     callback();\n\
                     uint256 balance = token.balanceOf(address(this));\n\
                     require(balance >= expected);\n\n\
                     2. Use reentrancy locks during flash\n\
                     3. Validate state changes atomically"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_callback_state_modification(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs swaps/liquidity changes in flash callback. \
                 This can manipulate prices and reserves during the flash.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect against callback price manipulation:\n\n\
                     1. Use TWAP oracles instead of spot prices\n\
                     2. Add slippage protection\n\
                     3. Implement flash loan guards in pools\n\
                     4. Check reserves before and after callback"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_oracle_in_flash(source) {
            let message = format!(
                "Function '{}' in contract '{}' reads oracle in flash callback. \
                 Oracle can be manipulated within the same transaction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect oracle reads from flash manipulation:\n\n\
                     1. Use time-weighted average prices (TWAP)\n\
                     2. Check for flash loan in progress\n\
                     3. Use multiple oracle sources\n\
                     4. Add manipulation-resistant oracle design"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_unvalidated_flash_callback(source) {
            let message = format!(
                "Function '{}' in contract '{}' executes callback without validation. \
                 Arbitrary callbacks can execute malicious code.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Validate flash loan callbacks:\n\n\
                     1. Verify callback source:\n\
                     require(msg.sender == address(pool));\n\n\
                     2. Use whitelisted callback targets\n\
                     3. Implement callback interface checks"
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
        let detector = FlashCallbackManipulationDetector::new();
        assert_eq!(detector.name(), "Flash Callback Manipulation");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
