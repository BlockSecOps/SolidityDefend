use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for multicall msg.value reuse vulnerabilities
///
/// Detects patterns where msg.value is reused across multiple calls
/// in batch/multicall operations, allowing double-spending of ETH.
pub struct MulticallMsgvalueReuseDetector {
    base: BaseDetector,
}

impl Default for MulticallMsgvalueReuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MulticallMsgvalueReuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("multicall-msgvalue-reuse"),
                "Multicall msg.value Reuse".to_string(),
                "Detects multicall/batch operations where msg.value can be reused \
                 across multiple calls, enabling ETH double-spending attacks."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Find multicall functions with msg.value
    fn find_multicall_msgvalue(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for multicall/batch functions
            if trimmed.contains("function ")
                && (trimmed.contains("multicall")
                    || trimmed.contains("batch")
                    || trimmed.contains("aggregate"))
                && trimmed.contains("payable")
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if msg.value is used in a loop or delegatecall
                if func_body.contains("msg.value")
                    && (func_body.contains("for (") || func_body.contains("delegatecall"))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find delegatecall loops with payable
    fn find_delegatecall_loop_payable(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") && trimmed.contains("payable") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for delegatecall in loop
                if func_body.contains("for (") && func_body.contains("delegatecall") {
                    // Check if msg.value is passed
                    if func_body.contains("msg.value") || func_body.contains("{value:") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find batch operations without value tracking
    fn find_untracked_value_batch(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") && trimmed.contains("payable") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for array of calls with value
                if (func_body.contains("calls[") || func_body.contains("data["))
                    && func_body.contains("msg.value")
                {
                    // Check if value is tracked/decremented
                    let tracks_value = func_body.contains("remainingValue")
                        || func_body.contains("valueUsed")
                        || func_body.contains("msg.value -")
                        || func_body.contains("-= ");

                    if !tracks_value {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find call forwarding msg.value in loop
    fn find_call_value_loop(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut in_loop = false;
        let mut loop_depth = 0;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Track loop context
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                in_loop = true;
            }

            for c in trimmed.chars() {
                match c {
                    '{' if in_loop => loop_depth += 1,
                    '}' if in_loop => {
                        loop_depth -= 1;
                        if loop_depth == 0 {
                            in_loop = false;
                        }
                    }
                    _ => {}
                }
            }

            // Check for .call with value in loop
            if in_loop
                && (trimmed.contains(".call{value:") || trimmed.contains(".call{ value:"))
                && trimmed.contains("msg.value")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
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

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
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

impl Detector for MulticallMsgvalueReuseDetector {
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

        for (line, func_name) in self.find_multicall_msgvalue(source) {
            let message = format!(
                "Function '{}' in contract '{}' is a payable multicall that may reuse msg.value. \
                 Each call in the batch can spend the same ETH value.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(837)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent msg.value reuse in multicall:\n\n\
                     1. Track remaining value and decrement per call:\n\
                     uint256 remainingValue = msg.value;\n\
                     for (...) {\n\
                         remainingValue -= values[i];\n\
                         target.call{value: values[i]}(...);\n\
                     }\n\n\
                     2. Or require exact value match:\n\
                     require(msg.value == totalValue, \"Wrong value\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_delegatecall_loop_payable(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses delegatecall in a loop with payable. \
                 msg.value is preserved across delegatecalls, enabling reuse.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(837)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid delegatecall loops with msg.value:\n\n\
                     1. Use call instead of delegatecall for value transfers\n\
                     2. Track and validate value consumption\n\
                     3. Use a value accumulator pattern"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_untracked_value_batch(source) {
            let message = format!(
                "Function '{}' in contract '{}' batches calls with msg.value without tracking. \
                 ETH can be spent multiple times.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(837)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Track value in batch operations:\n\n\
                     uint256 totalUsed;\n\
                     for (uint i = 0; i < calls.length; i++) {\n\
                         totalUsed += values[i];\n\
                         require(totalUsed <= msg.value, \"Insufficient value\");\n\
                         // ... call\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_call_value_loop(source) {
            let message = format!(
                "Function '{}' in contract '{}' forwards msg.value in a loop. \
                 Same ETH value sent to each iteration.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(837)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Don't reuse msg.value in loops:\n\n\
                     // BAD: Same value for each call\n\
                     for (...) target.call{value: msg.value}(...);\n\n\
                     // GOOD: Separate values array\n\
                     for (...) target.call{value: values[i]}(...);"
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
        let detector = MulticallMsgvalueReuseDetector::new();
        assert_eq!(detector.name(), "Multicall msg.value Reuse");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
