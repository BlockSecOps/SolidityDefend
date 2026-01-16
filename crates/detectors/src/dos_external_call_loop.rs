use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for DoS via external calls in loops
///
/// Detects patterns where external calls are made within loops,
/// allowing a single malicious recipient to block the entire operation.
pub struct DosExternalCallLoopDetector {
    base: BaseDetector,
}

impl Default for DosExternalCallLoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosExternalCallLoopDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("dos-external-call-loop"),
                "DoS External Call in Loop".to_string(),
                "Detects external calls within loops that can lead to denial of service \
                 if any recipient reverts or consumes excessive gas."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Reentrancy],
                Severity::High,
            ),
        }
    }

    /// Find external calls in loops
    fn find_calls_in_loops(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect for/while loops
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                let func_name = self.find_containing_function(&lines, line_num);
                let loop_end = self.find_block_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");

                // Check for various external call patterns
                if loop_body.contains("transfer(") {
                    let issue = "transfer() in loop".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                if loop_body.contains(".send(") {
                    let issue = "send() in loop".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                if loop_body.contains(".call{") || loop_body.contains(".call(") {
                    let issue = "call() in loop".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for interface/contract calls
                if self.has_external_interface_call(&loop_body) {
                    let issue = "external contract call in loop".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find push payment pattern violations
    fn find_push_payment_pattern(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect functions that distribute to multiple recipients
            if trimmed.contains("function ")
                && (trimmed.contains("distribute")
                    || trimmed.contains("Distribute")
                    || trimmed.contains("payout")
                    || trimmed.contains("Payout")
                    || trimmed.contains("reward")
                    || trimmed.contains("airdrop"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_block_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if it loops and transfers
                if (func_body.contains("for") || func_body.contains("while"))
                    && (func_body.contains("transfer(")
                        || func_body.contains(".send(")
                        || func_body.contains(".call{"))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find batch operations with external calls
    fn find_batch_external_calls(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect batch functions
            if trimmed.contains("function ")
                && (trimmed.contains("batch")
                    || trimmed.contains("Batch")
                    || trimmed.contains("multi")
                    || trimmed.contains("Multi")
                    || trimmed.contains("bulk"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_block_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for loop with external call and no try-catch
                if func_body.contains("for")
                    && (func_body.contains(".call{")
                        || func_body.contains("transfer(")
                        || self.has_external_interface_call(&func_body))
                    && !func_body.contains("try ")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find refund loops
    fn find_refund_loops(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect loops
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                let func_name = self.find_containing_function(&lines, line_num);
                let loop_end = self.find_block_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");

                // Check for refund pattern
                if (loop_body.contains("refund")
                    || loop_body.contains("Refund")
                    || loop_body.contains("withdraw")
                    || loop_body.contains("return"))
                    && (loop_body.contains("transfer(")
                        || loop_body.contains(".send(")
                        || loop_body.contains(".call{"))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn has_external_interface_call(&self, code: &str) -> bool {
        // Check for interface call patterns like IToken(addr).function()
        let interface_patterns = [
            "IERC20(", "IToken(", "IContract(", "IVault(", "IPool(",
            "oracle.", "router.", "factory.", "pool.", "vault.",
        ];

        for pattern in interface_patterns {
            if code.contains(pattern) && code.contains("(") {
                return true;
            }
        }

        // Generic pattern: ISomething(addr).method()
        for line in code.lines() {
            if line.contains("I") && line.contains("(") && line.contains(").") {
                // Rough check for interface pattern
                let trimmed = line.trim();
                if !trimmed.starts_with("//") && !trimmed.starts_with("if") {
                    return true;
                }
            }
        }

        false
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

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_block_end(&self, lines: &[&str], start: usize) -> usize {
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

impl Detector for DosExternalCallLoopDetector {
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

        for (line, func_name, issue) in self.find_calls_in_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' has DoS vulnerability: {}. \
                 A single malicious or failing recipient can block the entire operation.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use pull-over-push pattern:\n\n\
                     // Instead of:\n\
                     for (uint i = 0; i < recipients.length; i++) {\n\
                         recipients[i].transfer(amounts[i]); // DoS risk\n\
                     }\n\n\
                     // Use:\n\
                     mapping(address => uint256) pendingWithdrawals;\n\n\
                     function withdraw() external {\n\
                         uint256 amount = pendingWithdrawals[msg.sender];\n\
                         pendingWithdrawals[msg.sender] = 0;\n\
                         payable(msg.sender).transfer(amount);\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_push_payment_pattern(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses push payment pattern for distribution. \
                 Single failing recipient will revert entire distribution.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Convert to pull payment pattern:\n\n\
                     1. Store amounts in mapping instead of sending\n\
                     2. Let recipients claim their share\n\
                     3. Or use try-catch with failure tracking:\n\n\
                     try recipient.call{value: amount}(\"\") {\n\
                         // success\n\
                     } catch {\n\
                         failedPayments[recipient] = amount;\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_batch_external_calls(source) {
            let message = format!(
                "Function '{}' in contract '{}' makes batch external calls without error handling. \
                 Single failure will revert the entire batch.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add error handling for batch operations:\n\n\
                     for (uint i = 0; i < targets.length; i++) {\n\
                         try IContract(targets[i]).method() {\n\
                             // handle success\n\
                         } catch {\n\
                             // log failure, continue\n\
                             emit BatchCallFailed(targets[i]);\n\
                         }\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_refund_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' refunds in a loop. \
                 Contract rejecting refund will block all subsequent refunds.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement claimable refund pattern:\n\n\
                     mapping(address => uint256) refunds;\n\n\
                     function markRefund(address user, uint256 amount) internal {\n\
                         refunds[user] += amount;\n\
                     }\n\n\
                     function claimRefund() external {\n\
                         uint256 amount = refunds[msg.sender];\n\
                         refunds[msg.sender] = 0;\n\
                         payable(msg.sender).transfer(amount);\n\
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
        let detector = DosExternalCallLoopDetector::new();
        assert_eq!(detector.name(), "DoS External Call in Loop");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
