use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for DoS by failed transfer vulnerability
///
/// Detects when a function can be blocked if a transfer to an external address fails.
/// This is also known as the "push over pull" anti-pattern.
pub struct DosFailedTransferDetector {
    base: BaseDetector,
}

impl Default for DosFailedTransferDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosFailedTransferDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("dos-failed-transfer".to_string()),
                "DoS by Failed Transfer".to_string(),
                "Detects push pattern transfers that can cause DoS if recipient reverts. Use pull pattern instead.".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Check if function has DoS by failed transfer vulnerability
    fn check_dos_failed_transfer(&self, function_source: &str) -> bool {
        // Pattern 1: transfer() or send() in a function that updates state after
        let has_transfer = function_source.contains(".transfer(")
            || function_source.contains(".send(")
            || (function_source.contains(".call{value:") && !function_source.contains("(success,"));

        if !has_transfer {
            return false;
        }

        // Phase 52 FP Reduction: Skip if using proper call with success check
        // Pattern: (bool success, ) = payable(addr).call{value: ...}(""); require(success);
        let has_proper_call_check = function_source.contains("(bool success")
            && function_source.contains(".call{value:")
            && (function_source.contains("require(success")
                || function_source.contains("if (!success")
                || function_source.contains("if(!success"));

        if has_proper_call_check {
            return false;
        }

        // Phase 52 FP Reduction: Skip if using Address.sendValue (OZ pattern)
        if function_source.contains("Address.sendValue") || function_source.contains("sendValue(") {
            return false;
        }

        // Phase 52 FP Reduction: Skip pull pattern implementations
        // These are safe: mapping-based withdrawals
        let is_pull_pattern = (function_source.contains("pendingWithdraw")
            || function_source.contains("pendingReturns")
            || function_source.contains("balances[msg.sender]")
            || function_source.contains("owed[msg.sender]"))
            && function_source.contains("msg.sender");

        if is_pull_pattern {
            return false;
        }

        // Pattern 2: Transfer happens before state updates (push pattern)
        // Look for transfer followed by state changes (assignments, storage writes)
        let lines: Vec<&str> = function_source.lines().collect();
        let mut found_transfer = false;
        let mut has_state_change_after = false;

        for line in lines {
            let trimmed = line.trim();

            // Check for transfer
            if trimmed.contains(".transfer(") || trimmed.contains(".send(") {
                found_transfer = true;
                continue;
            }

            // If we found a transfer, check for state changes after
            if found_transfer {
                // State changes: assignments, mappings updates, array operations
                if trimmed.contains(" = ")
                    && !trimmed.starts_with("//")
                    && !trimmed.contains("==")
                    && !trimmed.contains("!=")
                    && !trimmed.contains("<=")
                    && !trimmed.contains(">=")
                {
                    has_state_change_after = true;
                    break;
                }
            }
        }

        // Pattern 3: Transfer in a loop (especially dangerous)
        let transfer_in_loop = has_transfer
            && (function_source.contains("for (") || function_source.contains("while ("));

        // Pattern 4: Transfer without error handling
        let no_error_handling = has_transfer
            && !function_source.contains("require(")
            && !function_source.contains("if (")
            && !function_source.contains("try ")
            && !function_source.contains("(bool success");

        // Pattern 5: Refund pattern (transfer to previous participant)
        let is_refund_pattern = has_transfer
            && (function_source.contains("refund")
                || function_source.contains("current")
                || function_source.contains("previous")
                || function_source.contains("leader")
                || function_source.contains("winner"));

        // Vulnerable if:
        // - Transfer in loop (always vulnerable)
        // - Refund pattern without error handling (auction/bidding DoS)
        // - Transfer before state change (violates checks-effects-interactions)
        transfer_in_loop || (is_refund_pattern && no_error_handling) || has_state_change_after
    }
}

impl Detector for DosFailedTransferDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check all functions
        for function in ctx.get_functions() {
            if function.body.is_none() {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            if self.check_dos_failed_transfer(&func_source) {
                let message = format!(
                    "Function '{}' uses push pattern for transfers which can cause DoS if recipient reverts. \
                    A malicious or buggy recipient contract can block this function by rejecting payments. \
                    Use the pull pattern (withdrawal pattern) instead where users withdraw their own funds.",
                    function.name.name
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_fix_suggestion(format!(
                        "Refactor '{}' to use pull pattern instead of push. \
                        Store pending withdrawals in a mapping and let users withdraw their own funds. \
                        Example: balances[user] = amount; then separate withdraw() function. \
                        Use OpenZeppelin's PullPayment contract for reference.",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DosFailedTransferDetector {
    /// Extract function source code from context
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DosFailedTransferDetector::new();
        assert_eq!(detector.name(), "DoS by Failed Transfer");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
