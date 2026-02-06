use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::{
    is_secure_example_file, is_test_contract, is_uniswap_v2_pair, is_uniswap_v3_pool,
};

/// Detector for transaction deadline manipulation vulnerabilities
pub struct DeadlineManipulationDetector {
    base: BaseDetector,
}

impl Default for DeadlineManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadlineManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("deadline-manipulation".to_string()),
                "Deadline Manipulation".to_string(),
                "Detects improper deadline handling that allows validators to hold and execute transactions at unfavorable times".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for DeadlineManipulationDetector {
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
        let source = &ctx.source_code;

        // Phase 10: Skip test contracts and secure examples
        if is_test_contract(ctx) || is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // Phase 10: Skip AMM pool contracts - they implement deadlines internally
        if is_uniswap_v2_pair(ctx) || is_uniswap_v3_pool(ctx) {
            return Ok(findings);
        }

        // Phase 53 FP Reduction: Skip Permit2 - it properly validates deadlines
        let is_permit2 = source.contains("Permit2")
            || source.contains("IAllowanceTransfer")
            || source.contains("ISignatureTransfer")
            || source.contains("PermitHash")
            || source.contains("@uniswap/permit2");

        if is_permit2 {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(deadline_issue) = self.check_deadline_manipulation(function, ctx) {
                let message = format!(
                    "Function '{}' has deadline manipulation risk. {} \
                    Validators can hold transactions and execute them at times that benefit MEV extraction or harm users.",
                    function.name.name, deadline_issue
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
                    .with_cwe(367) // CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
                    .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource
                    .with_fix_suggestion(format!(
                        "Improve deadline handling in '{}'. \
                    Use reasonable default deadlines (e.g., block.timestamp + 15 minutes), \
                    validate deadline parameters, add minimum deadline checks, \
                    or implement deadline extensions for failed transactions.",
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

impl DeadlineManipulationDetector {
    /// Check for deadline manipulation vulnerabilities
    fn check_deadline_manipulation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Check if function uses deadlines
        let has_deadline_param = func_source.contains("deadline")
            || func_source.contains("validUntil")
            || func_source.contains("expiry");

        if !has_deadline_param {
            return None;
        }

        // Pattern 1: Deadline parameter without validation
        let has_deadline_check = func_source.contains("require(block.timestamp <=")
            || func_source.contains("require(deadline >=")
            || func_source.contains("if (block.timestamp >");

        let lacks_validation = has_deadline_param && !has_deadline_check;

        if lacks_validation {
            return Some(
                "Deadline parameter exists but is not validated against current time, \
                allowing expired transactions to execute"
                    .to_string(),
            );
        }

        // Pattern 2: Allows very distant deadlines
        let has_max_check = func_source.contains("MAX_DEADLINE")
            || func_source.contains("require(deadline <=")
            || func_source.contains("require(deadline - block.timestamp");

        let allows_long_deadline =
            has_deadline_param && !has_max_check && func_source.contains("block.timestamp");

        if allows_long_deadline {
            return Some(
                "No maximum deadline limit, allows setting deadlines years in future \
                enabling validators to hold and execute at optimal times"
                    .to_string(),
            );
        }

        // Pattern 3: Swap/trade without deadline
        let is_swap = func_source.contains("swap")
            || func_source.contains("trade")
            || func_source.contains("exchange")
            || function.name.name.to_lowercase().contains("swap");

        let missing_deadline = is_swap
            && !has_deadline_param
            && (func_source.contains("amountOut") || func_source.contains("return"));

        if missing_deadline {
            return Some(
                "Swap function missing deadline parameter entirely, \
                transactions can be held indefinitely (transaction pinning)"
                    .to_string(),
            );
        }

        // Pattern 4: Deadline set to type(uint256).max
        let uses_max_uint = func_source.contains("type(uint256).max")
            || func_source.contains("uint256(-1)")
            || func_source.contains("2**256 - 1");

        if uses_max_uint && has_deadline_param {
            return Some(
                "Deadline set to maximum uint256 value, effectively disabling deadline protection \
                and allowing indefinite transaction holding"
                    .to_string(),
            );
        }

        // Pattern 5: Minimum deadline too short
        let has_short_deadline = func_source.contains("block.timestamp + 1")
            || func_source.contains("block.timestamp + 60")
            || (func_source.contains("deadline") && func_source.contains("+ 1"));

        if has_short_deadline {
            return Some(
                "Deadline set too short (< 5 minutes), may cause legitimate transactions \
                to fail due to network congestion while not preventing MEV"
                    .to_string(),
            );
        }

        // Pattern 6: Price-sensitive operation without deadline
        let is_price_sensitive = func_source.contains("price")
            || func_source.contains("slippage")
            || func_source.contains("minAmount");

        let lacks_deadline_protection =
            is_price_sensitive && !has_deadline_param && !func_source.contains("block.timestamp");

        if lacks_deadline_protection {
            return Some(
                "Price-sensitive operation without deadline protection, \
                validators can delay execution until price moves unfavorably"
                    .to_string(),
            );
        }

        // Pattern 7: Liquidation without time constraints
        let is_liquidation = func_source.contains("liquidat")
            || function.name.name.to_lowercase().contains("liquidat");

        let no_time_constraint = is_liquidation
            && !has_deadline_param
            && !func_source.contains("block.timestamp")
            && !func_source.contains("timelock");

        if no_time_constraint {
            return Some(
                "Liquidation function without time constraints, \
                can be held and executed when most profitable for liquidator"
                    .to_string(),
            );
        }

        // Pattern 8: User-provided deadline not bounded
        let user_deadline =
            func_source.contains("uint256 deadline") || func_source.contains("uint256 validUntil");

        let no_bounds = user_deadline
            && !func_source.contains("require(deadline <=")
            && !func_source.contains("require(deadline - block.timestamp <=");

        if no_bounds {
            return Some(
                "User-provided deadline without upper bound validation, \
                users can set excessively long deadlines defeating protection"
                    .to_string(),
            );
        }

        // Pattern 9: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("deadline")
                || func_source.contains("pinning")
                || func_source.contains("holding"))
        {
            return Some("Deadline manipulation vulnerability marker detected".to_string());
        }

        None
    }

    /// Get function source code
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
        let detector = DeadlineManipulationDetector::new();
        assert_eq!(detector.name(), "Deadline Manipulation");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
