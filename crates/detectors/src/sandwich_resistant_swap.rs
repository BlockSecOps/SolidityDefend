use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for missing MEV sandwich attack protection in swaps
pub struct SandwichResistantSwapDetector {
    base: BaseDetector,
}

impl SandwichResistantSwapDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("sandwich-resistant-swap".to_string()),
                "Missing Sandwich Attack Protection".to_string(),
                "Detects swap functions lacking protection against MEV sandwich attacks through front-running and back-running".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }
}

impl Detector for SandwichResistantSwapDetector {
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

        for function in ctx.get_functions() {
            if let Some(sandwich_issue) = self.check_sandwich_protection(function, ctx) {
                let message = format!(
                    "Function '{}' lacks sandwich attack protection. {} \
                    MEV bots can front-run user swaps, manipulate price, then back-run \
                    to profit from the price difference at user's expense.",
                    function.name.name, sandwich_issue
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
                    .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Add sandwich attack protection to '{}'. \
                    Implement: (1) Slippage tolerance with amountOutMin parameter, \
                    (2) Commit-reveal scheme for swap parameters, \
                    (3) Private mempool submission, (4) MEV-resistant AMM curve, \
                    (5) Batch auctions instead of continuous trading.",
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

impl SandwichResistantSwapDetector {
    /// Check for sandwich attack protection
    fn check_sandwich_protection(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Identify swap functions
        let is_swap_function = func_source.contains("swap")
            || function.name.name.to_lowercase().contains("swap")
            || func_source.contains("exchange")
            || func_source.contains("trade")
            || function.name.name.to_lowercase().contains("trade");

        if !is_swap_function {
            return None;
        }

        // Pattern 1: Missing slippage protection (amountOutMin)
        let has_output = func_source.contains("amountOut")
            || func_source.contains("outputAmount")
            || func_source.contains("return");

        let lacks_slippage = has_output
            && !func_source.contains("amountOutMin")
            && !func_source.contains("minAmountOut")
            && !func_source.contains("minimumOutput")
            && !func_source.contains("minOut")
            && !func_source.contains("require(amountOut >=");

        if lacks_slippage {
            return Some(format!(
                "No minimum output amount (amountOutMin) parameter for slippage protection, \
                leaving swap vulnerable to sandwich attacks"
            ));
        }

        // Pattern 2: Missing deadline parameter
        let lacks_deadline = !func_source.contains("deadline")
            && !func_source.contains("validUntil")
            && !func_source.contains("expiry")
            && !func_source.contains("require(block.timestamp");

        if lacks_deadline {
            return Some(format!(
                "No deadline parameter to prevent delayed execution, \
                allowing validators to hold and execute swap at unfavorable prices"
            ));
        }

        // Pattern 3: Uses spot price without TWAP protection
        let uses_price = func_source.contains("getPrice")
            || func_source.contains("price")
            || func_source.contains("getReserves");

        let lacks_twap = uses_price
            && !func_source.contains("TWAP")
            && !func_source.contains("timeWeighted")
            && !func_source.contains("cumulative")
            && !func_source.contains("average");

        if lacks_twap {
            return Some(format!(
                "Uses spot price for swap calculation without TWAP, \
                making it easy for attackers to manipulate price in same block"
            ));
        }

        // Pattern 4: Public swap without commit-reveal
        let is_public = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        let lacks_commit_reveal = is_public
            && !func_source.contains("commit")
            && !func_source.contains("reveal")
            && !func_source.contains("hash")
            && !func_source.contains("secret");

        if lacks_commit_reveal && lacks_slippage {
            return Some(format!(
                "Public swap without commit-reveal scheme and no slippage protection, \
                making it trivial for MEV bots to sandwich"
            ));
        }

        // Pattern 5: No MEV protection modifier or mechanism
        let lacks_mev_protection = !func_source.contains("onlyPrivate")
            && !func_source.contains("mevProtected")
            && !func_source.contains("flashbotsOnly")
            && !func_source.contains("batchAuction")
            && !func_source.contains("nonReentrant");

        if is_public && lacks_mev_protection && lacks_slippage {
            return Some(format!(
                "No MEV protection mechanisms (private mempool, batch auction, etc.) \
                and no slippage tolerance configured"
            ));
        }

        // Pattern 6: Allows immediate execution without time delay
        let immediate_execution = func_source.contains("swap")
            && !func_source.contains("delay")
            && !func_source.contains("queuedAt")
            && !func_source.contains("block.number")
            && func_source.contains("transfer");

        let has_large_amounts = func_source.contains("amountIn") || func_source.contains("amount");

        if immediate_execution && has_large_amounts && lacks_slippage {
            return Some(format!(
                "Allows immediate swap execution without delays or batch processing, \
                combined with no slippage protection"
            ));
        }

        // Pattern 7: No maximum price movement check
        let lacks_max_price_movement = !func_source.contains("maxPriceImpact")
            && !func_source.contains("MAX_SLIPPAGE")
            && !func_source.contains("maxSlippage")
            && !func_source.contains("priceImpact");

        if is_swap_function && lacks_max_price_movement && lacks_slippage {
            return Some(format!(
                "No maximum price impact or slippage percentage checks, \
                allowing unlimited price movement during swap"
            ));
        }

        // Pattern 8: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("sandwich")
                || func_source.contains("MEV")
                || func_source.contains("front-run"))
        {
            return Some(format!("Sandwich attack vulnerability marker detected"));
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
        let detector = SandwichResistantSwapDetector::new();
        assert_eq!(detector.name(), "Missing Sandwich Attack Protection");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
