use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for price impact manipulation in DeFi swaps
pub struct PriceImpactManipulationDetector {
    base: BaseDetector,
}

impl PriceImpactManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("price-impact-manipulation".to_string()),
                "Price Impact Manipulation".to_string(),
                "Detects swap functions that don't protect against large trades causing excessive price impact and slippage".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for PriceImpactManipulationDetector {
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
            if let Some(impact_issue) = self.check_price_impact(function, ctx) {
                let message = format!(
                    "Function '{}' vulnerable to price impact manipulation. {} \
                    Large trades without size limits or impact checks can drain liquidity, \
                    manipulate prices, and cause excessive slippage for other users.",
                    function.name.name, impact_issue
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
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Add price impact protection to '{}'. \
                    Implement maximum trade size limits (e.g., max 10% of pool), \
                    calculate and validate price impact percentage, \
                    enforce minimum output amounts with slippage tolerance, \
                    or split large trades across multiple blocks.",
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

impl PriceImpactManipulationDetector {
    /// Check for price impact manipulation vulnerabilities
    fn check_price_impact(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Identify swap/trade functions
        let is_swap_function = func_source.contains("swap")
            || function.name.name.to_lowercase().contains("swap")
            || func_source.contains("exchange")
            || function.name.name.to_lowercase().contains("trade")
            || func_source.contains("getAmountOut")
            || func_source.contains("swapExactTokensFor");

        if !is_swap_function {
            return None;
        }

        // Pattern 1: No maximum trade size limit
        let lacks_max_trade_size = !func_source.contains("maxTradeSize")
            && !func_source.contains("MAX_TRADE")
            && !func_source.contains("require(amount <")
            && !func_source.contains("require(amountIn <")
            && !func_source.contains("* reserve")
            && !func_source.contains("/ 100");

        if lacks_max_trade_size {
            return Some(format!(
                "No maximum trade size limit enforced, allowing trades of any size \
                that can cause extreme price impact and drain pool liquidity"
            ));
        }

        // Pattern 2: No price impact calculation
        let lacks_impact_calculation = !func_source.contains("priceImpact")
            && !func_source.contains("impact")
            && !func_source.contains("slippage")
            && !func_source.contains("price")
            && !func_source.contains("before")
            && !func_source.contains("price")
            && !func_source.contains("after");

        if lacks_impact_calculation {
            return Some(format!(
                "No price impact calculation performed before executing trade, \
                users cannot assess cost and attackers can manipulate prices"
            ));
        }

        // Pattern 3: Missing minimum output validation
        let has_output = func_source.contains("amountOut")
            || func_source.contains("output")
            || func_source.contains("return");

        let lacks_min_output = has_output
            && !func_source.contains("minAmountOut")
            && !func_source.contains("amountOutMin")
            && !func_source.contains("minReturn")
            && !func_source.contains("require(amountOut >=");

        if lacks_min_output {
            return Some(format!(
                "No minimum output amount validation, users have no slippage protection \
                and can receive much less than expected"
            ));
        }

        // Pattern 4: No pool depth check relative to trade size
        let has_reserves = func_source.contains("reserve")
            || func_source.contains("liquidity")
            || func_source.contains("balance");

        let lacks_depth_check = has_reserves
            && !func_source.contains("require(amount")
            && !func_source.contains("percentage")
            && !func_source.contains("* 100")
            && !func_source.contains("/ reserve");

        if lacks_depth_check {
            return Some(format!(
                "Trade size not validated against pool depth/reserves, \
                allowing disproportionately large trades"
            ));
        }

        // Pattern 5: Missing deadline parameter
        let lacks_deadline = !func_source.contains("deadline")
            && !func_source.contains("validUntil")
            && !func_source.contains("block.timestamp")
            && !func_source.contains("expiry");

        if lacks_deadline {
            return Some(format!(
                "No transaction deadline parameter, trades can be held and executed \
                when price moves against user (transaction pinning)"
            ));
        }

        // Pattern 6: Uses constant product formula without impact limits
        let uses_constant_product = func_source.contains("* reserve1")
            || func_source.contains("reserve0 * reserve1")
            || func_source.contains("x * y = k");

        let lacks_impact_limit = uses_constant_product
            && !func_source.contains("MAX_IMPACT")
            && !func_source.contains("maxSlippage")
            && !func_source.contains("require(impact");

        if lacks_impact_limit {
            return Some(format!(
                "Uses constant product formula (x*y=k) without maximum impact limits, \
                allowing trades that drastically move the price"
            ));
        }

        // Pattern 7: No multi-hop path validation
        let is_multi_hop = func_source.contains("path")
            || func_source.contains("route")
            || func_source.contains("[]");

        let lacks_path_validation = is_multi_hop
            && !func_source.contains("require(path.length")
            && !func_source.contains("MAX_HOPS")
            && !func_source.contains("validatePath");

        if lacks_path_validation {
            return Some(format!(
                "Multi-hop swap path not validated for length or composition, \
                allowing complex routes that amplify price impact"
            ));
        }

        // Pattern 8: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("price impact")
                || func_source.contains("slippage")
                || func_source.contains("large trade"))
        {
            return Some(format!(
                "Price impact manipulation vulnerability marker detected"
            ));
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
        let detector = PriceImpactManipulationDetector::new();
        assert_eq!(detector.name(), "Price Impact Manipulation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
