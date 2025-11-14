use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for price manipulation and front-running vulnerabilities
///
/// This detector identifies patterns where contracts rely on manipulable price sources
/// without proper validation, enabling front-running and price manipulation attacks.
///
/// **Vulnerability:** CWE-362 (Concurrent Execution), CWE-841 (Improper Enforcement of Behavioral Workflow)
/// **Severity:** High
///
/// ## Description
///
/// Price manipulation vulnerabilities occur when:
/// 1. Contract uses spot prices from AMMs (Uniswap, etc.) without TWAP
/// 2. Price oracles can be manipulated via flash loans
/// 3. No validation of price reasonableness or staleness
/// 4. Missing price deviation limits or circuit breakers
/// 5. Large trades can manipulate prices before/after victim transactions
///
/// This creates opportunities for:
/// - Flash loan attacks to manipulate price oracles
/// - Sandwich attacks on price-dependent operations
/// - Front-running trades to affect price calculations
/// - Oracle manipulation to extract value
/// - MEV extraction via price manipulation
///
/// Common vulnerable patterns:
/// - Direct calls to AMM `getAmountOut` without validation
/// - Using `balanceOf` for price calculations
/// - Spot price queries without TWAP
/// - No staleness checks on oracle prices
/// - Missing price deviation bounds
/// - No circuit breakers for extreme price moves
///
pub struct PriceManipulationFrontrunDetector {
    base: BaseDetector,
}

impl Default for PriceManipulationFrontrunDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PriceManipulationFrontrunDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("price-manipulation-frontrun".to_string()),
                "Price Manipulation Front-Running".to_string(),
                "Detects vulnerable price oracle usage that enables manipulation and front-running attacks"
                    .to_string(),
                vec![
                    DetectorCategory::MEV,
                    DetectorCategory::Logic,
                    DetectorCategory::DeFi,
                ],
                Severity::High,
            ),
        }
    }

    /// Checks if function has price manipulation vulnerability
    fn has_price_manipulation(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // Skip if function is internal/private
        if function.visibility != ast::Visibility::Public && function.visibility != ast::Visibility::External {
            return None;
        }

        // Skip ALL view/pure getter functions - they're read-only and implement price logic
        if (function.mutability == ast::StateMutability::View || function.mutability == ast::StateMutability::Pure) &&
           (func_name_lower.starts_with("get") || func_name_lower.starts_with("calculate") ||
            func_name_lower.starts_with("median") || func_name_lower.starts_with("twap")) {
            return None;
        }

        // Check for price-dependent operations
        let is_price_dependent = self.is_price_dependent(&func_source, &func_name_lower);
        if !is_price_dependent {
            return None;
        }

        // Pattern 1: Spot price from AMM without TWAP or alternative protections
        if self.uses_spot_price(&func_source) &&
           !self.has_twap_protection(&func_source) &&
           !self.has_price_bounds(&func_source) &&
           !self.has_circuit_breaker(&func_source) {
            return Some(format!(
                "Uses manipulable spot price from AMM. Function '{}' relies on spot price \
                (getAmountOut, getReserves) without TWAP protection. \
                Vulnerable to flash loan price manipulation",
                function.name.name
            ));
        }

        // Pattern 2: BalanceOf for pricing without validation
        if self.uses_balance_for_price(&func_source) && !self.has_price_validation(&func_source) {
            return Some(format!(
                "Uses balanceOf for price calculation. Function '{}' calculates prices \
                using token balances which can be manipulated via flash loans or large trades",
                function.name.name
            ));
        }

        // Pattern 3: External price oracle without staleness check or alternative protections
        // Allow deviation bounds, multiple oracles, circuit breakers, or price bounds as alternatives
        if self.uses_external_oracle(&func_source) &&
           !self.has_staleness_check(&func_source) &&
           !self.has_deviation_check(&func_source) &&
           !self.uses_multiple_oracles(&func_source) &&
           !self.has_circuit_breaker(&func_source) &&
           !self.has_price_bounds(&func_source) {
            return Some(format!(
                "Price oracle without staleness check. Function '{}' uses external price \
                oracle but doesn't validate timestamp/staleness. Stale prices enable arbitrage",
                function.name.name
            ));
        }

        // Pattern 4: No price deviation bounds or alternative protections
        // Allow staleness checks, multiple oracles, circuit breakers, or price bounds as alternatives
        if self.uses_price_feed(&func_source) &&
           !self.has_deviation_check(&func_source) &&
           !self.has_staleness_check(&func_source) &&
           !self.uses_multiple_oracles(&func_source) &&
           !self.has_circuit_breaker(&func_source) &&
           !self.has_price_bounds(&func_source) {
            return Some(format!(
                "Missing price deviation bounds. Function '{}' accepts prices without \
                validating reasonable deviation limits. Extreme price moves can be exploited",
                function.name.name
            ));
        }

        // Pattern 5: Large value operation without price impact check
        if self.is_large_value_operation(&func_source, &func_name_lower) &&
           !self.has_price_impact_check(&func_source) {
            return Some(format!(
                "Large value operation without price impact check. Function '{}' performs \
                significant value operations that can manipulate prices without validation",
                function.name.name
            ));
        }

        None
    }

    /// Checks if function is price-dependent
    fn is_price_dependent(&self, source: &str, func_name: &str) -> bool {
        func_name.contains("swap") ||
        func_name.contains("exchange") ||
        func_name.contains("trade") ||
        func_name.contains("liquidate") ||
        func_name.contains("borrow") ||
        func_name.contains("repay") ||
        source.contains("price") ||
        source.contains("getAmountOut") ||
        source.contains("getReserves") ||
        source.contains("balanceOf") && (source.contains("*") || source.contains("/"))
    }

    /// Checks for spot price usage from AMMs
    fn uses_spot_price(&self, source: &str) -> bool {
        source.contains("getAmountOut") ||
        source.contains("getReserves") ||
        (source.contains("reserve") && source.contains("/")) ||
        source.contains("spot") && source.contains("price")
    }

    /// Checks for TWAP protection
    fn has_twap_protection(&self, source: &str) -> bool {
        source.contains("TWAP") ||
        source.contains("twap") ||
        source.contains("timeWeighted") ||
        source.contains("averagePrice") ||
        source.contains("cumulativePrice") ||
        source.contains("observe") || // Uniswap V3 TWAP
        source.contains("tickCumulative")
    }

    /// Checks if balanceOf is used for price calculations
    fn uses_balance_for_price(&self, source: &str) -> bool {
        source.contains("balanceOf") &&
        (source.contains("*") || source.contains("/") || source.contains("mul") || source.contains("div")) &&
        (source.contains("price") || source.contains("amount") || source.contains("value"))
    }

    /// Checks for external oracle usage
    fn uses_external_oracle(&self, source: &str) -> bool {
        source.contains("oracle") ||
        source.contains("Oracle") ||
        source.contains("priceFeed") ||
        source.contains("getPrice") ||
        source.contains("latestAnswer") ||
        source.contains("latestRoundData")
    }

    /// Checks for staleness validation
    fn has_staleness_check(&self, source: &str) -> bool {
        ((source.contains("timestamp") || source.contains("updatedAt")) &&
         (source.contains("block.timestamp") || source.contains("block.number")) &&
         (source.contains("-") || source.contains("<=") || source.contains("<"))) ||
        (source.contains("MAX_DELAY") || source.contains("maxDelay") || source.contains("STALE")) ||
        // Recognize TWAP as inherent staleness protection
        self.has_twap_protection(source)
    }

    /// Checks for price validation
    fn has_price_validation(&self, source: &str) -> bool {
        (source.contains("require") || source.contains("revert")) &&
        source.contains("price") &&
        (source.contains(">") || source.contains("<") || source.contains("!="))
    }

    /// Checks if function uses price feeds
    fn uses_price_feed(&self, source: &str) -> bool {
        source.contains("getPrice") ||
        source.contains("latestAnswer") ||
        source.contains("latestRoundData") ||
        source.contains("priceFeed")
    }

    /// Checks for price deviation validation
    fn has_deviation_check(&self, source: &str) -> bool {
        (source.contains("maxDeviation") ||
         source.contains("priceDeviation") ||
         source.contains("deviationThreshold") ||
         source.contains("MAX_DEVIATION") ||
         source.contains("deviation")) &&
        (source.contains("require") || source.contains("revert") || source.contains("<=") || source.contains(">="))
    }

    /// Checks if this is a large value operation
    fn is_large_value_operation(&self, source: &str, func_name: &str) -> bool {
        func_name.contains("liquidate") ||
        func_name.contains("flash") ||
        source.contains("liquidation") ||
        source.contains("flashLoan") ||
        source.contains("flashSwap")
    }

    /// Checks for price impact validation
    fn has_price_impact_check(&self, source: &str) -> bool {
        source.contains("priceImpact") ||
        source.contains("slippage") ||
        (source.contains("before") && source.contains("after") && source.contains("price"))
    }

    /// Checks for circuit breaker pattern
    fn has_circuit_breaker(&self, source: &str) -> bool {
        source.contains("circuitBreaker") ||
        source.contains("circuit_breaker") ||
        (source.contains("paused") || source.contains("emergency"))
    }

    /// Checks for multiple oracle usage
    fn uses_multiple_oracles(&self, source: &str) -> bool {
        source.contains("median") ||
        source.contains("oracles[") ||
        source.contains("multiple") && source.contains("oracle")
    }

    /// Checks for price bounds (min/max)
    fn has_price_bounds(&self, source: &str) -> bool {
        (source.contains("minPrice") && source.contains("maxPrice")) ||
        (source.contains("min") && source.contains("max") && source.contains("price")) ||
        (source.contains("minAmountOut") || source.contains("amountOutMin"))
    }

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

impl Detector for PriceManipulationFrontrunDetector {
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
            if let Some(issue) = self.has_price_manipulation(function, ctx) {
                let message = format!(
                    "Function '{}' has price manipulation vulnerability. {} \
                    This enables flash loan attacks, sandwich attacks, and MEV extraction \
                    via price oracle manipulation. Attackers can manipulate prices and \
                    extract value from victim transactions",
                    function.name.name, issue
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
                    .with_cwe(362) // CWE-362: Concurrent Execution
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Fix price manipulation in '{}'. Implement: \
                        (1) Use TWAP (Time-Weighted Average Price) instead of spot prices; \
                        (2) Validate price staleness: require(block.timestamp - updatedAt <= MAX_DELAY); \
                        (3) Add price deviation bounds: require(newPrice >= minPrice && newPrice <= maxPrice); \
                        (4) Use multiple oracle sources and median prices; \
                        (5) Implement circuit breakers for extreme price moves; \
                        (6) Add price impact validation for large operations; \
                        (7) Consider commit-reveal for price-sensitive operations",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_metadata() {
        let detector = PriceManipulationFrontrunDetector::new();
        assert_eq!(detector.id().0, "price-manipulation-frontrun");
        assert_eq!(detector.name(), "Price Manipulation Front-Running");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detector_categories() {
        let detector = PriceManipulationFrontrunDetector::new();
        let categories = detector.categories();
        assert!(categories.contains(&DetectorCategory::MEV));
        assert!(categories.contains(&DetectorCategory::Logic));
        assert!(categories.contains(&DetectorCategory::DeFi));
    }
}
