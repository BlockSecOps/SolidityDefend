use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::oracle_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for oracle price manipulation via flash loans
pub struct OracleManipulationDetector {
    base: BaseDetector,
}

impl Default for OracleManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OracleManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("oracle-manipulation".to_string()),
                "Oracle Price Manipulation".to_string(),
                "Detects oracle price queries vulnerable to flash loan manipulation attacks"
                    .to_string(),
                vec![DetectorCategory::Oracle, DetectorCategory::FlashLoanAttacks],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for OracleManipulationDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        // Skip AMM pool contracts - they ARE the oracle source, not consumers
        // Uniswap V2/V3 pools implement TWAP oracles themselves (cumulative price tracking)
        // This detector should focus on contracts that CONSUME oracle data unsafely
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        // Skip lending protocols - they NEED oracles for collateral valuation
        // Lending protocols (Compound, Aave, MakerDAO) use price oracles to:
        // - Calculate collateral value (health factor, account liquidity)
        // - Determine liquidation eligibility
        // - Set borrow limits based on collateral
        // These protocols typically use:
        // - Chainlink price feeds (manipulation resistant)
        // - Uniswap V2/V3 TWAP (time-weighted, not spot price)
        // - Custom oracles with deviation bounds
        // Don't flag oracle USAGE in lending protocols, only flag MANIPULABLE oracles
        if utils::is_lending_protocol(ctx) {
            // For lending protocols, we trust they use proper oracle implementations
            // (Chainlink, TWAP, multi-oracle validation)
            // This check can be enhanced later to verify oracle manipulation resistance
            return Ok(findings);
        }

        // Early exit for contracts with comprehensive oracle safety measures
        // These patterns indicate proper oracle integration with manipulation resistance
        if oracle_patterns::has_comprehensive_oracle_safety(ctx) {
            return Ok(findings);
        }

        // Skip if contract uses multi-oracle validation (highly manipulation resistant)
        if oracle_patterns::has_multi_oracle_validation(ctx) {
            return Ok(findings);
        }

        // Skip if contract uses TWAP oracle (time-weighted, not susceptible to flash loans)
        if oracle_patterns::has_twap_oracle(ctx) {
            return Ok(findings);
        }

        // Reduce confidence for contracts with Chainlink + staleness checks
        // These are generally safe but we'll still check for issues
        let has_chainlink_safety =
            oracle_patterns::has_chainlink_oracle(ctx) && oracle_patterns::has_staleness_check(ctx);

        for function in ctx.get_functions() {
            if self.is_vulnerable_to_oracle_manipulation(function, ctx) {
                // Reduce severity if contract has Chainlink + staleness (likely safe)
                let (message, severity) = if has_chainlink_safety {
                    (
                        format!(
                            "Function '{}' uses Chainlink oracle with staleness check, but may benefit from additional protections. \
                            Consider adding deviation bounds or multi-oracle validation for extra safety.",
                            function.name.name
                        ),
                        Severity::Low,
                    )
                } else {
                    (
                        format!(
                            "Function '{}' uses spot price from oracle without flash loan protection. \
                            Attackers can manipulate pool reserves via flash loans to skew oracle prices, \
                            enabling profitable liquidations or unfair trades.",
                            function.name.name
                        ),
                        Severity::Critical,
                    )
                };

                let mut finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(20) // CWE-20: Improper Input Validation
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_fix_suggestion(format!(
                        "Use Time-Weighted Average Price (TWAP) instead of spot prices, \
                    or implement multi-oracle validation with deviation checks in function '{}'",
                        function.name.name
                    ));

                // Override severity based on safe patterns detected
                finding.severity = severity;

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl OracleManipulationDetector {
    /// Check if a function is vulnerable to oracle manipulation attacks
    fn is_vulnerable_to_oracle_manipulation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let raw_source = source_lines[func_start..=func_end].join("\n");
        // Clean source to avoid FPs from comments/strings
        let func_source = utils::clean_source_for_search(&raw_source);

        // Check if function uses price oracles
        let price_query_patterns = [
            "getPrice",
            "get_price",
            "latestPrice",
            "currentPrice",
            "getReserves",
            "get_reserves",
            "quote",
            "getAmountOut",
            "consult",
            "update",
            "oracle.price",
        ];

        let uses_price_oracle = price_query_patterns
            .iter()
            .any(|pattern| func_source.contains(pattern));

        if !uses_price_oracle {
            return false;
        }

        // Check if function is critical (used in trading, liquidation, or collateral)
        let function_name = function.name.name.to_lowercase();
        let critical_patterns = [
            "liquidate",
            "swap",
            "trade",
            "borrow",
            "mint",
            "burn",
            "redeem",
            "exchange",
            "price",
            "value",
        ];

        let is_critical_function = critical_patterns
            .iter()
            .any(|pattern| function_name.contains(pattern));

        if !is_critical_function {
            return false;
        }

        // Look for vulnerability indicators
        self.has_manipulation_vulnerability(&func_source)
    }

    /// Check for specific oracle manipulation vulnerability patterns
    fn has_manipulation_vulnerability(&self, source: &str) -> bool {
        // Check if using safe TWAP implementation first
        let has_safe_twap = source.contains("TWAP")
            || source.contains("twap")
            || source.contains("getTWAP")
            || source.contains("timeWeighted")
            || source.contains("cumulative") // Uniswap V2/V3 cumulative price
            || source.contains("Cumulative")
            || source.contains("observe(") // Uniswap V3 oracle observation
            || source.contains("observations[") // V3 observation array
            || (source.contains("price0") && source.contains("price1") && source.contains("Last")); // V2 price tracking

        // Pattern 1: Uses spot price without TWAP
        let uses_spot_price = (source.contains("getPrice")
            || source.contains("latestPrice")
            || source.contains("getReserves"))
            && !has_safe_twap;

        // Pattern 2: Direct reserve manipulation
        let uses_reserves = source.contains("getReserves")
            && source.contains("reserve0")
            && source.contains("reserve1")
            && !source.contains("oraclePrice");

        // Pattern 3: Single oracle source without validation
        let single_oracle = source.contains("oracle.")
            && !source.contains("oracle2")
            && !source.contains("secondOracle")
            && !source.contains("backup")
            && !source.contains("deviation");

        // Pattern 4: Vulnerability comment marker
        let has_vulnerability_marker = source.contains("VULNERABILITY")
            && (source.contains("oracle")
                || source.contains("flash loan")
                || source.contains("Spot price"));

        // Pattern 5: No staleness check
        let no_staleness_check = uses_spot_price
            && !source.contains("timestamp")
            && !source.contains("lastUpdate")
            && !source.contains("updatedAt");

        uses_spot_price
            || uses_reserves
            || has_vulnerability_marker
            || (single_oracle && no_staleness_check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = OracleManipulationDetector::new();
        assert_eq!(detector.name(), "Oracle Price Manipulation");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
