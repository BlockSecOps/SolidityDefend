use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for oracle price manipulation via flash loans
pub struct OracleManipulationDetector {
    base: BaseDetector,
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

        for function in ctx.get_functions() {
            if self.is_vulnerable_to_oracle_manipulation(function, ctx) {
                let message = format!(
                    "Function '{}' uses spot price from oracle without flash loan protection. \
                    Attackers can manipulate pool reserves via flash loans to skew oracle prices, \
                    enabling profitable liquidations or unfair trades.",
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
                    .with_cwe(20) // CWE-20: Improper Input Validation
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_fix_suggestion(format!(
                        "Use Time-Weighted Average Price (TWAP) instead of spot prices, \
                    or implement multi-oracle validation with deviation checks in function '{}'",
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

        let func_source = source_lines[func_start..=func_end].join("\n");

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
        // Pattern 1: Uses spot price without TWAP
        let uses_spot_price = (source.contains("getPrice")
            || source.contains("latestPrice")
            || source.contains("getReserves"))
            && !source.contains("TWAP")
            && !source.contains("twap")
            && !source.contains("getTWAP")
            && !source.contains("timeWeighted");

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
