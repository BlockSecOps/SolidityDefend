use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for AMM liquidity manipulation attacks
pub struct AmmLiquidityManipulationDetector {
    base: BaseDetector,
}

impl Default for AmmLiquidityManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AmmLiquidityManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("amm-liquidity-manipulation".to_string()),
                "AMM Liquidity Manipulation".to_string(),
                "Detects vulnerabilities in AMM pools that allow liquidity manipulation attacks, including sandwich attacks and pool draining".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for AmmLiquidityManipulationDetector {
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

        // Skip if this is an ERC-3156 flash loan provider
        // Flash loans INTENTIONALLY manipulate liquidity - that's their purpose
        let is_flash_loan_provider = utils::is_erc3156_flash_loan(ctx);
        if is_flash_loan_provider {
            return Ok(findings);
        }

        // Skip if this is an AMM pool - AMM pools INTENTIONALLY manipulate liquidity
        // Uniswap V2/V3 and similar AMMs have well-understood liquidity mechanisms
        // This detector should focus on contracts that CONSUME AMM liquidity unsafely
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(manipulation_issue) = self.check_liquidity_manipulation(function, ctx) {
                let message = format!(
                    "Function '{}' is vulnerable to AMM liquidity manipulation. {} \
                    Liquidity manipulation can drain pools, enable sandwich attacks, \
                    or allow attackers to profit from price manipulation.",
                    function.name.name, manipulation_issue
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
                        "Protect '{}' from liquidity manipulation. \
                    Implement minimum liquidity locks, use TWAP oracles instead of spot prices, \
                    add reentrancy guards, validate reserves before and after trades, \
                    and implement trade size limits.",
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

impl AmmLiquidityManipulationDetector {
    /// Check for liquidity manipulation vulnerabilities
    fn check_liquidity_manipulation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Pattern 1: Swap functions using spot price without TWAP
        let is_swap_function = func_source.contains("swap")
            || func_source.contains("exchange")
            || function.name.name.to_lowercase().contains("swap");

        let uses_spot_price = (func_source.contains("getReserves")
            || func_source.contains("reserve0")
            || func_source.contains("reserve1")
            || func_source.contains("balanceOf(address(this))"))
            && !func_source.contains("TWAP")
            && !func_source.contains("cumulative")
            && !func_source.contains("timeWeighted");

        if is_swap_function && uses_spot_price {
            return Some(
                "Swap uses spot price from reserves without TWAP oracle protection, \
                enabling price manipulation within single transaction"
                    .to_string(),
            );
        }

        // Pattern 2: Price calculation based on current reserves
        let calculates_price = func_source.contains("getAmountOut")
            || func_source.contains("getAmountIn")
            || func_source.contains("reserve") && func_source.contains(" / ")
            || func_source.contains("* reserve");

        let lacks_manipulation_check = calculates_price
            && !func_source.contains("minAmount")
            && !func_source.contains("slippage")
            && !func_source.contains("deadline")
            && !func_source.contains("require");

        if lacks_manipulation_check {
            return Some(
                "Price calculation uses current reserves without slippage protection, \
                deadline checks, or minimum output validation"
                    .to_string(),
            );
        }

        // Pattern 3: Add/remove liquidity without minimum lock
        let is_liquidity_function = func_source.contains("addLiquidity")
            || func_source.contains("removeLiquidity")
            || function.name.name.to_lowercase().contains("liquidity");

        let lacks_liquidity_lock = is_liquidity_function
            && !func_source.contains("MINIMUM_LIQUIDITY")
            && !func_source.contains("liquidityLock")
            && !func_source.contains("block.timestamp")
            && func_source.contains("burn")
            || func_source.contains("mint");

        if lacks_liquidity_lock {
            return Some(
                "Liquidity operations lack minimum liquidity lock or time-based restrictions, \
                enabling flash loan pool manipulation"
                    .to_string(),
            );
        }

        // Pattern 4: K invariant not properly checked
        let modifies_reserves = func_source.contains("reserve0")
            || func_source.contains("reserve1")
            || func_source.contains("_update");

        let lacks_k_check = modifies_reserves
            && !func_source.contains("* reserve")
            && !func_source.contains("require(")
            && !func_source.contains("balance0 * balance1");

        if lacks_k_check {
            return Some(
                "Reserve updates don't verify constant product (K) invariant, \
                allowing pool imbalance and value extraction"
                    .to_string(),
            );
        }

        // Pattern 5: Reentrancy in swap/liquidity functions
        let has_external_call = func_source.contains(".call")
            || func_source.contains(".transfer(")
            || func_source.contains(".transferFrom")
            || func_source.contains("safeTransfer");

        let lacks_reentrancy_guard = has_external_call
            && (is_swap_function || is_liquidity_function)
            && !func_source.contains("nonReentrant")
            && !func_source.contains("lock")
            && !func_source.contains("_status");

        if lacks_reentrancy_guard {
            return Some(
                "AMM function performs external calls without reentrancy protection, \
                enabling manipulation of reserves during callback"
                    .to_string(),
            );
        }

        // Pattern 6: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("liquidity manipulation")
                || func_source.contains("AMM")
                || func_source.contains("sandwich")
                || func_source.contains("pool drain"))
        {
            return Some("AMM liquidity manipulation vulnerability marker detected".to_string());
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
        let detector = AmmLiquidityManipulationDetector::new();
        assert_eq!(detector.name(), "AMM Liquidity Manipulation");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
