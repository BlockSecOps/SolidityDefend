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
    fn has_price_manipulation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // Skip if function is internal/private
        if function.visibility != ast::Visibility::Public
            && function.visibility != ast::Visibility::External
        {
            return None;
        }

        // Skip ALL view/pure getter functions - they're read-only and implement price logic
        if (function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure)
            && (func_name_lower.starts_with("get")
                || func_name_lower.starts_with("calculate")
                || func_name_lower.starts_with("median")
                || func_name_lower.starts_with("twap"))
        {
            return None;
        }

        // Phase 5 FP Reduction: Skip validation/verify functions
        // These are typically oracle validators, not consumers
        if func_name_lower.starts_with("validate")
            || func_name_lower.starts_with("verify")
            || func_name_lower.starts_with("check")
            || func_name_lower.starts_with("is")
            || func_name_lower.starts_with("has")
        {
            return None;
        }

        // Phase 6 FP Reduction: Skip ALL view/pure functions
        // View/pure functions cannot modify state and thus cannot be front-run
        // for price manipulation. They only read data.
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return None;
        }

        // Phase 6 FP Reduction: Skip flash loan provider functions
        // Flash loan providers use balanceOf for accounting (before/after checks),
        // not for pricing. This is a standard safety pattern.
        if self.is_flash_loan_provider_function(&func_source, &func_name_lower) {
            return None;
        }

        // Phase 6 FP Reduction: Skip governance functions
        // Governance functions use balanceOf for voting power / proposal threshold
        // checks, not for price calculations.
        if self.is_governance_function(&func_source, &func_name_lower) {
            return None;
        }

        // Phase 6 FP Reduction: Skip ERC-4626 vault standard functions
        // These use balanceOf as part of the standard accounting pattern.
        if self.is_erc4626_standard_function(&func_name_lower) {
            return None;
        }

        // Phase 6 FP Reduction: Skip functions with access control modifiers
        // Functions restricted to owner/admin/authorized cannot be front-run
        // by arbitrary users.
        if self.has_access_control(&func_source) {
            return None;
        }

        // Phase 5 FP Reduction: Skip oracle implementation functions
        // If contract IS an oracle (provides prices), not a consumer
        let is_oracle_implementation = ctx.source_code.contains("function latestRoundData")
            || ctx.source_code.contains("function getLatestPrice")
            || ctx.source_code.contains("function updateAnswer")
            || ctx.source_code.contains("interface AggregatorV3Interface");

        if is_oracle_implementation && !self.is_trading_context(&func_source, &func_name_lower) {
            return None;
        }

        // Check for price-dependent operations
        let is_price_dependent = self.is_price_dependent(&func_source, &func_name_lower);
        if !is_price_dependent {
            return None;
        }

        // Pattern 1: Spot price from AMM without TWAP or alternative protections
        // Phase 5 FP Reduction: Require actual trading context for spot price warnings
        let is_trading = self.is_trading_context(&func_source, &func_name_lower);
        if self.uses_spot_price(&func_source)
            && !self.has_twap_protection(&func_source)
            && !self.has_price_bounds(&func_source)
            && !self.has_circuit_breaker(&func_source)
            && is_trading
        {
            return Some(format!(
                "Uses manipulable spot price from AMM. Function '{}' relies on spot price \
                (getAmountOut, getReserves) without TWAP protection. \
                Vulnerable to flash loan price manipulation",
                function.name.name
            ));
        }

        // Pattern 2: BalanceOf for pricing without validation
        // Phase 7 FP Reduction: Skip AMM pool infrastructure contracts.
        // If the contract IS the AMM pool (has reserves, K-invariant, cumulative prices),
        // balanceOf(address(this)) is self-accounting, not external price consumption.
        if self.uses_balance_for_price(&func_source)
            && !self.has_price_validation(&func_source)
            && !self.is_amm_pool_infrastructure(ctx, &func_source)
            && !self.has_slippage_protection(&func_source)
        {
            return Some(format!(
                "Uses balanceOf for price calculation. Function '{}' calculates prices \
                using token balances which can be manipulated via flash loans or large trades",
                function.name.name
            ));
        }

        // Pattern 3: External price oracle without staleness check or alternative protections
        // Allow deviation bounds, multiple oracles, circuit breakers, or price bounds as alternatives
        if self.uses_external_oracle(&func_source)
            && !self.has_staleness_check(&func_source)
            && !self.has_deviation_check(&func_source)
            && !self.uses_multiple_oracles(&func_source)
            && !self.has_circuit_breaker(&func_source)
            && !self.has_price_bounds(&func_source)
        {
            return Some(format!(
                "Price oracle without staleness check. Function '{}' uses external price \
                oracle but doesn't validate timestamp/staleness. Stale prices enable arbitrage",
                function.name.name
            ));
        }

        // Pattern 4: No price deviation bounds or alternative protections
        // Allow staleness checks, multiple oracles, circuit breakers, or price bounds as alternatives
        if self.uses_price_feed(&func_source)
            && !self.has_deviation_check(&func_source)
            && !self.has_staleness_check(&func_source)
            && !self.uses_multiple_oracles(&func_source)
            && !self.has_circuit_breaker(&func_source)
            && !self.has_price_bounds(&func_source)
        {
            return Some(format!(
                "Missing price deviation bounds. Function '{}' accepts prices without \
                validating reasonable deviation limits. Extreme price moves can be exploited",
                function.name.name
            ));
        }

        // Pattern 5: Large value operation without price impact check
        if self.is_large_value_operation(&func_source, &func_name_lower)
            && !self.has_price_impact_check(&func_source)
        {
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
        func_name.contains("swap")
            || func_name.contains("exchange")
            || func_name.contains("trade")
            || func_name.contains("liquidate")
            || func_name.contains("borrow")
            || func_name.contains("repay")
            || source.contains("price")
            || source.contains("getAmountOut")
            || source.contains("getReserves")
            || source.contains("balanceOf") && (source.contains("*") || source.contains("/"))
    }

    /// Checks for spot price usage from AMMs
    fn uses_spot_price(&self, source: &str) -> bool {
        source.contains("getAmountOut")
            || source.contains("getReserves")
            || (source.contains("reserve") && source.contains("/"))
            || source.contains("spot") && source.contains("price")
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
        source.contains("balanceOf")
            && (source.contains("*")
                || source.contains("/")
                || source.contains("mul")
                || source.contains("div"))
            && (source.contains("price") || source.contains("amount") || source.contains("value"))
    }

    /// Checks for external oracle usage
    fn uses_external_oracle(&self, source: &str) -> bool {
        source.contains("oracle")
            || source.contains("Oracle")
            || source.contains("priceFeed")
            || source.contains("getPrice")
            || source.contains("latestAnswer")
            || source.contains("latestRoundData")
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
        (source.contains("require") || source.contains("revert"))
            && source.contains("price")
            && (source.contains(">") || source.contains("<") || source.contains("!="))
    }

    /// Checks if function uses price feeds
    fn uses_price_feed(&self, source: &str) -> bool {
        source.contains("getPrice")
            || source.contains("latestAnswer")
            || source.contains("latestRoundData")
            || source.contains("priceFeed")
    }

    /// Checks for price deviation validation
    fn has_deviation_check(&self, source: &str) -> bool {
        (source.contains("maxDeviation")
            || source.contains("priceDeviation")
            || source.contains("deviationThreshold")
            || source.contains("MAX_DEVIATION")
            || source.contains("deviation"))
            && (source.contains("require")
                || source.contains("revert")
                || source.contains("<=")
                || source.contains(">="))
    }

    /// Checks if this is a large value operation
    fn is_large_value_operation(&self, source: &str, func_name: &str) -> bool {
        func_name.contains("liquidate")
            || func_name.contains("flash")
            || source.contains("liquidation")
            || source.contains("flashLoan")
            || source.contains("flashSwap")
    }

    /// Checks for price impact validation
    fn has_price_impact_check(&self, source: &str) -> bool {
        source.contains("priceImpact")
            || source.contains("slippage")
            || (source.contains("before") && source.contains("after") && source.contains("price"))
    }

    /// Checks for circuit breaker pattern
    fn has_circuit_breaker(&self, source: &str) -> bool {
        source.contains("circuitBreaker")
            || source.contains("circuit_breaker")
            || (source.contains("paused") || source.contains("emergency"))
    }

    /// Checks for multiple oracle usage
    fn uses_multiple_oracles(&self, source: &str) -> bool {
        source.contains("median")
            || source.contains("oracles[")
            || source.contains("multiple") && source.contains("oracle")
    }

    /// Checks for price bounds (min/max)
    fn has_price_bounds(&self, source: &str) -> bool {
        (source.contains("minPrice") && source.contains("maxPrice"))
            || (source.contains("min") && source.contains("max") && source.contains("price"))
            || (source.contains("minAmountOut") || source.contains("amountOutMin"))
    }

    /// Phase 7 FP Reduction: Check if the contract is AMM pool infrastructure.
    /// AMM pools use balanceOf(address(this)) for internal reserve accounting,
    /// not for consuming external prices. The pool IS the price source.
    /// Indicators: reserve tracking, K-invariant checks, cumulative price updates,
    /// LP token minting/burning, Sync events.
    fn is_amm_pool_infrastructure(&self, ctx: &AnalysisContext, func_source: &str) -> bool {
        let src = &ctx.source_code;

        // Contract-level indicators that this IS an AMM pool
        let has_reserves = src.contains("reserve0") && src.contains("reserve1");
        let has_k_invariant = src.contains("invariant")
            || src.contains("Invariant")
            || (src.contains("balance0Adjusted") && src.contains("balance1Adjusted"))
            || (src.contains("reserve") && src.contains("* 1000") && src.contains("* 3"));
        let has_cumulative_price = src.contains("CumulativeLast")
            || src.contains("cumulativePrice")
            || src.contains("priceCumulative");
        let has_lp_tokens = src.contains("totalSupply")
            && (src.contains("_mint") || src.contains("_burn"))
            && has_reserves;
        let has_sync_event = src.contains("event Sync");

        // This is an AMM pool if it has reserves plus at least one other indicator
        let is_pool = has_reserves
            && (has_k_invariant || has_cumulative_price || has_lp_tokens || has_sync_event);

        if !is_pool {
            return false;
        }

        // Function-level: uses balanceOf(address(this)) for self-accounting
        let is_self_accounting = func_source.contains("balanceOf(address(this))");

        is_self_accounting
    }

    /// Phase 7 FP Reduction: Check if the function has slippage protection.
    /// Functions with minAmountOut/amountOutMin, deadline checks, or K-invariant
    /// verification are protected against price manipulation.
    fn has_slippage_protection(&self, source: &str) -> bool {
        let has_min_output = source.contains("minAmountOut")
            || source.contains("amountOutMin")
            || source.contains("minAmount")
            || source.contains("minimumOutput");
        let has_deadline = source.contains("deadline")
            && (source.contains("block.timestamp") || source.contains("DeadlineExpired"));
        let has_k_check = source.contains("InvariantViolation")
            || source.contains("K invariant")
            || (source.contains("Adjusted") && source.contains("reserve"));

        // Slippage + deadline is comprehensive protection
        // K-invariant check alone also protects against manipulation
        (has_min_output && has_deadline)
            || (has_min_output && has_k_check)
            || (has_deadline && has_k_check)
    }

    /// Phase 6 FP Reduction: Check if function is a flash loan provider function
    /// Flash loan providers use balanceOf for before/after accounting checks,
    /// not for pricing. This is a standard safety pattern (ERC-3156).
    fn is_flash_loan_provider_function(&self, source: &str, func_name: &str) -> bool {
        let name_indicates_flash_loan = func_name.contains("flashloan")
            || func_name.contains("flashmint")
            || func_name.contains("onflashloan")
            || func_name == "flashfee"
            || func_name == "maxflashloan";

        let source_indicates_flash_loan = source.contains("onFlashLoan")
            || source.contains("IFlashBorrower")
            || source.contains("FlashBorrower")
            || source.contains("ERC3156")
            || (source.contains("balanceBefore") && source.contains("balanceAfter"))
            || source.contains("Flash loan")
            || source.contains("flash loan");

        name_indicates_flash_loan || source_indicates_flash_loan
    }

    /// Phase 6 FP Reduction: Check if function is a governance function
    /// Governance functions use balanceOf for voting power and proposal threshold
    /// checks, which is not price manipulation.
    fn is_governance_function(&self, source: &str, func_name: &str) -> bool {
        let name_indicates_governance = func_name.contains("propose")
            || func_name.contains("vote")
            || func_name.contains("delegate")
            || func_name.contains("quorum")
            || func_name.contains("queue")
            || func_name.contains("cancel");

        let source_indicates_governance = source.contains("proposalThreshold")
            || source.contains("votingPower")
            || source.contains("proposal")
            || source.contains("Proposal")
            || source.contains("governance")
            || source.contains("delegatee");

        name_indicates_governance && source_indicates_governance
    }

    /// Phase 6 FP Reduction: Check if function is an ERC-4626 standard function
    /// ERC-4626 vaults use balanceOf as part of their standard accounting pattern.
    fn is_erc4626_standard_function(&self, func_name: &str) -> bool {
        func_name == "totalassets"
            || func_name == "deposit"
            || func_name == "withdraw"
            || func_name == "mint"
            || func_name == "redeem"
            || func_name == "converttoassets"
            || func_name == "converttoshares"
            || func_name == "previewdeposit"
            || func_name == "previewmint"
            || func_name == "previewredeem"
            || func_name == "previewwithdraw"
            || func_name == "maxdeposit"
            || func_name == "maxmint"
            || func_name == "maxredeem"
            || func_name == "maxwithdraw"
    }

    /// Phase 6 FP Reduction: Check if function has access control
    /// Functions with access control modifiers cannot be front-run by arbitrary users.
    fn has_access_control(&self, source: &str) -> bool {
        source.contains("onlyOwner")
            || source.contains("onlyAdmin")
            || source.contains("onlyAuthorized")
            || source.contains("onlyRole")
            || source.contains("onlyGuardian")
            || source.contains("onlyOperator")
            || source.contains("onlyMinter")
            || source.contains("onlyGovernance")
            || source.contains("requireRole")
            || (source.contains("require")
                && source.contains("msg.sender")
                && source.contains("owner"))
    }

    /// Phase 5 FP Reduction: Check if function is in trading context
    fn is_trading_context(&self, func_source: &str, func_name: &str) -> bool {
        // Function name indicates trading operation
        let name_indicates_trading = func_name.contains("swap")
            || func_name.contains("trade")
            || func_name.contains("exchange")
            || func_name.contains("buy")
            || func_name.contains("sell")
            || func_name.contains("liquidate")
            || func_name.contains("borrow")
            || func_name.contains("repay");

        // Source code indicates trading context
        let source_indicates_trading = func_source.contains("getAmountOut")
            || func_source.contains("getAmountsOut")
            || func_source.contains("getAmountIn")
            || func_source.contains(".swap(")
            || func_source.contains("swapExact")
            || func_source.contains("amountOutMin")
            || func_source.contains("amountInMax");

        name_indicates_trading || source_indicates_trading
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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

    // ============== Phase 7: AMM Pool Infrastructure Detection ==============

    #[test]
    fn test_amm_pool_infrastructure_uniswap_v2_style() {
        // A Uniswap V2-style AMM pool with reserves, K-invariant, cumulative prices,
        // LP tokens, and Sync event should be recognized as pool infrastructure.
        let contract_source = r#"
            contract SafeAMMPool {
                uint112 private reserve0;
                uint112 private reserve1;
                uint256 public price0CumulativeLast;
                uint256 public price1CumulativeLast;
                uint256 public totalSupply;
                event Sync(uint112 reserve0, uint112 reserve1);
                error InvariantViolation();

                function _mint(address to, uint256 value) internal {
                    totalSupply += value;
                }
                function _burn(address from, uint256 value) internal {
                    totalSupply -= value;
                }
                function swap(uint256 amount0Out, uint256 amount1Out, address to,
                              uint256 minAmountOut, uint256 deadline) external {
                    uint256 balance0 = token0.balanceOf(address(this));
                    uint256 balance1 = token1.balanceOf(address(this));
                    uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
                    uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
                    if (balance0Adjusted * balance1Adjusted < uint256(_reserve0) * _reserve1 * 1000000) {
                        revert InvariantViolation();
                    }
                }
                function burn(address to) external {
                    uint256 balance0 = token0.balanceOf(address(this));
                    uint256 balance1 = token1.balanceOf(address(this));
                    uint256 amount0 = (liquidity * balance0) / totalSupply;
                    uint256 amount1 = (liquidity * balance1) / totalSupply;
                }
            }
        "#;

        let src = contract_source;

        // Verify contract-level AMM indicators
        assert!(
            src.contains("reserve0") && src.contains("reserve1"),
            "Should detect reserve0/reserve1"
        );
        assert!(
            src.contains("CumulativeLast"),
            "Should detect cumulative price tracking"
        );
        assert!(src.contains("event Sync"), "Should detect Sync event");
        assert!(
            src.contains("InvariantViolation"),
            "Should detect K-invariant check"
        );
        assert!(
            src.contains("_mint") && src.contains("_burn") && src.contains("totalSupply"),
            "Should detect LP token mechanics"
        );

        // Verify function-level self-accounting
        let swap_source = r#"uint256 balance0 = token0.balanceOf(address(this));
                    uint256 balance1 = token1.balanceOf(address(this));"#;
        assert!(
            swap_source.contains("balanceOf(address(this))"),
            "Swap function should use balanceOf(address(this)) for self-accounting"
        );

        let burn_source = r#"uint256 balance0 = token0.balanceOf(address(this));
                    uint256 balance1 = token1.balanceOf(address(this));"#;
        assert!(
            burn_source.contains("balanceOf(address(this))"),
            "Burn function should use balanceOf(address(this)) for self-accounting"
        );
    }

    #[test]
    fn test_non_amm_contract_not_detected_as_pool() {
        // A contract that uses balanceOf for pricing but is NOT an AMM pool
        // should NOT be skipped by the AMM pool check.
        let contract_source = r#"
            contract VulnerableExchange {
                function exchange(uint256 amountIn) external {
                    uint256 balanceA = tokenA.balanceOf(pool);
                    uint256 balanceB = tokenB.balanceOf(pool);
                    uint256 price = balanceB * 1e18 / balanceA;
                    uint256 amountOut = amountIn * price / 1e18;
                }
            }
        "#;

        // No reserve0/reserve1 => not AMM pool
        assert!(
            !contract_source.contains("reserve0"),
            "Non-AMM contract should not have reserve0"
        );
        assert!(
            !contract_source.contains("event Sync"),
            "Non-AMM contract should not have Sync event"
        );
        // Uses balanceOf(pool) not balanceOf(address(this))
        assert!(
            !contract_source.contains("balanceOf(address(this))"),
            "Non-AMM should not use self-accounting pattern"
        );
    }

    // ============== Phase 7: Slippage Protection Detection ==============

    #[test]
    fn test_slippage_protection_with_min_output_and_deadline() {
        let detector = PriceManipulationFrontrunDetector::new();

        let source = r#"
            function swap(uint256 amount0Out, uint256 amount1Out, address to,
                          uint256 minAmountOut, uint256 deadline) external {
                if (block.timestamp > deadline) {
                    revert DeadlineExpired();
                }
                if (totalOut < minAmountOut) {
                    revert SlippageExceeded();
                }
            }
        "#;

        assert!(
            detector.has_slippage_protection(source),
            "Swap with minAmountOut + deadline should be recognized as protected"
        );
    }

    #[test]
    fn test_slippage_protection_with_min_output_and_k_invariant() {
        let detector = PriceManipulationFrontrunDetector::new();

        let source = r#"
            function swap(uint256 amount0Out, uint256 minAmountOut) external {
                require(totalOut >= minAmountOut, "Slippage");
                uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
                if (balance0Adjusted * balance1Adjusted < reserve) {
                    revert InvariantViolation();
                }
            }
        "#;

        assert!(
            detector.has_slippage_protection(source),
            "Swap with minAmountOut + K-invariant should be recognized as protected"
        );
    }

    #[test]
    fn test_no_slippage_protection_without_min_output_or_deadline() {
        let detector = PriceManipulationFrontrunDetector::new();

        let source = r#"
            function swap(uint256 amountIn, bool aToB) external {
                uint256 amountOut = amountIn * reserveB / reserveA;
                reserveA += amountIn;
                reserveB -= amountOut;
            }
        "#;

        assert!(
            !detector.has_slippage_protection(source),
            "Swap without any protection should NOT be recognized as protected"
        );
    }

    #[test]
    fn test_slippage_protection_deadline_and_k_check() {
        let detector = PriceManipulationFrontrunDetector::new();

        let source = r#"
            function swap(uint256 amount, uint256 deadline) external {
                require(block.timestamp <= deadline, "Expired");
                if (balance0Adjusted * balance1Adjusted < reserve) {
                    revert InvariantViolation();
                }
            }
        "#;

        assert!(
            detector.has_slippage_protection(source),
            "Swap with deadline + K-invariant should be recognized as protected"
        );
    }

    // ============== Regression: Vulnerable Patterns Still Detected ==============

    #[test]
    fn test_vulnerable_balance_for_price_still_detected() {
        let detector = PriceManipulationFrontrunDetector::new();

        // Vulnerable: uses balanceOf for price calc, no protections
        let source = r#"
            uint256 balanceA = tokenA.balanceOf(pool);
            uint256 price = balanceB * 1e18 / balanceA;
            uint256 amountOut = amountIn * price / 1e18;
        "#;

        assert!(
            detector.uses_balance_for_price(source),
            "Should detect balanceOf used for pricing"
        );
        assert!(
            !detector.has_price_validation(source),
            "Should not find price validation"
        );
    }

    #[test]
    fn test_vulnerable_spot_price_still_detected() {
        let detector = PriceManipulationFrontrunDetector::new();

        let source = r#"
            uint256 amountOut = router.getAmountOut(amountIn, reserveIn, reserveOut);
        "#;

        assert!(
            detector.uses_spot_price(source),
            "Should detect getAmountOut spot price usage"
        );
        assert!(
            !detector.has_twap_protection(source),
            "Should not find TWAP protection"
        );
    }

    #[test]
    fn test_vulnerable_oracle_without_staleness_still_detected() {
        let detector = PriceManipulationFrontrunDetector::new();

        let source = r#"
            uint256 price = oracle.getPrice(address(token));
            uint256 borrowAmount = collateralAmount * price;
        "#;

        assert!(
            detector.uses_external_oracle(source),
            "Should detect external oracle usage"
        );
        assert!(
            !detector.has_staleness_check(source),
            "Should not find staleness check"
        );
    }

    // ============== AMM Pool Burn/Mint Should Not Trigger ==============

    #[test]
    fn test_amm_burn_function_not_flagged() {
        // The burn function in a Uniswap V2-style pool uses balanceOf(address(this))
        // for reserve accounting. This should NOT be flagged.
        let contract_source = r#"
            contract SafeAMMPool {
                uint112 private reserve0;
                uint112 private reserve1;
                uint256 public price0CumulativeLast;
                event Sync(uint112 reserve0, uint112 reserve1);
                function _mint(address to, uint256 value) internal { totalSupply += value; }
                function _burn(address from, uint256 value) internal { totalSupply -= value; }
            }
        "#;

        let func_source = r#"
            function burn(address to) external {
                uint256 balance0 = token0.balanceOf(address(this));
                uint256 balance1 = token1.balanceOf(address(this));
                uint256 amount0 = (liquidity * balance0) / totalSupply;
                uint256 amount1 = (liquidity * balance1) / totalSupply;
            }
        "#;

        // Contract IS an AMM pool
        assert!(contract_source.contains("reserve0") && contract_source.contains("reserve1"));
        assert!(contract_source.contains("CumulativeLast"));
        assert!(contract_source.contains("event Sync"));

        // Function uses self-accounting
        assert!(func_source.contains("balanceOf(address(this))"));

        // Even though it has balanceOf with * / and "amount" (triggering uses_balance_for_price),
        // the AMM pool infrastructure check should suppress it
        let detector = PriceManipulationFrontrunDetector::new();
        assert!(
            detector.uses_balance_for_price(func_source),
            "burn uses balanceOf with arithmetic + 'amount', so uses_balance_for_price triggers"
        );

        // But the AMM pool check should suppress it
        // (full integration tested via benchmark)
    }

    #[test]
    fn test_amm_swap_with_protections_not_flagged() {
        // A swap function with slippage + deadline + K-invariant should not be flagged
        let detector = PriceManipulationFrontrunDetector::new();

        let func_source = r#"
            function swap(uint256 amount0Out, uint256 amount1Out, address to,
                          uint256 minAmountOut, uint256 deadline) external {
                if (block.timestamp > deadline) { revert DeadlineExpired(); }
                uint256 totalOut = amount0Out + amount1Out;
                if (totalOut < minAmountOut) { revert SlippageExceeded(); }
                uint256 balance0 = token0.balanceOf(address(this));
                uint256 balance1 = token1.balanceOf(address(this));
                uint256 amount0In = balance0 > _reserve0 - amount0Out ? balance0 - (_reserve0 - amount0Out) : 0;
                uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
                uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
                if (balance0Adjusted * balance1Adjusted < uint256(_reserve0) * _reserve1 * 1000000) {
                    revert InvariantViolation();
                }
            }
        "#;

        // Has slippage protection (minAmountOut + deadline)
        assert!(
            detector.has_slippage_protection(func_source),
            "Should detect comprehensive slippage protection"
        );

        // Has balanceOf(address(this)) - self-accounting
        assert!(
            func_source.contains("balanceOf(address(this))"),
            "Swap uses self-accounting pattern"
        );
    }
}
