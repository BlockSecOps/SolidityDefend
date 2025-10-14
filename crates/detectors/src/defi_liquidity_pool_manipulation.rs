//! DeFi Liquidity Pool Manipulation Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

use ast::Function;

pub struct LiquidityPoolManipulationDetector {
    base: BaseDetector,
}

impl LiquidityPoolManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("defi-liquidity-pool-manipulation".to_string()),
                "Liquidity Pool Manipulation".to_string(),
                "Detects missing K-value validation, price oracle manipulation, and flash loan attacks on AMM invariants".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Oracle],
                Severity::Critical,
            ),
        }
    }

    fn is_amm_pool(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("swap")
            || source.contains("addliquidity")
            || source.contains("removeliquidity"))
            && (source.contains("reserve")
                || source.contains("balance")
                || source.contains("liquidity"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check swap functions
        if name.contains("swap") {
            // Check for K-value validation (x * y = k invariant)
            let has_k_check = (source_lower.contains("reserve0")
                && source_lower.contains("reserve1"))
                && (source_lower.contains("*") && source_lower.contains(">="));
            let has_invariant =
                source_lower.contains("invariant") || source_lower.contains("constant");

            if !has_k_check && !has_invariant {
                issues.push((
                    "Missing K-value invariant validation (x * y >= k)".to_string(),
                    Severity::Critical,
                    "Validate invariant: require(reserve0After * reserve1After >= reserve0Before * reserve1Before, \"K\");".to_string()
                ));
            }

            // Check for flash loan manipulation protection
            let has_reentrancy_guard = source_lower.contains("nonreentrant")
                || source_lower.contains("locked")
                || source_lower.contains("reentrancyguard");
            let has_balance_check = source_lower.contains("balanceof(address(this))")
                || source_lower.contains("balance") && source_lower.contains("require");

            if !has_reentrancy_guard {
                issues.push((
                    "No reentrancy protection (flash loan attack risk)".to_string(),
                    Severity::Critical,
                    "Add reentrancy guard: modifier nonReentrant or use ReentrancyGuard from OpenZeppelin".to_string()
                ));
            }

            if !has_balance_check {
                issues.push((
                    "Missing balance validation before swap".to_string(),
                    Severity::High,
                    "Validate balances: uint balance0 = IERC20(token0).balanceOf(address(this)); require(balance0 >= reserve0 + amount0In);".to_string()
                ));
            }

            // Check for price manipulation via single-block oracle
            let has_twap = source_lower.contains("twap") || source_lower.contains("timeweighted");
            let has_cumulative =
                source_lower.contains("cumulative") || source_lower.contains("price0cumulative");
            let uses_spot_price =
                source_lower.contains("getamountout") && !has_twap && !has_cumulative;

            if uses_spot_price {
                issues.push((
                    "Using spot price for swaps (manipulation risk)".to_string(),
                    Severity::High,
                    "Use TWAP: Implement time-weighted average price over multiple blocks instead of spot price".to_string()
                ));
            }

            // Check for slippage protection
            let has_min_output = source_lower.contains("minamount")
                || source_lower.contains("amountoutmin")
                || (source_lower.contains("amount") && source_lower.contains(">="));

            if !has_min_output {
                issues.push((
                    "No slippage protection (frontrunning risk)".to_string(),
                    Severity::High,
                    "Add slippage: require(amountOut >= amountOutMin, \"Insufficient output\");"
                        .to_string(),
                ));
            }

            // Check for deadline validation
            let has_deadline = source_lower.contains("deadline")
                && (source_lower.contains("block.timestamp") || source_lower.contains("timestamp"));

            if !has_deadline {
                issues.push((
                    "Missing deadline parameter (stuck transaction risk)".to_string(),
                    Severity::Medium,
                    "Add deadline: require(block.timestamp <= deadline, \"Transaction expired\");"
                        .to_string(),
                ));
            }
        }

        // Check liquidity addition/removal
        if name.contains("addliquidity") || name.contains("mint") {
            // Check for minimum liquidity lock
            let has_min_liquidity = source_lower.contains("minimum_liquidity")
                || (source_lower.contains("1000") && source_lower.contains("mint"));

            if name.contains("addliquidity") && !has_min_liquidity {
                issues.push((
                    "No minimum liquidity lock (pool initialization attack)".to_string(),
                    Severity::High,
                    "Lock minimum: if (totalSupply == 0) { liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY; _mint(address(0), MINIMUM_LIQUIDITY); }".to_string()
                ));
            }

            // Check for balanced liquidity provision
            let has_ratio_check = source_lower.contains("amount0")
                && source_lower.contains("amount1")
                && (source_lower.contains("reserve0") || source_lower.contains("reserve1"));

            if !has_ratio_check {
                issues.push((
                    "No ratio validation for liquidity provision".to_string(),
                    Severity::Medium,
                    "Validate ratio: require(amount0 * reserve1 == amount1 * reserve0, \"Invalid ratio\");".to_string()
                ));
            }
        }

        if name.contains("removeliquidity") || name.contains("burn") {
            // Check for sandwich attack protection
            let has_min_amounts = (source_lower.contains("amount0min")
                && source_lower.contains("amount1min"))
                || source_lower.contains("minamount");

            if !has_min_amounts {
                issues.push((
                    "No minimum amount protection on liquidity removal".to_string(),
                    Severity::High,
                    "Add minimums: require(amount0 >= amount0Min && amount1 >= amount1Min, \"Insufficient output\");".to_string()
                ));
            }
        }

        // Check price getter functions
        if name.contains("getprice") || name.contains("getamountout") {
            // Check for flash loan resistant pricing
            let has_block_check =
                source_lower.contains("block.timestamp") || source_lower.contains("block.number");

            if !has_block_check {
                issues.push((
                    "Price oracle without timestamp (flash loan manipulation)".to_string(),
                    Severity::Critical,
                    "Use TWAP: Store price0CumulativeLast and price1CumulativeLast with block timestamps".to_string()
                ));
            }
        }

        // Check for reserve synchronization
        if name.contains("sync") || name.contains("skim") {
            let has_access_control = source_lower.contains("onlyowner")
                || source_lower.contains("require")
                || source_lower.contains("internal");

            if name.contains("skim") && !has_access_control {
                issues.push((
                    "Public skim function (reserve manipulation risk)".to_string(),
                    Severity::Medium,
                    "Add access control: function skim() external onlyOwner or make it internal"
                        .to_string(),
                ));
            }
        }

        issues
    }
}

impl Default for LiquidityPoolManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for LiquidityPoolManipulationDetector {
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

        if !self.is_amm_pool(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
            for (message, severity, remediation) in issues {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("{} in '{}'", message, function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
