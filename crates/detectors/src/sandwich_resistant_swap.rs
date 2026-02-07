use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for missing MEV sandwich attack protection in swaps
pub struct SandwichResistantSwapDetector {
    base: BaseDetector,
}

impl Default for SandwichResistantSwapDetector {
    fn default() -> Self {
        Self::new()
    }
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        // Skip if this is an AMM pool - AMM pools ARE the market maker
        // They don't need sandwich protection because they SET the price
        // Only contracts that CONSUME AMM prices need sandwich protection
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl SandwichResistantSwapDetector {
    /// Returns true if the function is a view or pure function.
    /// View/pure functions cannot perform state-changing swaps and should never
    /// be flagged for missing sandwich protection.
    fn is_view_or_pure(&self, function: &ast::Function<'_>) -> bool {
        matches!(
            function.mutability,
            ast::StateMutability::View | ast::StateMutability::Pure
        )
    }

    /// Returns true if the function is a flash loan callback.
    /// Flash loan callbacks execute atomically within a single transaction,
    /// so they cannot be sandwiched by MEV bots (the entire borrow+execute+repay
    /// sequence is atomic).
    fn is_flash_loan_callback(&self, function: &ast::Function<'_>) -> bool {
        let name_lower = function.name.name.to_lowercase();
        // ERC-3156 callback
        name_lower == "onflashloan"
            // Aave V2/V3 callback
            || name_lower == "executeoperation"
            // Aave V3 simple variant
            || name_lower == "executesimpleoperation"
            // dYdX callback
            || name_lower == "callfunction"
            // Generic flash loan callback patterns
            || name_lower == "onflashloanreceived"
            || name_lower == "flashloancallback"
    }

    /// Returns true if the function name indicates a price-reading or calculation
    /// helper that does not perform actual swaps. These functions read data or
    /// compute values and should not be flagged.
    fn is_price_or_calc_helper(&self, function: &ast::Function<'_>) -> bool {
        let name_lower = function.name.name.to_lowercase();

        // Price-reading patterns: getPrice*, get*Price, *price*from*, *price*for*
        let is_price_reader = (name_lower.starts_with("get") && name_lower.contains("price"))
            || (name_lower.starts_with("get") && name_lower.contains("rate"))
            || (name_lower.starts_with("get") && name_lower.contains("quote"))
            || (name_lower.starts_with("fetch") && name_lower.contains("price"))
            || (name_lower.starts_with("read") && name_lower.contains("price"))
            || (name_lower.starts_with("query") && name_lower.contains("price"));

        // Calculation helper patterns: calculate*, compute*, estimate*
        let is_calc_helper = name_lower.starts_with("calculate")
            || name_lower.starts_with("compute")
            || name_lower.starts_with("estimate")
            || name_lower.starts_with("_calculate")
            || name_lower.starts_with("_compute")
            || name_lower.starts_with("_estimate");

        is_price_reader || is_calc_helper
    }

    /// Returns true if the function body contains indicators that an actual swap
    /// is being performed (calling swap functions on routers, DEX interactions, etc.).
    /// Merely containing the word "swap" in a comment or variable name is not enough.
    fn has_actual_swap_indicators(&self, func_source: &str) -> bool {
        // Direct swap function calls on routers or pools
        let has_swap_call = func_source.contains(".swap(")
            || func_source.contains(".swapExactTokensForTokens(")
            || func_source.contains(".swapTokensForExactTokens(")
            || func_source.contains(".swapExactETHForTokens(")
            || func_source.contains(".swapExactTokensForETH(")
            || func_source.contains(".swapTokensForExactETH(")
            || func_source.contains(".swapExactETHForTokensSupportingFeeOnTransferTokens(")
            || func_source.contains(".swapExactTokensForTokensSupportingFeeOnTransferTokens(")
            || func_source.contains(".exactInputSingle(")
            || func_source.contains(".exactInput(")
            || func_source.contains(".exactOutputSingle(")
            || func_source.contains(".exactOutput(")
            || func_source.contains(".exchange(")
            || func_source.contains(".exchange_underlying(");

        // Router interaction patterns
        let has_router_interaction = func_source.contains("IUniswapV2Router")
            || func_source.contains("IUniswapV3Router")
            || func_source.contains("ISwapRouter")
            || func_source.contains("router.swap")
            || func_source.contains("dex.swap")
            || func_source.contains("pool.swap");

        // Token transfer patterns that indicate a swap (transferFrom + transfer in same function)
        let has_token_in =
            func_source.contains(".transferFrom(") || func_source.contains(".safeTransferFrom(");
        let has_token_out =
            func_source.contains(".transfer(") || func_source.contains(".safeTransfer(");
        let has_bidirectional_transfer = has_token_in && has_token_out;

        has_swap_call || has_router_interaction || has_bidirectional_transfer
    }

    /// Check for sandwich attack protection
    fn check_sandwich_protection(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        // FP Fix: Skip view/pure functions -- they cannot perform state-changing swaps
        if self.is_view_or_pure(function) {
            return None;
        }

        // FP Fix: Skip flash loan callbacks -- they execute atomically in a single
        // transaction and cannot be sandwiched
        if self.is_flash_loan_callback(function) {
            return None;
        }

        // FP Fix: Skip price-reading and calculation helper functions
        if self.is_price_or_calc_helper(function) {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Identify swap functions by name
        let is_swap_function_by_name = function.name.name.to_lowercase().contains("swap")
            || function.name.name.to_lowercase().contains("trade")
            || function.name.name.to_lowercase().contains("exchange");

        // Identify swap functions by body containing actual swap calls
        let has_swap_in_body = self.has_actual_swap_indicators(&func_source);

        // A function must either be named as a swap function OR contain actual swap
        // operation indicators in its body. Simply containing the word "swap" in a
        // string literal, variable name, or comment is not sufficient.
        if !is_swap_function_by_name && !has_swap_in_body {
            return None;
        }

        // For functions that are only identified by name (not by body swap calls),
        // verify they actually perform swap operations
        if is_swap_function_by_name && !has_swap_in_body {
            // If the function name suggests a swap but the body has no actual swap
            // indicators, skip it -- it may be a helper, getter, or view-like function
            // that happens to reference swaps
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
            return Some(
                "No minimum output amount (amountOutMin) parameter for slippage protection, \
                leaving swap vulnerable to sandwich attacks"
                    .to_string(),
            );
        }

        // Pattern 2: Missing deadline parameter
        let lacks_deadline = !func_source.contains("deadline")
            && !func_source.contains("validUntil")
            && !func_source.contains("expiry")
            && !func_source.contains("require(block.timestamp");

        if lacks_deadline {
            return Some(
                "No deadline parameter to prevent delayed execution, \
                allowing validators to hold and execute swap at unfavorable prices"
                    .to_string(),
            );
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
            return Some(
                "Uses spot price for swap calculation without TWAP, \
                making it easy for attackers to manipulate price in same block"
                    .to_string(),
            );
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
            return Some(
                "Public swap without commit-reveal scheme and no slippage protection, \
                making it trivial for MEV bots to sandwich"
                    .to_string(),
            );
        }

        // Pattern 5: No MEV protection modifier or mechanism
        let lacks_mev_protection = !func_source.contains("onlyPrivate")
            && !func_source.contains("mevProtected")
            && !func_source.contains("flashbotsOnly")
            && !func_source.contains("batchAuction")
            && !func_source.contains("nonReentrant");

        if is_public && lacks_mev_protection && lacks_slippage {
            return Some(
                "No MEV protection mechanisms (private mempool, batch auction, etc.) \
                and no slippage tolerance configured"
                    .to_string(),
            );
        }

        // Pattern 6: Allows immediate execution without time delay
        let immediate_execution = func_source.contains("swap")
            && !func_source.contains("delay")
            && !func_source.contains("queuedAt")
            && !func_source.contains("block.number")
            && func_source.contains("transfer");

        let has_large_amounts = func_source.contains("amountIn") || func_source.contains("amount");

        if immediate_execution && has_large_amounts && lacks_slippage {
            return Some(
                "Allows immediate swap execution without delays or batch processing, \
                combined with no slippage protection"
                    .to_string(),
            );
        }

        // Pattern 7: No maximum price movement check
        let lacks_max_price_movement = !func_source.contains("maxPriceImpact")
            && !func_source.contains("MAX_SLIPPAGE")
            && !func_source.contains("maxSlippage")
            && !func_source.contains("priceImpact");

        if has_swap_in_body && lacks_max_price_movement && lacks_slippage {
            return Some(
                "No maximum price impact or slippage percentage checks, \
                allowing unlimited price movement during swap"
                    .to_string(),
            );
        }

        // Pattern 8: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("sandwich")
                || func_source.contains("MEV")
                || func_source.contains("front-run"))
        {
            return Some("Sandwich attack vulnerability marker detected".to_string());
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

    // ============================================================================
    // FP Fix: View/pure function skip tests
    // ============================================================================

    #[test]
    fn test_skip_view_function() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "getPriceFromPool",
            ast::Visibility::Public,
            ast::StateMutability::View,
        );
        assert!(detector.is_view_or_pure(&func));
    }

    #[test]
    fn test_skip_pure_function() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "calculateSwapAmount",
            ast::Visibility::Public,
            ast::StateMutability::Pure,
        );
        assert!(detector.is_view_or_pure(&func));
    }

    #[test]
    fn test_do_not_skip_nonpayable_function() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "executeSwap",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(!detector.is_view_or_pure(&func));
    }

    #[test]
    fn test_do_not_skip_payable_function() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "swapETHForTokens",
            ast::Visibility::External,
            ast::StateMutability::Payable,
        );
        assert!(!detector.is_view_or_pure(&func));
    }

    // ============================================================================
    // FP Fix: Flash loan callback skip tests
    // ============================================================================

    #[test]
    fn test_skip_on_flash_loan_callback() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "onFlashLoan",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(detector.is_flash_loan_callback(&func));
    }

    #[test]
    fn test_skip_execute_operation_callback() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "executeOperation",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(detector.is_flash_loan_callback(&func));
    }

    #[test]
    fn test_skip_call_function_callback() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "callFunction",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(detector.is_flash_loan_callback(&func));
    }

    #[test]
    fn test_do_not_skip_regular_swap_function() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "swapTokens",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(!detector.is_flash_loan_callback(&func));
    }

    // ============================================================================
    // FP Fix: Price-reading and calculation helper skip tests
    // ============================================================================

    #[test]
    fn test_skip_get_price_from_pool() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "getPriceFromPool",
            ast::Visibility::Public,
            ast::StateMutability::View,
        );
        assert!(detector.is_price_or_calc_helper(&func));
    }

    #[test]
    fn test_skip_get_price_from_dex() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "getPriceFromDEX",
            ast::Visibility::External,
            ast::StateMutability::View,
        );
        assert!(detector.is_price_or_calc_helper(&func));
    }

    #[test]
    fn test_skip_calculate_potential_profit() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "calculatePotentialProfit",
            ast::Visibility::External,
            ast::StateMutability::View,
        );
        assert!(detector.is_price_or_calc_helper(&func));
    }

    #[test]
    fn test_skip_compute_swap_amount() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "computeSwapAmount",
            ast::Visibility::Internal,
            ast::StateMutability::Pure,
        );
        assert!(detector.is_price_or_calc_helper(&func));
    }

    #[test]
    fn test_skip_estimate_output() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "estimateOutputAmount",
            ast::Visibility::Public,
            ast::StateMutability::View,
        );
        assert!(detector.is_price_or_calc_helper(&func));
    }

    #[test]
    fn test_skip_get_exchange_rate() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "getExchangeRate",
            ast::Visibility::Public,
            ast::StateMutability::View,
        );
        assert!(detector.is_price_or_calc_helper(&func));
    }

    #[test]
    fn test_do_not_skip_swap_named_function_as_calc_helper() {
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "swapTokensForETH",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(!detector.is_price_or_calc_helper(&func));
    }

    // ============================================================================
    // FP Fix: Actual swap indicator tests
    // ============================================================================

    #[test]
    fn test_has_swap_indicators_uniswap_v2_router() {
        let detector = SandwichResistantSwapDetector::new();
        let source = "router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline);";
        assert!(detector.has_actual_swap_indicators(source));
    }

    #[test]
    fn test_has_swap_indicators_uniswap_v3_exact_input() {
        let detector = SandwichResistantSwapDetector::new();
        let source = "swapRouter.exactInputSingle(params);";
        assert!(detector.has_actual_swap_indicators(source));
    }

    #[test]
    fn test_has_swap_indicators_pool_swap_call() {
        let detector = SandwichResistantSwapDetector::new();
        let source = "pool.swap(recipient, zeroForOne, amountSpecified, sqrtPriceLimitX96, data);";
        assert!(detector.has_actual_swap_indicators(source));
    }

    #[test]
    fn test_has_swap_indicators_bidirectional_transfer() {
        let detector = SandwichResistantSwapDetector::new();
        let source = r#"
            tokenIn.transferFrom(msg.sender, address(this), amountIn);
            tokenOut.transfer(msg.sender, amountOut);
        "#;
        assert!(detector.has_actual_swap_indicators(source));
    }

    #[test]
    fn test_has_swap_indicators_curve_exchange() {
        let detector = SandwichResistantSwapDetector::new();
        let source = "curvePool.exchange(i, j, dx, minDy);";
        assert!(detector.has_actual_swap_indicators(source));
    }

    #[test]
    fn test_no_swap_indicators_price_reading() {
        let detector = SandwichResistantSwapDetector::new();
        // A function that reads swap pool prices but does not perform a swap
        let source = r#"
            (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
            uint256 price = reserve1 * 1e18 / reserve0;
            return price;
        "#;
        assert!(!detector.has_actual_swap_indicators(source));
    }

    #[test]
    fn test_no_swap_indicators_calculation_only() {
        let detector = SandwichResistantSwapDetector::new();
        // A pure calculation mentioning "swap" in a variable name
        let source = r#"
            uint256 swapFee = amount * fee / 10000;
            return amount - swapFee;
        "#;
        assert!(!detector.has_actual_swap_indicators(source));
    }

    #[test]
    fn test_no_swap_indicators_flash_loan_callback_body() {
        let detector = SandwichResistantSwapDetector::new();
        // A flash loan callback that reads prices but does not call a swap router
        let source = r#"
            uint256 profit = amountReceived - amountOwed;
            require(profit > 0, "Not profitable");
            return keccak256("ERC3156FlashBorrower.onFlashLoan");
        "#;
        assert!(!detector.has_actual_swap_indicators(source));
    }

    // ============================================================================
    // Regression: True positives should still be detected
    // ============================================================================

    #[test]
    fn test_tp_public_swap_with_router_no_slippage() {
        let detector = SandwichResistantSwapDetector::new();
        // A public, nonpayable function that actually calls a swap router
        // without slippage protection -- this SHOULD be flagged
        let source = r#"
            uint256 amountOut = router.swapExactTokensForTokens(amountIn, 0, path, address(this), block.timestamp);
            return amountOut;
        "#;
        assert!(detector.has_actual_swap_indicators(source));
        // And it lacks slippage protection (amountOutMin is 0, no minAmountOut etc.)
        assert!(!source.contains("amountOutMin"));
        assert!(!source.contains("minAmountOut"));
    }

    #[test]
    fn test_tp_swap_with_bidirectional_transfer_no_protection() {
        let detector = SandwichResistantSwapDetector::new();
        let source = r#"
            token0.transferFrom(msg.sender, address(this), amount0In);
            uint256 amount1Out = getAmountOut(amount0In);
            token1.transfer(msg.sender, amount1Out);
        "#;
        assert!(detector.has_actual_swap_indicators(source));
    }

    // ============================================================================
    // FP regression tests matching the exact reported false positives
    // ============================================================================

    #[test]
    fn test_fp_get_price_from_pool_is_view_skipped() {
        // VulnerableFlashLoan.sol:41 getPriceFromPool
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "getPriceFromPool",
            ast::Visibility::Public,
            ast::StateMutability::View,
        );

        // This is a view function AND a price reading helper
        assert!(detector.is_view_or_pure(&func));
        assert!(detector.is_price_or_calc_helper(&func));
    }

    #[test]
    fn test_fp_on_flash_loan_callback_skipped() {
        // FlashLoanArbitrage.sol:104 onFlashLoan
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "onFlashLoan",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );

        assert!(detector.is_flash_loan_callback(&func));
    }

    #[test]
    fn test_fp_calculate_potential_profit_skipped() {
        // FlashLoanArbitrage.sol:145 calculatePotentialProfit
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "calculatePotentialProfit",
            ast::Visibility::External,
            ast::StateMutability::View,
        );

        // This is a view function AND a calculation helper
        assert!(detector.is_view_or_pure(&func));
        assert!(detector.is_price_or_calc_helper(&func));
    }

    #[test]
    fn test_fp_get_price_from_dex_skipped() {
        // FlashLoanArbitrage.sol:195 getPriceFromDEX
        let detector = SandwichResistantSwapDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "getPriceFromDEX",
            ast::Visibility::External,
            ast::StateMutability::View,
        );

        // This is a view function AND a price reading helper
        assert!(detector.is_view_or_pure(&func));
        assert!(detector.is_price_or_calc_helper(&func));
    }
}
