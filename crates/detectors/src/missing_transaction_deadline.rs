use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for missing transaction deadline vulnerabilities
///
/// This detector identifies functions that perform time-sensitive operations
/// (swaps, trades, orders) without deadline parameters, allowing transactions
/// to be executed at unfavorable times, enabling MEV extraction and stale execution.
///
/// **Vulnerability:** CWE-682 (Incorrect Calculation), CWE-362 (Concurrent Execution)
/// **Severity:** Medium
///
/// ## Description
///
/// Missing transaction deadline vulnerabilities occur when:
/// 1. Swap/trade functions accept no deadline parameter
/// 2. Transactions can be held and executed later at worse prices
/// 3. MEV bots can delay execution for profit extraction
/// 4. Orders execute when conditions have changed significantly
/// 5. No expiration validation for pending operations
///
/// This creates opportunities for:
/// - Miners/validators delaying transactions for MEV
/// - Transactions executing at stale prices
/// - Sandwich attacks with timing control
/// - Expired orders executing unexpectedly
/// - Loss of funds due to price movements
///
/// Common vulnerable patterns:
/// - Swap functions without `deadline` parameter
/// - Trade execution without `block.timestamp` checks
/// - Order execution without expiration validation
/// - Batch operations without time limits
/// - Cross-chain operations without timeout
///
pub struct MissingTransactionDeadlineDetector {
    base: BaseDetector,
}

impl Default for MissingTransactionDeadlineDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MissingTransactionDeadlineDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-transaction-deadline".to_string()),
                "Missing Transaction Deadline".to_string(),
                "Detects time-sensitive operations without deadline parameters or expiration checks"
                    .to_string(),
                vec![
                    DetectorCategory::MEV,
                    DetectorCategory::Logic,
                    DetectorCategory::DeFi,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Checks if function is missing transaction deadline
    fn has_missing_deadline(
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

        // Skip view/pure functions
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return None;
        }

        // Skip interface functions (no body) - only IERC20 standard functions
        if (func_source.trim().is_empty() || !func_source.contains("{"))
            && (func_name_lower == "transfer"
                || func_name_lower == "transferfrom"
                || func_name_lower == "approve"
                || func_name_lower == "balanceof")
        {
            return None;
        }

        // Skip simple deposit functions that only credit user balance (no conversion/price)
        // Must have all these characteristics: named "deposit", has transferFrom, no price/swap/rate logic
        if func_name_lower == "deposit" &&
           func_source.contains("transferFrom") &&
           func_source.contains("balances[msg.sender") &&
           !func_source.contains("swap") &&
           !func_source.contains("exchange") &&
           !func_source.contains("price") &&
           !func_source.contains("rate") &&
           !func_source.contains("getAmount") &&
           !func_source.contains("*") &&  // No multiplication (conversion)
           !func_source.contains("/")
        {
            // No division (rate calculation)
            return None;
        }

        // Check if function is time-sensitive
        if !self.is_time_sensitive(&func_source, &func_name_lower) {
            return None;
        }

        // Skip AMM pair/pool-level swap functions (deadline enforced at router level)
        if self.is_amm_pool_function(&func_source, &func_name_lower, ctx) {
            return None;
        }

        // FP Reduction: Only flag contracts that manage their own liquidity reserves.
        // Consumer/wrapper contracts delegate to external DEX which enforces its own deadlines.
        if !self.manages_own_liquidity(ctx) {
            return None;
        }

        // Check for deadline protection (including alternative mechanisms)
        let has_deadline = self.has_deadline_parameter(function)
            || self.has_deadline_validation(&func_source)
            || self.has_expiration_check(&func_source)
            || self.has_alternative_timing_protection(&func_source);

        if !has_deadline {
            let operation_type = self.get_operation_type(&func_name_lower);
            return Some(format!(
                "Missing transaction deadline. {} operation '{}' has no deadline parameter \
                or expiration validation. Transaction can be executed at any time, \
                potentially at unfavorable conditions",
                operation_type, function.name.name
            ));
        }

        None
    }

    /// Checks if operation is time-sensitive (requires deadline protection)
    /// Only DEX/trading operations are truly time-sensitive
    /// Simple withdraw/deposit/claim operations do NOT need deadlines
    fn is_time_sensitive(&self, source: &str, func_name: &str) -> bool {
        // FP Reduction: Cancel/pause/stop functions are not time-sensitive trading ops
        if func_name.starts_with("cancel")
            || func_name.starts_with("pause")
            || func_name.starts_with("stop")
            || func_name == "emergencywithdraw"
        {
            return false;
        }

        // DEX/Trading function names - THESE need deadlines
        let is_trading_function = func_name.contains("swap")
            || func_name.contains("trade")
            || func_name.contains("exchange")
            || func_name.contains("fill"); // Order fill

        // FP Reduction: Trading functions by name must actually handle token transfers
        // to be time-sensitive. Functions named "swap" that only modify address variables
        // (e.g., library replacement, proxy upgrade) are not DeFi swaps.
        if is_trading_function {
            let has_value_flow = source.contains("transfer")
                || source.contains("transferFrom")
                || source.contains("safeTransfer")
                || source.contains("call{value:")
                || source.contains(".swap(")
                || source.contains("swapExact")
                || source.contains("getAmountOut")
                || source.contains("amountOut")
                || source.contains("IUniswap")
                || source.contains("IPancake")
                || source.contains("msg.value");
            if !has_value_flow {
                return false;
            }
        }

        // Uniswap V4 hooks are callbacks, not user-initiated - no deadline needed
        if func_name.contains("beforeswap")
            || func_name.contains("afterswap")
            || func_name.contains("beforeadd")
            || func_name.contains("afteradd")
            || func_name.contains("beforeremove")
            || func_name.contains("afterremove")
        {
            return false;
        }

        // ERC-7683 cross-chain intent functions - deadlines managed by intent protocol
        if func_name.contains("openorder")
            || func_name.contains("fillorder")
            || func_name.contains("resolveorder")
            || func_name.contains("settleorder")
        {
            if source.contains("CrossChain")
                || source.contains("Intent")
                || source.contains("Permit2")
            {
                return false;
            }
        }

        // Cross-chain bridge operations - timing managed by bridge protocol
        if (func_name.contains("bridge")
            || func_name.contains("relay")
            || func_name.contains("finalize"))
            && (source.contains("L1")
                || source.contains("L2")
                || source.contains("messenger")
                || source.contains("crossDomain")
                || source.contains("bridge"))
        {
            return false;
        }

        // Buy/sell only if price-sensitive (DEX context), not ticket/NFT purchases
        let is_price_sensitive_buy_sell = (func_name.contains("buy") || func_name.contains("sell"))
            && self.has_price_calculation(source)
            && !self.is_fixed_price_purchase(source, func_name);

        // Source contains DEX/trading operations (comment-aware to avoid FPs
        // from vulnerability documentation that mentions these patterns)
        let source_indicates_trading = self.has_keyword_in_code(source, ".swap(")
            || self.has_keyword_in_code(source, "IUniswap")
            || self.has_keyword_in_code(source, "IPancake")
            || self.has_keyword_in_code(source, "ICurve")
            || self.has_keyword_in_code(source, "IBalancer")
            || self.has_keyword_in_code(source, "getAmountOut")
            || self.has_keyword_in_code(source, "getAmountsOut")
            || self.has_keyword_in_code(source, "getAmountIn")
            || self.has_keyword_in_code(source, "amountOutMin")
            || self.has_keyword_in_code(source, "amountInMax")
            || self.has_keyword_in_code(source, "sqrtPriceLimit");

        // Execute/redeem only if they're order/swap execution in a DEX context,
        // not general multisig execute, allowance-based order systems, or vault redemptions.
        // ERC4626 redeem() and standard vault withdrawals do NOT need deadlines.
        let is_vault_redemption = func_name.contains("redeem")
            && (source.contains("shares")
                || source.contains("previewRedeem")
                || source.contains("_burn"))
            && !source.contains(".swap(")
            && !source.contains("IUniswap");

        let is_order_execution = (func_name.contains("execute") || func_name.contains("redeem"))
            && (source.contains("order")
                || source.contains(".swap(")
                || source.contains("getAmountOut"))
            && !self.is_non_trading_execution(source, func_name)
            && !is_vault_redemption;

        // EXPLICITLY NOT time-sensitive (no deadline needed):
        // - Simple withdraw() - just pulls user's balance, no price exposure
        // - Simple deposit() - just credits user's balance, no price exposure
        // - Simple claim() - just claims rewards, no price exposure
        // - These are user operations that don't depend on external prices

        is_trading_function
            || is_price_sensitive_buy_sell
            || source_indicates_trading
            || is_order_execution
    }

    /// Check if source contains price calculation logic (indicates DEX context)
    fn has_price_calculation(&self, source: &str) -> bool {
        source.contains("price")
            || source.contains("rate")
            || source.contains("getAmount")
            || source.contains("reserve")
            || source.contains("oracle")
            || source.contains("quoter")
            || source.contains("sqrt")
            || source.contains("k = ") // x * y = k AMM
    }

    /// Checks if a buy/sell function is a fixed-price purchase (lottery ticket, NFT mint, etc.)
    /// These are NOT time-sensitive DEX operations
    fn is_fixed_price_purchase(&self, source: &str, func_name: &str) -> bool {
        // Lottery ticket, NFT mint, or fixed-price token purchase patterns
        let is_ticket_or_nft =
            func_name.contains("ticket") || func_name.contains("mint") || func_name.contains("nft");

        // Fixed price patterns: exact price constants (not dynamic getPrice() calls)
        let has_fixed_price_constant = source.contains("ticketPrice")
            || source.contains("mintPrice")
            || source.contains("msg.value == ticketPrice")
            || source.contains("msg.value == mintPrice")
            || source.contains("PRICE")  // Named constant price
            || source.contains("cost =")  // Fixed cost variable
            || (source.contains("msg.value") && source.contains("==") && !source.contains("getPrice"));

        // participants.push pattern (lottery)
        let is_lottery = source.contains("participants.push");

        // Only consider it fixed-price if there is no dynamic price fetching
        let has_dynamic_price = source.contains("getPrice")
            || source.contains("getAmount")
            || source.contains("oracle")
            || source.contains("latestRoundData");

        is_ticket_or_nft || is_lottery || (has_fixed_price_constant && !has_dynamic_price)
    }

    /// Checks if an execute/redeem function is NOT a trading execution
    /// (multisig execute, allowance-based order management, etc.)
    fn is_non_trading_execution(&self, source: &str, func_name: &str) -> bool {
        // Multisig pattern: signature verification, not trading
        let is_multisig = source.contains("ecrecover")
            || source.contains("signatures")
            || source.contains("threshold")
            || source.contains("signers");

        // Pure allowance-based order execution (no price dependency)
        // Has "order" but operates on allowance, not price
        let is_allowance_order = source.contains("allowance")
            && !source.contains("getAmount")
            && !source.contains("amountOut")
            && !source.contains("swap");

        // Generic execute with just "data" parameter (proxy/multisig pattern)
        let is_generic_execute = func_name == "execute"
            && !source.contains("swap")
            && !source.contains("amountOut")
            && !source.contains("getAmount");

        is_multisig || is_allowance_order || is_generic_execute
    }

    /// Checks if the contract manages its own liquidity (has reserve state variables).
    /// Only contracts with their own AMM reserves need deadline protection.
    /// Consumer/wrapper contracts delegate to external DEX which has its own deadlines.
    fn manages_own_liquidity(&self, ctx: &AnalysisContext) -> bool {
        for var in ctx.contract.state_variables.iter() {
            let name = var.name.name.to_lowercase();
            if name.contains("reserve") {
                return true;
            }
        }
        false
    }

    /// Checks if this is an AMM pair/pool-level swap function
    /// Pool-level swap functions intentionally do NOT have deadlines;
    /// deadlines are enforced at the router level.
    fn is_amm_pool_function(&self, source: &str, func_name: &str, ctx: &AnalysisContext) -> bool {
        if !func_name.contains("swap") {
            return false;
        }

        let contract_source = &ctx.source_code;

        // UniswapV2Pair/V3Pool patterns: K invariant, reserve updates, lock modifier
        let has_k_invariant = source.contains("* uint(") // K = x * y check
            || source.contains(">= uint(")  // balance check pattern
            || source.contains("_update(");

        let has_pool_patterns = contract_source.contains("getReserves")
            && (contract_source.contains("_reserve0") || contract_source.contains("reserve0"))
            && (contract_source.contains("token0") || contract_source.contains("token1"));

        // Reentrancy lock is common in pool contracts
        let has_lock = source.contains("lock") || contract_source.contains("modifier lock");

        // Pool contracts typically have mint/burn/sync alongside swap
        let has_pool_lifecycle = contract_source.contains("fn mint")
            || contract_source.contains("function mint")
            || (contract_source.contains("function burn")
                && contract_source.contains("function sync"));

        // FP Reduction: Contracts that directly implement swap logic with reserves
        // (not calling an external router) manage deadlines at the router level
        let is_direct_swap_impl = func_name.contains("swap")
            && (source.contains("reserve") || source.contains("balanceOf(address(this))"))
            && (source.contains("amountOut")
                || source.contains("getAmountOut")
                || source.contains("k ="))
            && !source.contains("IUniswap")
            && !source.contains("IPancake")
            && !source.contains("router");

        // Must match multiple pool indicators to avoid false matches
        (has_k_invariant && has_lock)
            || (has_pool_patterns && has_pool_lifecycle)
            || is_direct_swap_impl
    }

    /// Checks if the function has alternative timing/price protection mechanisms
    /// that serve a similar purpose to deadlines.
    ///
    /// NOTE: Slippage protection alone (minAmountOut) is NOT sufficient to replace
    /// a deadline. A MEV bot can hold a transaction until the price reaches exactly
    /// the minimum output, then execute it. Only stronger mechanisms qualify:
    /// TWAP, circuit breakers, price bounds, multi-oracle, price impact validation.
    fn has_alternative_timing_protection(&self, source: &str) -> bool {
        // TWAP usage (resistant to single-block manipulation, implies time-averaged pricing)
        // Use comment-aware check since "TWAP" often appears in vulnerability comments
        let has_twap = self.has_keyword_in_code(source, "TWAP")
            || self.has_keyword_in_code(source, "twap")
            || self.has_keyword_in_code(source, "getTWAP")
            || self.has_keyword_in_code(source, "observe(");

        // Price bounds (minPrice/maxPrice require checks - bidirectional constraint)
        let has_price_bounds = (self.has_keyword_in_code(source, "minPrice")
            || self.has_keyword_in_code(source, "maxPrice"))
            && source.contains("require");

        // Circuit breaker protection (halts trading during volatility)
        let has_circuit_breaker = self.has_keyword_in_code(source, "circuitBreaker")
            || self.has_keyword_in_code(source, "circuit_breaker")
            || self.has_keyword_in_code(source, "CircuitBreaker");

        // Price impact validation (before/after price checks)
        // Require actual variable usage, not just mentioned in comments
        let has_price_impact_check = (self.has_keyword_in_code(source, "priceBefore")
            && self.has_keyword_in_code(source, "priceAfter"))
            || self.has_keyword_in_code(source, "MAX_IMPACT")
            || self.has_keyword_in_code(source, "maxImpact")
            || self.has_keyword_in_code(source, "maxPriceImpact");

        // Multi-oracle / median price (resistant to single oracle manipulation)
        let has_multi_oracle = self.has_keyword_in_code(source, "getMedianPrice")
            || self.has_keyword_in_code(source, "medianPrice")
            || self.has_keyword_in_code(source, "MIN_ORACLES");

        has_twap
            || has_price_bounds
            || has_circuit_breaker
            || has_price_impact_check
            || has_multi_oracle
    }

    /// Checks if a keyword appears in actual code lines (not just in comments).
    /// This prevents false matches on patterns mentioned in comments like
    /// "// VULNERABLE: no TWAP" or "// Should check: priceAfter"
    fn has_keyword_in_code(&self, source: &str, keyword: &str) -> bool {
        for line in source.lines() {
            let trimmed = line.trim();
            // Skip full-line comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }
            // For lines with inline comments, only check the code portion
            let code_part = if let Some(idx) = trimmed.find("//") {
                &trimmed[..idx]
            } else {
                trimmed
            };
            if code_part.contains(keyword) {
                return true;
            }
        }
        false
    }

    /// Checks if function has deadline parameter
    fn has_deadline_parameter(&self, function: &ast::Function<'_>) -> bool {
        function.parameters.iter().any(|param| {
            if let Some(name) = &param.name {
                let name_lower = name.name.to_lowercase();
                name_lower.contains("deadline")
                    || name_lower.contains("expiry")
                    || name_lower.contains("expiration")
                    || name_lower.contains("timeout")
                    || name_lower.contains("validuntil")
            } else {
                false
            }
        })
    }

    /// Checks for deadline validation in source
    fn has_deadline_validation(&self, source: &str) -> bool {
        (source.contains("block.timestamp") &&
         (source.contains("<=") || source.contains("<") || source.contains("require")) &&
         (source.contains("deadline") || source.contains("expiry") || source.contains("validUntil"))) ||
        // Check for explicit timestamp comparisons
        (source.contains("require") &&
         source.contains("block.timestamp") &&
         (source.contains("deadline") || source.contains("expiry")))
    }

    /// Checks for expiration validation (for orders/positions)
    fn has_expiration_check(&self, source: &str) -> bool {
        (source.contains("expiration") || source.contains("expiry") || source.contains("expiresAt"))
            && source.contains("block.timestamp")
            && (source.contains("require") || source.contains("<=") || source.contains("<"))
    }

    /// Gets operation type for error message
    fn get_operation_type(&self, func_name: &str) -> &str {
        if func_name.contains("swap") {
            "Swap"
        } else if func_name.contains("trade") {
            "Trade"
        } else if func_name.contains("exchange") {
            "Exchange"
        } else if func_name.contains("buy") || func_name.contains("sell") {
            "Purchase/Sale"
        } else if func_name.contains("execute") || func_name.contains("fill") {
            "Order execution"
        } else if func_name.contains("redeem") {
            "Redemption"
        } else if func_name.contains("withdraw") {
            "Withdrawal"
        } else if func_name.contains("liquidate") {
            "Liquidation"
        } else if func_name.contains("claim") {
            "Claim"
        } else {
            "Time-sensitive"
        }
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

impl Detector for MissingTransactionDeadlineDetector {
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

        // FP Reduction: Skip secure/fixed example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip attack/phishing contracts
        if crate::utils::is_attack_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Only analyze contracts with trading/swap functions.
        // deposit/withdraw/redeem are NOT time-sensitive by default (no deadline needed),
        // so exclude them from the gate to reduce FPs on vault/staking contracts.
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        let contract_has_trading_fn = contract_func_names.iter().any(|n| {
            n.contains("swap")
                || n.contains("trade")
                || n.contains("exchange")
                || n.contains("fill")
                || n.contains("buy")
                || n.contains("sell")
                || n.contains("addliquidity")
                || n.contains("removeliquidity")
        });
        let contract_name_relevant = contract_name_lower.contains("swap")
            || contract_name_lower.contains("router")
            || contract_name_lower.contains("exchange")
            || contract_name_lower.contains("dex")
            || contract_name_lower.contains("trading");
        if !contract_has_trading_fn && !contract_name_relevant {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(issue) = self.has_missing_deadline(function, ctx) {
                let message = format!(
                    "Function '{}' is missing transaction deadline. {} \
                    This allows MEV bots to delay execution for profit, transactions to execute \
                    at stale prices, and users to lose funds due to unfavorable timing. \
                    Transactions sitting in mempool can be executed when conditions have significantly changed",
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
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(362) // CWE-362: Concurrent Execution
                    .with_fix_suggestion(format!(
                        "Add deadline to '{}'. Implement: \
                        (1) Add 'deadline' parameter: function {}(... uint256 deadline); \
                        (2) Validate deadline: require(block.timestamp <= deadline, 'Transaction expired'); \
                        (3) For orders: Store expiration and check on execution; \
                        (4) Use reasonable deadline in frontend: block.timestamp + 15 minutes; \
                        (5) For batch operations: Apply deadline to entire batch; \
                        (6) Document deadline behavior for users",
                        function.name.name,
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
        let detector = MissingTransactionDeadlineDetector::new();
        assert_eq!(detector.id().0, "missing-transaction-deadline");
        assert_eq!(detector.name(), "Missing Transaction Deadline");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detector_categories() {
        let detector = MissingTransactionDeadlineDetector::new();
        let categories = detector.categories();
        assert!(categories.contains(&DetectorCategory::MEV));
        assert!(categories.contains(&DetectorCategory::Logic));
        assert!(categories.contains(&DetectorCategory::DeFi));
    }

    #[test]
    fn test_fixed_price_purchase_detection() {
        let detector = MissingTransactionDeadlineDetector::new();

        // Lottery ticket purchase - should be detected as fixed price
        assert!(detector.is_fixed_price_purchase(
            "require(msg.value == ticketPrice); participants.push(msg.sender);",
            "buyticket"
        ));

        // NFT mint by function name - should be detected as fixed price
        assert!(detector.is_fixed_price_purchase("require(msg.value >= mintPrice);", "mintnft"));

        // DEX buy with getAmountOut - should NOT be detected as fixed price
        assert!(!detector.is_fixed_price_purchase(
            "uint256 amountOut = getAmountOut(amountIn); price = oracle.getPrice();",
            "buytokens"
        ));

        // DEX buy with dynamic getPrice() - should NOT be detected as fixed price
        assert!(!detector.is_fixed_price_purchase(
            "uint256 price = getPrice(); uint256 cost = amount * price; require(msg.value >= cost);",
            "buy"
        ));
    }

    #[test]
    fn test_non_trading_execution_detection() {
        let detector = MissingTransactionDeadlineDetector::new();

        // Multisig execute - should be detected as non-trading
        assert!(detector.is_non_trading_execution(
            "bytes32 dataHash = keccak256(data); address recovered = ecrecover(dataHash, v, r, s); require(signers[recovered]);",
            "execute"
        ));

        // Allowance-based order - should be detected as non-trading
        assert!(detector.is_non_trading_execution(
            "uint256 allowance = token.allowance(order.trader, address(this)); require(allowance >= order.amount);",
            "executeorder"
        ));

        // Generic execute without swap context - should be detected as non-trading
        assert!(detector.is_non_trading_execution(
            "require(msg.sender == owner); (bool success,) = target.call(data);",
            "execute"
        ));

        // DEX order execution - should NOT be detected as non-trading
        assert!(!detector.is_non_trading_execution(
            "uint256 amountOut = getAmountOut(order.amount); swap(order.tokenIn, order.tokenOut);",
            "executeorder"
        ));
    }

    #[test]
    fn test_alternative_timing_protection() {
        let detector = MissingTransactionDeadlineDetector::new();

        // TWAP usage in actual code - qualifies as alternative protection
        assert!(detector.has_alternative_timing_protection("uint256 twapPrice = getTWAP();"));

        // TWAP mentioned only in a comment - should NOT qualify
        assert!(!detector.has_alternative_timing_protection(
            "// VULNERABLE: no TWAP\nuint256 amountOut = getAmountOut(amountIn);"
        ));

        // Price bounds - qualifies as alternative protection
        assert!(detector.has_alternative_timing_protection(
            "require(price >= minPrice && price <= maxPrice, 'Price out of bounds');"
        ));

        // Circuit breaker - qualifies as alternative protection
        assert!(detector.has_alternative_timing_protection(
            "require(!circuitBreakerActive, 'Circuit breaker active');"
        ));

        // Price impact check with both priceBefore and priceAfter in code
        assert!(detector.has_alternative_timing_protection(
            "uint256 priceBefore = getPrice();\n// do swap\nuint256 priceAfter = getPrice();"
        ));

        // Price impact check with priceAfter only in comment - should NOT qualify
        assert!(!detector.has_alternative_timing_protection(
            "uint256 priceBefore = getPrice();\n// Should check: priceAfter <= priceBefore * 1.01"
        ));

        // Multi-oracle median - qualifies as alternative protection
        assert!(detector.has_alternative_timing_protection("uint256 price = getMedianPrice();"));

        // Slippage protection alone does NOT qualify (MEV can wait for exact minAmountOut)
        assert!(!detector.has_alternative_timing_protection(
            "require(amountOut >= minAmountOut, 'Slippage too high');"
        ));

        // No protection at all - should return false
        assert!(!detector.has_alternative_timing_protection(
            "uint256 amountOut = amountIn * reserveB / reserveA; token.transfer(msg.sender, amountOut);"
        ));
    }

    #[test]
    fn test_is_time_sensitive_excludes_lottery() {
        let detector = MissingTransactionDeadlineDetector::new();

        // Lottery buyTicket should NOT be time-sensitive
        // ticketPrice contains "price" which triggers has_price_calculation,
        // but is_fixed_price_purchase should catch it
        assert!(!detector.is_time_sensitive(
            "require(msg.value == ticketPrice, 'Wrong price'); participants.push(msg.sender);",
            "buyticket"
        ));
    }

    #[test]
    fn test_is_time_sensitive_keeps_real_dex_swap() {
        let detector = MissingTransactionDeadlineDetector::new();

        // Real DEX swap should remain time-sensitive
        assert!(detector.is_time_sensitive(
            "uint256 amountOut = getAmountOut(amountIn); token.transfer(msg.sender, amountOut);",
            "swap"
        ));
    }

    #[test]
    fn test_is_time_sensitive_excludes_multisig_execute() {
        let detector = MissingTransactionDeadlineDetector::new();

        // Multisig execute with signature verification - not time-sensitive
        assert!(!detector.is_time_sensitive(
            "bytes32 hash = keccak256(data); address signer = ecrecover(hash, v, r, s); require(signers[signer]); (bool ok,) = target.call(data);",
            "execute"
        ));
    }
}
