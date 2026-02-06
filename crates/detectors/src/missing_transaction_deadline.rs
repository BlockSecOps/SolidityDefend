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

        // Check for deadline protection
        let has_deadline = self.has_deadline_parameter(function)
            || self.has_deadline_validation(&func_source)
            || self.has_expiration_check(&func_source);

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
        // DEX/Trading function names - THESE need deadlines
        let is_trading_function = func_name.contains("swap")
            || func_name.contains("trade")
            || func_name.contains("exchange")
            || func_name.contains("fill"); // Order fill

        // Buy/sell only if price-sensitive (DEX context)
        let is_price_sensitive_buy_sell = (func_name.contains("buy") || func_name.contains("sell"))
            && self.has_price_calculation(source);

        // Source contains DEX/trading operations
        let source_indicates_trading = source.contains(".swap(")
            || source.contains("IUniswap")
            || source.contains("IPancake")
            || source.contains("ICurve")
            || source.contains("IBalancer")
            || source.contains("getAmountOut")
            || source.contains("getAmountsOut")
            || source.contains("getAmountIn")
            || source.contains("amountOutMin")
            || source.contains("amountInMax")
            || source.contains("sqrtPriceLimit");

        // Liquidation functions need deadlines (price-dependent)
        let is_liquidation = func_name.contains("liquidat")
            && (source.contains("price") || source.contains("collateral"));

        // Execute/redeem only if they're order/swap execution, not general contract calls
        let is_order_execution = (func_name.contains("execute") || func_name.contains("redeem"))
            && (source.contains("order") || source.contains("swap") || source.contains("price"));

        // EXPLICITLY NOT time-sensitive (no deadline needed):
        // - Simple withdraw() - just pulls user's balance, no price exposure
        // - Simple deposit() - just credits user's balance, no price exposure
        // - Simple claim() - just claims rewards, no price exposure
        // - These are user operations that don't depend on external prices

        is_trading_function
            || is_price_sensitive_buy_sell
            || source_indicates_trading
            || is_liquidation
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
}
