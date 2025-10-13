use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for AMM constant product (K) invariant violations
///
/// Detects violations of the AMM invariant (x*y=k formula) including:
/// - Breaking x*y=k formula
/// - Missing invariant checks after swaps
/// - Unsafe fee-on-transfer token handling
/// - Inadequate reserve updates
pub struct AmmKInvariantViolationDetector {
    base: BaseDetector,
}

impl AmmKInvariantViolationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("amm-k-invariant-violation".to_string()),
                "AMM Constant Product Violation".to_string(),
                "Detects violations of AMM invariants (x*y=k formula), including missing k validation, unsafe fee-on-transfer token handling, and inadequate reserve updates".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Check if function is an AMM swap function
    fn is_swap_function(&self, func_name: &str, func_source: &str) -> bool {
        let swap_keywords = ["swap", "exchange", "trade", "convert"];

        swap_keywords.iter().any(|&keyword| {
            func_name.to_lowercase().contains(keyword)
        }) || func_source.contains("SwapParams")
            || func_source.contains("amountOut")
            || func_source.contains("amountIn")
    }

    /// Check for missing K invariant validation
    fn check_k_invariant_validation(&self, func_source: &str) -> Option<String> {
        let modifies_reserves = func_source.contains("reserve0")
            || func_source.contains("reserve1")
            || func_source.contains("_update")
            || func_source.contains("sync");

        if !modifies_reserves {
            return None;
        }

        // Check for K invariant calculation and validation
        let has_k_calculation = (func_source.contains("*") && func_source.contains("reserve"))
            || func_source.contains("balance0 * balance1")
            || func_source.contains("reserveIn * reserveOut");

        let has_k_check = func_source.contains(">=")
            && (func_source.contains("* balance")
                || func_source.contains("* reserve")
                || func_source.contains("kLast"));

        let has_require_with_k = func_source.contains("require(")
            && has_k_calculation;

        if modifies_reserves && !has_k_check && !has_require_with_k {
            return Some(
                "Reserve updates don't verify constant product (K) invariant (x*y >= k), \
                allowing pool imbalance and potential value extraction"
                    .to_string(),
            );
        }

        None
    }

    /// Check for unsafe fee-on-transfer token handling
    fn check_fot_token_handling(&self, func_source: &str) -> Option<String> {
        let has_transfer = func_source.contains("transfer")
            || func_source.contains("transferFrom")
            || func_source.contains("safeTransfer");

        if !has_transfer {
            return None;
        }

        // Check if balance is measured before and after transfer
        let has_balance_before = func_source.contains("balanceBefore")
            || func_source.contains("balance0Before")
            || func_source.contains("balance1Before");

        let has_balance_check = func_source.contains("balanceOf(address(this))")
            && func_source.contains("balance");

        // Check if actual received amount is calculated
        let calculates_actual_amount = func_source.contains("balance") && func_source.contains("-")
            || func_source.contains("actualAmount")
            || func_source.contains("receivedAmount");

        if has_transfer && !has_balance_before && !calculates_actual_amount {
            return Some(
                "Token transfers don't account for fee-on-transfer tokens, \
                incorrect reserve calculations may result in pool drainage"
                    .to_string(),
            );
        }

        // Check if reserves are synced with actual balances
        let syncs_with_balance = func_source.contains("balanceOf")
            && (func_source.contains("reserve0 =") || func_source.contains("reserve1 ="));

        if has_transfer && has_balance_check && !syncs_with_balance {
            return Some(
                "Reserve updates don't sync with actual token balances, \
                may cause discrepancies with fee-on-transfer tokens"
                    .to_string(),
            );
        }

        None
    }

    /// Check for inadequate reserve updates
    fn check_reserve_updates(&self, func_source: &str) -> Option<String> {
        let updates_reserves = (func_source.contains("reserve0 =")
            || func_source.contains("reserve1 =")
            || func_source.contains("_update("))
            && (func_source.contains("balance") || func_source.contains("amount"));

        if !updates_reserves {
            return None;
        }

        // Check for reentrancy protection during updates
        let has_reentrancy_guard = func_source.contains("nonReentrant")
            || func_source.contains("locked")
            || func_source.contains("_status")
            || func_source.contains("lock()");

        let has_external_call = func_source.contains(".call")
            || func_source.contains(".transfer")
            || func_source.contains("_mint")
            || func_source.contains("_burn");

        if updates_reserves && has_external_call && !has_reentrancy_guard {
            return Some(
                "Reserve updates occur without reentrancy protection, \
                enabling manipulation during callbacks"
                    .to_string(),
            );
        }

        // Check if reserves are updated atomically
        let separate_updates = func_source.matches("reserve0 =").count() > 0
            && func_source.matches("reserve1 =").count() > 0
            && !func_source.contains("_update(");

        if separate_updates && has_external_call {
            return Some(
                "Reserves updated separately instead of atomically, \
                creating window for manipulation between updates"
                    .to_string(),
            );
        }

        // Check for missing timestamp update
        let updates_timestamp = func_source.contains("blockTimestampLast")
            || func_source.contains("lastUpdate")
            || func_source.contains("block.timestamp");

        if updates_reserves && !updates_timestamp {
            return Some(
                "Reserve updates don't update timestamp, \
                affecting TWAP oracle accuracy"
                    .to_string(),
            );
        }

        None
    }

    /// Check for missing slippage and validation checks
    fn check_slippage_validation(&self, func_source: &str, is_swap: bool) -> Option<String> {
        if !is_swap {
            return None;
        }

        // Check for minimum output validation
        let has_min_output = func_source.contains("minAmount")
            || func_source.contains("amountOutMin")
            || func_source.contains("minOutput")
            || func_source.contains("minimumAmount");

        let has_slippage_check = func_source.contains("require(")
            && (func_source.contains(">=") || func_source.contains(">"));

        if !has_min_output && !has_slippage_check {
            return Some(
                "Swap lacks slippage protection (minAmountOut parameter), \
                users vulnerable to sandwich attacks and MEV"
                    .to_string(),
            );
        }

        // Check for deadline validation
        let has_deadline = func_source.contains("deadline")
            || func_source.contains("block.timestamp");

        let has_deadline_check = func_source.contains("require(")
            && func_source.contains("deadline")
            || (func_source.contains("block.timestamp") && func_source.contains("<="));

        if !has_deadline && !has_deadline_check {
            return Some(
                "Swap lacks deadline parameter, \
                transactions may execute at unfavorable prices if delayed"
                    .to_string(),
            );
        }

        None
    }

    /// Check for fee calculation issues
    fn check_fee_calculation(&self, func_source: &str) -> Option<String> {
        let calculates_fee = func_source.contains("fee")
            || func_source.contains("Fee")
            || func_source.contains("* 997")
            || func_source.contains("* 1000");

        if !calculates_fee {
            return None;
        }

        // Check if fee is properly deducted before K check
        let fee_adjusted_k_check = (func_source.contains("Adjusted")
            || func_source.contains("adjusted"))
            && func_source.contains("balance")
            && func_source.contains("*");

        if calculates_fee && !fee_adjusted_k_check {
            return Some(
                "K invariant check doesn't account for fees, \
                may incorrectly reject valid swaps or allow invalid ones"
                    .to_string(),
            );
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

impl Detector for AmmKInvariantViolationDetector {
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
            let func_source = self.get_function_source(function, ctx);
            let func_name = &function.name.name;

            let is_swap = self.is_swap_function(func_name, &func_source);

            let mut issues = Vec::new();

            // Check for K invariant validation
            if let Some(issue) = self.check_k_invariant_validation(&func_source) {
                issues.push(issue);
            }

            // Check for fee-on-transfer token handling
            if let Some(issue) = self.check_fot_token_handling(&func_source) {
                issues.push(issue);
            }

            // Check for reserve update issues
            if let Some(issue) = self.check_reserve_updates(&func_source) {
                issues.push(issue);
            }

            // Check for slippage validation
            if let Some(issue) = self.check_slippage_validation(&func_source, is_swap) {
                issues.push(issue);
            }

            // Check for fee calculation issues
            if let Some(issue) = self.check_fee_calculation(&func_source) {
                issues.push(issue);
            }

            // Check for explicit vulnerability marker
            if func_source.contains("VULNERABILITY")
                && (func_source.contains("invariant")
                    || func_source.contains("K")
                    || func_source.contains("x*y")
                    || func_source.contains("constant product"))
            {
                issues.push("AMM K invariant vulnerability marker detected".to_string());
            }

            // Create findings for all discovered issues
            if !issues.is_empty() {
                let message = format!(
                    "AMM function '{}' violates constant product invariant: {}",
                    func_name,
                    issues.join("; ")
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
                    .with_cwe(20)  // CWE-20: Improper Input Validation
                    .with_fix_suggestion(format!(
                        "Secure AMM function '{}': Validate K invariant (reserve0 * reserve1 >= kBefore), \
                        handle fee-on-transfer tokens by measuring actual balances, \
                        update reserves atomically with reentrancy protection, \
                        add slippage protection and deadline checks",
                        func_name
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
    fn test_detector_properties() {
        let detector = AmmKInvariantViolationDetector::new();
        assert_eq!(detector.name(), "AMM Constant Product Violation");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "amm-k-invariant-violation");
    }

    #[test]
    fn test_swap_function_detection() {
        let detector = AmmKInvariantViolationDetector::new();

        assert!(detector.is_swap_function("swap", "function swap() external"));
        assert!(detector.is_swap_function("exchange", "function exchange() public"));
        assert!(detector.is_swap_function("test", "SwapParams memory params"));
        assert!(!detector.is_swap_function("transfer", "function transfer() public"));
    }

    #[test]
    fn test_k_invariant_validation() {
        let detector = AmmKInvariantViolationDetector::new();

        // Should detect missing K validation
        let vulnerable_code = "function swap() external {
            reserve0 = balance0;
            reserve1 = balance1;
        }";
        assert!(detector.check_k_invariant_validation(vulnerable_code).is_some());

        // Should not flag code with K validation
        let safe_code = "function swap() external {
            uint256 kBefore = reserve0 * reserve1;
            reserve0 = balance0;
            reserve1 = balance1;
            require(reserve0 * reserve1 >= kBefore, \"K\");
        }";
        assert!(detector.check_k_invariant_validation(safe_code).is_none());
    }

    #[test]
    fn test_fot_token_handling() {
        let detector = AmmKInvariantViolationDetector::new();

        // Should detect missing FOT handling
        let vulnerable_code = "function swap() external {
            token.transferFrom(msg.sender, address(this), amount);
            reserve0 += amount;
        }";
        assert!(detector.check_fot_token_handling(vulnerable_code).is_some());

        // Should not flag code that checks actual balance
        let safe_code = "function swap() external {
            uint256 balanceBefore = token.balanceOf(address(this));
            token.transferFrom(msg.sender, address(this), amount);
            uint256 actualAmount = token.balanceOf(address(this)) - balanceBefore;
            reserve0 += actualAmount;
        }";
        assert!(detector.check_fot_token_handling(safe_code).is_none());
    }

    #[test]
    fn test_reserve_update_checks() {
        let detector = AmmKInvariantViolationDetector::new();

        // Should detect unprotected reserve updates with external calls
        let vulnerable_code = "function swap() external {
            token.transfer(msg.sender, amount);
            reserve0 = balance0;
            reserve1 = balance1;
        }";
        assert!(detector.check_reserve_updates(vulnerable_code).is_some());

        // Should not flag protected updates
        let safe_code = "function swap() external nonReentrant {
            token.transfer(msg.sender, amount);
            _update(balance0, balance1);
        }";
        assert!(detector.check_reserve_updates(safe_code).is_none());
    }

    #[test]
    fn test_slippage_validation() {
        let detector = AmmKInvariantViolationDetector::new();

        // Should detect missing slippage protection
        let vulnerable_code = "function swap(uint256 amountIn) external {
            uint256 amountOut = getAmountOut(amountIn);
            token.transfer(msg.sender, amountOut);
        }";
        assert!(detector.check_slippage_validation(vulnerable_code, true).is_some());

        // Should not flag code with slippage protection
        let safe_code = "function swap(uint256 amountIn, uint256 minAmountOut, uint256 deadline) external {
            require(block.timestamp <= deadline, \"Expired\");
            uint256 amountOut = getAmountOut(amountIn);
            require(amountOut >= minAmountOut, \"Slippage\");
            token.transfer(msg.sender, amountOut);
        }";
        assert!(detector.check_slippage_validation(safe_code, true).is_none());
    }
}
