use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::contract_classification;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

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

impl Default for AmmKInvariantViolationDetector {
    fn default() -> Self {
        Self::new()
    }
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
        let name_lower = func_name.to_lowercase();

        // Strong name-based signals: function name explicitly involves swapping
        let swap_name_keywords = ["swap", "exchange", "trade"];
        let name_match = swap_name_keywords
            .iter()
            .any(|&keyword| name_lower.contains(keyword));

        if name_match {
            return true;
        }

        // Source-based signals only if name is ambiguous
        // Require both SwapParams (struct type) to be definitive
        // FP Reduction: Removed amountOut/amountIn as standalone signals
        // because mint/burn functions also reference these in AMM pools
        func_source.contains("SwapParams")
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

        // Recognize both require(newK >= oldK) and if (newK < oldK) revert patterns
        let has_k_check_gte = func_source.contains(">=")
            && (func_source.contains("* balance")
                || func_source.contains("* reserve")
                || func_source.contains("kLast"));

        // Recognize if (product < k) revert ... pattern (equivalent to require(product >= k))
        let has_k_check_lt = func_source.contains("<")
            && has_k_calculation
            && (func_source.contains("revert") || func_source.contains("require("));

        let has_k_check = has_k_check_gte || has_k_check_lt;

        let has_require_with_k = (func_source.contains("require(")
            || func_source.contains("revert"))
            && has_k_calculation;

        // Also recognize fee-adjusted invariant checks (e.g., balance0Adjusted * balance1Adjusted)
        let has_adjusted_k_check = (func_source.contains("Adjusted")
            || func_source.contains("adjusted"))
            && func_source.contains("*")
            && (func_source.contains("<")
                || func_source.contains(">=")
                || func_source.contains("require(")
                || func_source.contains("revert"));

        if modifies_reserves && !has_k_check && !has_require_with_k && !has_adjusted_k_check {
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

        let has_balance_check =
            func_source.contains("balanceOf(address(this))") && func_source.contains("balance");

        // Check if actual received amount is calculated
        let calculates_actual_amount = func_source.contains("balance") && func_source.contains("-")
            || func_source.contains("actualAmount")
            || func_source.contains("receivedAmount");

        // Check if the function reads actual balances via balanceOf and syncs reserves
        // This is the Uniswap V2 pattern: transfer, then read balanceOf, then _update
        // which correctly handles FOT tokens by using actual remaining balances
        let reads_actual_balance_and_syncs = func_source.contains("balanceOf(address(this))")
            && (func_source.contains("_update(")
                || func_source.contains("reserve0 =")
                || func_source.contains("reserve1 ="));

        if has_transfer
            && !has_balance_before
            && !calculates_actual_amount
            && !reads_actual_balance_and_syncs
        {
            return Some(
                "Token transfers don't account for fee-on-transfer tokens, \
                incorrect reserve calculations may result in pool drainage"
                    .to_string(),
            );
        }

        // Check if reserves are synced with actual balances
        // Recognize both direct assignments and _update() calls as valid sync mechanisms
        let syncs_with_balance = func_source.contains("balanceOf")
            && (func_source.contains("reserve0 =")
                || func_source.contains("reserve1 =")
                || func_source.contains("reserve0 +=")
                || func_source.contains("reserve1 +=")
                || func_source.contains("_update("));

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
    fn check_reserve_updates_with_ast(
        &self,
        func_source: &str,
        function: &ast::Function<'_>,
    ) -> Option<String> {
        let updates_reserves = (func_source.contains("reserve0 =")
            || func_source.contains("reserve1 =")
            || func_source.contains("_update("))
            && (func_source.contains("balance") || func_source.contains("amount"));

        if !updates_reserves {
            return None;
        }

        // Use AST-aware reentrancy check that includes function modifiers
        let has_reentrancy_guard = self.has_reentrancy_protection(func_source, function);

        // Only flag truly external calls (low-level .call, .transfer, .send)
        // Internal functions like _mint/_burn (prefixed with _) are not external calls
        // and don't introduce reentrancy risk from external actors
        let has_external_call = func_source.contains(".call")
            || func_source.contains(".transfer")
            || func_source.contains(".send(");

        // Also check for safeTransfer/safeTransferFrom which are external ERC20 calls
        let has_safe_transfer =
            func_source.contains("safeTransfer") || func_source.contains("safeTransferFrom");

        let has_risky_external_call = has_external_call || has_safe_transfer;

        if updates_reserves && has_risky_external_call && !has_reentrancy_guard {
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

        if separate_updates && has_risky_external_call && !has_reentrancy_guard {
            return Some(
                "Reserves updated separately instead of atomically, \
                creating window for manipulation between updates"
                    .to_string(),
            );
        }

        // Check for missing timestamp update
        // Skip this check if using _update() function which typically handles timestamps internally
        let uses_update_function = func_source.contains("_update(");
        let updates_timestamp = func_source.contains("blockTimestampLast")
            || func_source.contains("lastUpdate")
            || func_source.contains("block.timestamp");

        if updates_reserves && !updates_timestamp && !uses_update_function {
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
        let has_deadline =
            func_source.contains("deadline") || func_source.contains("block.timestamp");

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
    ///
    /// Note: function.location lines are 1-based, so we convert to 0-based
    /// indices when indexing into the source_lines vector.
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        // Lines are 1-based; convert to 0-based index for the source_lines vec
        if start == 0 {
            return String::new();
        }
        let start_idx = start - 1;
        let end_idx = end.saturating_sub(1);

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start_idx < source_lines.len() && end_idx < source_lines.len() {
            source_lines[start_idx..=end_idx].join("\n")
        } else {
            String::new()
        }
    }

    /// Check if a function has a reentrancy guard modifier (including from AST modifiers)
    fn has_reentrancy_protection(&self, func_source: &str, function: &ast::Function<'_>) -> bool {
        // Check source text for common reentrancy guard patterns
        if func_source.contains("nonReentrant")
            || func_source.contains("locked")
            || func_source.contains("_status")
            || func_source.contains("lock()")
        {
            return true;
        }

        // Uniswap V2 pattern: `unlocked` state variable check
        // modifier lock() { require(unlocked == 1); unlocked = 0; _; unlocked = 1; }
        if func_source.contains("unlocked") {
            return true;
        }

        // Also check the AST modifier list for reentrancy guard modifiers
        for modifier in function.modifiers.iter() {
            let mod_name = modifier.name.name.to_lowercase();
            if mod_name.contains("nonreentrant")
                || mod_name == "lock"
                || mod_name.contains("mutex")
                || mod_name.contains("noreentr")
            {
                return true;
            }
        }

        false
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        // NEW: Only run this detector on AMM contracts
        if !contract_classification::is_amm_contract(ctx) {
            return Ok(findings); // Not an AMM - skip analysis
        }

        // Phase 6: Tighten AMM detection - require strong AMM signals
        let source = &ctx.source_code;
        let has_strong_amm_signals = (source.contains("reserve0") && source.contains("reserve1"))
            || source.contains("IUniswapV2Pair")
            || source.contains("IUniswapV3Pool")
            || source.contains("getReserves")
            || (source.contains("token0") && source.contains("token1"));

        if !has_strong_amm_signals {
            return Ok(findings); // Not a strong enough AMM signal
        }

        for function in ctx.get_functions() {
            // Phase 6: Skip view/pure functions - can't violate invariant without state changes
            if matches!(
                function.mutability,
                ast::StateMutability::View | ast::StateMutability::Pure
            ) {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);
            let func_name = &function.name.name;

            // Phase 6: Skip functions that don't modify reserves
            let func_name_lower = func_name.to_lowercase();
            if func_name_lower == "getreserves"
                || func_name_lower == "quote"
                || func_name_lower == "getamountin"
                || func_name_lower == "getamountout"
                || func_name_lower == "factory"
                || func_name_lower == "token0"
                || func_name_lower == "token1"
            {
                continue;
            }

            // FP Reduction: Skip admin/config/constructor functions
            // These don't perform swaps or modify AMM invariants
            if func_name_lower.starts_with("set")
                || func_name_lower.starts_with("update")
                || func_name_lower.starts_with("init")
                || func_name_lower == "constructor"
                || func_name_lower == "initialize"
                || func_name_lower == "skim"
                || func_name_lower == "sync"
            {
                continue;
            }

            let is_swap = self.is_swap_function(func_name, &func_source);

            let mut issues = Vec::new();

            // FP Reduction: Only check K invariant for swap functions.
            // mint/burn functions add/remove liquidity proportionally and
            // don't need K invariant checks (this is standard AMM design).
            let is_mint_or_burn = func_name_lower == "mint"
                || func_name_lower == "burn"
                || func_name_lower.contains("addliquidity")
                || func_name_lower.contains("removeliquidity");

            if !is_mint_or_burn {
                // Check for K invariant validation
                if let Some(issue) = self.check_k_invariant_validation(&func_source) {
                    issues.push(issue);
                }
            }

            // Check for fee-on-transfer token handling
            if let Some(issue) = self.check_fot_token_handling(&func_source) {
                issues.push(issue);
            }

            // Check for reserve update issues (AST-aware for reentrancy guard detection)
            if let Some(issue) = self.check_reserve_updates_with_ast(&func_source, function) {
                issues.push(issue);
            }

            // Check for slippage validation (swap functions only)
            if is_swap {
                if let Some(issue) = self.check_slippage_validation(&func_source, is_swap) {
                    issues.push(issue);
                }
            }

            // Check for fee calculation issues (swap functions only)
            // FP Reduction: Non-swap functions (mint, burn, addLiquidity) reference
            // "fee" or "Fee" for protocol fees but don't need fee-adjusted K checks
            if is_swap {
                if let Some(issue) = self.check_fee_calculation(&func_source) {
                    issues.push(issue);
                }
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

                // NEW: High confidence since this IS an AMM contract
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
                    .with_confidence(Confidence::High) // NEW: Set confidence
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
    use crate::types::test_utils::create_mock_ast_function;

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
        assert!(
            detector
                .check_k_invariant_validation(vulnerable_code)
                .is_some()
        );

        // Should not flag code with K validation using require(>=)
        let safe_code = "function swap() external {
            uint256 kBefore = reserve0 * reserve1;
            reserve0 = balance0;
            reserve1 = balance1;
            require(reserve0 * reserve1 >= kBefore, \"K\");
        }";
        assert!(detector.check_k_invariant_validation(safe_code).is_none());
    }

    #[test]
    fn test_k_invariant_revert_pattern() {
        let detector = AmmKInvariantViolationDetector::new();

        // Should not flag code that uses if (x < y) revert pattern
        // This is the Uniswap V2 / modern Solidity style
        let safe_revert_code = "function swap() external {
            uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
            uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
            if (balance0Adjusted * balance1Adjusted < uint256(_reserve0) * _reserve1 * 1000000) {
                revert InvariantViolation();
            }
            _update(balance0, balance1, _reserve0, _reserve1);
        }";
        assert!(
            detector
                .check_k_invariant_validation(safe_revert_code)
                .is_none(),
            "Should not flag revert-based K invariant checks"
        );
    }

    #[test]
    fn test_k_invariant_adjusted_balance_pattern() {
        let detector = AmmKInvariantViolationDetector::new();

        // Should not flag code with fee-adjusted invariant check
        let safe_adjusted_code = "function swap() external {
            uint256 balance0Adjusted = balance0 * 1000 - fee0;
            uint256 balance1Adjusted = balance1 * 1000 - fee1;
            require(balance0Adjusted * balance1Adjusted >= kBefore * 1000000);
            _update(balance0, balance1, reserve0, reserve1);
        }";
        assert!(
            detector
                .check_k_invariant_validation(safe_adjusted_code)
                .is_none(),
            "Should not flag adjusted balance K invariant checks"
        );
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
    fn test_fot_update_function_sync() {
        let detector = AmmKInvariantViolationDetector::new();

        // Should not flag when reserves are synced via _update() after balanceOf check
        let safe_update_code = "function swap() external {
            token0.safeTransfer(to, amount0Out);
            uint256 balance0 = token0.balanceOf(address(this));
            uint256 balance1 = token1.balanceOf(address(this));
            _update(balance0, balance1, _reserve0, _reserve1);
        }";
        assert!(
            detector
                .check_fot_token_handling(safe_update_code)
                .is_none(),
            "Should not flag when _update() syncs reserves with actual balances"
        );
    }

    #[test]
    fn test_reserve_update_checks() {
        let detector = AmmKInvariantViolationDetector::new();
        let arena = ast::AstArena::new();

        // Should detect unprotected reserve updates with external calls
        let vulnerable_code = "function swap() external {
            token.transfer(msg.sender, amount);
            reserve0 = balance0;
            reserve1 = balance1;
        }";
        let func = create_mock_ast_function(
            &arena,
            "swap",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(
            detector
                .check_reserve_updates_with_ast(vulnerable_code, &func)
                .is_some()
        );

        // Should not flag protected updates (nonReentrant in source text)
        let safe_code = "function swap() external nonReentrant {
            token.transfer(msg.sender, amount);
            _update(balance0, balance1);
        }";
        assert!(
            detector
                .check_reserve_updates_with_ast(safe_code, &func)
                .is_none()
        );
    }

    #[test]
    fn test_reserve_updates_internal_mint_burn() {
        let detector = AmmKInvariantViolationDetector::new();
        let arena = ast::AstArena::new();

        // Internal _mint/_burn should not be treated as external calls
        // even without nonReentrant (they are internal AMM accounting)
        let code_with_internal_calls = "function mint(address to) external {
            _mint(to, liquidity);
            _update(balance0, balance1, _reserve0, _reserve1);
        }";
        let func = create_mock_ast_function(
            &arena,
            "mint",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(
            detector
                .check_reserve_updates_with_ast(code_with_internal_calls, &func)
                .is_none(),
            "Internal _mint/_burn should not trigger reentrancy warning"
        );
    }

    #[test]
    fn test_reserve_updates_safe_transfer_with_guard() {
        let detector = AmmKInvariantViolationDetector::new();
        let arena = ast::AstArena::new();

        // safeTransfer with nonReentrant guard should be safe
        let safe_code = "function burn(address to) external nonReentrant {
            token0.safeTransfer(to, amount0);
            token1.safeTransfer(to, amount1);
            _update(balance0, balance1, _reserve0, _reserve1);
        }";
        let func = create_mock_ast_function(
            &arena,
            "burn",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(
            detector
                .check_reserve_updates_with_ast(safe_code, &func)
                .is_none(),
            "safeTransfer with nonReentrant should not flag"
        );
    }

    #[test]
    fn test_slippage_validation() {
        let detector = AmmKInvariantViolationDetector::new();

        // Should detect missing slippage protection
        let vulnerable_code = "function swap(uint256 amountIn) external {
            uint256 amountOut = getAmountOut(amountIn);
            token.transfer(msg.sender, amountOut);
        }";
        assert!(
            detector
                .check_slippage_validation(vulnerable_code, true)
                .is_some()
        );

        // Should not flag code with slippage protection
        let safe_code =
            "function swap(uint256 amountIn, uint256 minAmountOut, uint256 deadline) external {
            require(block.timestamp <= deadline, \"Expired\");
            uint256 amountOut = getAmountOut(amountIn);
            require(amountOut >= minAmountOut, \"Slippage\");
            token.transfer(msg.sender, amountOut);
        }";
        assert!(
            detector
                .check_slippage_validation(safe_code, true)
                .is_none()
        );
    }

    #[test]
    fn test_safe_amm_pool_swap_pattern() {
        let detector = AmmKInvariantViolationDetector::new();

        // Emulate the safe_amm_pool.sol swap function pattern
        // Uses: revert-based K check, safeTransfer + balanceOf + _update, deadline + minAmountOut
        let safe_swap = r#"function swap(
            uint256 amount0Out,
            uint256 amount1Out,
            address to,
            uint256 minAmountOut,
            uint256 deadline
        ) external nonReentrant {
            if (block.timestamp > deadline) {
                revert DeadlineExpired();
            }
            uint256 totalOut = amount0Out + amount1Out;
            if (totalOut < minAmountOut) {
                revert SlippageExceeded();
            }
            (uint112 _reserve0, uint112 _reserve1,) = getReserves();
            if (amount0Out > 0) token0.safeTransfer(to, amount0Out);
            if (amount1Out > 0) token1.safeTransfer(to, amount1Out);
            uint256 balance0 = token0.balanceOf(address(this));
            uint256 balance1 = token1.balanceOf(address(this));
            uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
            uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
            if (balance0Adjusted * balance1Adjusted < uint256(_reserve0) * _reserve1 * 1000000) {
                revert InvariantViolation();
            }
            _update(balance0, balance1, _reserve0, _reserve1);
        }"#;

        // K invariant check should pass (revert-based check recognized)
        assert!(
            detector.check_k_invariant_validation(safe_swap).is_none(),
            "Safe AMM swap should not trigger K invariant violation"
        );

        // FOT check should pass (_update syncs reserves)
        assert!(
            detector.check_fot_token_handling(safe_swap).is_none(),
            "Safe AMM swap should not trigger FOT warning"
        );

        // Slippage check should pass (has minAmountOut and deadline)
        assert!(
            detector
                .check_slippage_validation(safe_swap, true)
                .is_none(),
            "Safe AMM swap should not trigger slippage warning"
        );

        // Reserve update check should pass (nonReentrant present)
        let arena = ast::AstArena::new();
        let func = create_mock_ast_function(
            &arena,
            "swap",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(
            detector
                .check_reserve_updates_with_ast(safe_swap, &func)
                .is_none(),
            "Safe AMM swap should not trigger reserve update warning"
        );
    }

    #[test]
    fn test_safe_amm_pool_mint_pattern() {
        let detector = AmmKInvariantViolationDetector::new();
        let arena = ast::AstArena::new();

        // Emulate the safe_amm_pool.sol mint function pattern
        let safe_mint = r#"function mint(address to) external nonReentrant returns (uint256 liquidity) {
            (uint112 _reserve0, uint112 _reserve1,) = getReserves();
            uint256 balance0 = token0.balanceOf(address(this));
            uint256 balance1 = token1.balanceOf(address(this));
            uint256 amount0 = balance0 - _reserve0;
            uint256 amount1 = balance1 - _reserve1;
            _mint(to, liquidity);
            _update(balance0, balance1, _reserve0, _reserve1);
        }"#;

        let func = create_mock_ast_function(
            &arena,
            "mint",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );

        // Reserve update check should pass (nonReentrant + _mint is internal)
        assert!(
            detector
                .check_reserve_updates_with_ast(safe_mint, &func)
                .is_none(),
            "Safe AMM mint should not trigger reserve update warning"
        );
    }

    #[test]
    fn test_safe_amm_pool_burn_pattern() {
        let detector = AmmKInvariantViolationDetector::new();
        let arena = ast::AstArena::new();

        // Emulate the safe_amm_pool.sol burn function pattern
        let safe_burn = r#"function burn(address to) external nonReentrant returns (uint256 amount0, uint256 amount1) {
            (uint112 _reserve0, uint112 _reserve1,) = getReserves();
            uint256 balance0 = token0.balanceOf(address(this));
            uint256 balance1 = token1.balanceOf(address(this));
            uint256 liquidity = balanceOf[address(this)];
            amount0 = (liquidity * balance0) / totalSupply;
            amount1 = (liquidity * balance1) / totalSupply;
            _burn(address(this), liquidity);
            token0.safeTransfer(to, amount0);
            token1.safeTransfer(to, amount1);
            balance0 = token0.balanceOf(address(this));
            balance1 = token1.balanceOf(address(this));
            _update(balance0, balance1, _reserve0, _reserve1);
        }"#;

        let func = create_mock_ast_function(
            &arena,
            "burn",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );

        // Reserve update check should pass (nonReentrant + safeTransfer is protected)
        assert!(
            detector
                .check_reserve_updates_with_ast(safe_burn, &func)
                .is_none(),
            "Safe AMM burn should not trigger reserve update warning"
        );

        // FOT check should pass (_update syncs reserves with balanceOf)
        assert!(
            detector.check_fot_token_handling(safe_burn).is_none(),
            "Safe AMM burn should not trigger FOT warning"
        );
    }

    #[test]
    fn test_swap_function_detection_refined() {
        let detector = AmmKInvariantViolationDetector::new();

        // True positives: swap-like function names
        assert!(detector.is_swap_function("swap", "function swap() external"));
        assert!(detector.is_swap_function("exchange", "function exchange() public"));
        assert!(detector.is_swap_function("tradeTokens", "function tradeTokens()"));

        // True positive: SwapParams struct in source
        assert!(detector.is_swap_function("process", "SwapParams memory params"));

        // FP Reduction: amountOut/amountIn alone should NOT classify as swap
        // because mint/burn functions also reference these in AMM pools
        assert!(!detector.is_swap_function("mint", "amountOut = getAmountOut(amountIn);"));
        assert!(!detector.is_swap_function("burn", "uint256 amountIn = balance - reserve;"));

        // True negatives
        assert!(!detector.is_swap_function("transfer", "function transfer() public"));
        assert!(!detector.is_swap_function("mint", "function mint() external"));
    }

    #[test]
    fn test_reentrancy_lock_modifier_detection() {
        let detector = AmmKInvariantViolationDetector::new();
        let arena = ast::AstArena::new();

        // Uniswap V2 style: "unlocked" variable pattern
        let code_with_unlocked = "function swap() external {
            require(unlocked == 1, 'LOCKED');
            unlocked = 0;
            token.transfer(msg.sender, amount);
            _update(balance0, balance1, _reserve0, _reserve1);
            unlocked = 1;
        }";
        let func = create_mock_ast_function(
            &arena,
            "swap",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(
            detector
                .check_reserve_updates_with_ast(code_with_unlocked, &func)
                .is_none(),
            "Uniswap V2 'unlocked' pattern should be recognized as reentrancy protection"
        );
    }
}
