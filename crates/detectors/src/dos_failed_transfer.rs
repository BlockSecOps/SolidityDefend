use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for DoS by failed transfer vulnerability
///
/// Detects when a function can be blocked if a transfer to an external address fails.
/// This is also known as the "push over pull" anti-pattern.
pub struct DosFailedTransferDetector {
    base: BaseDetector,
}

impl Default for DosFailedTransferDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosFailedTransferDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("dos-failed-transfer".to_string()),
                "DoS by Failed Transfer".to_string(),
                "Detects push pattern transfers that can cause DoS if recipient reverts. Use pull pattern instead.".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Check if a `.transfer(` call is an ETH transfer (1 arg) vs ERC20 transfer (2 args).
    /// ETH: `payable(addr).transfer(amount)` -- single argument
    /// ERC20: `token.transfer(to, amount)` -- two arguments (contains a comma)
    fn is_eth_transfer_line(line: &str) -> bool {
        if let Some(pos) = line.find(".transfer(") {
            let after = &line[pos + ".transfer(".len()..];
            // Find the matching closing paren, counting nested parens
            let mut depth = 1usize;
            let mut args = String::new();
            for ch in after.chars() {
                if ch == '(' {
                    depth += 1;
                } else if ch == ')' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                args.push(ch);
            }
            // ETH transfer has no comma at depth 0 in its argument list
            let mut d = 0usize;
            for ch in args.chars() {
                match ch {
                    '(' => d += 1,
                    ')' => {
                        if d > 0 {
                            d -= 1;
                        }
                    }
                    ',' if d == 0 => return false, // Two args = ERC20
                    _ => {}
                }
            }
            return true; // Single arg = ETH transfer
        }
        false
    }

    /// Check if a transfer line sends to `msg.sender` (caller cannot DoS themselves)
    fn transfer_is_to_msg_sender(line: &str) -> bool {
        // payable(msg.sender).transfer(...)  or  msg.sender.transfer(...)
        let trimmed = line.trim();
        trimmed.contains("msg.sender).transfer(") || trimmed.contains("msg.sender.transfer(")
    }

    /// Check if function source has any ETH transfer (not ERC20) that could cause DoS
    fn has_eth_transfer(source: &str) -> bool {
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.contains(".transfer(") && Self::is_eth_transfer_line(trimmed) {
                return true;
            }
            if trimmed.contains(".send(") {
                return true;
            }
        }
        false
    }

    /// Check if a transfer in a loop uses varying recipients (from array/mapping)
    fn loop_has_varying_recipients(source: &str) -> bool {
        let mut in_loop = false;
        let mut brace_depth = 0i32;
        let mut loop_brace_depth = 0i32;

        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }

            // Detect loop start
            if !in_loop
                && (trimmed.starts_with("for ")
                    || trimmed.starts_with("for(")
                    || trimmed.starts_with("while ")
                    || trimmed.starts_with("while("))
            {
                in_loop = true;
                loop_brace_depth = brace_depth;
            }

            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;

            // Check if we exited the loop
            if in_loop && brace_depth <= loop_brace_depth {
                in_loop = false;
            }

            // Inside a loop, check for ETH transfer to varying recipient
            if in_loop && trimmed.contains(".transfer(") && Self::is_eth_transfer_line(trimmed) {
                // If the recipient is msg.sender or a fixed address, it is not varying
                if !Self::transfer_is_to_msg_sender(trimmed) {
                    return true;
                }
            }
            if in_loop && trimmed.contains(".send(") {
                if !trimmed.contains("msg.sender.send(") {
                    return true;
                }
            }
        }
        false
    }

    /// Check if function has DoS by failed transfer vulnerability
    fn check_dos_failed_transfer(&self, function_source: &str) -> bool {
        // Only consider ETH transfers (.transfer with 1 arg, .send)
        // ERC20 .transfer(to, amount) has a different risk profile and is not the
        // classic push-over-pull DoS vector
        let has_eth_transfer = Self::has_eth_transfer(function_source);

        // Also check for .call{value:} without success check
        let has_unchecked_call = function_source.contains(".call{value:")
            && !function_source.contains("(success,")
            && !function_source.contains("(bool success");

        if !has_eth_transfer && !has_unchecked_call {
            return false;
        }

        // Phase 52 FP Reduction: Skip if using proper call with success check
        let has_proper_call_check = function_source.contains("(bool success")
            && function_source.contains(".call{value:")
            && (function_source.contains("require(success")
                || function_source.contains("if (!success")
                || function_source.contains("if(!success"));

        if has_proper_call_check {
            return false;
        }

        // Phase 52 FP Reduction: Skip if using Address.sendValue (OZ pattern)
        if function_source.contains("Address.sendValue") || function_source.contains("sendValue(") {
            return false;
        }

        // Phase 52 FP Reduction: Skip pull pattern implementations
        let is_pull_pattern = (function_source.contains("pendingWithdraw")
            || function_source.contains("pendingReturns")
            || function_source.contains("balances[msg.sender]")
            || function_source.contains("owed[msg.sender]"))
            && function_source.contains("msg.sender");

        if is_pull_pattern {
            return false;
        }

        // FP Reduction: Skip if all ETH transfers go to msg.sender
        // The caller cannot DoS themselves, so single-recipient transfers to
        // msg.sender are not a DoS vector
        if has_eth_transfer && Self::all_eth_transfers_to_msg_sender(function_source) {
            return false;
        }

        // FP Reduction: Skip flash loan provider patterns
        // Flash loan providers intentionally transfer then callback -- by design
        if Self::is_flash_loan_pattern(function_source) {
            return false;
        }

        // FP Reduction: Skip try/catch wrapped ETH transfers
        if Self::all_eth_transfers_in_try_catch(function_source) {
            return false;
        }

        // Pattern 2: ETH Transfer happens before state updates (push pattern)
        let lines: Vec<&str> = function_source.lines().collect();
        let mut found_eth_transfer = false;
        let mut has_state_change_after = false;

        for line in &lines {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }

            // Check for ETH transfer
            if (trimmed.contains(".transfer(") && Self::is_eth_transfer_line(trimmed))
                || trimmed.contains(".send(")
            {
                // Skip if this transfer is to msg.sender
                if !Self::transfer_is_to_msg_sender(trimmed) {
                    found_eth_transfer = true;
                }
                continue;
            }

            // If we found a non-msg.sender ETH transfer, check for state changes after
            if found_eth_transfer {
                if trimmed.contains(" = ")
                    && !trimmed.starts_with("//")
                    && !trimmed.contains("==")
                    && !trimmed.contains("!=")
                    && !trimmed.contains("<=")
                    && !trimmed.contains(">=")
                {
                    has_state_change_after = true;
                    break;
                }
            }
        }

        // Pattern 3: ETH Transfer in a loop to varying recipients (especially dangerous)
        let transfer_in_loop =
            has_eth_transfer && Self::loop_has_varying_recipients(function_source);

        // Pattern 4: Transfer without error handling
        let no_error_handling = has_eth_transfer
            && !function_source.contains("require(")
            && !function_source.contains("if (")
            && !function_source.contains("try ")
            && !function_source.contains("(bool success");

        // Pattern 5: Refund pattern (transfer to previous participant, not msg.sender)
        let is_refund_pattern = has_eth_transfer
            && !Self::all_eth_transfers_to_msg_sender(function_source)
            && (function_source.contains("refund")
                || function_source.contains("previous")
                || function_source.contains("leader")
                || function_source.contains("highestBidder"));

        // Vulnerable if:
        // - ETH transfer in loop to varying recipients
        // - Refund pattern without error handling (auction/bidding DoS)
        // - ETH transfer to non-sender before state change
        transfer_in_loop || (is_refund_pattern && no_error_handling) || has_state_change_after
    }

    /// Check if ALL ETH transfers in the function go to msg.sender
    fn all_eth_transfers_to_msg_sender(source: &str) -> bool {
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.contains(".transfer(") && Self::is_eth_transfer_line(trimmed) {
                if !Self::transfer_is_to_msg_sender(trimmed) {
                    return false;
                }
            }
            if trimmed.contains(".send(") && !trimmed.contains("msg.sender.send(") {
                return false;
            }
        }
        true
    }

    /// Detect flash loan provider pattern: ETH transfer followed by callback
    fn is_flash_loan_pattern(source: &str) -> bool {
        let has_flash_loan_indicator = source.contains("flashLoan")
            || source.contains("flash_loan")
            || source.contains("onFlashLoan")
            || source.contains("FlashBorrower")
            || source.contains("flashloan");

        let has_callback_after_transfer =
            source.contains("onFlashLoan") || source.contains("FlashBorrower");

        has_flash_loan_indicator && has_callback_after_transfer
    }

    /// Check if all ETH transfers are wrapped in try/catch
    fn all_eth_transfers_in_try_catch(source: &str) -> bool {
        let mut in_try = false;
        let mut try_depth = 0i32;
        let mut try_brace_depth = 0i32;
        let mut brace_depth = 0i32;

        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }

            if trimmed.contains("try ") && !in_try {
                in_try = true;
                try_brace_depth = brace_depth;
                try_depth += 1;
            }

            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;

            // Check if we exited the try/catch block
            if in_try && brace_depth <= try_brace_depth {
                in_try = false;
                try_depth -= 1;
            }

            // If we find an ETH transfer outside try/catch, return false
            if !in_try {
                if trimmed.contains(".transfer(") && Self::is_eth_transfer_line(trimmed) {
                    return false;
                }
                if trimmed.contains(".send(") {
                    return false;
                }
            }
        }

        // If we never found a transfer outside try/catch and try_depth was used
        try_depth >= 0 // Always true if we get here; transfers were all inside try
    }
}

impl Detector for DosFailedTransferDetector {
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


        // Check all functions
        for function in ctx.get_functions() {
            if function.body.is_none() {
                continue;
            }

            // FP Reduction: Skip internal/private functions (not externally callable)
            if function.visibility == ast::Visibility::Internal
                || function.visibility == ast::Visibility::Private
            {
                continue;
            }

            // FP Reduction: Skip view/pure functions (cannot perform transfers)
            if function.mutability == ast::StateMutability::View
                || function.mutability == ast::StateMutability::Pure
            {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            if self.check_dos_failed_transfer(&func_source) {
                let message = format!(
                    "Function '{}' uses push pattern for transfers which can cause DoS if recipient reverts. \
                    A malicious or buggy recipient contract can block this function by rejecting payments. \
                    Use the pull pattern (withdrawal pattern) instead where users withdraw their own funds.",
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
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_fix_suggestion(format!(
                        "Refactor '{}' to use pull pattern instead of push. \
                        Store pending withdrawals in a mapping and let users withdraw their own funds. \
                        Example: balances[user] = amount; then separate withdraw() function. \
                        Use OpenZeppelin's PullPayment contract for reference.",
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

impl DosFailedTransferDetector {
    /// Extract function source code from context
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
        let detector = DosFailedTransferDetector::new();
        assert_eq!(detector.name(), "DoS by Failed Transfer");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    // Helper to test the core logic
    fn check(source: &str) -> bool {
        let d = DosFailedTransferDetector::new();
        d.check_dos_failed_transfer(source)
    }

    // ---- True Positives: should detect ----

    #[test]
    fn tp_eth_transfer_in_loop_varying_recipients() {
        let source = r#"
        function distribute(address[] memory recipients, uint256[] memory amounts) external {
            for (uint256 i = 0; i < recipients.length; i++) {
                payable(recipients[i]).transfer(amounts[i]);
            }
        }
        "#;
        assert!(
            check(source),
            "Should flag ETH transfers in loop to varying recipients"
        );
    }

    #[test]
    fn tp_auction_refund_to_previous_bidder() {
        let source = r#"
        function placeBid() external payable {
            require(msg.value > highestBid, "Bid too low");
            if (highestBidder != address(0)) {
                payable(highestBidder).transfer(highestBid);
            }
            highestBidder = msg.sender;
            highestBid = msg.value;
        }
        "#;
        assert!(
            check(source),
            "Should flag auction refund to previous bidder"
        );
    }

    #[test]
    fn tp_eth_transfer_before_state_update() {
        let source = r#"
        function payout(address payable recipient) external {
            payable(recipient).transfer(100);
            totalPaid = totalPaid + 100;
        }
        "#;
        assert!(
            check(source),
            "Should flag ETH transfer before state update to non-sender"
        );
    }

    #[test]
    fn tp_send_in_loop() {
        let source = r#"
        function distribute(address[] memory recipients) external {
            for (uint256 i = 0; i < recipients.length; i++) {
                recipients[i].send(1 ether);
            }
        }
        "#;
        assert!(
            check(source),
            "Should flag .send() in loop to varying recipients"
        );
    }

    // ---- False Positives: should NOT detect ----

    #[test]
    fn fp_erc20_transfer_not_eth() {
        let source = r#"
        function swap(uint256 amountIn, bool aToB) external {
            uint256 amountOut = amountIn * reserveB / reserveA;
            reserveA += amountIn;
            reserveB -= amountOut;
            tokenA.transferFrom(msg.sender, address(this), amountIn);
            tokenB.transfer(msg.sender, amountOut);
        }
        "#;
        assert!(
            !check(source),
            "Should NOT flag ERC20 .transfer(to, amount) - 2-arg call"
        );
    }

    #[test]
    fn fp_erc20_transfer_in_loop() {
        let source = r#"
        function migrateToV2(address[] calldata tokens, uint256[] calldata amounts) external {
            for (uint256 i = 0; i < tokens.length; i++) {
                IERC20(tokens[i]).transfer(fakeProtocol, amounts[i]);
            }
        }
        "#;
        assert!(!check(source), "Should NOT flag ERC20 transfers in loop");
    }

    #[test]
    fn fp_eth_transfer_to_msg_sender() {
        let source = r#"
        function withdraw(uint256 amount) external {
            require(deposits[msg.sender] >= amount);
            deposits[msg.sender] -= amount;
            payable(msg.sender).transfer(amount);
        }
        "#;
        assert!(!check(source), "Should NOT flag ETH transfer to msg.sender");
    }

    #[test]
    fn fp_flash_loan_provider_pattern() {
        let source = r#"
        function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
            uint256 balanceBefore = address(this).balance;
            payable(receiver).transfer(amount);
            IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
            require(address(this).balance >= balanceBefore);
        }
        "#;
        assert!(
            !check(source),
            "Should NOT flag flash loan provider pattern"
        );
    }

    #[test]
    fn fp_proper_call_with_success_check() {
        let source = "
        function send(address payable to, uint256 amount) external {
            (bool success, ) = to.call{value: amount}(\"\");
            require(success, \"Transfer failed\");
        }
        ";
        assert!(
            !check(source),
            "Should NOT flag call with value and success check"
        );
    }

    #[test]
    fn fp_pull_pattern() {
        let source = r#"
        function withdraw() external {
            uint256 amount = pendingWithdrawals[msg.sender];
            pendingWithdraw = 0;
            payable(msg.sender).transfer(amount);
        }
        "#;
        assert!(
            !check(source),
            "Should NOT flag pull pattern implementation"
        );
    }

    #[test]
    fn fp_address_sendvalue() {
        let source = r#"
        function refund(address payable to, uint256 amount) external {
            Address.sendValue(to, amount);
        }
        "#;
        assert!(
            !check(source),
            "Should NOT flag Address.sendValue (OZ pattern)"
        );
    }

    #[test]
    fn fp_eth_transfer_in_loop_to_msg_sender() {
        // Transfer in loop but always to msg.sender -- not DoS-prone
        let source = r#"
        function claimAll(uint256[] memory poolIds) external {
            for (uint256 i = 0; i < poolIds.length; i++) {
                uint256 reward = rewards[poolIds[i]][msg.sender];
                rewards[poolIds[i]][msg.sender] = 0;
                payable(msg.sender).transfer(reward);
            }
        }
        "#;
        assert!(
            !check(source),
            "Should NOT flag loop transfers all to msg.sender"
        );
    }

    // ---- ETH vs ERC20 distinction tests ----

    #[test]
    fn test_is_eth_transfer_line_single_arg() {
        assert!(DosFailedTransferDetector::is_eth_transfer_line(
            "payable(addr).transfer(amount)"
        ));
    }

    #[test]
    fn test_is_eth_transfer_line_two_args_is_erc20() {
        assert!(!DosFailedTransferDetector::is_eth_transfer_line(
            "token.transfer(msg.sender, amountOut)"
        ));
    }

    #[test]
    fn test_is_eth_transfer_line_nested_parens() {
        // ERC20 with nested function call in first arg
        assert!(!DosFailedTransferDetector::is_eth_transfer_line(
            "IERC20(token).transfer(address(this), amount)"
        ));
    }

    #[test]
    fn test_transfer_is_to_msg_sender() {
        assert!(DosFailedTransferDetector::transfer_is_to_msg_sender(
            "payable(msg.sender).transfer(amount)"
        ));
        assert!(!DosFailedTransferDetector::transfer_is_to_msg_sender(
            "payable(recipient).transfer(amount)"
        ));
    }
}
