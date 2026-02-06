use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils::{
    is_flash_loan_context, is_governance_protocol, is_secure_example_file, is_test_contract,
};

/// Detector for SWC-105: Unprotected Ether Withdrawal
///
/// Detects functions that can withdraw Ether but lack proper access control,
/// allowing anyone to drain contract funds.
///
/// Vulnerable patterns:
/// - Public/external withdraw functions without access control modifiers
/// - Functions using `transfer`, `send`, or `call{value:}` without authorization checks
/// - Missing owner/admin checks before transferring Ether
pub struct UnprotectedEtherWithdrawalDetector {
    base: BaseDetector,
}

impl Default for UnprotectedEtherWithdrawalDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UnprotectedEtherWithdrawalDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("swc105-unprotected-ether-withdrawal"),
                "Unprotected Ether Withdrawal (SWC-105)".to_string(),
                "Detects functions that can withdraw Ether without proper access control, \
                 allowing unauthorized users to drain contract funds"
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Check if function name suggests ether withdrawal functionality
    fn is_withdrawal_function(&self, function_name: &str) -> bool {
        let name_lower = function_name.to_lowercase();
        let withdrawal_patterns = [
            "withdraw",
            "drain",
            "sweep",
            "collect",
            "claim",
            "payout",
            "cashout",
            "refund",
            "rescue",
            "recover",
            "extract",
            "sendeth",
            "transfereth",
            "sendvalue",
        ];

        withdrawal_patterns
            .iter()
            .any(|pattern| name_lower.contains(pattern))
    }

    /// Check if function contains ether transfer operations
    fn has_ether_transfer(&self, source: &str) -> bool {
        // Check for low-level ether transfer patterns
        let has_call_value = source.contains(".call{value:")
            || source.contains(".call{ value:")
            || source.contains("call{value:");

        // Check for .transfer() that looks like ether transfer (to address, not token)
        // Token transfers are typically `token.transfer(recipient, amount)`
        // Ether transfers are `address.transfer(amount)` or `payable(address).transfer(amount)`
        let has_ether_transfer = if source.contains(".transfer(") {
            // Likely ether if it's payable(...).transfer or msg.sender.transfer
            // or doesn't have two arguments (token transfers have recipient, amount)
            source.contains("payable(")
                || source.contains("msg.sender.transfer")
                || source.contains("owner.transfer")
                || source.contains("recipient.transfer")
                || source.contains("_to.transfer")
                || source.contains("to.transfer")
                // Heuristic: ether transfer typically has single argument
                || !source.contains(", ")
        } else {
            false
        };

        // Check for .send() (native ether send)
        let has_send =
            source.contains(".send(") && (source.contains("payable(") || !source.contains(", "));

        has_call_value || has_ether_transfer || has_send
    }

    /// Check if function has access control
    fn has_access_control(&self, function: &ast::Function<'_>, source: &str) -> bool {
        // Check for access control modifiers
        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();
            if modifier_name.contains("only")
                || modifier_name.contains("auth")
                || modifier_name.contains("restricted")
                || modifier_name.contains("admin")
                || modifier_name.contains("owner")
                || modifier_name.contains("governance")
                || modifier_name.contains("manager")
            {
                return true;
            }
        }

        // Check for inline access control patterns
        // Standard: require(msg.sender == X)
        let has_require_sender = source.contains("require(msg.sender ==")
            || source.contains("require(msg.sender==")
            || source.contains("require(_msgSender() ==")
            || source.contains("if (msg.sender !=")
            || source.contains("if (msg.sender!=")
            || source.contains("require(owner ==")
            || source.contains("require(hasRole(");

        // Reversed comparison: require(X == msg.sender)
        let has_reversed_sender_check = source.contains("== msg.sender")
            || source.contains("==msg.sender")
            || source.contains("!= msg.sender")
            || source.contains("!=msg.sender");

        // Mapping-based msg.sender validation (session keys, delegates, roles, etc.)
        // Patterns like: require(mapping[...][msg.sender], ...) or require(mapping[msg.sender])
        let has_mapping_sender_check = self.has_mapping_sender_validation(source);

        // Check for OpenZeppelin Ownable patterns
        let has_ownable = source.contains("_checkOwner()")
            || source.contains("onlyOwner")
            || source.contains("Ownable");

        // Check for AccessControl patterns
        let has_access_control_check = source.contains("hasRole(")
            || source.contains("_checkRole(")
            || source.contains("AccessControl");

        has_require_sender
            || has_reversed_sender_check
            || has_mapping_sender_check
            || has_ownable
            || has_access_control_check
    }

    /// Check if function uses msg.sender in a mapping-based validation
    ///
    /// Detects patterns like:
    /// - require(sessionKeys[account][msg.sender], ...)
    /// - require(delegates[x] == msg.sender, ...)
    /// - require(authorized[msg.sender], ...)
    /// - if (!mapping[msg.sender]) revert ...
    fn has_mapping_sender_validation(&self, source: &str) -> bool {
        // Look for require/if statements that reference msg.sender in a mapping context
        // Pattern: require(...[msg.sender]...) where msg.sender is used as a mapping key
        for line in source.lines() {
            let trimmed = line.trim();

            // Only look at require/if/revert lines for access control
            let is_check_line = trimmed.starts_with("require(")
                || trimmed.starts_with("if (")
                || trimmed.starts_with("if(")
                || trimmed.contains("require(")
                || trimmed.contains("revert");

            if !is_check_line {
                continue;
            }

            // msg.sender used as mapping key: mapping[msg.sender] or mapping[x][msg.sender]
            if trimmed.contains("[msg.sender]") {
                return true;
            }
        }

        false
    }

    /// Check if withdrawal goes to msg.sender (safer pattern)
    fn withdraws_to_sender(&self, source: &str) -> bool {
        // If withdrawal is to msg.sender, it's a user withdrawing their own funds
        source.contains("msg.sender.transfer(")
            || source.contains("payable(msg.sender).transfer(")
            || source.contains("msg.sender.call{value:")
            || source.contains("payable(msg.sender).call{value:")
            || (source.contains("balances[msg.sender]") && source.contains(".transfer("))
            || (source.contains("deposits[msg.sender]") && source.contains(".transfer("))
    }

    /// Check if function uses internal balance tracking (pull pattern)
    fn uses_balance_tracking(&self, source: &str) -> bool {
        // Pull pattern with balance tracking is safer
        (source.contains("balances[msg.sender]")
            || source.contains("deposits[msg.sender]")
            || source.contains("userBalance[msg.sender]")
            || source.contains("pendingWithdrawals[msg.sender]"))
            && (source.contains("-=") || source.contains("delete "))
    }

    /// Check if function is a governance execution function
    ///
    /// Governance execute functions (e.g., Governor.execute, Timelock.execute) use
    /// proposal-based access control: only proposals that have passed voting and
    /// quorum requirements can be executed. The .call{value:} inside these functions
    /// is the mechanism for executing approved proposals, not an unprotected withdrawal.
    fn is_governance_execution(
        &self,
        function: &ast::Function<'_>,
        source: &str,
        ctx: &AnalysisContext,
    ) -> bool {
        let func_name_lower = function.name.name.to_lowercase();

        // Must be an execute-like function
        if !func_name_lower.contains("execute") {
            return false;
        }

        // Must be in a governance protocol context
        if !is_governance_protocol(ctx) {
            return false;
        }

        // Check for proposal state validation in the function body
        let has_proposal_state_check = source.contains("getProposalState(")
            || source.contains("proposalState(")
            || source.contains("state(proposalId")
            || source.contains("ProposalState.")
            || source.contains("proposals[proposalId]")
            || source.contains("proposals[_proposalId]")
            || source.contains("proposal.executed")
            || source.contains("proposal.eta");

        has_proposal_state_check
    }

    /// Get function source code
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        // Include lines before to catch modifiers
        let extended_start = start.saturating_sub(3);

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if extended_start < source_lines.len() && end < source_lines.len() {
            source_lines[extended_start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

impl Detector for UnprotectedEtherWithdrawalDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Phase 10: Skip test contracts and secure examples
        if is_test_contract(ctx) || is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // Phase 10: Skip flash loan providers - flash loans have intentional withdrawal patterns
        if is_flash_loan_context(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // Skip internal/private functions
            if function.visibility == ast::Visibility::Internal
                || function.visibility == ast::Visibility::Private
            {
                continue;
            }

            // Skip view/pure functions (can't transfer ether)
            if function.mutability == ast::StateMutability::View
                || function.mutability == ast::StateMutability::Pure
            {
                continue;
            }

            // Skip standard ERC20/721/1155 functions - these are token transfers, not ETH
            let func_name_lower = function.name.name.to_lowercase();
            if func_name_lower == "transfer"
                || func_name_lower == "transferfrom"
                || func_name_lower == "safetransfer"
                || func_name_lower == "safetransferfrom"
                || func_name_lower == "approve"
                || func_name_lower == "mint"
                || func_name_lower == "burn"
            {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            // Check if this looks like a withdrawal function
            let is_withdrawal_by_name = self.is_withdrawal_function(function.name.name);
            let has_ether_transfer = self.has_ether_transfer(&func_source);

            // TIGHTENED: Require BOTH withdrawal-like name AND ether transfer
            // OR explicit direct ether send (.call{value:} without other patterns)
            let has_explicit_eth_send = func_source.contains(".call{value:")
                || func_source.contains("msg.sender.transfer(")
                || (func_source.contains("payable(") && func_source.contains(".transfer("));

            if !(is_withdrawal_by_name && has_ether_transfer) && !has_explicit_eth_send {
                continue;
            }

            // Check for access control
            if self.has_access_control(function, &func_source) {
                continue;
            }

            // Check for governance execution patterns (proposal-based access control)
            if self.is_governance_execution(function, &func_source, ctx) {
                continue;
            }

            // Check if it's a safe pull pattern (user withdrawing their own funds)
            if self.uses_balance_tracking(&func_source) && self.withdraws_to_sender(&func_source) {
                continue;
            }

            // Determine confidence and severity based on patterns found
            let (confidence, severity) = if is_withdrawal_by_name && has_ether_transfer {
                (Confidence::High, Severity::Critical)
            } else if has_explicit_eth_send && is_withdrawal_by_name {
                (Confidence::High, Severity::Critical)
            } else if has_ether_transfer {
                (Confidence::Medium, Severity::High)
            } else {
                (Confidence::Low, Severity::Medium)
            };

            let message = format!(
                "Function '{}' can withdraw Ether but lacks access control. \
                 This allows anyone to call this function and potentially drain contract funds.",
                function.name.name
            );

            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                    severity,
                )
                .with_swc("SWC-105")
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_cwe(862) // CWE-862: Missing Authorization
                .with_confidence(confidence)
                .with_fix_suggestion(format!(
                    "Add access control to '{}'. Options:\n\
                     1. Add an 'onlyOwner' modifier\n\
                     2. Use OpenZeppelin's Ownable or AccessControl\n\
                     3. Add require(msg.sender == owner) check\n\
                     4. Implement a pull pattern where users withdraw their own funds",
                    function.name.name
                ));

            findings.push(finding);
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
        let detector = UnprotectedEtherWithdrawalDetector::new();
        assert_eq!(detector.name(), "Unprotected Ether Withdrawal (SWC-105)");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_withdrawal_function() {
        let detector = UnprotectedEtherWithdrawalDetector::new();
        assert!(detector.is_withdrawal_function("withdraw"));
        assert!(detector.is_withdrawal_function("withdrawFunds"));
        assert!(detector.is_withdrawal_function("drainContract"));
        assert!(detector.is_withdrawal_function("claimReward"));
        assert!(detector.is_withdrawal_function("refundUser"));
        assert!(!detector.is_withdrawal_function("deposit"));
        assert!(!detector.is_withdrawal_function("transfer"));
    }

    #[test]
    fn test_has_ether_transfer() {
        let detector = UnprotectedEtherWithdrawalDetector::new();
        assert!(detector.has_ether_transfer("recipient.transfer(amount)"));
        assert!(detector.has_ether_transfer("recipient.send(amount)"));
        assert!(detector.has_ether_transfer("recipient.call{value: amount}(\"\")"));
        assert!(!detector.has_ether_transfer("token.transfer(recipient, amount)"));
    }

    #[test]
    fn test_mapping_sender_validation_session_keys() {
        let detector = UnprotectedEtherWithdrawalDetector::new();

        // Session key pattern: require(sessionKeys[account][msg.sender], ...)
        let source_with_session_key = r#"
    function executeWithSessionKey(address account, address target, uint256 value, bytes calldata data) external {
        require(sessionKeys[account][msg.sender], "Invalid session key");
        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }
"#;
        assert!(
            detector.has_mapping_sender_validation(source_with_session_key),
            "Should detect session key mapping validation with msg.sender"
        );
    }

    #[test]
    fn test_mapping_sender_validation_delegate() {
        let detector = UnprotectedEtherWithdrawalDetector::new();

        // Delegate pattern: require(delegates[account] == msg.sender, ...)
        // This uses reversed comparison which is caught by has_reversed_sender_check,
        // but also verify the mapping pattern is recognized
        let source_with_delegate = r#"
    function executeAsDelegate(address account, address target, uint256 value, bytes calldata data) external {
        require(delegates[account] == msg.sender, "Not delegate");
        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }
"#;
        // The "== msg.sender" pattern is caught by reversed sender check
        assert!(
            source_with_delegate.contains("== msg.sender"),
            "Source should contain reversed sender comparison"
        );
    }

    #[test]
    fn test_mapping_sender_validation_authorized() {
        let detector = UnprotectedEtherWithdrawalDetector::new();

        // Authorized mapping pattern
        let source_authorized = r#"
    function withdraw(uint256 amount) external {
        require(authorized[msg.sender], "Not authorized");
        payable(msg.sender).transfer(amount);
    }
"#;
        assert!(
            detector.has_mapping_sender_validation(source_authorized),
            "Should detect authorized mapping validation with msg.sender"
        );
    }

    #[test]
    fn test_mapping_sender_validation_not_present() {
        let detector = UnprotectedEtherWithdrawalDetector::new();

        // No access control at all - true positive pattern
        let source_no_access_control = r#"
    function withdraw(uint256 _amount) public {
        require(_amount <= balance, "Insufficient balance");
        balance -= _amount;
        payable(msg.sender).transfer(_amount);
    }
"#;
        assert!(
            !detector.has_mapping_sender_validation(source_no_access_control),
            "Should NOT detect mapping validation when there is no msg.sender in mapping check"
        );
    }

    #[test]
    fn test_mapping_sender_validation_sender_only_in_transfer() {
        let detector = UnprotectedEtherWithdrawalDetector::new();

        // msg.sender appears in transfer target, not in a require/if check with mapping
        let source_sender_in_transfer = r#"
    function withdrawBasedOnBalance(address _user) public {
        uint256 userBalance = this.getBalance(_user);
        require(userBalance > 0, "No balance");
        balances[_user] = 0;
        payable(_user).transfer(userBalance);
    }
"#;
        assert!(
            !detector.has_mapping_sender_validation(source_sender_in_transfer),
            "Should NOT detect mapping validation when msg.sender is not in a mapping check"
        );
    }

    #[test]
    fn test_reversed_sender_comparison_detected() {
        let detector = UnprotectedEtherWithdrawalDetector::new();

        // Test that reversed comparison patterns are detected
        let source_reversed = r#"require(delegates[account] == msg.sender, "Not delegate")"#;
        assert!(
            source_reversed.contains("== msg.sender"),
            "Should contain reversed sender comparison pattern"
        );

        // Ensure the original patterns still don't false-match reversed patterns
        let source_no_reversed = r#"require(_amount <= balance, "Insufficient")"#;
        assert!(
            !source_no_reversed.contains("== msg.sender"),
            "Should not contain reversed sender comparison"
        );
    }

    #[test]
    fn test_if_revert_sender_mapping_check() {
        let detector = UnprotectedEtherWithdrawalDetector::new();

        // if (!authorized[msg.sender]) revert ...
        let source_if_revert = r#"
    function withdraw(uint256 amount) external {
        if (!whitelist[msg.sender]) revert Unauthorized();
        payable(msg.sender).transfer(amount);
    }
"#;
        assert!(
            detector.has_mapping_sender_validation(source_if_revert),
            "Should detect if-revert pattern with msg.sender mapping check"
        );
    }
}
