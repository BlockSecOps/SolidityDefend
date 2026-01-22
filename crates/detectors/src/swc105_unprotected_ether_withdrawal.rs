use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils::{is_flash_loan_context, is_secure_example_file, is_test_contract};

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
        let has_send = source.contains(".send(")
            && (source.contains("payable(") || !source.contains(", "));

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
        let has_require_sender = source.contains("require(msg.sender ==")
            || source.contains("require(msg.sender==")
            || source.contains("require(_msgSender() ==")
            || source.contains("if (msg.sender !=")
            || source.contains("if (msg.sender!=")
            || source.contains("require(owner ==")
            || source.contains("require(hasRole(");

        // Check for OpenZeppelin Ownable patterns
        let has_ownable = source.contains("_checkOwner()")
            || source.contains("onlyOwner")
            || source.contains("Ownable");

        // Check for AccessControl patterns
        let has_access_control_check = source.contains("hasRole(")
            || source.contains("_checkRole(")
            || source.contains("AccessControl");

        has_require_sender || has_ownable || has_access_control_check
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
        assert_eq!(
            detector.name(),
            "Unprotected Ether Withdrawal (SWC-105)"
        );
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
}
