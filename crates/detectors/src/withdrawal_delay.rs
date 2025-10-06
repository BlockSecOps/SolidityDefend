use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for withdrawal delay vulnerabilities in staking systems
pub struct WithdrawalDelayDetector {
    base: BaseDetector,
}

impl WithdrawalDelayDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("withdrawal-delay".to_string()),
                "Withdrawal Delay Vulnerability".to_string(),
                "Detects vulnerabilities in stake withdrawal mechanisms that can lock funds indefinitely or enable unfair delays".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Detector for WithdrawalDelayDetector {
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
            if let Some(withdrawal_issue) = self.check_withdrawal_delay(function, ctx) {
                let message = format!(
                    "Function '{}' has withdrawal delay vulnerability. {} \
                    Improper withdrawal mechanisms can lock user funds indefinitely or enable denial of service.",
                    function.name.name,
                    withdrawal_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                .with_cwe(667) // CWE-667: Improper Locking
                .with_fix_suggestion(format!(
                    "Fix withdrawal mechanism in '{}'. \
                    Implement maximum withdrawal delay caps, add emergency withdrawal options with penalties, \
                    prevent admin from extending delays arbitrarily, implement fair queue systems, \
                    add partial withdrawal capabilities, and document clear withdrawal timelines.",
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

impl WithdrawalDelayDetector {
    /// Check for withdrawal delay vulnerabilities
    fn check_withdrawal_delay(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check if function is related to withdrawals
        let is_withdrawal_function = func_source.contains("withdraw") ||
                                    func_source.contains("Withdraw") ||
                                    func_source.contains("unstake") ||
                                    func_source.contains("exit") ||
                                    function.name.name.to_lowercase().contains("withdraw");

        if !is_withdrawal_function {
            return None;
        }

        // Pattern 1: Unbounded withdrawal delay
        let has_delay = func_source.contains("delay") ||
                       func_source.contains("lock") ||
                       func_source.contains("period");

        let no_max_delay = has_delay &&
                          !func_source.contains("MAX_DELAY") &&
                          !func_source.contains("maxDelay") &&
                          is_withdrawal_function;

        if no_max_delay {
            return Some(format!(
                "Withdrawal delay has no maximum cap, \
                admin can set arbitrarily long delays locking funds indefinitely"
            ));
        }

        // Pattern 2: Admin can arbitrarily extend withdrawal delay
        let admin_can_modify = func_source.contains("onlyOwner") ||
                              func_source.contains("onlyAdmin");

        let modifies_delay = (func_source.contains("delay =") ||
                            func_source.contains("setDelay") ||
                            func_source.contains("updateDelay")) &&
                           admin_can_modify;

        if modifies_delay && is_withdrawal_function {
            return Some(format!(
                "Admin can modify withdrawal delay without limits, \
                centralization risk enabling fund lockup"
            ));
        }

        // Pattern 3: No emergency withdrawal mechanism
        let has_emergency = func_source.contains("emergency") ||
                           func_source.contains("Emergency") ||
                           func_source.contains("instant") ||
                           func_source.contains("immediate");

        let lacks_emergency = is_withdrawal_function &&
                             has_delay &&
                             !has_emergency;

        if lacks_emergency {
            return Some(format!(
                "No emergency withdrawal option even with penalty, \
                users cannot access funds in urgent situations"
            ));
        }

        // Pattern 4: Withdrawal queue without fairness guarantees
        let has_queue = func_source.contains("queue") ||
                       func_source.contains("Queue") ||
                       func_source.contains("pending");

        let no_fifo_enforcement = has_queue &&
                                 is_withdrawal_function &&
                                 !func_source.contains("FIFO") &&
                                 !func_source.contains("order");

        if no_fifo_enforcement {
            return Some(format!(
                "Withdrawal queue without FIFO enforcement, \
                allows queue jumping or unfair withdrawal ordering"
            ));
        }

        // Pattern 5: Delay can be extended retroactively
        let checks_original_delay = func_source.contains("initialDelay") ||
                                   func_source.contains("originalDelay") ||
                                   func_source.contains("requestTime");

        let no_retroactive_protection = has_delay &&
                                       is_withdrawal_function &&
                                       !checks_original_delay;

        if no_retroactive_protection {
            return Some(format!(
                "Withdrawal delay can be extended retroactively, \
                users who initiated withdrawal may face unexpected delays"
            ));
        }

        // Pattern 6: Single point of failure for withdrawal processing
        let has_single_processor = func_source.contains("processor") ||
                                  func_source.contains("operator");

        let no_backup_mechanism = has_single_processor &&
                                 is_withdrawal_function &&
                                 !func_source.contains("backup") &&
                                 !func_source.contains("fallback");

        if no_backup_mechanism {
            return Some(format!(
                "Single withdrawal processor without backup, \
                if processor fails, all withdrawals blocked"
            ));
        }

        // Pattern 7: No partial withdrawal capability
        let full_withdrawal_only = func_source.contains("balance[msg.sender]") &&
                                  is_withdrawal_function &&
                                  !func_source.contains("amount") &&
                                  !func_source.contains("partial");

        if full_withdrawal_only {
            return Some(format!(
                "Only full withdrawal allowed, no partial withdrawals, \
                users must exit entirely even for small amounts"
            ));
        }

        // Pattern 8: Withdrawal depends on external call
        let has_external_call = func_source.contains(".call") ||
                               func_source.contains(".transfer") ||
                               func_source.contains(".send");

        let blocking_external_call = has_external_call &&
                                     is_withdrawal_function &&
                                     !func_source.contains("nonReentrant") &&
                                     func_source.contains("require");

        if blocking_external_call {
            return Some(format!(
                "Withdrawal requires successful external call, \
                failing calls can permanently block withdrawals"
            ));
        }

        // Pattern 9: Withdrawal disabled by circuit breaker
        let has_circuit_breaker = func_source.contains("paused") ||
                                 func_source.contains("Paused") ||
                                 func_source.contains("whenNotPaused");

        let no_emergency_override = has_circuit_breaker &&
                                   is_withdrawal_function &&
                                   !has_emergency;

        if no_emergency_override {
            return Some(format!(
                "Withdrawal can be paused without emergency override, \
                admin can indefinitely block all withdrawals"
            ));
        }

        // Pattern 10: Withdrawal window expires
        let has_expiry = func_source.contains("expire") ||
                        func_source.contains("deadline") ||
                        func_source.contains("validUntil");

        let withdrawal_expires = has_expiry &&
                                is_withdrawal_function &&
                                !func_source.contains("extend") &&
                                !func_source.contains("renew");

        if withdrawal_expires {
            return Some(format!(
                "Withdrawal requests expire without renewal option, \
                users lose withdrawal opportunity and must restart process"
            ));
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
        let detector = WithdrawalDelayDetector::new();
        assert_eq!(detector.name(), "Withdrawal Delay Vulnerability");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
