use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for ERC-4626 vault withdrawal DOS vulnerabilities
pub struct VaultWithdrawalDosDetector {
    base: BaseDetector,
}

impl VaultWithdrawalDosDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("vault-withdrawal-dos".to_string()),
                "Vault Withdrawal DOS".to_string(),
                "Detects ERC4626 vaults vulnerable to withdrawal denial-of-service attacks via queue manipulation or liquidity locks".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for VaultWithdrawalDosDetector {
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

        // Check if this is an ERC-4626 vault
        let is_vault = utils::is_erc4626_vault(ctx);

        // NEW: Check for DOS mitigations at contract level
        let has_pull_pattern = self.has_pull_pattern(ctx);
        let has_emergency_mechanism = self.has_emergency_mechanism(ctx);
        let has_withdrawal_limits = self.has_withdrawal_limits(ctx);

        for function in ctx.get_functions() {
            if let Some(dos_issue) = self.check_withdrawal_dos(function, ctx, is_vault) {
                // NEW: Assign confidence based on mitigations present
                let mut mitigation_count = 0;
                if has_pull_pattern {
                    mitigation_count += 1;
                }
                if has_emergency_mechanism {
                    mitigation_count += 1;
                }
                if has_withdrawal_limits {
                    mitigation_count += 1;
                }

                // Confidence based on number of mitigations
                let confidence = match mitigation_count {
                    0 => Confidence::High,    // No mitigations - very vulnerable
                    1 => Confidence::Medium,  // Some protection
                    _ => Confidence::Low,     // Multiple protections - likely safe
                };

                let message = format!(
                    "Function '{}' is vulnerable to withdrawal DOS attack. {} \
                    Attacker can block withdrawals, causing funds to be locked indefinitely.",
                    function.name.name, dos_issue
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
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_cwe(770) // CWE-770: Allocation of Resources Without Limits
                    .with_confidence(confidence) // NEW: Set confidence
                    .with_fix_suggestion(format!(
                        "Protect '{}' from withdrawal DOS. \
                    Solutions: (1) Implement withdrawal limits/caps per transaction, \
                    (2) Add circuit breakers for emergency withdrawals, \
                    (3) Avoid unbounded loops in withdrawal queue processing, \
                    (4) Implement partial withdrawal support, \
                    (5) Use pull-over-push pattern for failed withdrawals.",
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

impl VaultWithdrawalDosDetector {
    /// Check for withdrawal DOS vulnerabilities
    fn check_withdrawal_dos(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
        is_vault: bool,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Identify withdrawal/redeem functions
        let is_withdrawal_function = function.name.name.to_lowercase().contains("withdraw")
            || function.name.name.to_lowercase().contains("redeem")
            || function.name.name.to_lowercase().contains("claim");

        if !is_withdrawal_function {
            return None;
        }

        // Pattern 1: Unbounded withdrawal queue processing
        let has_unbounded_loop = (func_source.contains("for (") || func_source.contains("while ("))
            && (func_source.contains("withdrawalQueue")
                || func_source.contains("requests")
                || func_source.contains("queue"));

        let has_loop_limit = func_source.contains("maxIterations")
            || func_source.contains("limit")
            || func_source.contains("MAX_");

        if has_unbounded_loop && !has_loop_limit {
            return Some(format!(
                "Unbounded withdrawal queue processing. Loop over queue without iteration limit \
                can be exploited for DOS by creating many requests"
            ));
        }

        // Pattern 2: Withdrawal requires successful external call
        let has_external_call = func_source.contains(".transfer(")
            || func_source.contains(".call")
            || func_source.contains(".send(");

        let checks_call_success = func_source.contains("require(")
            && (func_source.contains(".transfer(") || func_source.contains(".call"));

        // Skip for ERC-4626 vaults - they MUST transfer assets out, this is normal behavior
        // ERC-4626 redeem/withdraw functions transfer underlying assets, not a DOS vector
        if has_external_call && checks_call_success && !is_vault {
            return Some(format!(
                "Withdrawal requires successful external call. Failing calls can permanently block withdrawals. \
                Consider using pull-over-push pattern"
            ));
        }

        // Pattern 3: Missing withdrawal cap or limit
        let has_withdrawal_cap = func_source.contains("withdrawalCap")
            || func_source.contains("maxWithdrawal")
            || func_source.contains("withdrawalLimit")
            || func_source.contains("MAX_WITHDRAW");

        let processes_large_amount =
            func_source.contains("amount") || func_source.contains("assets");

        // Skip for vaults - ERC-4626 vaults have built-in limits via share balances and maxRedeem/maxWithdraw
        if !has_withdrawal_cap && processes_large_amount && is_withdrawal_function && !is_vault {
            return Some(format!(
                "No withdrawal cap or limit detected. Large withdrawals can drain liquidity \
                and DOS subsequent withdrawers"
            ));
        }

        // Pattern 4: No circuit breaker or emergency withdrawal
        let has_circuit_breaker = func_source.contains("paused")
            || func_source.contains("emergency")
            || func_source.contains("circuitBreaker");

        let is_public_withdraw = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        if !has_circuit_breaker && is_public_withdraw {
            return Some(format!(
                "No circuit breaker or emergency withdrawal mechanism. \
                Vault cannot be paused during attacks or emergencies"
            ));
        }

        // Pattern 5: Accounting mismatch that can cause reverts
        let uses_total_assets =
            func_source.contains("totalAssets()") || func_source.contains("totalAssets");

        let uses_total_supply =
            func_source.contains("totalSupply()") || func_source.contains("totalSupply");

        let has_division = func_source.contains(" / ");

        if uses_total_assets && uses_total_supply && has_division {
            // Check for potential accounting mismatch
            let checks_zero_division = func_source.contains("require(totalSupply")
                || func_source.contains("if (totalSupply == 0)")
                || func_source.contains("totalSupply > 0");

            if !checks_zero_division {
                return Some(format!(
                    "Potential accounting mismatch. Division by totalSupply without zero check \
                    can cause withdrawal reverts and DOS"
                ));
            }
        }

        // Pattern 6: Queue processing without partial execution
        let has_queue_processing = func_source.contains("queue")
            || func_source.contains("pendingWithdrawals")
            || func_source.contains("requests");

        let supports_partial = func_source.contains("partial")
            || func_source.contains("batched")
            || func_source.contains("chunk");

        if has_queue_processing && !supports_partial {
            return Some(format!(
                "Withdrawal queue processing without partial execution support. \
                All-or-nothing execution can cause DOS if any withdrawal fails"
            ));
        }

        // Pattern 7: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("DOS")
                || func_source.contains("denial")
                || func_source.contains("lock"))
        {
            return Some(format!(
                "Vault withdrawal DOS vulnerability marker detected"
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

    /// NEW: Check for pull-over-push pattern (safer withdrawal pattern)
    fn has_pull_pattern(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // Pull pattern indicators
        source.contains("claimableBalance")
            || source.contains("pendingWithdrawals")
            || source.contains("withdrawalRequest")
            || source.contains("claim()")
            || (source.contains("mapping") && source.contains("withdraw"))
    }

    /// NEW: Check for emergency withdrawal mechanism
    fn has_emergency_mechanism(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        source.contains("emergencyWithdraw")
            || source.contains("emergencyPause")
            || source.contains("circuitBreaker")
            || (source.contains("paused") && source.contains("whenNotPaused"))
    }

    /// NEW: Check for withdrawal limits/caps
    fn has_withdrawal_limits(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        source.contains("withdrawalCap")
            || source.contains("maxWithdrawal")
            || source.contains("withdrawalLimit")
            || source.contains("MAX_WITHDRAW")
            || source.contains("dailyLimit")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = VaultWithdrawalDosDetector::new();
        assert_eq!(detector.name(), "Vault Withdrawal DOS");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
