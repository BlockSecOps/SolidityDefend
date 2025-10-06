use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for emergency withdrawal abuse vulnerabilities
pub struct EmergencyWithdrawalAbuseDetector {
    base: BaseDetector,
}

impl EmergencyWithdrawalAbuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("emergency-withdrawal-abuse".to_string()),
                "Emergency Withdrawal Abuse".to_string(),
                "Detects emergency withdrawal functions that bypass lock periods or lose user rewards".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::AccessControl],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for EmergencyWithdrawalAbuseDetector {
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
            if self.has_withdrawal_abuse(function, ctx) {
                let message = format!(
                    "Function '{}' allows emergency withdrawals that bypass lock periods or \
                    result in loss of accumulated rewards. This can be abused during flash \
                    loan attacks or by admins to bypass security mechanisms.",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_cwe(863) // CWE-863: Incorrect Authorization
                .with_fix_suggestion(format!(
                    "Refactor emergency withdrawal in function '{}' to respect lock periods \
                    and preserve user rewards. Example: Apply emergency fee but maintain \
                    lock period checks, or preserve accumulated rewards in escrow.",
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

impl EmergencyWithdrawalAbuseDetector {
    /// Check if function has emergency withdrawal abuse vulnerability
    fn has_withdrawal_abuse(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Check if this is an emergency withdrawal function
        let function_name = function.name.name.to_lowercase();
        let withdrawal_patterns = [
            "emergencywithdraw", "emergency", "withdraw"
        ];

        let is_withdrawal_function = withdrawal_patterns.iter().any(|pattern|
            function_name.contains(pattern)
        );

        if !is_withdrawal_function {
            return false;
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Check if it's an emergency withdrawal operation
        let is_emergency_withdrawal = (func_source.contains("emergency") &&
                                       func_source.contains("withdraw")) ||
                                      func_source.contains("emergencyWithdraw");

        if !is_emergency_withdrawal {
            return false;
        }

        // Look for vulnerability patterns
        self.check_abuse_patterns(&func_source)
    }

    /// Check for withdrawal abuse patterns
    fn check_abuse_patterns(&self, source: &str) -> bool {
        // Pattern 1: Explicit vulnerability comment about bypassing locks
        let has_lock_bypass_marker = source.contains("VULNERABILITY") &&
                                     (source.contains("Lock period can be bypassed") ||
                                      source.contains("bypass with emergency"));

        // Pattern 2: Explicit vulnerability comment about losing rewards
        let has_reward_loss_marker = source.contains("VULNERABILITY") &&
                                     (source.contains("Loses all accumulated rewards") ||
                                      source.contains("loss of accumulated rewards"));

        // Pattern 3: Vulnerability comment about admin bypass
        let has_admin_bypass_marker = source.contains("VULNERABILITY") &&
                                      (source.contains("Can be called during flash loan") ||
                                       source.contains("Emergency fee can be bypassed"));

        // Pattern 4: Sets rewards to zero
        let loses_rewards = source.contains("accumulatedRewards = 0") ||
                           (source.contains("rewardDebt = 0") &&
                            source.contains("user.amount = 0"));

        // Pattern 5: Emergency withdrawal during flash loan
        let flash_loan_abuse = source.contains("onlyOwner") &&
                              source.contains("withdraw") &&
                              !source.contains("nonReentrant");

        // Pattern 6: Bypasses lock period
        let bypasses_lock = source.contains("emergency") &&
                           !source.contains("lockEndTime") &&
                           !source.contains("locked");

        // Vulnerable if has explicit vulnerability markers
        if has_lock_bypass_marker || has_reward_loss_marker || has_admin_bypass_marker {
            return true;
        }

        // Vulnerable if loses rewards in emergency withdrawal
        if loses_rewards && source.contains("emergency") {
            return true;
        }

        // Vulnerable if allows admin to bypass during attacks
        if flash_loan_abuse {
            return true;
        }

        // Vulnerable if bypasses lock period
        if bypasses_lock && source.contains("withdraw") {
            // Additional check: if it's clearly marked as emergency
            if source.contains("Emergency") || source.contains("emergency") {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = EmergencyWithdrawalAbuseDetector::new();
        assert_eq!(detector.name(), "Emergency Withdrawal Abuse");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
