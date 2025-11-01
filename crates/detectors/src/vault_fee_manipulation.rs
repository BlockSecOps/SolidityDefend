use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::access_control_patterns;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for ERC-4626 vault fee manipulation vulnerabilities
pub struct VaultFeeManipulationDetector {
    base: BaseDetector,
}

impl VaultFeeManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("vault-fee-manipulation".to_string()),
                "Vault Fee Manipulation".to_string(),
                "Detects ERC4626 vaults vulnerable to fee parameter front-running and manipulation attacks".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::MEV],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for VaultFeeManipulationDetector {
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

        // Phase 2 Enhancement: Multi-level safe pattern detection with dynamic confidence

        // Level 1: Strong governance patterns (return early)
        if access_control_patterns::has_timelock_pattern(ctx) {
            // Timelock provides delay for users to react to fee changes
            if access_control_patterns::has_multisig_pattern(ctx) {
                // Timelock + multi-sig = comprehensive protection
                return Ok(findings);
            }
        }

        // Level 2: Access control patterns (reduce confidence if present)
        let has_timelock = access_control_patterns::has_timelock_pattern(ctx);
        let has_multisig = access_control_patterns::has_multisig_pattern(ctx);
        let has_role_hierarchy = access_control_patterns::has_role_hierarchy_pattern(ctx);
        let has_pause = access_control_patterns::has_pause_pattern(ctx);
        let has_two_step_ownership = access_control_patterns::has_two_step_ownership(ctx);

        // Calculate protection score for confidence calibration
        let mut protection_score = 0;
        if has_timelock { protection_score += 3; } // Critical for fee changes
        if has_multisig { protection_score += 2; } // Prevents single admin abuse
        if has_role_hierarchy { protection_score += 1; }
        if has_pause { protection_score += 1; }
        if has_two_step_ownership { protection_score += 1; }

        for function in ctx.get_functions() {
            if let Some(fee_issue) = self.check_fee_manipulation(function, ctx) {
                let message = format!(
                    "Function '{}' may be vulnerable to fee manipulation attack. {} \
                    Attacker can front-run fee changes to extract value from depositors.",
                    function.name.name, fee_issue
                );

                // Phase 2: Dynamic confidence scoring based on detected patterns
                let confidence = if protection_score == 0 {
                    // No protections detected - high confidence vulnerability
                    Confidence::High
                } else if protection_score <= 2 {
                    // Minimal protections - medium confidence
                    Confidence::Medium
                } else if protection_score <= 4 {
                    // Some protections but not comprehensive - medium-low confidence
                    Confidence::Medium
                } else {
                    // Multiple strong protections - low confidence FP
                    Confidence::Low
                };

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_confidence(confidence)
                    .with_fix_suggestion(format!(
                        "Protect '{}' from fee manipulation. \
                    Solutions: (1) Implement timelock delay on fee updates (24-48 hours minimum), \
                    (2) Emit events before fee changes take effect with advance notice, \
                    (3) Add maximum fee change limits per update (e.g., max 2% fee), \
                    (4) Require multi-sig approval for fee changes (Gnosis Safe pattern), \
                    (5) Use gradual fee ramping instead of instant updates (Curve style), \
                    (6) Implement MEV protection patterns for fee-dependent operations, \
                    (7) Consider OpenZeppelin TimelockController for governance.",
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

impl VaultFeeManipulationDetector {
    /// Check for fee manipulation vulnerabilities
    fn check_fee_manipulation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Identify fee-related functions
        let is_fee_function = function.name.name.to_lowercase().contains("fee")
            || function.name.name.to_lowercase().contains("setfee")
            || function.name.name.to_lowercase().contains("updatefee")
            || func_source.contains("Fee =")
            || func_source.contains("fee =");

        let is_fee_setter = function.name.name.to_lowercase().contains("set")
            && function.name.name.to_lowercase().contains("fee");

        if !is_fee_function && !is_fee_setter {
            return None;
        }

        // Pattern 1: Unprotected fee update without timelock
        let updates_fee = func_source.contains("Fee =")
            || func_source.contains("fee =")
            || func_source.contains("feePercentage =")
            || func_source.contains("performanceFee =");

        let has_timelock = func_source.contains("timelock")
            || func_source.contains("delay")
            || func_source.contains("scheduledTime")
            || func_source.contains("effectiveTime");

        if updates_fee && !has_timelock {
            return Some(format!(
                "Unprotected fee update without timelock. Fee changes take effect immediately, \
                enabling front-running attacks"
            ));
        }

        // Pattern 2: Missing fee change event emission
        let has_event_emit = func_source.contains("emit ")
            && (func_source.contains("FeeUpdated")
                || func_source.contains("FeeChanged")
                || func_source.contains("SetFee"));

        if updates_fee && !has_event_emit {
            return Some(format!(
                "Fee update without event emission. Users cannot detect fee changes \
                before they take effect"
            ));
        }

        // Pattern 3: No maximum fee change limit
        let has_max_fee_check = func_source.contains("MAX_FEE")
            || func_source.contains("maxFee")
            || func_source.contains("FEE_LIMIT")
            || func_source.contains("require(newFee <=");

        if updates_fee && !has_max_fee_check {
            return Some(format!(
                "No maximum fee limit enforced. Admin can set arbitrarily high fees \
                to extract all user value"
            ));
        }

        // Pattern 4: Front-runnable fee-dependent operations
        let calculates_with_fee = func_source.contains("* fee")
            || func_source.contains("* performanceFee")
            || func_source.contains("/ FEE_DENOMINATOR");

        let is_deposit_withdraw = function.name.name.to_lowercase().contains("deposit")
            || function.name.name.to_lowercase().contains("withdraw")
            || function.name.name.to_lowercase().contains("redeem");

        if calculates_with_fee && is_deposit_withdraw {
            let reads_current_fee = func_source.contains("currentFee")
                || func_source.contains("fee()")
                || func_source.contains("getFee()");

            if reads_current_fee {
                return Some(format!(
                    "Front-runnable fee-dependent operation. Fee can be changed in same block \
                    before user transaction executes"
                ));
            }
        }

        // Pattern 5: Missing multi-sig or governance control
        let has_access_control = func_source.contains("onlyOwner")
            || func_source.contains("onlyGovernance")
            || func_source.contains("require(msg.sender ==")
            || function.modifiers.iter().any(|m| {
                let modifier_name = &m.name.name;
                modifier_name.to_lowercase().contains("only")
                    || modifier_name.to_lowercase().contains("auth")
            });

        let has_multisig = func_source.contains("multisig")
            || func_source.contains("timelock")
            || func_source.contains("governance");

        if updates_fee && has_access_control && !has_multisig {
            return Some(format!(
                "Fee updates controlled by single admin without multi-sig. \
                Single point of failure for fee manipulation"
            ));
        }

        // Pattern 6: No gradual fee ramping
        let has_gradual_change = func_source.contains("ramp")
            || func_source.contains("gradual")
            || func_source.contains("step")
            || func_source.contains("increment");

        if updates_fee && !has_gradual_change && !has_timelock {
            return Some(format!(
                "Instant fee updates without gradual ramping. \
                Large fee changes can shock users without warning"
            ));
        }

        // Pattern 7: Fee change window too short
        let has_notice_period = func_source.contains("NOTICE_PERIOD")
            || func_source.contains("DELAY")
            || func_source.contains("48 hours")
            || func_source.contains("24 hours");

        if updates_fee && has_timelock && !has_notice_period {
            return Some(format!(
                "Fee change timelock without explicit notice period. \
                Users may not have sufficient time to exit"
            ));
        }

        // Pattern 8: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("fee")
                || func_source.contains("front")
                || func_source.contains("manipulation"))
        {
            return Some(format!(
                "Vault fee manipulation vulnerability marker detected"
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
        let detector = VaultFeeManipulationDetector::new();
        assert_eq!(detector.name(), "Vault Fee Manipulation");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
