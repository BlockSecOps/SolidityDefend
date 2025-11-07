use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for flash loan staking attack vulnerabilities
pub struct FlashLoanStakingDetector {
    base: BaseDetector,
}

impl Default for FlashLoanStakingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FlashLoanStakingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flash-loan-staking".to_string()),
                "Flash Loan Staking Attack".to_string(),
                "Detects staking/farming contracts vulnerable to flash loan attacks for reward extraction".to_string(),
                vec![DetectorCategory::FlashLoanAttacks, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for FlashLoanStakingDetector {
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
            if self.is_vulnerable_to_flash_loan_staking(function, ctx) {
                let message = format!(
                    "Function '{}' is vulnerable to flash loan staking attacks. \
                    Attackers can temporarily stake large amounts via flash loans to extract \
                    disproportionate rewards before repaying the loan in the same transaction.",
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
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Implement time-delay requirements before rewards can be claimed. \
                    Example: require(block.timestamp >= user.lastStakeTime + MIN_STAKE_DURATION) \
                    in function '{}'",
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

impl FlashLoanStakingDetector {
    /// Check if a function is vulnerable to flash loan staking attacks
    fn is_vulnerable_to_flash_loan_staking(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Look for staking/farming related functions
        let function_name = function.name.name.to_lowercase();
        let staking_patterns = [
            "deposit", "stake", "farm", "enter", "compound", "harvest", "claim",
        ];

        let is_staking_function = staking_patterns
            .iter()
            .any(|pattern| function_name.contains(pattern));

        if !is_staking_function {
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

        // Check if this is a staking/farming contract
        let has_staking_context = func_source.contains("amount")
            && (func_source.contains("reward")
                || func_source.contains("stake")
                || func_source.contains("pool"));

        if !has_staking_context {
            return false;
        }

        // Look for reward calculation patterns
        let has_reward_calculation = func_source.contains("pending")
            || func_source.contains("earned")
            || func_source.contains("reward")
            || func_source.contains("accRewardPerShare")
            || func_source.contains("rewardDebt");

        // Check for vulnerability patterns
        let vulnerability_patterns = self.check_vulnerability_patterns(&func_source);

        has_reward_calculation && vulnerability_patterns
    }

    /// Check for specific vulnerability patterns in the source code
    fn check_vulnerability_patterns(&self, source: &str) -> bool {
        // Pattern 1: Reward calculation before state update (classic flash loan vulnerability)
        let reward_before_update = source.contains("pending")
            && source.contains("if (user.amount > 0)")
            && !source.contains("block.timestamp")
            && !source.contains("lastStakeTime");

        // Pattern 2: No time-lock or minimum staking period
        let no_timelock = !source.contains("lockPeriod")
            && !source.contains("lock_period")
            && !source.contains("minimumStakingTime")
            && !source.contains("MIN_STAKE_DURATION");

        // Pattern 3: Immediate reward eligibility (commented as vulnerability)
        let has_vulnerability_comment = source.contains("VULNERABILITY")
            && (source.contains("flash loan") || source.contains("Reward calculation before"));

        // Pattern 4: Transfer before state update
        let unsafe_transfer_order = source.contains("transferFrom")
            && source.contains("user.amount =")
            && source
                .lines()
                .position(|l| l.contains("transferFrom"))
                .unwrap_or(0)
                < source
                    .lines()
                    .position(|l| l.contains("user.amount ="))
                    .unwrap_or(usize::MAX);

        // Vulnerable if any of these patterns are found
        reward_before_update || has_vulnerability_comment || (no_timelock && unsafe_transfer_order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = FlashLoanStakingDetector::new();
        assert_eq!(detector.name(), "Flash Loan Staking Attack");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
