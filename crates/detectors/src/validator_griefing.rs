use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for validator griefing attack vulnerabilities
pub struct ValidatorGriefingDetector {
    base: BaseDetector,
}

impl ValidatorGriefingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("validator-griefing".to_string()),
                "Validator Griefing Attack".to_string(),
                "Detects vulnerabilities where validators can be griefed through malicious actions that harm validators without benefiting attackers".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }
}

impl Detector for ValidatorGriefingDetector {
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
            if let Some(griefing_issue) = self.check_validator_griefing(function, ctx) {
                let message = format!(
                    "Function '{}' has validator griefing vulnerability. {} \
                    Attackers can harm validators without economic benefit, leading to validator exits and network destabilization.",
                    function.name.name, griefing_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(405) // CWE-405: Asymmetric Resource Consumption (Amplification)
                .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                .with_fix_suggestion(format!(
                    "Mitigate validator griefing in '{}'. \
                    Implement griefing-cost mechanisms (deposit requirements), add rate limiting per address, \
                    require minimum stake for reporting, implement reputation systems, \
                    add penalties for false accusations, and create validator insurance pools.",
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

impl ValidatorGriefingDetector {
    /// Check for validator griefing vulnerabilities
    fn check_validator_griefing(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check if function affects validators
        let affects_validators = func_source.contains("validator")
            || func_source.contains("Validator")
            || func_source.contains("stake")
            || func_source.contains("slash");

        if !affects_validators {
            return None;
        }

        // Pattern 1: Free or low-cost slashing reports
        let is_report_function = func_source.contains("report")
            || func_source.contains("accuse")
            || func_source.contains("slash")
            || function.name.name.to_lowercase().contains("report");

        let no_cost_to_report = is_report_function
            && !func_source.contains("require(msg.value")
            && !func_source.contains("deposit")
            && !func_source.contains("bond");

        if no_cost_to_report {
            return Some(format!(
                "Validator reporting or slashing has no cost to reporter, \
                enables free griefing attacks through false accusations"
            ));
        }

        // Pattern 2: No rate limiting on validator actions
        let has_rate_limit = func_source.contains("lastAction")
            || func_source.contains("rateLimit")
            || func_source.contains("cooldown")
            || func_source.contains("timestamp");

        let lacks_rate_limit =
            affects_validators && !has_rate_limit && func_source.contains("external");

        if lacks_rate_limit {
            return Some(format!(
                "No rate limiting on validator-affecting actions, \
                allows spam attacks to overwhelm validators or slashing logic"
            ));
        }

        // Pattern 3: Anyone can report without stake requirement
        let has_stake_requirement = func_source.contains("stakedAmount")
            || func_source.contains("minStake")
            || func_source.contains("require") && func_source.contains("stake");

        let no_stake_required =
            is_report_function && !has_stake_requirement && func_source.contains("public");

        if no_stake_required {
            return Some(format!(
                "No minimum stake requirement for reporting misbehavior, \
                attackers without skin in the game can grief validators"
            ));
        }

        // Pattern 4: Failed slashing doesn't penalize reporter
        let penalizes_false_reports = func_source.contains("slashReporter")
            || func_source.contains("penalizeReporter")
            || func_source.contains("false") && func_source.contains("penalty");

        let no_reporter_penalty =
            is_report_function && !penalizes_false_reports && func_source.contains("slash");

        if no_reporter_penalty {
            return Some(format!(
                "No penalty for false or failed slashing accusations, \
                encourages frivolous reports to grief validators"
            ));
        }

        // Pattern 5: Exit queue can be flooded
        let is_exit_function = func_source.contains("exit")
            || func_source.contains("withdraw")
            || function.name.name.to_lowercase().contains("exit");

        let no_exit_limit = is_exit_function
            && affects_validators
            && !func_source.contains("MAX_EXIT")
            && !func_source.contains("exitQueue");

        if no_exit_limit {
            return Some(format!(
                "Validator exit queue has no flood protection, \
                mass exit can delay legitimate withdrawals (griefing)"
            ));
        }

        // Pattern 6: Forced participation in expensive operations
        let expensive_operation = func_source.contains("loop")
            || func_source.contains("for")
            || func_source.contains("while");

        let forced_participation = expensive_operation
            && affects_validators
            && !func_source.contains("optional")
            && func_source.contains("require");

        if forced_participation {
            return Some(format!(
                "Validators forced to participate in expensive operations, \
                attacker can trigger high gas costs for all validators"
            ));
        }

        // Pattern 7: Validator registration without deposit
        let is_registration = func_source.contains("register")
            || func_source.contains("Register")
            || function.name.name.to_lowercase().contains("register");

        let no_registration_deposit = is_registration
            && affects_validators
            && !func_source.contains("deposit")
            && !func_source.contains("stake");

        if no_registration_deposit {
            return Some(format!(
                "Validator registration without deposit requirement, \
                enables Sybil attacks to spam validator set (griefing)"
            ));
        }

        // Pattern 8: Reward distribution can be blocked
        let is_reward_function = func_source.contains("reward")
            || func_source.contains("Reward")
            || func_source.contains("distribute");

        let blockable_rewards = is_reward_function
            && func_source.contains("revert")
            && !func_source.contains("try")
            && !func_source.contains("pull");

        if blockable_rewards {
            return Some(format!(
                "Reward distribution uses push pattern that can be blocked, \
                single failing validator can prevent all rewards (griefing)"
            ));
        }

        // Pattern 9: Validator metadata spam
        let updates_metadata = func_source.contains("metadata")
            || func_source.contains("info")
            || func_source.contains("details");

        let no_update_limit = updates_metadata
            && affects_validators
            && !func_source.contains("cooldown")
            && !func_source.contains("lastUpdate");

        if no_update_limit {
            return Some(format!(
                "Validator metadata updates without rate limiting, \
                enables spam of update events causing high gas costs"
            ));
        }

        // Pattern 10: Unprotected validator ejection
        let can_eject = func_source.contains("remove")
            || func_source.contains("kick")
            || func_source.contains("eject");

        let no_ejection_protection = can_eject
            && affects_validators
            && !func_source.contains("onlyGovernance")
            && !func_source.contains("multisig");

        if no_ejection_protection {
            return Some(format!(
                "Validator ejection mechanism lacks strong access control, \
                malicious admin can grief validators by removing them"
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
        let detector = ValidatorGriefingDetector::new();
        assert_eq!(detector.name(), "Validator Griefing Attack");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
