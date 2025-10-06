use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for slashing mechanism vulnerabilities in staking systems
pub struct SlashingMechanismDetector {
    base: BaseDetector,
}

impl SlashingMechanismDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("slashing-mechanism".to_string()),
                "Slashing Mechanism Vulnerability".to_string(),
                "Detects vulnerabilities in validator slashing mechanisms that can lead to unfair penalties or griefing attacks".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Detector for SlashingMechanismDetector {
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
            if let Some(slashing_issue) = self.check_slashing_vulnerability(function, ctx) {
                let message = format!(
                    "Function '{}' has slashing mechanism vulnerability. {} \
                    Improper slashing logic can lead to validator griefing, unfair penalties, or loss of staked funds.",
                    function.name.name,
                    slashing_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                .with_fix_suggestion(format!(
                    "Fix slashing mechanism in '{}'. \
                    Implement cooldown periods between slashings, add maximum slashing limits per period, \
                    require evidence verification with dispute periods, implement progressive penalties, \
                    add multi-signature requirements for large slashings, and protect against double-slashing.",
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

impl SlashingMechanismDetector {
    /// Check for slashing mechanism vulnerabilities
    fn check_slashing_vulnerability(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check if function is related to slashing
        let is_slashing_function = func_source.contains("slash") ||
                                  func_source.contains("Slash") ||
                                  func_source.contains("penalty") ||
                                  func_source.contains("Penalty") ||
                                  function.name.name.to_lowercase().contains("slash");

        if !is_slashing_function {
            return None;
        }

        // Pattern 1: No cooldown between slashing events
        let has_cooldown = func_source.contains("lastSlash") ||
                          func_source.contains("slashTime") ||
                          func_source.contains("cooldown") ||
                          func_source.contains("SLASH_DELAY");

        let lacks_cooldown = is_slashing_function &&
                            !has_cooldown &&
                            (func_source.contains("stake") || func_source.contains("balance"));

        if lacks_cooldown {
            return Some(format!(
                "No cooldown period between slashing events, \
                allows rapid repeated slashing of same validator (griefing attack)"
            ));
        }

        // Pattern 2: No maximum slashing limit per period
        let has_max_limit = func_source.contains("MAX_SLASH") ||
                           func_source.contains("maxSlash") ||
                           func_source.contains("slashLimit") ||
                           func_source.contains("MAX_PENALTY");

        let lacks_limit = is_slashing_function &&
                         !has_max_limit &&
                         (func_source.contains("amount") || func_source.contains("stake"));

        if lacks_limit {
            return Some(format!(
                "No maximum slashing amount limit per time period, \
                validator can lose entire stake from single event"
            ));
        }

        // Pattern 3: Slashing without evidence verification
        let has_evidence_check = func_source.contains("proof") ||
                                func_source.contains("evidence") ||
                                func_source.contains("verify") ||
                                func_source.contains("signature");

        let lacks_evidence = is_slashing_function &&
                            !has_evidence_check &&
                            func_source.contains("require");

        if lacks_evidence {
            return Some(format!(
                "Slashing triggered without evidence verification, \
                allows arbitrary slashing without proof of misbehavior"
            ));
        }

        // Pattern 4: No dispute or appeal period
        let has_dispute_period = func_source.contains("dispute") ||
                                func_source.contains("appeal") ||
                                func_source.contains("challenge") ||
                                func_source.contains("DISPUTE_PERIOD");

        let lacks_dispute = is_slashing_function &&
                           !has_dispute_period &&
                           func_source.contains("stake");

        if lacks_dispute {
            return Some(format!(
                "Slashing executes immediately without dispute period, \
                no mechanism for validators to challenge false accusations"
            ));
        }

        // Pattern 5: Single address can trigger slashing
        let has_multisig = func_source.contains("onlyOwner") ||
                          func_source.contains("onlyAdmin") ||
                          func_source.contains("multisig") ||
                          func_source.contains("quorum");

        let single_caller = is_slashing_function &&
                           !has_multisig &&
                           func_source.contains("external");

        if single_caller {
            return Some(format!(
                "Single address can trigger slashing without multi-signature, \
                centralization risk and potential for malicious slashing"
            ));
        }

        // Pattern 6: No double-slashing protection
        let has_double_slash_protection = func_source.contains("slashed[") ||
                                         func_source.contains("hasBeenSlashed") ||
                                         func_source.contains("alreadySlashed");

        let lacks_double_protection = is_slashing_function &&
                                     !has_double_slash_protection &&
                                     func_source.contains("mapping");

        if lacks_double_protection {
            return Some(format!(
                "No protection against double-slashing for same offense, \
                validator can be penalized multiple times for single misbehavior"
            ));
        }

        // Pattern 7: Slashing amount not proportional
        let has_proportional_logic = func_source.contains("percentage") ||
                                    func_source.contains("percent") ||
                                    func_source.contains("multiplier") ||
                                    func_source.contains("severity");

        let lacks_proportionality = is_slashing_function &&
                                   !has_proportional_logic &&
                                   func_source.contains("amount");

        if lacks_proportionality {
            return Some(format!(
                "Slashing amount not proportional to offense severity, \
                fixed penalty may be too harsh for minor violations"
            ));
        }

        // Pattern 8: No grace period for first offenses
        let has_grace_period = func_source.contains("firstOffense") ||
                              func_source.contains("offenseCount") ||
                              func_source.contains("violations") ||
                              func_source.contains("strikes");

        let lacks_grace = is_slashing_function &&
                         !has_grace_period &&
                         func_source.contains("slash");

        if lacks_grace {
            return Some(format!(
                "No grace period or warning system for first offenses, \
                harsh penalties applied immediately without progressive discipline"
            ));
        }

        // Pattern 9: Slashing affects delegators unfairly
        let affects_delegators = func_source.contains("delegator") ||
                                func_source.contains("Delegator");

        let no_delegator_protection = affects_delegators &&
                                     is_slashing_function &&
                                     !func_source.contains("delegatorProtection") &&
                                     !func_source.contains("insurance");

        if no_delegator_protection {
            return Some(format!(
                "Validator slashing affects delegators without protection, \
                delegators punished for validator misbehavior they cannot control"
            ));
        }

        // Pattern 10: Slashing burns funds instead of redistributing
        let burns_funds = func_source.contains("burn") ||
                         func_source.contains("address(0)");

        let no_redistribution = burns_funds &&
                               is_slashing_function &&
                               !func_source.contains("distribute") &&
                               !func_source.contains("reward");

        if no_redistribution {
            return Some(format!(
                "Slashed funds burned instead of redistributed to honest validators, \
                reduces economic security and validator incentives"
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
        let detector = SlashingMechanismDetector::new();
        assert_eq!(detector.name(), "Slashing Mechanism Vulnerability");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
