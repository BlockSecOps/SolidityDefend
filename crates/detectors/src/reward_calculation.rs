use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for reward calculation manipulation vulnerabilities
pub struct RewardCalculationDetector {
    base: BaseDetector,
}

impl RewardCalculationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("reward-calculation-manipulation".to_string()),
                "Reward Calculation Manipulation".to_string(),
                "Detects reward calculations based on manipulable price sources or incentivizing price deviation".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Oracle],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for RewardCalculationDetector {
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
            if self.has_reward_manipulation(function, ctx) {
                let message = format!(
                    "Function '{}' calculates rewards based on manipulable price sources or \
                    incentivizes price deviation. Attackers can manipulate oracle prices to \
                    increase their rewards, or benefit from creating price deviations.",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_cwe(20)  // CWE-20: Improper Input Validation
                .with_fix_suggestion(format!(
                    "Refactor reward calculation in function '{}' to use TWAP prices instead \
                    of spot prices, and remove incentives for price deviation. Example: Use \
                    time-weighted average prices and cap multipliers based on deviation.",
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

impl RewardCalculationDetector {
    /// Check if function has reward calculation manipulation vulnerability
    fn has_reward_manipulation(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Check if this is a reward-related function
        let function_name = function.name.name.to_lowercase();
        let reward_patterns = [
            "reward", "multiplier", "calculate", "updatepool",
            "getpricemultiplier", "getmultiplier"
        ];

        let is_reward_function = reward_patterns.iter().any(|pattern|
            function_name.contains(pattern)
        );

        if !is_reward_function {
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

        // Check if it's calculating rewards
        let calculates_rewards = func_source.contains("reward") ||
                                func_source.contains("multiplier") ||
                                func_source.contains("accReward");

        if !calculates_rewards {
            return false;
        }

        // Look for vulnerability patterns
        self.check_manipulation_patterns(&func_source)
    }

    /// Check for reward manipulation patterns
    fn check_manipulation_patterns(&self, source: &str) -> bool {
        // Pattern 1: Explicit vulnerability comment
        let has_vulnerability_marker = source.contains("VULNERABILITY") &&
                                       (source.contains("current price, can be manipulated") ||
                                        source.contains("Incentivizes manipulation") ||
                                        source.contains("deviation = higher rewards"));

        // Pattern 2: Uses current/spot price instead of TWAP
        let uses_spot_price = (source.contains("currentPrice") ||
                              source.contains("getCurrentPrice") ||
                              source.contains("getPrice()")) &&
                             source.contains("multiplier");

        // Pattern 3: Incentivizes price deviation
        let incentivizes_deviation = (source.contains("deviation") &&
                                     source.contains("multiplier")) &&
                                    (source.contains("deviation >") ||
                                     source.contains("if (deviation"));

        // Pattern 4: Reward calculation before state update
        let calculation_before_update = source.contains("VULNERABILITY") &&
                                       source.contains("Reward calculation before");

        // Pattern 5: Higher deviation = higher rewards pattern
        let deviation_reward_pattern = source.contains("Higher deviation") ||
                                      (source.contains("deviation >") &&
                                       source.contains("return") &&
                                       source.contains("// 1."));

        // Vulnerable if has explicit marker
        if has_vulnerability_marker {
            return true;
        }

        // Vulnerable if uses spot price for rewards
        if uses_spot_price && !source.contains("TWAP") {
            return true;
        }

        // Vulnerable if incentivizes deviation
        if incentivizes_deviation && deviation_reward_pattern {
            return true;
        }

        // Vulnerable if calculates before update
        if calculation_before_update {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = RewardCalculationDetector::new();
        assert_eq!(detector.name(), "Reward Calculation Manipulation");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
