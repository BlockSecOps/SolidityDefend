use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for validator front-running vulnerabilities
pub struct ValidatorFrontRunningDetector {
    base: BaseDetector,
}

impl Default for ValidatorFrontRunningDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorFrontRunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("validator-front-running".to_string()),
                "Validator Front-Running".to_string(),
                "Detects vulnerabilities where validators can front-run user transactions for profit or extract MEV".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for ValidatorFrontRunningDetector {
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

        // Skip AMM pool contracts - validator MEV is expected and inherent to their design
        // AMMs enable price discovery and arbitrage through validator ordering
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(frontrun_issue) = self.check_validator_frontrunning(function, ctx) {
                let message = format!(
                    "Function '{}' has validator front-running vulnerability. {} \
                    Validators can observe pending transactions and extract value by front-running users.",
                    function.name.name, frontrun_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_fix_suggestion(format!(
                    "Mitigate validator front-running in '{}'. \
                    Implement commit-reveal schemes, use threshold encryption, \
                    add validator rotation, implement fair sequencing service integration, \
                    use batch auctions instead of continuous, and add MEV redistribution mechanisms.",
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

impl ValidatorFrontRunningDetector {
    /// Check for validator front-running vulnerabilities
    fn check_validator_frontrunning(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Skip functions with access control - not vulnerable to public front-running
        let has_access_control = func_source.contains("onlyOwner")
            || func_source.contains("onlyAdmin")
            || func_source.contains("onlyGovernance")
            || func_source.contains("onlyValidator")
            || func_source.contains("require(msg.sender ==");

        if has_access_control {
            return None;
        }

        // Skip internal/private functions - not callable by validators
        if function.visibility != ast::Visibility::External
            && function.visibility != ast::Visibility::Public
        {
            return None;
        }

        // Skip view/pure functions - no state changes to front-run
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return None;
        }

        // Skip time-locked or commit-reveal protected operations
        let has_timing_protection = func_source.contains("timelock")
            || func_source.contains("delay")
            || func_source.contains("commit")
            || func_source.contains("reveal")
            || func_source.contains("deadline");

        if has_timing_protection {
            return None;
        }

        // Only flag high-risk MEV patterns
        let is_high_risk_mev = func_source.contains("liquidat")
            || func_source.contains("arbitrage")
            || (func_source.contains("claim") && func_source.contains("first"))
            || func_source.contains("frontrun");

        if !is_high_risk_mev {
            return None;
        }

        // Pattern 1: Liquidation without MEV protection
        if func_source.contains("liquidat") {
            let no_protection = !func_source.contains("batch")
                && !func_source.contains("auction")
                && !func_source.contains("redistribute");

            if no_protection {
                return Some(
                    "Liquidation function without MEV protection, \
                    validators can front-run liquidations for profit"
                        .to_string(),
                );
            }
        }

        // Pattern 2: Arbitrage function exposed publicly
        if func_source.contains("arbitrage") {
            return Some(
                "Arbitrage function exposed publicly, \
                validators can extract arbitrage MEV by front-running"
                    .to_string(),
            );
        }

        // Pattern 3: First-come-first-serve claim without protection
        if func_source.contains("claim") && func_source.contains("first") {
            let no_commit_reveal = !func_source.contains("commit")
                && !func_source.contains("reveal")
                && !func_source.contains("signature");

            if no_commit_reveal {
                return Some(
                    "First-come-first-serve claim without commit-reveal, \
                    validators can front-run claims"
                        .to_string(),
                );
            }
        }

        // Pattern 4: Explicit front-run vulnerable pattern
        if func_source.contains("frontrun") {
            return Some(
                "Function explicitly marked as front-run vulnerable, \
                requires MEV protection mechanisms"
                    .to_string(),
            );
        }

        // Pattern 5: Validator priority in queue
        let has_queue = func_source.contains("queue") || func_source.contains("Queue");

        let validator_priority = has_queue
            && (func_source.contains("validator") || func_source.contains("isValidator"))
            && !func_source.contains("fair");

        if validator_priority {
            return Some(
                "Validators have priority in queue, \
                can skip ahead of user transactions for profitable operations"
                    .to_string(),
            );
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
        let detector = ValidatorFrontRunningDetector::new();
        assert_eq!(detector.name(), "Validator Front-Running");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
