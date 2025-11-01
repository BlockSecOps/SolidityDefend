use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for validator front-running vulnerabilities
pub struct ValidatorFrontRunningDetector {
    base: BaseDetector,
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
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check if function involves value-extractable operations
        let is_value_operation = func_source.contains("stake")
            || func_source.contains("reward")
            || func_source.contains("withdraw")
            || func_source.contains("claim")
            || func_source.contains("swap");

        if !is_value_operation {
            return None;
        }

        // Pattern 1: Validator selection visible before execution
        let selects_validator = func_source.contains("selectValidator")
            || func_source.contains("chooseValidator")
            || func_source.contains("assignValidator");

        let no_commitment = selects_validator
            && !func_source.contains("commit")
            && !func_source.contains("hash")
            && !func_source.contains("reveal");

        if no_commitment {
            return Some(format!(
                "Validator selection visible in mempool without commitment, \
                validators can selectively include/exclude transactions"
            ));
        }

        // Pattern 2: Reward distribution without anti-frontrun protection
        let distributes_rewards = func_source.contains("distribute")
            || func_source.contains("reward")
            || function.name.name.to_lowercase().contains("reward");

        let no_protection = distributes_rewards
            && !func_source.contains("commit")
            && !func_source.contains("private")
            && !func_source.contains("encrypted");

        if no_protection {
            return Some(format!(
                "Reward distribution visible in mempool, \
                validators can front-run to claim rewards first"
            ));
        }

        // Pattern 3: Staking without validator rotation
        let is_staking =
            func_source.contains("stake") || function.name.name.to_lowercase().contains("stake");

        let no_rotation = is_staking
            && !func_source.contains("rotate")
            && !func_source.contains("shuffle")
            && !func_source.contains("random");

        if no_rotation {
            return Some(format!(
                "Validator assignment without rotation, \
                same validators can repeatedly front-run same users"
            ));
        }

        // Pattern 4: Price-sensitive operations without sequencing
        let is_price_sensitive = func_source.contains("price")
            || func_source.contains("amount")
            || func_source.contains("slippage");

        let no_fair_sequencing = is_price_sensitive
            && is_value_operation
            && !func_source.contains("batch")
            && !func_source.contains("auction");

        if no_fair_sequencing {
            return Some(format!(
                "Price-sensitive operations without fair sequencing, \
                validators can reorder transactions for MEV extraction"
            ));
        }

        // Pattern 5: Validator can observe withdrawal amounts
        let is_withdrawal = func_source.contains("withdraw")
            || function.name.name.to_lowercase().contains("withdraw");

        let withdrawal_visible = is_withdrawal
            && func_source.contains("amount")
            && !func_source.contains("private")
            && !func_source.contains("encrypted");

        if withdrawal_visible {
            return Some(format!(
                "Withdrawal amounts visible to validators before execution, \
                enables targeted front-running of large withdrawals"
            ));
        }

        // Pattern 6: No MEV redistribution mechanism
        let generates_mev = func_source.contains("liquidat")
            || func_source.contains("arbitrage")
            || func_source.contains("swap");

        let no_mev_sharing = generates_mev
            && !func_source.contains("redistribute")
            && !func_source.contains("share")
            && !func_source.contains("burn");

        if no_mev_sharing {
            return Some(format!(
                "MEV-generating operations without redistribution, \
                validators capture full MEV without sharing with users"
            ));
        }

        // Pattern 7: Validator can see claim intentions
        let is_claim =
            func_source.contains("claim") || function.name.name.to_lowercase().contains("claim");

        let claim_visible =
            is_claim && !func_source.contains("commit") && !func_source.contains("signature");

        if claim_visible {
            return Some(format!(
                "Claim operations visible in mempool, \
                validators can front-run to claim before users"
            ));
        }

        // Pattern 8: Continuous trading instead of batch auctions
        let is_trading = func_source.contains("trade")
            || func_source.contains("swap")
            || func_source.contains("exchange");

        let continuous_trading = is_trading
            && !func_source.contains("batch")
            && !func_source.contains("auction")
            && !func_source.contains("round");

        if continuous_trading {
            return Some(format!(
                "Continuous trading model without batching, \
                validators have information advantage for every trade"
            ));
        }

        // Pattern 9: No transaction ordering constraints
        let has_ordering_constraint = func_source.contains("sequence")
            || func_source.contains("order")
            || func_source.contains("nonce");

        let no_ordering =
            is_value_operation && !has_ordering_constraint && func_source.contains("public");

        if no_ordering {
            return Some(format!(
                "No transaction ordering constraints, \
                validators can reorder transactions arbitrarily for profit"
            ));
        }

        // Pattern 10: Validator priority in queue
        let has_queue = func_source.contains("queue") || func_source.contains("Queue");

        let validator_priority = has_queue
            && (func_source.contains("validator") || func_source.contains("isValidator"))
            && !func_source.contains("fair");

        if validator_priority {
            return Some(format!(
                "Validators have priority in queue, \
                can skip ahead of user transactions for profitable operations"
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
        let detector = ValidatorFrontRunningDetector::new();
        assert_eq!(detector.name(), "Validator Front-Running");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
