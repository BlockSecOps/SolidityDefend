use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::mev_protection_patterns;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for generalized MEV extraction vulnerabilities
pub struct MevExtractableValueDetector {
    base: BaseDetector,
}

impl MevExtractableValueDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("mev-extractable-value".to_string()),
                "MEV Extractable Value".to_string(),
                "Detects contracts with extractable MEV through front-running, back-running, or transaction ordering manipulation".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for MevExtractableValueDetector {
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
            if let Some(mev_issue) = self.check_mev_extractable(function, ctx) {
                let func_source = self.get_function_source(function, ctx);

                // NEW: Calculate confidence based on protections
                let confidence = self.calculate_confidence(function, &func_source);

                let message = format!(
                    "Function '{}' has extractable MEV. {} \
                    Searchers can extract value through transaction ordering, front-running, or back-running.",
                    function.name.name, mev_issue
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
                    .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_confidence(confidence) // NEW: Set confidence
                    .with_fix_suggestion(format!(
                        "Reduce MEV extractability in '{}'. \
                    Implement: (1) Commit-reveal schemes, (2) Batch processing/auctions, \
                    (3) Private transaction pools (Flashbots), (4) Time-weighted mechanisms, \
                    (5) MEV-resistant AMM curves, (6) Encrypted mempools.",
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

impl MevExtractableValueDetector {
    /// Check for MEV extraction opportunities
    fn check_mev_extractable(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Skip if this is an ERC-4337 paymaster/account abstraction contract
        // Paymaster functions (recovery, session keys, nonce management) are not MEV-vulnerable
        // They're administrative operations that don't involve extractable value
        let is_paymaster = utils::is_erc4337_paymaster(ctx);
        if is_paymaster {
            return None; // Paymaster operations are not MEV targets
        }

        // NEW: Early exit if function has sufficient MEV protection
        if mev_protection_patterns::has_sufficient_mev_protection(function, &func_source, ctx) {
            return None; // Protected - no MEV risk
        }

        // Pattern 1: Public function with value transfer without protection (TIGHTENED)
        let is_public = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        let has_value_transfer = func_source.contains("transfer")
            || func_source.contains("send")
            || func_source.contains("call{value:");

        // NEW: Check for specific protections
        let lacks_mev_protection = is_public
            && has_value_transfer
            && !mev_protection_patterns::has_slippage_protection(&func_source)
            && !mev_protection_patterns::has_deadline_protection(&func_source)
            && !mev_protection_patterns::is_user_operation(&func_source, &function.name.name);

        if lacks_mev_protection {
            return Some(format!(
                "Public function with value transfer lacks MEV protection (no slippage/deadline checks), \
                enabling front-running and back-running attacks"
            ));
        }

        // Pattern 2: Profitable liquidation without auction mechanism
        let is_liquidation = func_source.contains("liquidat")
            || function.name.name.to_lowercase().contains("liquidat");

        let has_profit = func_source.contains("bonus")
            || func_source.contains("reward")
            || func_source.contains("incentive");

        let no_auction = is_liquidation
            && has_profit
            && !func_source.contains("auction")
            && !func_source.contains("bid")
            && !func_source.contains("dutch");

        if no_auction {
            return Some(format!(
                "Profitable liquidation without auction mechanism, \
                enabling MEV extraction through priority gas auctions (PGA)"
            ));
        }

        // Pattern 3: Arbitrage-able price differences
        let has_pricing = func_source.contains("price") || func_source.contains("getAmount");

        let has_swap = func_source.contains("swap") || func_source.contains("exchange");

        let arbitrage_opportunity = has_pricing
            && has_swap
            && !func_source.contains("TWAP")
            && !func_source.contains("oracle")
            && !func_source.contains("batch");

        if arbitrage_opportunity {
            return Some(format!(
                "Swap function with spot pricing creates arbitrage opportunities, \
                MEV bots can profit from price differences"
            ));
        }

        // Pattern 4: State changes visible in mempool before execution (TIGHTENED)
        // Only flag if it's NOT a user operation and affects global state
        let changes_state =
            func_source.contains("=") || func_source.contains("+=") || func_source.contains("-=");

        let affects_global_state = (func_source.contains("totalSupply")
            || func_source.contains("reserve0")
            || func_source.contains("reserve1")
            || func_source.contains("globalPrice"))
            && !func_source.contains("[msg.sender]");

        let is_mev_vulnerable_state_change = is_public
            && changes_state
            && affects_global_state
            && !mev_protection_patterns::is_user_operation(&func_source, &function.name.name)
            && !func_source.contains("private")
            && !func_source.contains("encrypted");

        if is_mev_vulnerable_state_change {
            return Some(format!(
                "State changes to global state (totalSupply/reserves/price) visible in public mempool, \
                allowing MEV bots to react and extract value"
            ));
        }

        // Pattern 5: Reward distribution without commit-reveal
        let distributes_rewards = func_source.contains("reward")
            || func_source.contains("distribute")
            || func_source.contains("claim");

        let no_commit_reveal = distributes_rewards
            && !func_source.contains("commit")
            && !func_source.contains("reveal")
            && !func_source.contains("hash");

        if no_commit_reveal {
            return Some(format!(
                "Reward distribution without commit-reveal, \
                enables front-running of reward claims"
            ));
        }

        // Pattern 6: First-come-first-served with high value
        let is_fcfs =
            func_source.contains("first") || function.name.name.to_lowercase().contains("first");

        let high_value = func_source.contains("mint")
            || func_source.contains("claim")
            || func_source.contains("buy");

        let fcfs_mev = is_fcfs
            && high_value
            && !func_source.contains("queue")
            && !func_source.contains("lottery");

        if fcfs_mev {
            return Some(format!(
                "First-come-first-served mechanism for high-value operations, \
                creates priority gas auction (PGA) MEV"
            ));
        }

        // Pattern 7: Oracle update function without access control (TIGHTENED)
        let updates_oracle = func_source.contains("updatePrice")
            || func_source.contains("setPrice")
            || function.name.name.to_lowercase().contains("update");

        let affects_defi =
            updates_oracle && (func_source.contains("price") || func_source.contains("rate"));

        // NEW: Check for access control
        let lacks_access_control = !mev_protection_patterns::has_mev_limiting_access_control(function);

        if affects_defi && is_public && lacks_access_control {
            return Some(format!(
                "Public oracle update function without access control enables MEV through oracle manipulation, \
                can be front-run or back-run for profit"
            ));
        }

        // Pattern 8: Multi-step operation without atomicity
        let has_multiple_calls = func_source.matches(".call(").count() > 1
            || func_source.matches(".transfer(").count() > 1;

        let lacks_atomicity = has_multiple_calls
            && !func_source.contains("require")
            && !func_source.contains("revert");

        if lacks_atomicity {
            return Some(format!(
                "Multi-step operation without atomicity guarantees, \
                enables MEV through transaction insertion between steps"
            ));
        }

        // Pattern 9: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("MEV")
                || func_source.contains("front-run")
                || func_source.contains("extractable"))
        {
            return Some(format!(
                "MEV extractable value vulnerability marker detected"
            ));
        }

        None
    }

    /// Calculate confidence based on number of MEV protections
    fn calculate_confidence(&self, function: &ast::Function<'_>, func_source: &str) -> Confidence {
        let protection_count = mev_protection_patterns::count_mev_protections(function, func_source);

        match protection_count {
            0 => Confidence::High,    // No protections - high confidence in MEV risk
            1 => Confidence::Medium,  // Some protection - medium confidence
            _ => Confidence::Low,     // Multiple protections - low confidence (may be false positive)
        }
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
        let detector = MevExtractableValueDetector::new();
        assert_eq!(detector.name(), "MEV Extractable Value");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
