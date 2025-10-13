use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for missing front-running protection mechanisms
pub struct FrontRunningMitigationDetector {
    base: BaseDetector,
}

impl FrontRunningMitigationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("front-running-mitigation".to_string()),
                "Missing Front-Running Mitigation".to_string(),
                "Detects functions vulnerable to front-running attacks without proper MEV protection mechanisms".to_string(),
                vec![DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }
}

impl Detector for FrontRunningMitigationDetector {
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
            if let Some(frontrun_issue) = self.check_frontrunning_risk(function, ctx) {
                let message = format!(
                    "Function '{}' lacks front-running protection. {} \
                    Front-runners can extract MEV by observing mempool and inserting their transactions before yours.",
                    function.name.name, frontrun_issue
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
                    .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Add front-running protection to '{}'. \
                    Implement: (1) Commit-reveal scheme with time delay, \
                    (2) Deadline parameter for transaction validity, \
                    (3) Minimum output amount (slippage protection), \
                    (4) Batch auctions or frequent batch auctions (FBA), \
                    (5) Private mempool (Flashbots Protect), \
                    (6) Time-weighted average pricing (TWAP).",
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

impl FrontRunningMitigationDetector {
    fn check_frontrunning_risk(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let func_name = &function.name.name;

        // Pattern 1: Bid/auction functions without commit-reveal
        let is_bidding =
            func_name.contains("bid") || func_name.contains("Bid") || func_name.contains("auction");

        if is_bidding {
            let has_commit_reveal = func_source.contains("commit")
                || func_source.contains("reveal")
                || func_source.contains("hash")
                || func_source.contains("secret");

            if !has_commit_reveal {
                return Some(format!(
                    "Bidding function '{}' lacks commit-reveal scheme. \
                    Attackers can see your bid and outbid you",
                    func_name
                ));
            }
        }

        // Pattern 2: Swap/trade functions without slippage protection
        let is_trading = func_name.contains("swap")
            || func_name.contains("trade")
            || func_name.contains("exchange")
            || func_name.contains("buy")
            || func_name.contains("sell");

        if is_trading {
            let has_slippage = func_source.contains("minAmount")
                || func_source.contains("minOut")
                || func_source.contains("slippage")
                || func_source.contains("amountOutMin");

            let has_deadline = func_source.contains("deadline")
                || func_source.contains("expiry")
                || func_source.contains("block.timestamp");

            if !has_slippage {
                return Some(format!(
                    "Trading function '{}' missing slippage protection (minAmountOut). \
                    Vulnerable to sandwich attacks",
                    func_name
                ));
            }

            if !has_deadline {
                return Some(format!(
                    "Trading function '{}' missing deadline parameter. \
                    Transaction can be held and executed at unfavorable time",
                    func_name
                ));
            }
        }

        // Pattern 3: Price-sensitive operations without protection
        let uses_price = func_source.contains("price")
            || func_source.contains("getPrice")
            || func_source.contains("rate");

        let is_vulnerable_operation = func_name.contains("liquidate")
            || func_name.contains("mint")
            || func_name.contains("redeem")
            || func_name.contains("borrow");

        if uses_price && is_vulnerable_operation {
            let has_protection = func_source.contains("TWAP")
                || func_source.contains("timeWeighted")
                || func_source.contains("oracle")
                || func_source.contains("minAmount");

            if !has_protection {
                return Some(format!(
                    "Price-dependent function '{}' vulnerable to front-running. \
                    No TWAP, oracle, or minimum amount protection",
                    func_name
                ));
            }
        }

        // Pattern 4: State changes visible in mempool
        let changes_critical_state = func_source.contains("approve")
            || func_source.contains("transfer")
            || func_source.contains("withdraw");

        if changes_critical_state {
            let has_nonce_or_commitment = func_source.contains("nonce")
                || func_source.contains("commitment")
                || func_source.contains("signature");

            // Only flag if it's a high-value operation
            let is_high_value = func_source.contains("balance")
                || func_source.contains("amount")
                || func_source.contains("value");

            if is_high_value && !has_nonce_or_commitment {
                // Don't flag simple transfers, focus on complex operations
                if func_source.contains("calculate")
                    || func_source.contains("swap")
                    || func_source.contains("convert")
                {
                    return Some(format!(
                        "Function '{}' performs high-value state changes observable in mempool. \
                        Consider commit-reveal or private transactions",
                        func_name
                    ));
                }
            }
        }

        None
    }

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
        let detector = FrontRunningMitigationDetector::new();
        assert_eq!(detector.name(), "Missing Front-Running Mitigation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
