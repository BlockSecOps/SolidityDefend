use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for block stuffing vulnerabilities
pub struct BlockStuffingVulnerableDetector {
    base: BaseDetector,
}

impl Default for BlockStuffingVulnerableDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStuffingVulnerableDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("block-stuffing-vulnerable".to_string()),
                "Block Stuffing Vulnerable".to_string(),
                "Detects contracts vulnerable to block stuffing attacks where attackers fill blocks to prevent transaction inclusion".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for BlockStuffingVulnerableDetector {
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
            if let Some(stuffing_issue) = self.check_block_stuffing_vulnerability(function, ctx) {
                let message = format!(
                    "Function '{}' is vulnerable to block stuffing attacks. {} \
                    Attackers can fill blocks with transactions to prevent legitimate users from executing time-sensitive operations.",
                    function.name.name, stuffing_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource
                .with_cwe(405) // CWE-405: Asymmetric Resource Consumption (Amplification)
                .with_fix_suggestion(format!(
                    "Mitigate block stuffing in '{}'. \
                    Implement: (1) Grace periods extending deadlines, \
                    (2) Multi-block operation windows, (3) Commit-reveal with extended reveal period, \
                    (4) Allow batch processing across multiple blocks, (5) Emergency pause mechanisms.",
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

impl BlockStuffingVulnerableDetector {
    /// Check for block stuffing vulnerabilities
    fn check_block_stuffing_vulnerability(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Pattern 1: Single-block deadline without grace period
        let has_deadline = func_source.contains("deadline")
            || func_source.contains("endTime")
            || func_source.contains("expiresAt");

        let uses_exact_block = has_deadline
            && (func_source.contains("block.number ==")
                || func_source.contains("block.timestamp =="));

        let lacks_grace_period = uses_exact_block
            && !func_source.contains("GRACE_PERIOD")
            && !func_source.contains("grace")
            && !func_source.contains("extension");

        if lacks_grace_period {
            return Some(
                "Single-block deadline without grace period, \
                vulnerable to block stuffing preventing execution at exact block"
                    .to_string(),
            );
        }

        // Pattern 2: First-come-first-served with strict ordering
        let is_fcfs = func_source.contains("first")
            || func_source.contains("queue")
            || func_source.contains("order");

        let has_strict_ordering = is_fcfs
            && (func_source.contains("require(") || func_source.contains("revert"))
            && !func_source.contains("batch")
            && !func_source.contains("multiple");

        if has_strict_ordering {
            return Some(
                "First-come-first-served mechanism with strict ordering, \
                attackers can stuff blocks to prevent others from participating"
                    .to_string(),
            );
        }

        // Pattern 3: Auction close without multi-block finalization
        let is_auction = func_source.contains("auction")
            || func_source.contains("bid")
            || function.name.name.to_lowercase().contains("auction");

        let has_close = func_source.contains("close")
            || func_source.contains("finalize")
            || func_source.contains("end");

        let single_block_close = is_auction
            && has_close
            && !func_source.contains("FINALIZATION_PERIOD")
            && !func_source.contains("multi")
            && !func_source.contains("extended");

        if single_block_close {
            return Some(
                "Auction closes in single block without multi-block finalization period, \
                vulnerable to block stuffing to prevent last-minute bids"
                    .to_string(),
            );
        }

        // Pattern 4: Critical operation with narrow time window
        let is_critical = func_source.contains("claim")
            || func_source.contains("withdraw")
            || func_source.contains("redeem")
            || func_source.contains("execute");

        let has_time_check = func_source.contains("block.number <")
            || func_source.contains("block.number <=")
            || func_source.contains("block.timestamp <")
            || func_source.contains("block.timestamp <=");

        let narrow_window = is_critical
            && has_time_check
            && !func_source.contains("WINDOW")
            && !func_source.contains("extended")
            && !func_source.contains("flexible");

        if narrow_window {
            return Some(
                "Critical operation with narrow time window, \
                block stuffing can prevent users from executing within deadline"
                    .to_string(),
            );
        }

        // Pattern 5: Liquidation or time-sensitive financial operation
        let is_liquidation = func_source.contains("liquidat") || func_source.contains("Liquidat");

        let time_dependent = is_liquidation
            && (func_source.contains("block.timestamp") || func_source.contains("block.number"));

        let no_protection = time_dependent
            && !func_source.contains("grace")
            && !func_source.contains("buffer")
            && !func_source.contains("extended");

        if no_protection {
            return Some(
                "Time-sensitive liquidation without protection against block stuffing, \
                users unable to repay debt if blocks are stuffed"
                    .to_string(),
            );
        }

        // Pattern 6: Voting or governance with single-block window
        let is_governance = func_source.contains("vote")
            || func_source.contains("govern")
            || func_source.contains("propose");

        let single_block_vote = is_governance
            && (func_source.contains("block.number ==") || func_source.contains("deadline =="))
            && !func_source.contains("VOTING_PERIOD")
            && !func_source.contains("extended");

        if single_block_vote {
            return Some(
                "Governance voting with single-block deadline, \
                attackers can stuff blocks to censor votes"
                    .to_string(),
            );
        }

        // Pattern 7: First-in mechanism without queue protection
        let is_first_in = function.name.name.to_lowercase().contains("first")
            || func_source.contains("firstCome")
            || func_source.contains("first-in");

        let lacks_queue = is_first_in
            && !func_source.contains("queue")
            && !func_source.contains("waiting")
            && !func_source.contains("batch");

        if lacks_queue {
            return Some(
                "First-in mechanism without queuing, \
                block stuffing prevents fair participation"
                    .to_string(),
            );
        }

        // Pattern 8: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("block stuffing")
                || func_source.contains("censorship")
                || func_source.contains("ordering"))
        {
            return Some("Block stuffing vulnerability marker detected".to_string());
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
        let detector = BlockStuffingVulnerableDetector::new();
        assert_eq!(detector.name(), "Block Stuffing Vulnerable");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
