use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for auction timing manipulation vulnerabilities
pub struct AuctionTimingDetector {
    base: BaseDetector,
}

impl Default for AuctionTimingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AuctionTimingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("auction-timing-manipulation".to_string()),
                "Auction Timing Manipulation".to_string(),
                "Detects auction mechanisms with predictable timing, enabling MEV bot front-running".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Detector for AuctionTimingDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        for function in ctx.get_functions() {
            if self.has_auction_timing_vulnerability(function, ctx) {
                let message = format!(
                    "Function '{}' allows auction creation with predictable timing and \
                    unrestricted access. MEV bots can monitor the mempool, front-run the \
                    auction start, and prepare optimal bids before other participants.",
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
                    .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Add access control to auction start in function '{}' and implement \
                    unpredictable timing using commit-reveal or VRF. Example: \
                    modifier onlyAuctioneer() or use block hash for randomized start time.",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl AuctionTimingDetector {
    /// Check if function has auction timing vulnerability
    fn has_auction_timing_vulnerability(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Check if this is an auction-related function
        let function_name = function.name.name.to_lowercase();
        let auction_patterns = [
            "auction",
            "batch",
            "startauction",
            "createauction",
            "initiateauction",
            "beginauction",
        ];

        let is_auction_function = auction_patterns
            .iter()
            .any(|pattern| function_name.contains(pattern));

        if !is_auction_function {
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

        // Check if it's creating/starting an auction
        let creates_auction = func_source.contains("startTime")
            || func_source.contains("endTime")
            || func_source.contains("auctionId")
            || func_source.contains("batchId");

        if !creates_auction {
            return false;
        }

        // Look for vulnerability patterns
        self.check_timing_protection(&func_source, function)
    }

    /// Check if function lacks proper timing protection
    fn check_timing_protection(&self, source: &str, function: &ast::Function<'_>) -> bool {
        // Pattern 1: Explicit vulnerability comment
        let has_vulnerability_marker = source.contains("VULNERABILITY")
            && (source.contains("Anyone can start")
                || source.contains("Predictable timing")
                || source.contains("timing manipulation"));

        // Pattern 2: Uses block.timestamp for timing without randomization
        let uses_block_timestamp = source.contains("block.timestamp");

        // Pattern 3: Missing access control
        let has_access_control = source.contains("onlyOwner")
            || source.contains("onlyAuctioneer")
            || source.contains("require(msg.sender")
            || source.contains("onlyRole");

        // Pattern 4: Missing randomization mechanisms
        let has_randomization = source.contains("random")
            || source.contains("VRF")
            || source.contains("blockhash")
            || source.contains("commit")
            || source.contains("reveal");

        // Check function visibility - public/external without modifiers is vulnerable
        let is_unrestricted = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        // Vulnerable if has explicit marker
        if has_vulnerability_marker {
            return true;
        }

        // Vulnerable if unrestricted + predictable timing
        if is_unrestricted && uses_block_timestamp && !has_access_control && !has_randomization {
            return true;
        }

        // Vulnerable if creates auction without any protection
        if uses_block_timestamp
            && !has_access_control
            && !has_randomization
            && (source.contains("auction.startTime =")
                || source.contains("startTime = block.timestamp"))
        {
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
        let detector = AuctionTimingDetector::new();
        assert_eq!(detector.name(), "Auction Timing Manipulation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
