use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for weak or predictable randomness sources
pub struct InsufficientRandomnessDetector {
    base: BaseDetector,
}

impl InsufficientRandomnessDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("insufficient-randomness".to_string()),
                "Insufficient Randomness".to_string(),
                "Detects use of weak or manipulable randomness sources like block.timestamp or blockhash".to_string(),
                vec![DetectorCategory::Validation],
                Severity::High,
            ),
        }
    }
}

impl Detector for InsufficientRandomnessDetector {
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
            if let Some(randomness_issue) = self.check_weak_randomness(function, ctx) {
                let message = format!(
                    "Function '{}' uses weak randomness source. {} \
                    Predictable randomness enables attackers to manipulate outcomes in lotteries, games, or selection processes.",
                    function.name.name, randomness_issue
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
                    .with_cwe(338) // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
                    .with_cwe(330) // CWE-330: Use of Insufficiently Random Values
                    .with_fix_suggestion(format!(
                        "Use secure randomness in '{}'. \
                    Implement: (1) Chainlink VRF for verifiable randomness, \
                    (2) Commit-reveal scheme with multi-block delay, \
                    (3) External oracle for random number generation, \
                    (4) Avoid block.timestamp, blockhash, or block.number, \
                    (5) Use Randao for Ethereum 2.0.",
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

impl InsufficientRandomnessDetector {
    fn check_weak_randomness(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check for secure randomness first
        let has_secure_randomness = func_source.contains("VRFConsumer")
            || func_source.contains("requestRandomness")
            || func_source.contains("fulfillRandomness")
            || func_source.contains("Chainlink")
            || func_source.contains("VRFCoordinator");

        if has_secure_randomness {
            return None; // Using secure randomness, no issue
        }

        // Pattern 1: block.timestamp for randomness
        if func_source.contains("block.timestamp")
            && (func_source.contains("random")
                || func_source.contains("lottery")
                || func_source.contains("keccak256"))
        {
            return Some(format!(
                "Uses block.timestamp for randomness generation. \
                Miners can manipulate timestamp within ~15 second range to influence outcome"
            ));
        }

        // Pattern 2: blockhash for randomness
        if func_source.contains("blockhash")
            && (func_source.contains("random")
                || func_source.contains("lottery")
                || func_source.contains("keccak256"))
        {
            return Some(format!(
                "Uses blockhash for randomness. \
                Only last 256 blocks accessible, miners can influence, not available for future blocks"
            ));
        }

        // Pattern 3: block.number for randomness
        if func_source.contains("block.number")
            && (func_source.contains("random")
                || func_source.contains("lottery")
                || func_source.contains("%")
                || func_source.contains("mod"))
        {
            return Some(format!(
                "Uses block.number for randomness. \
                Completely predictable, miners control block production timing"
            ));
        }

        // Pattern 4: msg.sender or tx.origin in randomness
        if (func_source.contains("msg.sender") || func_source.contains("tx.origin"))
            && func_source.contains("keccak256")
            && func_source.contains("abi.encodePacked")
        {
            let has_only_user_data = !func_source.contains("nonce")
                && !func_source.contains("secret")
                && !func_source.contains("commitment");

            if has_only_user_data {
                return Some(format!(
                    "Uses user address in randomness without commitment scheme. \
                    Users can predict outcomes and selectively participate"
                ));
            }
        }

        // Pattern 5: block.difficulty (deprecated in post-merge Ethereum)
        if func_source.contains("block.difficulty")
            && (func_source.contains("random") || func_source.contains("keccak256"))
        {
            return Some(format!(
                "Uses block.difficulty for randomness (deprecated post-merge). \
                Now always returns 0, previously manipulable by miners"
            ));
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
        let detector = InsufficientRandomnessDetector::new();
        assert_eq!(detector.name(), "Insufficient Randomness");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
