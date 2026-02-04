use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for weak or predictable randomness sources
pub struct InsufficientRandomnessDetector {
    base: BaseDetector,
}

impl Default for InsufficientRandomnessDetector {
    fn default() -> Self {
        Self::new()
    }
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

        // Phase 52 FP Reduction: Skip interface-only contracts
        if utils::is_interface_only(ctx) {
            return Ok(findings);
        }

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
                    .with_swc("SWC-120") // SWC-120: Weak Sources of Randomness from Chain Attributes
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
    /// Phase 52 FP Reduction: Check if timestamp is used for deadline/expiry (not randomness)
    fn is_deadline_usage(&self, func_source: &str, function: &ast::Function<'_>) -> bool {
        // Check if function has deadline/expiry parameter
        let has_deadline_param = function.parameters.iter().any(|p| {
            if let Some(name) = &p.name {
                let lower = name.name.to_lowercase();
                lower.contains("expiry")
                    || lower.contains("deadline")
                    || lower.contains("validuntil")
                    || lower.contains("expires")
                    || lower.contains("timeout")
            } else {
                false
            }
        });

        if has_deadline_param {
            return true;
        }

        // Check for deadline variable patterns in source
        let has_deadline_var = func_source.contains("expiry")
            || func_source.contains("deadline")
            || func_source.contains("validUntil")
            || func_source.contains("expires");

        // Check if timestamp is only used in comparisons (deadline check), not arithmetic
        let is_comparison_only = (func_source.contains("block.timestamp <=")
            || func_source.contains("block.timestamp >=")
            || func_source.contains("block.timestamp <")
            || func_source.contains("block.timestamp >")
            || func_source.contains("<= block.timestamp")
            || func_source.contains(">= block.timestamp")
            || func_source.contains("< block.timestamp")
            || func_source.contains("> block.timestamp"))
            && !func_source.contains("block.timestamp +")
            && !func_source.contains("block.timestamp -")
            && !func_source.contains("block.timestamp *")
            && !func_source.contains("block.timestamp %");

        has_deadline_var && is_comparison_only
    }

    fn check_weak_randomness(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

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

        // Phase 52 FP Reduction: Skip deadline/expiry checks
        // Functions like delegateBySig use timestamp for expiry validation, not randomness
        if self.is_deadline_usage(&func_source, function) {
            return None;
        }

        // Pattern 1: block.timestamp for randomness
        // Phase 52: Only flag if actually used for randomness (not just present with keccak256)
        let uses_timestamp_for_randomness = func_source.contains("block.timestamp")
            && (func_source.contains("random")
                || func_source.contains("lottery")
                // Only flag keccak256 if timestamp is part of randomness generation
                || (func_source.contains("keccak256")
                    && (func_source.contains("block.timestamp +")
                        || func_source.contains("block.timestamp,")
                        || func_source.contains("abi.encodePacked") && func_source.contains("block.timestamp"))));

        // Exclude deadline patterns even if keccak256 is present (e.g., signature validation)
        if uses_timestamp_for_randomness
            && !func_source.contains("expiry")
            && !func_source.contains("deadline")
            && !func_source.contains("validUntil")
        {
            return Some(
                "Uses block.timestamp for randomness generation. \
                Miners can manipulate timestamp within ~15 second range to influence outcome"
                    .to_string(),
            );
        }

        // Pattern 2: blockhash for randomness
        if func_source.contains("blockhash")
            && (func_source.contains("random")
                || func_source.contains("lottery")
                || func_source.contains("keccak256"))
        {
            return Some("Uses blockhash for randomness. \
                Only last 256 blocks accessible, miners can influence, not available for future blocks".to_string());
        }

        // Pattern 3: block.number for randomness
        if func_source.contains("block.number")
            && (func_source.contains("random")
                || func_source.contains("lottery")
                || func_source.contains("%")
                || func_source.contains("mod"))
        {
            return Some(
                "Uses block.number for randomness. \
                Completely predictable, miners control block production timing"
                    .to_string(),
            );
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
                return Some(
                    "Uses user address in randomness without commitment scheme. \
                    Users can predict outcomes and selectively participate"
                        .to_string(),
                );
            }
        }

        // Pattern 5: block.difficulty (deprecated in post-merge Ethereum)
        if func_source.contains("block.difficulty")
            && (func_source.contains("random") || func_source.contains("keccak256"))
        {
            return Some(
                "Uses block.difficulty for randomness (deprecated post-merge). \
                Now always returns 0, previously manipulable by miners"
                    .to_string(),
            );
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
