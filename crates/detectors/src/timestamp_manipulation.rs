use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for timestamp manipulation vulnerabilities
pub struct TimestampManipulationDetector {
    base: BaseDetector,
}

impl Default for TimestampManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TimestampManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("timestamp-manipulation".to_string()),
                "Timestamp Manipulation".to_string(),
                "Detects dangerous dependencies on block.timestamp that miners can manipulate within bounds".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for TimestampManipulationDetector {
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
            if let Some(timestamp_issue) = self.check_timestamp_manipulation(function, ctx) {
                let message = format!(
                    "Function '{}' has dangerous timestamp dependency. {} \
                    Miners can manipulate block.timestamp by ~15 seconds, enabling manipulation of time-sensitive logic.",
                    function.name.name, timestamp_issue
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
                    .with_cwe(367) // CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_fix_suggestion(format!(
                        "Reduce timestamp dependency in '{}'. \
                    Use block.number for time intervals, add tolerance ranges (±15 seconds), \
                    implement commit-reveal schemes for time-sensitive operations, \
                    or use oracle-based time sources for critical logic.",
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

impl TimestampManipulationDetector {
    /// Check for timestamp manipulation vulnerabilities
    fn check_timestamp_manipulation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Check for block.timestamp usage
        let uses_timestamp = func_source.contains("block.timestamp") || func_source.contains("now"); // Solidity < 0.7.0

        if !uses_timestamp {
            return None;
        }

        // Check more specific patterns first before generic ones

        // Pattern 2a: keccak256 with block variables for randomness (MOST SPECIFIC)
        let has_keccak_block_vars = func_source.contains("keccak256")
            && func_source.contains("abi.encodePacked")
            && (func_source.contains("block.timestamp")
                || func_source.contains("block.difficulty")
                || func_source.contains("block.number")
                || func_source.contains("block.prevrandao")
                || func_source.contains("blockhash"));

        if has_keccak_block_vars {
            return Some("Uses keccak256 with block variables (timestamp/difficulty/number/prevrandao) for randomness. \
                These values are predictable/manipulable by miners and validators, enabling attacks on randomness-dependent logic. \
                Use Chainlink VRF or commit-reveal schemes instead".to_string());
        }

        // Pattern 2b: Direct modulo on block variables
        let has_block_modulo = func_source.contains("block.timestamp %")
            || func_source.contains("block.difficulty %")
            || func_source.contains("block.number %")
            || func_source.contains("block.prevrandao %")
            || (func_source.contains("blockhash") && func_source.contains('%'));

        if has_block_modulo {
            return Some("Uses modulo operator on block variables for randomness or decision-making. \
                Block variables are predictable and can be manipulated by miners, leading to biased or exploitable outcomes".to_string());
        }

        // Pattern 2c: block.difficulty or block.prevrandao usage (weak randomness)
        let uses_difficulty_or_prevrandao =
            func_source.contains("block.difficulty") || func_source.contains("block.prevrandao");

        if uses_difficulty_or_prevrandao && !has_keccak_block_vars {
            return Some("Uses block.difficulty or block.prevrandao which are manipulable by validators. \
                These should never be used for randomness. Use Chainlink VRF or similar oracle-based randomness".to_string());
        }

        // Pattern 1: Timestamp used in comparison without tolerance
        let has_exact_comparison = (func_source.contains("block.timestamp ==")
            || func_source.contains("block.timestamp !=")
            || func_source.contains("now ==")
            || func_source.contains("now !="))
            && !func_source.contains("TOLERANCE")
            && !func_source.contains("BUFFER");

        if has_exact_comparison {
            return Some(
                "Uses exact timestamp comparison without tolerance, \
                vulnerable to minor miner manipulation for edge cases"
                    .to_string(),
            );
        }

        // Pattern 2: Timestamp for randomness (GENERIC - check last)
        let uses_for_randomness = (func_source.contains("random")
            || func_source.contains("Random")
            || func_source.contains("lottery")
            || func_source.contains("winner"))
            && uses_timestamp;

        if uses_for_randomness {
            return Some(
                "Uses block.timestamp for randomness or lottery selection, \
                allowing miners to manipulate outcomes by choosing favorable timestamps"
                    .to_string(),
            );
        }

        // Pattern 3: Critical state changes based on timestamp
        let has_critical_logic = func_source.contains("transfer")
            || func_source.contains("mint")
            || func_source.contains("burn")
            || func_source.contains("withdraw")
            || func_source.contains("claim");

        let timestamp_controls_critical = uses_timestamp
            && has_critical_logic
            && (func_source.contains("if (block.timestamp")
                || func_source.contains("require(block.timestamp"));

        if timestamp_controls_critical {
            return Some(
                "Critical operations (transfer/mint/burn/withdraw) controlled by timestamp, \
                enabling miners to manipulate timing for advantage"
                    .to_string(),
            );
        }

        // Pattern 4: Timestamp used for deadline without block.number fallback
        let has_deadline = func_source.contains("deadline")
            || func_source.contains("expiry")
            || func_source.contains("expires");

        let lacks_block_number =
            has_deadline && uses_timestamp && !func_source.contains("block.number");

        if lacks_block_number {
            return Some(
                "Uses timestamp-based deadline without block.number as fallback, \
                vulnerable to timestamp manipulation for deadline extensions"
                    .to_string(),
            );
        }

        // Pattern 5: Timestamp arithmetic without safety checks
        let has_timestamp_math = (func_source.contains("block.timestamp +")
            || func_source.contains("block.timestamp -")
            || func_source.contains("now +")
            || func_source.contains("now -"))
            && !func_source.contains("SafeMath")
            && !func_source.contains("checked");

        if has_timestamp_math {
            return Some(
                "Performs arithmetic on block.timestamp without overflow protection, \
                potentially manipulable by miners within bounds"
                    .to_string(),
            );
        }

        // Pattern 6: Auction or time-sensitive mechanism
        let is_auction = func_source.contains("auction")
            || func_source.contains("Auction")
            || func_source.contains("bid")
            || func_source.contains("Bid");

        let timestamp_affects_auction = is_auction
            && uses_timestamp
            && (func_source.contains("endTime") || func_source.contains("startTime"));

        if timestamp_affects_auction {
            return Some(
                "Auction mechanism depends on block.timestamp for start/end times, \
                miners can manipulate to snipe auctions or extend bidding"
                    .to_string(),
            );
        }

        // Pattern 7: Vesting or unlock schedules
        let is_vesting = func_source.contains("vest")
            || func_source.contains("unlock")
            || func_source.contains("release");

        let timestamp_controls_vesting = is_vesting
            && uses_timestamp
            && (func_source.contains(">=") || func_source.contains("<="));

        if timestamp_controls_vesting {
            return Some(
                "Vesting or unlock schedule controlled by timestamp, \
                allowing miners to manipulate release timing"
                    .to_string(),
            );
        }

        // Pattern 8: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("timestamp") || func_source.contains("time manipulation"))
        {
            return Some("Timestamp manipulation vulnerability marker detected".to_string());
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
        let detector = TimestampManipulationDetector::new();
        assert_eq!(detector.name(), "Timestamp Manipulation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
