use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for batch transfer overflow vulnerability
///
/// Detects the pattern where array.length * value can overflow, bypassing balance checks.
/// This was exploited in the BeautyChain (BEC) token hack.
pub struct BatchTransferOverflowDetector {
    base: BaseDetector,
}

impl Default for BatchTransferOverflowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchTransferOverflowDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("batch-transfer-overflow".to_string()),
                "Batch Transfer Overflow".to_string(),
                "Detects multiplication of array length with value that can overflow in batch transfers".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::Critical,
            ),
        }
    }

    /// Check if function has batch transfer overflow vulnerability
    fn check_batch_transfer_overflow(&self, function_source: &str, function_name: &str) -> bool {
        // Must be a batch/multi transfer function
        let is_batch_function = function_name.to_lowercase().contains("batch")
            || function_name.to_lowercase().contains("multi")
            || function_name.to_lowercase().contains("group");

        if !is_batch_function {
            // Also check source for batch patterns
            if !(function_source.contains("[] memory") || function_source.contains("[] calldata")) {
                return false;
            }
        }

        // Pattern 1: array.length * value (direct overflow risk)
        let has_length_multiplication = (function_source.contains(".length *")
            || function_source.contains("* _value")
            || function_source.contains("* value"))
            && function_source.contains(".length");

        // Pattern 2: Intermediate variable multiplying count with value
        let has_count_value_mult = function_source.contains("count =")
            && function_source.contains(".length")
            && (function_source.contains("count *") || function_source.contains("* count"));

        // Pattern 3: Using unchecked block with multiplication (bypasses Solidity 0.8+ overflow protection)
        let unchecked_multiplication = function_source.contains("unchecked")
            && function_source.contains('*')
            && function_source.contains(".length");

        // Check if using safe math or checked arithmetic
        let has_safe_math = function_source.contains("SafeMath")
            || function_source.contains("checked_mul")
            || function_source.contains(".mul(");

        // Check Solidity version hint
        let likely_old_solidity = function_source.contains("pragma solidity")
            && (function_source.contains("0.4")
                || function_source.contains("0.5")
                || function_source.contains("0.6")
                || function_source.contains("0.7"));

        // Vulnerable if:
        // - Has length*value multiplication AND no safe math
        // - OR unchecked multiplication with array length
        // - OR old Solidity version (< 0.8.0) without SafeMath
        (has_length_multiplication || has_count_value_mult)
            && !has_safe_math
            && (unchecked_multiplication
                || likely_old_solidity
                || !function_source.contains("checked"))
    }
}

impl Detector for BatchTransferOverflowDetector {
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

        // Get source to check Solidity version
        let source = &ctx.source_code;

        // Check all functions
        for function in ctx.get_functions() {
            if function.body.is_none() {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            // Combine function source with contract source for version check
            let combined_source = format!("{}\n{}", source, func_source);

            if self.check_batch_transfer_overflow(&combined_source, function.name.name) {
                let message = format!(
                    "Function '{}' has batch transfer overflow vulnerability. \
                    Multiplication of array length with value (count * value) can overflow in Solidity <0.8.0 or in unchecked blocks, \
                    bypassing balance checks and allowing unlimited token minting. \
                    This was exploited in the BeautyChain (BEC) token hack causing $1B in damage.",
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
                    .with_cwe(190) // CWE-190: Integer Overflow
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_fix_suggestion(format!(
                        "Fix batch transfer overflow in '{}'. \
                        Options: (1) Use Solidity 0.8.0+ with checked arithmetic, \
                        (2) Use SafeMath library for multiplication, \
                        (3) Check each transfer individually: for each receiver require(balance >= value), \
                        (4) Validate count * value >= count && count * value >= value before use.",
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

impl BatchTransferOverflowDetector {
    /// Extract function source code from context
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
        let detector = BatchTransferOverflowDetector::new();
        assert_eq!(detector.name(), "Batch Transfer Overflow");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
