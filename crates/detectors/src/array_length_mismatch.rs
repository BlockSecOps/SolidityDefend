use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for array length mismatch vulnerability
///
/// Detects functions that accept multiple arrays but don't validate they have the same length.
/// This can cause out-of-bounds access, incorrect calculations, or silent failures.
pub struct ArrayLengthMismatchDetector {
    base: BaseDetector,
}

impl Default for ArrayLengthMismatchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ArrayLengthMismatchDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("array-length-mismatch".to_string()),
                "Array Length Mismatch".to_string(),
                "Detects functions accepting multiple arrays without validating equal lengths"
                    .to_string(),
                vec![DetectorCategory::Validation, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    /// Check if function has array length mismatch vulnerability
    fn check_array_length_mismatch(&self, function_source: &str) -> bool {
        // Must accept multiple array parameters
        let array_params: Vec<&str> = function_source
            .lines()
            .filter(|line| {
                (line.contains("[] memory") || line.contains("[] calldata"))
                    && !line.trim().starts_with("//")
            })
            .collect();

        // Need at least 2 array parameters
        if array_params.len() < 2 {
            return false;
        }

        // Check if there's a loop that uses array indices
        let has_loop_with_index = function_source.contains("for (")
            && function_source.contains("[i]")
            && (function_source.contains(".length") || function_source.contains("< "));

        if !has_loop_with_index {
            return false;
        }

        // Check for length validation
        let has_length_check = function_source.contains(".length ==")
            || function_source.contains(".length !=")
            || function_source.contains("require") && function_source.contains("length");

        // Vulnerable if:
        // - Has multiple array parameters AND
        // - Uses arrays in a loop with indices AND
        // - No length equality validation
        !has_length_check
    }
}

impl Detector for ArrayLengthMismatchDetector {
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

        // Check all functions
        for function in ctx.get_functions() {
            if function.body.is_none() {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            if self.check_array_length_mismatch(&func_source) {
                let message = format!(
                    "Function '{}' accepts multiple arrays but doesn't validate they have equal lengths. \
                    This can cause out-of-bounds access if one array is shorter, \
                    leading to reverts, incorrect data processing, or exploitable behavior.",
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
                    .with_cwe(20) // CWE-20: Improper Input Validation
                    .with_cwe(129) // CWE-129: Improper Validation of Array Index
                    .with_fix_suggestion(format!(
                        "Add array length validation to '{}'. \
                        At function start, add: require(array1.length == array2.length, \"Array length mismatch\"); \
                        For multiple arrays: require(arr1.length == arr2.length && arr2.length == arr3.length, \"Length mismatch\"); \
                        This prevents out-of-bounds access and ensures consistent data processing.",
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

impl ArrayLengthMismatchDetector {
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
        let detector = ArrayLengthMismatchDetector::new();
        assert_eq!(detector.name(), "Array Length Mismatch");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
