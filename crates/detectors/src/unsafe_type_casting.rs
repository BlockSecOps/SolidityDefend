use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for unsafe type casting that can lead to data loss
pub struct UnsafeTypeCastingDetector {
    base: BaseDetector,
}

impl UnsafeTypeCastingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("unsafe-type-casting".to_string()),
                "Unsafe Type Casting".to_string(),
                "Detects unsafe type conversions that can lead to data loss, truncation, or unexpected behavior".to_string(),
                vec![DetectorCategory::Validation],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for UnsafeTypeCastingDetector {
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
            if let Some(casting_issues) = self.check_unsafe_casting(function, ctx) {
                for (line_offset, issue_desc) in casting_issues {
                    let message = format!(
                        "Function '{}' contains unsafe type casting. {} \
                        Unsafe type conversions can lead to data loss, value truncation, or unexpected behavior.",
                        function.name.name,
                        issue_desc
                    );

                    let finding = self.base.create_finding(
                        ctx,
                        message,
                        (function.name.location.start().line() + line_offset) as u32,
                        0,
                        20,
                    )
                    .with_cwe(704) // CWE-704: Incorrect Type Conversion or Cast
                    .with_cwe(197) // CWE-197: Numeric Truncation Error
                    .with_fix_suggestion(format!(
                        "Add safe type casting in '{}'. \
                        Implement: (1) Validate value ranges before casting, \
                        (2) Use require() to check bounds, \
                        (3) Use SafeCast library from OpenZeppelin, \
                        (4) Avoid downcasting without validation, \
                        (5) Check for sign preservation in int/uint conversions.",
                        function.name.name
                    ));

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UnsafeTypeCastingDetector {
    fn check_unsafe_casting(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<Vec<(usize, String)>> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let lines: Vec<&str> = func_source.lines().collect();
        let mut issues = Vec::new();

        for (line_idx, line) in lines.iter().enumerate() {
            // Pattern 1: Downcasting (larger type to smaller type)
            if self.is_downcast(line) {
                let has_validation = self.has_range_check(&lines, line_idx);

                if !has_validation {
                    issues.push((
                        line_idx,
                        format!("Unsafe downcast detected without range validation. Value may exceed target type capacity")
                    ));
                }
            }

            // Pattern 2: int to uint conversion (sign loss)
            if self.is_int_to_uint(line) {
                let has_sign_check = self.has_sign_check(&lines, line_idx);

                if !has_sign_check {
                    issues.push((
                        line_idx,
                        format!("int to uint conversion without sign check. Negative values will wrap to large positive")
                    ));
                }
            }

            // Pattern 3: uint to int conversion (overflow risk)
            if self.is_uint_to_int(line) {
                let has_overflow_check = self.has_range_check(&lines, line_idx);

                if !has_overflow_check {
                    issues.push((
                        line_idx,
                        format!("uint to int conversion without overflow check. Large values may become negative")
                    ));
                }
            }

            // Pattern 4: address conversions without validation
            if self.is_address_cast(line) {
                let has_validation = line.contains("!= address(0)") ||
                                    line.contains("require") ||
                                    self.has_address_validation(&lines, line_idx);

                if !has_validation {
                    issues.push((
                        line_idx,
                        format!("address type casting without validation. May result in zero address")
                    ));
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn is_downcast(&self, line: &str) -> bool {
        // uint256 -> uint8/uint16/uint32/uint64/uint128
        let downcast_patterns = [
            "uint8(", "uint16(", "uint32(", "uint64(", "uint128(",
        ];

        for pattern in &downcast_patterns {
            if line.contains(pattern) && line.contains("uint256") {
                return true;
            }
        }
        false
    }

    fn is_int_to_uint(&self, line: &str) -> bool {
        line.contains("uint(") && line.contains("int") ||
        line.contains("uint256(") && line.contains("int256") ||
        line.contains("uint128(") && line.contains("int128")
    }

    fn is_uint_to_int(&self, line: &str) -> bool {
        line.contains("int(") && line.contains("uint") ||
        line.contains("int256(") && line.contains("uint256") ||
        line.contains("int128(") && line.contains("uint128")
    }

    fn is_address_cast(&self, line: &str) -> bool {
        line.contains("address(uint160(") ||
        line.contains("address(bytes20(") ||
        (line.contains("address(") && line.contains("uint"))
    }

    fn has_range_check(&self, lines: &[&str], current_line: usize) -> bool {
        // Check few lines before for require() with range check
        let start = if current_line >= 3 { current_line - 3 } else { 0 };

        for i in start..current_line {
            if lines[i].contains("require") &&
               (lines[i].contains("<=") || lines[i].contains("<") ||
                lines[i].contains("type(") || lines[i].contains("max")) {
                return true;
            }
        }
        false
    }

    fn has_sign_check(&self, lines: &[&str], current_line: usize) -> bool {
        // Check few lines before for require() with sign check
        let start = if current_line >= 3 { current_line - 3 } else { 0 };

        for i in start..current_line {
            if lines[i].contains("require") &&
               (lines[i].contains(">= 0") || lines[i].contains("> -1")) {
                return true;
            }
        }
        false
    }

    fn has_address_validation(&self, lines: &[&str], current_line: usize) -> bool {
        // Check few lines before for address validation
        let start = if current_line >= 3 { current_line - 3 } else { 0 };

        for i in start..current_line {
            if lines[i].contains("require") &&
               (lines[i].contains("!= address(0)") || lines[i].contains("!= 0")) {
                return true;
            }
        }
        false
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
        let detector = UnsafeTypeCastingDetector::new();
        assert_eq!(detector.name(), "Unsafe Type Casting");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
