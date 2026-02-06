use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::is_test_contract;

/// Detector for unsafe type casting that can lead to data loss
pub struct UnsafeTypeCastingDetector {
    base: BaseDetector,
}

impl Default for UnsafeTypeCastingDetector {
    fn default() -> Self {
        Self::new()
    }
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

        // Phase 9 FP Reduction: Skip test contracts
        if is_test_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // Phase 9 FP Reduction: Skip internal pure/view functions (less critical)
            if function.visibility == ast::Visibility::Internal
                && (function.mutability == ast::StateMutability::Pure
                    || function.mutability == ast::StateMutability::View)
            {
                continue;
            }

            if let Some(casting_issues) = self.check_unsafe_casting(function, ctx) {
                for (line_offset, issue_desc) in casting_issues {
                    let message = format!(
                        "Function '{}' contains unsafe type casting. {} \
                        Unsafe type conversions can lead to data loss, value truncation, or unexpected behavior.",
                        function.name.name, issue_desc
                    );

                    let finding = self
                        .base
                        .create_finding(
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
    /// Check if a line is within an unchecked block
    /// Unchecked blocks explicitly indicate developer awareness of overflow behavior
    fn is_in_unchecked_block(&self, lines: &[&str], current_line: usize) -> bool {
        let mut depth = 0;
        let mut in_unchecked = false;

        // Scan backwards to find if we're inside an unchecked block
        for i in (0..=current_line).rev() {
            let line = lines[i].trim();

            // Count braces to track depth
            for c in line.chars().rev() {
                match c {
                    '}' => depth += 1,
                    '{' => {
                        if depth > 0 {
                            depth -= 1;
                        } else if line.contains("unchecked") {
                            return true;
                        }
                    }
                    _ => {}
                }
            }

            // Found unchecked keyword
            if line.contains("unchecked") && line.contains("{") {
                in_unchecked = true;
            }
        }

        in_unchecked
    }

    /// Check if this is a safe literal cast (e.g., uint8(18), uint8(6))
    /// Literal values are always safe as they're known at compile time
    fn is_safe_literal_cast(&self, line: &str) -> bool {
        // Match patterns like uint8(18), uint16(255), int8(-1)
        // These are safe because literals are validated at compile time
        let patterns = [
            "uint8(", "uint16(", "uint32(", "uint64(", "uint128(", "int8(", "int16(", "int32(",
            "int64(", "int128(",
        ];

        for pattern in &patterns {
            if let Some(start) = line.find(pattern) {
                let after = &line[start + pattern.len()..];
                // Check if followed by a numeric literal (optionally negative)
                let trimmed = after.trim_start_matches('-').trim_start();
                if trimmed
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                {
                    // Check it's a pure number followed by )
                    if let Some(end) = trimmed.find(')') {
                        let num_part = &trimmed[..end];
                        if num_part.chars().all(|c| c.is_ascii_digit() || c == '_') {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if function uses SafeCast library (OpenZeppelin)
    /// SafeCast is audited and handles overflow/underflow safely
    fn uses_safe_cast(&self, func_source: &str) -> bool {
        func_source.contains("SafeCast.")
            || func_source.contains(".toUint8(")
            || func_source.contains(".toUint16(")
            || func_source.contains(".toUint32(")
            || func_source.contains(".toUint64(")
            || func_source.contains(".toUint128(")
            || func_source.contains(".toUint256(")
            || func_source.contains(".toInt8(")
            || func_source.contains(".toInt16(")
            || func_source.contains(".toInt32(")
            || func_source.contains(".toInt64(")
            || func_source.contains(".toInt128(")
            || func_source.contains(".toInt256(")
    }

    fn check_unsafe_casting(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<Vec<(usize, String)>> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Skip if function uses SafeCast library - it handles safety
        if self.uses_safe_cast(&func_source) {
            return None;
        }

        let lines: Vec<&str> = func_source.lines().collect();
        let mut issues = Vec::new();

        for (line_idx, line) in lines.iter().enumerate() {
            // Skip safe literal casts (e.g., uint8(18))
            if self.is_safe_literal_cast(line) {
                continue;
            }

            // Phase 9 FP Reduction: Skip casts inside unchecked blocks
            // Developers using unchecked are aware of overflow behavior
            if self.is_in_unchecked_block(&lines, line_idx) {
                continue;
            }

            // Phase 54 FP Reduction: Skip assembly blocks with explicit size validation
            if self.is_in_assembly_with_validation(&lines, line_idx) {
                continue;
            }

            // Phase 54 FP Reduction: Skip Chainlink latestRoundData pattern
            if self.is_chainlink_round_data_pattern(line, &lines, line_idx) {
                continue;
            }

            // Phase 54 FP Reduction: Skip enum casts (compiler validates)
            if self.is_enum_cast(line, ctx) {
                continue;
            }

            // Pattern 1: Downcasting (larger type to smaller type)
            if self.is_downcast(line) {
                let has_validation = self.has_range_check(&lines, line_idx);
                let has_type_max_check = self.has_type_max_check(&lines, line_idx);

                if !has_validation && !has_type_max_check {
                    issues.push((
                        line_idx,
                        "Unsafe downcast detected without range validation. Value may exceed target type capacity".to_string()
                    ));
                }
            }

            // Pattern 2: int to uint conversion (sign loss)
            if self.is_int_to_uint(line) {
                let has_sign_check = self.has_sign_check(&lines, line_idx);

                if !has_sign_check {
                    issues.push((
                        line_idx,
                        "int to uint conversion without sign check. Negative values will wrap to large positive".to_string()
                    ));
                }
            }

            // Pattern 3: uint to int conversion (overflow risk)
            if self.is_uint_to_int(line) {
                let has_overflow_check = self.has_range_check(&lines, line_idx);

                if !has_overflow_check {
                    issues.push((
                        line_idx,
                        "uint to int conversion without overflow check. Large values may become negative".to_string()
                    ));
                }
            }

            // Pattern 4: address conversions without validation
            if self.is_address_cast(line) {
                let has_validation = line.contains("!= address(0)")
                    || line.contains("require")
                    || self.has_address_validation(&lines, line_idx);

                if !has_validation {
                    issues.push((
                        line_idx,
                        "address type casting without validation. May result in zero address"
                            .to_string(),
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
        let downcast_patterns = ["uint8(", "uint16(", "uint32(", "uint64(", "uint128("];

        for pattern in &downcast_patterns {
            if line.contains(pattern) && line.contains("uint256") {
                return true;
            }
        }
        false
    }

    fn is_int_to_uint(&self, line: &str) -> bool {
        line.contains("uint(") && line.contains("int")
            || line.contains("uint256(") && line.contains("int256")
            || line.contains("uint128(") && line.contains("int128")
    }

    fn is_uint_to_int(&self, line: &str) -> bool {
        line.contains("int(") && line.contains("uint")
            || line.contains("int256(") && line.contains("uint256")
            || line.contains("int128(") && line.contains("uint128")
    }

    fn is_address_cast(&self, line: &str) -> bool {
        // Phase 54 FP Reduction: address <-> uint160 is SAFE (same size: 160 bits)
        // Only flag other address conversions
        if line.contains("address(uint160(") || line.contains("uint160(address(") {
            // This is safe - address and uint160 are the same size
            return false;
        }

        line.contains("address(bytes20(")
            || (line.contains("address(") && line.contains("uint") && !line.contains("uint160"))
    }

    fn has_range_check(&self, lines: &[&str], current_line: usize) -> bool {
        // Check few lines before for require() with range check
        let start = current_line.saturating_sub(3);

        for i in start..current_line {
            if lines[i].contains("require")
                && (lines[i].contains("<=")
                    || lines[i].contains("<")
                    || lines[i].contains("type(")
                    || lines[i].contains("max"))
            {
                return true;
            }
        }
        false
    }

    /// Phase 9 FP Reduction: Check for type(uintX).max bounds checks
    /// Pattern: require(value <= type(uint64).max, "...")
    fn has_type_max_check(&self, lines: &[&str], current_line: usize) -> bool {
        let start = current_line.saturating_sub(5);

        for i in start..current_line {
            let line = lines[i];
            // Check for type(uintX).max pattern
            if line.contains("type(uint") && line.contains(").max") {
                return true;
            }
            // Check for common max constants
            if line.contains("MAX_UINT") || line.contains("type(") && line.contains("max") {
                return true;
            }
        }
        false
    }

    fn has_sign_check(&self, lines: &[&str], current_line: usize) -> bool {
        // Check few lines before for require() with sign check
        let start = current_line.saturating_sub(3);

        for i in start..current_line {
            if lines[i].contains("require")
                && (lines[i].contains(">= 0") || lines[i].contains("> -1"))
            {
                return true;
            }
        }
        false
    }

    fn has_address_validation(&self, lines: &[&str], current_line: usize) -> bool {
        // Check few lines before for address validation
        let start = current_line.saturating_sub(3);

        for i in start..current_line {
            if lines[i].contains("require")
                && (lines[i].contains("!= address(0)") || lines[i].contains("!= 0"))
            {
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

    /// Phase 54 FP Reduction: Check if cast is inside assembly block with validation
    fn is_in_assembly_with_validation(&self, lines: &[&str], current_line: usize) -> bool {
        let mut in_assembly = false;
        let mut has_validation = false;

        // Scan backwards to check if we're in an assembly block
        for i in (0..=current_line).rev() {
            let line = lines[i].trim();

            if line.contains("assembly") && line.contains("{") {
                in_assembly = true;
                break;
            }

            // Check for size/bounds validation in assembly
            if line.contains("and(")
                || line.contains("shr(")
                || line.contains("shl(")
                || line.contains("mod(")
                || line.contains("lt(")
                || line.contains("gt(")
            {
                has_validation = true;
            }
        }

        in_assembly && has_validation
    }

    /// Phase 54 FP Reduction: Check for Chainlink latestRoundData pattern
    /// Chainlink returns int256 for answer which needs to be converted
    fn is_chainlink_round_data_pattern(
        &self,
        line: &str,
        lines: &[&str],
        current_line: usize,
    ) -> bool {
        // Check if this line or nearby lines have latestRoundData
        let context_start = current_line.saturating_sub(5);
        let context_end = std::cmp::min(current_line + 2, lines.len());

        for i in context_start..context_end {
            if lines[i].contains("latestRoundData")
                || lines[i].contains("AggregatorV3Interface")
                || lines[i].contains("priceFeed")
            {
                // Check if we're converting the answer (int256 -> uint256)
                if line.contains("uint256(") && line.contains("answer") {
                    return true;
                }
                // Also safe if there's a positive check before
                if lines[i].contains("answer >") || lines[i].contains("answer >=") {
                    return true;
                }
            }
        }

        false
    }

    /// Phase 54 FP Reduction: Check if this is an enum cast
    /// Enum casts are validated by the compiler
    fn is_enum_cast(&self, line: &str, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // Check if source defines enums
        if !source.contains("enum ") {
            return false;
        }

        // Look for enum type cast patterns
        // e.g., Status(uint8Value), MyEnum(value)
        // These are safe as the compiler validates the value range

        // Extract potential enum type from cast
        let patterns = ["uint8(", "uint16(", "uint32("];
        for pattern in &patterns {
            if let Some(idx) = line.find(pattern) {
                // Check if casting from an enum value
                let before = &line[..idx];
                if before.ends_with("= ") || before.ends_with("return ") {
                    // Check if the variable being cast is an enum
                    if source.contains("enum") {
                        // Check for enum cast pattern (EnumType(value))
                        let after = &line[idx + pattern.len()..];
                        if after.contains(")") {
                            let cast_content = &after[..after.find(')').unwrap_or(after.len())];
                            // If casting an enum member or simple variable, likely safe
                            if !cast_content.contains("msg.")
                                && !cast_content.contains("block.")
                                && !cast_content.contains("tx.")
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
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
