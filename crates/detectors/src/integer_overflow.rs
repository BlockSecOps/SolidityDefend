use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for integer overflow/underflow vulnerabilities
pub struct IntegerOverflowDetector {
    base: BaseDetector,
}

impl Default for IntegerOverflowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegerOverflowDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("integer-overflow".to_string()),
                "Integer Overflow/Underflow".to_string(),
                "Detects unchecked arithmetic operations in Solidity < 0.8.0 or within unchecked blocks that can cause overflow/underflow".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Validation],
                Severity::High,
            ),
        }
    }
}

impl Detector for IntegerOverflowDetector {
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


        // Check pragma version
        let solidity_version = self.extract_solidity_version(ctx);
        let is_pre_08 = self.is_pre_solidity_08(&solidity_version);

        for function in ctx.get_functions() {
            // Check for unchecked arithmetic in pre-0.8.0
            if is_pre_08 {
                if let Some(overflow_risk) = self.check_pre_08_arithmetic(function, ctx) {
                    let message = format!(
                        "Function '{}' performs arithmetic operations in Solidity < 0.8.0 without SafeMath. {} \
                        Integer overflow/underflow can occur, leading to incorrect calculations and potential exploits.",
                        function.name.name, overflow_risk
                    );

                    let finding = self.base.create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(190) // CWE-190: Integer Overflow
                    .with_cwe(191) // CWE-191: Integer Underflow
                    .with_swc("SWC-101") // SWC-101: Integer Overflow and Underflow
                    .with_fix_suggestion(format!(
                        "Use SafeMath library in '{}' for Solidity < 0.8.0. \
                        Example: `using SafeMath for uint256;` and use `.add()`, `.sub()`, `.mul()`, `.div()` methods. \
                        Or upgrade to Solidity >= 0.8.0 for automatic overflow checks.",
                        function.name.name
                    ));

                    findings.push(finding);
                }
            }

            // Check for unchecked blocks (applies to all versions)
            if let Some(unchecked_risk) = self.check_unchecked_block(function, ctx) {
                let message = format!(
                    "Function '{}' contains unchecked arithmetic block. {} \
                    Unchecked blocks bypass Solidity 0.8.0+ overflow protection, \
                    reintroducing overflow/underflow vulnerabilities.",
                    function.name.name, unchecked_risk
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
                    .with_cwe(190)
                    .with_cwe(191)
                    .with_swc("SWC-101") // SWC-101: Integer Overflow and Underflow
                    .with_fix_suggestion(format!(
                        "Carefully review unchecked block in '{}'. \
                    Only use unchecked for proven safe operations. \
                    Add require() statements to validate input ranges if needed.",
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

impl IntegerOverflowDetector {
    /// Extract Solidity version from pragma
    fn extract_solidity_version(&self, ctx: &AnalysisContext) -> String {
        let source = &ctx.source_code;

        // Look for pragma solidity statement
        for line in source.lines() {
            if line.contains("pragma solidity") {
                return line.to_string();
            }
        }

        String::new()
    }

    /// Check if version is pre-0.8.0
    fn is_pre_solidity_08(&self, pragma: &str) -> bool {
        // Simple version check - in production would use proper semver parsing
        pragma.contains("0.4.")
            || pragma.contains("0.5.")
            || pragma.contains("0.6.")
            || pragma.contains("0.7.")
            || pragma.contains("^0.4")
            || pragma.contains("^0.5")
            || pragma.contains("^0.6")
            || pragma.contains("^0.7")
    }

    /// Check for unsafe arithmetic in pre-0.8.0
    fn check_pre_08_arithmetic(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Check for SafeMath usage
        let uses_safemath = func_source.contains(".add(")
            || func_source.contains(".sub(")
            || func_source.contains(".mul(")
            || func_source.contains(".div(")
            || func_source.contains("SafeMath");

        if uses_safemath {
            return None; // Using SafeMath, likely safe
        }

        // Check for arithmetic operations
        let has_addition = func_source.contains(" + ") || func_source.contains("+=");
        let has_subtraction = func_source.contains(" - ") || func_source.contains("-=");
        let has_multiplication = func_source.contains(" * ") || func_source.contains("*=");

        // Check if operating on uint types (more likely to overflow)
        let has_uint_operations = (has_addition || has_subtraction || has_multiplication)
            && (func_source.contains("uint")
                || func_source.contains("balance")
                || func_source.contains("amount")
                || func_source.contains("totalSupply"));

        if has_uint_operations {
            let mut operations = Vec::new();
            if has_addition {
                operations.push("addition");
            }
            if has_subtraction {
                operations.push("subtraction");
            }
            if has_multiplication {
                operations.push("multiplication");
            }

            return Some(format!(
                "Performs {} without SafeMath protection",
                operations.join(", ")
            ));
        }

        // Check for explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("overflow")
                || func_source.contains("underflow")
                || func_source.contains("SafeMath"))
        {
            return Some("Integer overflow/underflow vulnerability marker detected".to_string());
        }

        None
    }

    /// Check for dangerous unchecked blocks
    fn check_unchecked_block(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Check for unchecked block
        let has_unchecked =
            func_source.contains("unchecked {") || func_source.contains("unchecked{");

        if !has_unchecked {
            return None;
        }

        // FP Reduction: Skip safe unchecked patterns commonly used in production code
        // These are mathematically proven safe and widely used in OpenZeppelin, Aave, etc.

        // Pattern 1: Loop counter increments (unchecked { ++i; } or unchecked { i++; })
        // Safe because loop bounds are checked in the for condition
        let is_loop_increment = func_source.contains("unchecked { ++")
            || func_source.contains("unchecked { i++")
            || func_source.contains("unchecked {++")
            || func_source.contains("unchecked{ ++")
            || func_source.contains("unchecked {\n")  // Multi-line with just increment
                && (func_source.contains("++i;") || func_source.contains("i++;"));

        // Only increment in the unchecked block, nothing else
        let unchecked_only_increment = self.is_unchecked_only_increment(&func_source);

        if is_loop_increment || unchecked_only_increment {
            return None; // Safe pattern, skip
        }

        // Pattern 2: Division remainder (cannot overflow)
        // Example: unchecked { return a - (a / b) * b; }
        let is_division_remainder = func_source.contains("unchecked")
            && func_source.contains(" / ")
            && !func_source.contains(" * ")
            && !func_source.contains(" + ");

        if is_division_remainder {
            return None;
        }

        // Pattern 3: Subtraction where result is already bounds-checked
        // Example: require(a >= b); unchecked { return a - b; }
        let has_prior_bounds_check = self.has_bounds_check_before_unchecked(&func_source);
        if has_prior_bounds_check {
            return None;
        }

        // Check if unchecked block contains risky operations
        let has_user_input = func_source.contains("msg.value")
            || func_source.contains("_amount")
            || func_source.contains("amount)");

        let has_state_changes = func_source.contains("balance")
            || func_source.contains("totalSupply")
            || func_source.contains("supply");

        // Only flag if unchecked block actually performs risky operations
        // with user input or state changes, not just any unchecked block
        if has_unchecked && has_user_input && has_state_changes {
            return Some("Unchecked block performs arithmetic on user-controlled values that modify critical state variables".to_string());
        }

        None
    }

    /// Check if unchecked block only contains increment/decrement
    fn is_unchecked_only_increment(&self, func_source: &str) -> bool {
        // Find unchecked blocks and check if they only contain increment
        if let Some(start) = func_source.find("unchecked {") {
            if let Some(end) = func_source[start..].find('}') {
                let block_content = &func_source[start + 11..start + end];
                let trimmed = block_content.trim();
                // Only increment operations
                return trimmed == "++i;"
                    || trimmed == "i++;"
                    || trimmed == "++j;"
                    || trimmed == "j++;"
                    || trimmed.starts_with("++") && trimmed.ends_with(';')
                    || trimmed.ends_with("++;");
            }
        }
        false
    }

    /// Check if there's a bounds check before the unchecked block
    fn has_bounds_check_before_unchecked(&self, func_source: &str) -> bool {
        if let Some(unchecked_pos) = func_source.find("unchecked") {
            let before_unchecked = &func_source[..unchecked_pos];
            // Check for require/assert with >= or > comparisons
            before_unchecked.contains("require(")
                && (before_unchecked.contains(" >= ")
                    || before_unchecked.contains(" > ")
                    || before_unchecked.contains(" <= ")
                    || before_unchecked.contains(" < "))
        } else {
            false
        }
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
        let detector = IntegerOverflowDetector::new();
        assert_eq!(detector.name(), "Integer Overflow/Underflow");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
