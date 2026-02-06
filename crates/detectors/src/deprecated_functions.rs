use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for deprecated Solidity functions and patterns
pub struct DeprecatedFunctionsDetector {
    base: BaseDetector,
}

impl Default for DeprecatedFunctionsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DeprecatedFunctionsDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("deprecated-functions".to_string()),
                "Deprecated Functions".to_string(),
                "Detects usage of deprecated Solidity functions and patterns that should be replaced with modern alternatives".to_string(),
                vec![DetectorCategory::Validation],
                Severity::Low,
            ),
        }
    }

    /// Get deprecated patterns with their fix messages
    fn get_deprecated_patterns(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            (
                ".send(",
                "Use .call{value: amount}(\"\") instead of .send() for better error handling",
            ),
            (
                "selfdestruct(",
                "selfdestruct is deprecated. Consider alternative contract upgrade patterns",
            ),
            (
                "block.difficulty",
                "block.difficulty deprecated post-merge. Use block.prevrandao instead",
            ),
            (
                " throw;",
                "throw keyword removed. Use require(), assert(), or revert() instead",
            ),
            (
                "suicide(",
                "suicide renamed to selfdestruct (also deprecated). Use upgrade patterns",
            ),
        ]
    }

    /// Check if a line contains a 'var ' keyword as actual variable declaration
    /// and not part of a longer word like 'variable' or 'invariant'
    fn is_var_keyword(&self, line: &str) -> bool {
        // 'var' must be followed by whitespace and a variable name
        // and preceded by nothing or whitespace/opening paren
        let trimmed = line.trim();

        // Check for 'var ' at start of line (possibly after whitespace)
        if trimmed.starts_with("var ") {
            return true;
        }

        // Check for 'var ' after common tokens like '(' or '='
        if line.contains("(var ") || line.contains("= var ") || line.contains(", var ") {
            return true;
        }

        false
    }

    /// Check if a line uses 'years' as a time unit, not as part of a word
    fn is_years_time_unit(&self, line: &str) -> bool {
        // Solidity time units: 'years' must be preceded by a number
        // Examples: "1 years", "10 years", "365 * years"
        let line_lower = line.to_lowercase();

        // Check for patterns like "N years" where N is a number
        for word_idx in line_lower.match_indices("years") {
            let before = &line_lower[..word_idx.0];
            let after_idx = word_idx.0 + 5;

            // Check what comes after 'years' - should be end of token
            if after_idx < line_lower.len() {
                let next_char = line_lower.chars().nth(after_idx).unwrap_or(' ');
                if next_char.is_alphanumeric() {
                    // Part of a longer word like 'yearsElapsed'
                    continue;
                }
            }

            // Check what comes before 'years' - should be a number or * or whitespace
            let trimmed_before = before.trim_end();
            if trimmed_before.is_empty() {
                continue;
            }

            let last_char = trimmed_before.chars().last().unwrap_or(' ');
            if last_char.is_ascii_digit() || last_char == '*' || last_char == ')' {
                return true;
            }
        }

        false
    }
}

impl Detector for DeprecatedFunctionsDetector {
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
        let contract_source = ctx.source_code.as_str();

        // Clean source to remove comments and strings for accurate detection
        let cleaned_source = utils::clean_source_for_search(contract_source);

        // Check for deprecated patterns using cleaned source
        for (pattern, fix_msg) in self.get_deprecated_patterns() {
            // Find all occurrences in actual code (not comments/strings)
            for (line_num, line_content) in utils::find_pattern_lines(contract_source, pattern) {
                // Double-check the cleaned version contains the pattern on this line
                if let Some(cleaned_line) = cleaned_source.lines().nth((line_num - 1) as usize) {
                    if !cleaned_line.contains(pattern) {
                        continue; // Pattern was in comment or string
                    }
                }

                let pattern_display = pattern.trim_end_matches('(').trim();
                let message = format!(
                    "Deprecated function or pattern '{}' detected at line {}. {}",
                    pattern_display, line_num, fix_msg
                );

                // Calculate column position
                let col = line_content.find(pattern).unwrap_or(0) as u32;

                let finding = self
                    .base
                    .create_finding(ctx, message, line_num, col, pattern.len() as u32)
                    .with_cwe(477) // CWE-477: Use of Obsolete Function
                    .with_fix_suggestion(format!(
                        "Replace deprecated '{}'. {}",
                        pattern_display, fix_msg
                    ));

                findings.push(finding);
            }
        }

        // Check for 'var' keyword (requires special handling)
        for (line_num, line) in contract_source.lines().enumerate() {
            // Check in cleaned source to avoid comments
            if let Some(cleaned_line) = cleaned_source.lines().nth(line_num) {
                if self.is_var_keyword(cleaned_line) {
                    let message = format!(
                        "Deprecated 'var' keyword detected at line {}. Use explicit types like uint256, address, etc.",
                        line_num + 1
                    );

                    let col = line.find("var ").unwrap_or(0) as u32;

                    let finding = self
                        .base
                        .create_finding(ctx, message, (line_num + 1) as u32, col, 3)
                        .with_cwe(477)
                        .with_fix_suggestion(
                            "Replace 'var' with explicit type declaration (uint256, address, bytes32, etc.)".to_string()
                        );

                    findings.push(finding);
                }
            }
        }

        // Check for 'years' time unit (requires special handling)
        for (line_num, line) in contract_source.lines().enumerate() {
            // Check in cleaned source to avoid comments
            if let Some(cleaned_line) = cleaned_source.lines().nth(line_num) {
                if self.is_years_time_unit(cleaned_line) {
                    let message = format!(
                        "Deprecated 'years' time unit detected at line {}. Use explicit seconds calculation (365 days).",
                        line_num + 1
                    );

                    let col = line.to_lowercase().find("years").unwrap_or(0) as u32;

                    let finding = self
                        .base
                        .create_finding(ctx, message, (line_num + 1) as u32, col, 5)
                        .with_cwe(477)
                        .with_fix_suggestion(
                            "Replace 'years' with explicit calculation: 365 days or 365 * 24 hours"
                                .to_string(),
                        );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DeprecatedFunctionsDetector::new();
        assert_eq!(detector.name(), "Deprecated Functions");
        assert_eq!(detector.default_severity(), Severity::Low);
        assert!(detector.is_enabled());
    }
}
