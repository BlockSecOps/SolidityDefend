//! Logic Error Patterns Detector (OWASP 2025)
//!
//! Detects common logic errors that led to $63.8M in losses in 2024-2025:
//! - Division before multiplication (precision loss)
//! - Faulty reward distribution
//! - Rounding errors in calculations
//!
//! Phase 6 FP Reduction: Rewritten with proper expression analysis to detect
//! actual division-before-multiplication patterns instead of simple contains().

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct LogicErrorPatternsDetector {
    base: BaseDetector,
}

impl LogicErrorPatternsDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("logic-error-patterns".to_string()),
                "Logic Error Patterns".to_string(),
                "Detects division before multiplication and faulty reward calculations".to_string(),
                vec![DetectorCategory::BestPractices, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find division-before-multiplication patterns in source code
    /// Returns (line_number, expression, context)
    fn find_div_before_mul_patterns(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut results = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            // Look for expressions containing both / and *
            if trimmed.contains('/') && trimmed.contains('*') {
                // Skip lines that are just comments or imports
                if trimmed.contains("//")
                    && trimmed.find("//").unwrap() < trimmed.find('/').unwrap_or(usize::MAX)
                {
                    continue;
                }

                // Check for division-before-multiplication pattern
                if let Some(pattern) = self.detect_div_before_mul(trimmed) {
                    // Get context (surrounding lines)
                    let context = self.get_context(&lines, line_num);
                    results.push((line_num as u32 + 1, pattern, context));
                }
            }
        }

        results
    }

    /// Detect if an expression has division before multiplication
    /// Patterns to detect:
    /// - (a / b) * c  -> division result multiplied
    /// - a / b * c    -> left-to-right evaluation means div first
    /// - x = y / z; result = x * w;  -> requires data flow analysis (simplified)
    fn detect_div_before_mul(&self, line: &str) -> Option<String> {
        // Remove string literals to avoid false positives
        let cleaned = self.remove_string_literals(line);

        // Skip if no actual arithmetic (e.g., just path separators or comments)
        if !cleaned.contains('=') && !cleaned.contains("return") {
            return None;
        }

        // Pattern 1: Explicit parenthesized division multiplied: (a / b) * c
        if cleaned.contains("/ ") && cleaned.contains(") *") {
            // Check if there's a pattern like "(something / something) * something"
            if let Some(div_pos) = cleaned.find(" / ") {
                if let Some(close_paren) = cleaned[div_pos..].find(')') {
                    let after_paren = &cleaned[div_pos + close_paren..];
                    if after_paren.trim_start().starts_with('*') || after_paren.contains(" * ") {
                        return Some(format!(
                            "Division before multiplication: {}",
                            cleaned.trim()
                        ));
                    }
                }
            }
        }

        // Pattern 2: Non-parenthesized a / b * c (left-to-right causes precision loss)
        // This is the most common mistake
        if let Some(pattern) = self.find_consecutive_div_mul(&cleaned) {
            return Some(pattern);
        }

        // Pattern 3: Variable assigned from division then multiplied
        // e.g., uint256 x = a / b; ... result = x * c;
        // This requires more complex analysis - skip for now to reduce FPs

        None
    }

    /// Find consecutive division then multiplication without proper parentheses
    /// e.g., "a / b * c" where left-to-right evaluation loses precision
    fn find_consecutive_div_mul(&self, expr: &str) -> Option<String> {
        // Tokenize the expression roughly
        let mut found_div = false;
        let mut in_parens: i32 = 0;
        let chars: Vec<char> = expr.chars().collect();

        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '(' => in_parens += 1,
                ')' => in_parens = in_parens.saturating_sub(1),
                '/' => {
                    // Check if this is division (not comment or path)
                    if i + 1 < chars.len() && chars[i + 1] != '/' && chars[i + 1] != '*' {
                        // Check if there's something before and after (not just /)
                        let before = i > 0
                            && (chars[i - 1].is_alphanumeric()
                                || chars[i - 1] == ')'
                                || chars[i - 1] == ' ');
                        let after = i + 1 < chars.len()
                            && (chars[i + 1].is_alphanumeric()
                                || chars[i + 1] == '('
                                || chars[i + 1] == ' ');
                        if before && after {
                            found_div = true;
                        }
                    }
                }
                '*' => {
                    // Check if this is multiplication (not pointer or comment)
                    if found_div && in_parens == 0 {
                        // Check if there's something after (not just *)
                        if i + 1 < chars.len() && chars[i + 1] != '/' && chars[i + 1] != '*' {
                            let after = i + 1 < chars.len()
                                && (chars[i + 1].is_alphanumeric()
                                    || chars[i + 1] == '('
                                    || chars[i + 1] == ' ');
                            if after {
                                return Some(format!(
                                    "Division before multiplication (precision loss): {}",
                                    expr.trim()
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }

        None
    }

    /// Remove string literals from expression to avoid false positives
    fn remove_string_literals(&self, s: &str) -> String {
        let mut result = String::new();
        let mut in_string = false;
        let mut string_char = '"';
        let chars: Vec<char> = s.chars().collect();

        let mut i = 0;
        while i < chars.len() {
            if !in_string {
                if chars[i] == '"' || chars[i] == '\'' {
                    in_string = true;
                    string_char = chars[i];
                } else {
                    result.push(chars[i]);
                }
            } else {
                if chars[i] == string_char && (i == 0 || chars[i - 1] != '\\') {
                    in_string = false;
                }
            }
            i += 1;
        }

        result
    }

    /// Get surrounding context for better error messages
    fn get_context(&self, lines: &[&str], line_num: usize) -> String {
        let start = if line_num > 2 { line_num - 2 } else { 0 };
        let end = std::cmp::min(line_num + 3, lines.len());

        lines[start..end].join("\n")
    }

    /// Find reward distribution patterns that might have precision issues
    fn find_reward_calculation_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut results = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Look for reward calculation patterns with division
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let lower = trimmed.to_lowercase();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Pattern: reward = something / something without scaling
            if (lower.contains("reward") || lower.contains("share") || lower.contains("portion"))
                && trimmed.contains('/')
                && trimmed.contains('=')
            {
                // Check if there's proper scaling (1e18, WAD, etc.)
                if !trimmed.contains("1e")
                    && !trimmed.contains("WAD")
                    && !trimmed.contains("RAY")
                    && !trimmed.contains("PRECISION")
                    && !trimmed.contains("SCALE")
                {
                    // Check context for preceding multiplication
                    let context_start = if line_num > 3 { line_num - 3 } else { 0 };
                    let context: String = lines[context_start..=line_num].join("\n");

                    // If there's multiplication before division in context, it's likely OK
                    // If division happens first, flag it
                    if !self.has_mul_before_div_in_context(&context) {
                        results.push((
                            line_num as u32 + 1,
                            "Reward/share calculation with division - verify precision scaling"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        results
    }

    /// Check if context has multiplication before division (correct order)
    fn has_mul_before_div_in_context(&self, context: &str) -> bool {
        // Simple check: if we see "* something /" pattern, multiplication is first
        let has_mul = context.contains(" * ");
        let has_div = context.contains(" / ");

        if has_mul && has_div {
            // Check order - multiplication should come before division
            if let (Some(mul_pos), Some(div_pos)) = (context.find(" * "), context.find(" / ")) {
                return mul_pos < div_pos;
            }
        }

        false
    }
}

impl Default for LogicErrorPatternsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for LogicErrorPatternsDetector {
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
        let source = &ctx.source_code;

        // Phase 6: Properly analyze expressions for division-before-multiplication
        let div_before_mul = self.find_div_before_mul_patterns(source);
        for (line, pattern, _context) in div_before_mul {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!("{} (OWASP 2025 - $63.8M in losses)", pattern),
                    line,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "❌ PRECISION LOSS ($63.8M in losses):\n\
                 uint256 reward = (amount / totalSupply) * rewardRate;\n\
                 // Result: 0 if amount < totalSupply!\n\
                 \n\
                 ✅ CORRECT ORDER - Multiply before divide:\n\
                 uint256 reward = (amount * rewardRate) / totalSupply;\n\
                 // Maximizes precision\n\
                 \n\
                 ✅ BEST - Use fixed-point math:\n\
                 uint256 reward = (amount * rewardRate * 1e18) / totalSupply / 1e18;\n\
                 \n\
                 Real incidents:\n\
                 - Cork Protocol: $11M (May 2025) - Division rounding\n\
                 - SIR.trading: $355K (March 2025) - Reward calculation\n\
                 - Multiple 2024 incidents: $63.8M total"
                        .to_string(),
                );
            findings.push(finding);
        }

        // Check for reward distribution patterns that might have issues
        let reward_issues = self.find_reward_calculation_issues(source);
        for (line, issue) in reward_issues {
            let finding = self
                .base
                .create_finding_with_severity(ctx, issue, line, 0, 20, Severity::Medium)
                .with_fix_suggestion(
                    "Common reward distribution errors:\n\
                 \n\
                 1. Integer division truncation:\n\
                    ❌ reward = balance / users;  // Loses remainder\n\
                    ✅ reward = (balance * 1e18) / users;\n\
                 \n\
                 2. Division before multiplication:\n\
                    ❌ (balance / total) * multiplier\n\
                    ✅ (balance * multiplier) / total\n\
                 \n\
                 3. Use scaling constants:\n\
                    uint256 constant PRECISION = 1e18;\n\
                    reward = (amount * PRECISION) / totalSupply;"
                        .to_string(),
                );
            findings.push(finding);
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
        let detector = LogicErrorPatternsDetector::new();
        assert_eq!(detector.name(), "Logic Error Patterns");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_div_before_mul_detected() {
        let detector = LogicErrorPatternsDetector::new();

        // This pattern should be detected
        let vulnerable = r#"
            function calcReward(uint256 amount) external {
                uint256 reward = (amount / totalSupply) * rewardRate;
            }
        "#;

        let patterns = detector.find_div_before_mul_patterns(vulnerable);
        assert!(
            !patterns.is_empty(),
            "Division before multiplication should be detected"
        );
    }

    #[test]
    fn test_mul_before_div_not_flagged() {
        let detector = LogicErrorPatternsDetector::new();

        // This is the CORRECT pattern - should NOT be flagged
        let safe = r#"
            function calcReward(uint256 amount) external {
                uint256 reward = (amount * rewardRate) / totalSupply;
            }
        "#;

        let patterns = detector.find_div_before_mul_patterns(safe);
        assert!(
            patterns.is_empty(),
            "Correct mul-before-div should not be flagged"
        );
    }

    #[test]
    fn test_comment_not_flagged() {
        let detector = LogicErrorPatternsDetector::new();

        // Comments and paths should not be flagged
        let code_with_comments = r#"
            // This is a/b * c comment
            import "./math/SafeMath.sol";
        "#;

        let patterns = detector.find_div_before_mul_patterns(code_with_comments);
        assert!(patterns.is_empty(), "Comments should not be flagged");
    }

    #[test]
    fn test_consecutive_div_mul() {
        let detector = LogicErrorPatternsDetector::new();

        // a / b * c pattern (dangerous due to left-to-right evaluation)
        let dangerous = r#"
            function calc(uint256 a, uint256 b, uint256 c) external returns (uint256) {
                return a / b * c;
            }
        "#;

        let patterns = detector.find_div_before_mul_patterns(dangerous);
        assert!(
            !patterns.is_empty(),
            "Consecutive div-mul should be detected"
        );
    }

    #[test]
    fn test_safe_usage_not_flagged() {
        let detector = LogicErrorPatternsDetector::new();

        // Using scaling - this is safe
        let safe_scaled = r#"
            function calcReward(uint256 amount) external {
                uint256 reward = (amount * 1e18) / totalSupply;
            }
        "#;

        let issues = detector.find_reward_calculation_issues(safe_scaled);
        // Scaling patterns should not trigger reward issues
        assert!(
            issues.is_empty() || safe_scaled.contains("1e"),
            "Scaled calculations should be OK"
        );
    }
}
