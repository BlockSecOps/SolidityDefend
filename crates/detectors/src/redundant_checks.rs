use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for redundant validation checks that waste gas
pub struct RedundantChecksDetector {
    base: BaseDetector,
}

impl RedundantChecksDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("redundant-checks".to_string()),
                "Redundant Checks".to_string(),
                "Detects redundant validation checks that unnecessarily waste gas, including duplicate require statements, unnecessary overflow checks, and redundant modifiers".to_string(),
                vec![DetectorCategory::Logic],
                Severity::Low,
            ),
        }
    }
}

impl Detector for RedundantChecksDetector {
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
            if let Some(redundant_issues) = self.check_redundant_checks(function, ctx) {
                for issue_desc in redundant_issues {
                    let message = format!(
                        "Function '{}' contains redundant checks. {} \
                        Redundant checks waste gas and increase transaction costs unnecessarily.",
                        function.name.name, issue_desc
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
                        .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                        .with_fix_suggestion(format!(
                            "Remove redundant checks in '{}'. \
                        Consider: (1) Eliminate duplicate require() statements, \
                        (2) Combine multiple checks into single require(), \
                        (3) Remove overflow checks in Solidity >=0.8, \
                        (4) Avoid checking same condition in modifier and function, \
                        (5) Use custom errors instead of require with strings.",
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

impl RedundantChecksDetector {
    fn check_redundant_checks(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<Vec<String>> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let mut issues = Vec::new();

        // Pattern 1: Duplicate require statements
        let require_statements = self.extract_requires(&func_source);
        for (i, req1) in require_statements.iter().enumerate() {
            for req2 in require_statements.iter().skip(i + 1) {
                if self.are_similar_checks(req1, req2) {
                    issues.push(format!(
                        "Duplicate require check: '{}' appears multiple times",
                        req1.trim()
                    ));
                    break;
                }
            }
        }

        // Pattern 2: Redundant overflow checks in Solidity >=0.8
        let contract_source = ctx.source_code.as_str();
        let is_solidity_08_plus = contract_source.contains("pragma solidity ^0.8")
            || contract_source.contains("pragma solidity 0.8")
            || contract_source.contains("pragma solidity >=0.8");

        if is_solidity_08_plus {
            if func_source.contains("require(")
                && (func_source.contains(" + ") || func_source.contains(" - "))
                && (func_source.contains("overflow") || func_source.contains("underflow"))
            {
                issues.push("Manual overflow/underflow check in Solidity 0.8+. Built-in protection makes this redundant".to_string());
            }
        }

        // Pattern 3: Checking same condition in modifier and function
        if let Some(modifiers) = self.extract_modifiers(&func_source) {
            for modifier in modifiers {
                let modifier_source = self.find_modifier_source(contract_source, &modifier);
                if !modifier_source.is_empty() {
                    for req in &require_statements {
                        if modifier_source.contains(req.trim()) {
                            issues.push(format!(
                                "Redundant check in function body. Already validated by modifier '{}'",
                                modifier
                            ));
                        }
                    }
                }
            }
        }

        // Pattern 4: Unnecessary zero checks for unsigned integers
        if func_source.contains("require(") && func_source.contains(">= 0") {
            if func_source.contains("uint")
                || func_source.contains("amount >= 0")
                || func_source.contains("value >= 0")
            {
                issues.push(
                    "Redundant check: uint >= 0 is always true for unsigned integers".to_string(),
                );
            }
        }

        // Pattern 5: Multiple checks that could be combined
        let consecutive_requires = self.count_consecutive_requires(&func_source);
        if consecutive_requires > 2 {
            issues.push(format!(
                "{} consecutive require statements. Consider combining into fewer checks",
                consecutive_requires
            ));
        }

        // Pattern 6: Checking msg.sender != address(0)
        if func_source.contains("require(msg.sender != address(0)")
            || func_source.contains("require(msg.sender != 0")
        {
            issues.push("Redundant check: msg.sender can never be address(0)".to_string());
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn extract_requires(&self, source: &str) -> Vec<String> {
        let mut requires = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("require(") {
                if let Some(end) = trimmed.find(");") {
                    requires.push(trimmed[8..end].to_string());
                }
            }
        }

        requires
    }

    fn are_similar_checks(&self, check1: &str, check2: &str) -> bool {
        // Normalize whitespace for comparison
        let normalized1: String = check1.split_whitespace().collect::<Vec<_>>().join(" ");
        let normalized2: String = check2.split_whitespace().collect::<Vec<_>>().join(" ");

        normalized1 == normalized2
    }

    fn extract_modifiers(&self, source: &str) -> Option<Vec<String>> {
        // Look for function declaration line with modifiers
        let lines: Vec<&str> = source.lines().collect();
        for line in &lines {
            if line.contains("function ") {
                let modifiers: Vec<String> = line
                    .split_whitespace()
                    .filter(|word| {
                        !word.starts_with("function")
                            && !word.starts_with("(")
                            && !word.starts_with("public")
                            && !word.starts_with("private")
                            && !word.starts_with("external")
                            && !word.starts_with("internal")
                            && !word.starts_with("view")
                            && !word.starts_with("pure")
                            && !word.starts_with("payable")
                            && !word.starts_with("returns")
                            && !word.starts_with("{")
                            && word.chars().next().unwrap_or(' ').is_alphabetic()
                    })
                    .skip(1) // Skip function name
                    .map(|s| s.to_string())
                    .collect();

                if !modifiers.is_empty() {
                    return Some(modifiers);
                }
            }
        }
        None
    }

    fn find_modifier_source(&self, contract_source: &str, modifier_name: &str) -> String {
        let lines: Vec<&str> = contract_source.lines().collect();
        let mut in_modifier = false;
        let mut modifier_lines = Vec::new();
        let mut brace_count = 0;

        for line in lines {
            if line
                .trim()
                .starts_with(&format!("modifier {}", modifier_name))
            {
                in_modifier = true;
                brace_count = 0;
            }

            if in_modifier {
                modifier_lines.push(line);
                brace_count += line.matches('{').count() as i32;
                brace_count -= line.matches('}').count() as i32;

                if brace_count <= 0 && line.contains('}') {
                    break;
                }
            }
        }

        modifier_lines.join("\n")
    }

    fn count_consecutive_requires(&self, source: &str) -> usize {
        let lines: Vec<&str> = source.lines().collect();
        let mut max_consecutive = 0;
        let mut current_consecutive = 0;

        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("require(") {
                current_consecutive += 1;
                max_consecutive = max_consecutive.max(current_consecutive);
            } else if !trimmed.is_empty() && !trimmed.starts_with("//") {
                current_consecutive = 0;
            }
        }

        max_consecutive
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
        let detector = RedundantChecksDetector::new();
        assert_eq!(detector.name(), "Redundant Checks");
        assert_eq!(detector.default_severity(), Severity::Low);
        assert!(detector.is_enabled());
    }
}
