use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for unchecked arithmetic operations that can overflow/underflow
pub struct UncheckedMathDetector {
    base: BaseDetector,
}

impl UncheckedMathDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("unchecked-math".to_string()),
                "Unchecked Math Operations".to_string(),
                "Detects arithmetic operations in unchecked blocks that can overflow or underflow without reversion".to_string(),
                vec![DetectorCategory::Validation],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for UncheckedMathDetector {
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
            if let Some(unchecked_issues) = self.check_unchecked_math(function, ctx) {
                for issue_desc in unchecked_issues {
                    let message = format!(
                        "Function '{}' contains unchecked arithmetic operations. {} \
                        Unchecked math can silently overflow/underflow leading to incorrect calculations and potential exploits.",
                        function.name.name, issue_desc
                    );

                    let finding = self.base.create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(190) // CWE-190: Integer Overflow or Wraparound
                    .with_fix_suggestion(format!(
                        "Remove unsafe unchecked blocks in '{}'. \
                        Solidity 0.8+ has built-in overflow protection. \
                        Only use 'unchecked' for gas optimization when overflow is mathematically impossible. \
                        Add explicit validation or use OpenZeppelin SafeMath for Solidity <0.8.",
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

impl UncheckedMathDetector {
    fn check_unchecked_math(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<Vec<String>> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let mut issues = Vec::new();

        // Pattern 1: Check for unchecked blocks with arithmetic
        if func_source.contains("unchecked") {
            let has_addition = func_source.contains(" + ");
            let has_subtraction = func_source.contains(" - ");
            let has_multiplication = func_source.contains(" * ");
            let has_exponentiation = func_source.contains("**");

            if has_addition {
                issues.push(
                    "Unchecked addition detected. Addition can overflow without reversion"
                        .to_string(),
                );
            }
            if has_subtraction {
                issues.push(
                    "Unchecked subtraction detected. Subtraction can underflow without reversion"
                        .to_string(),
                );
            }
            if has_multiplication {
                issues.push("Unchecked multiplication detected. Multiplication can overflow without reversion".to_string());
            }
            if has_exponentiation {
                issues.push("Unchecked exponentiation detected. Exponentiation can overflow without reversion".to_string());
            }
        }

        // Pattern 2: Pre-0.8 Solidity without SafeMath
        let contract_source = ctx.source_code.as_str();
        let is_pre_08 = contract_source.contains("pragma solidity ^0.7")
            || contract_source.contains("pragma solidity 0.7")
            || contract_source.contains("pragma solidity ^0.6")
            || contract_source.contains("pragma solidity 0.6")
            || contract_source.contains("pragma solidity ^0.5")
            || contract_source.contains("pragma solidity 0.5");

        if is_pre_08 {
            let uses_safemath = contract_source.contains("SafeMath")
                || func_source.contains(".add(")
                || func_source.contains(".sub(")
                || func_source.contains(".mul(")
                || func_source.contains(".div(");

            if !uses_safemath {
                let has_arithmetic = func_source.contains(" + ")
                    || func_source.contains(" - ")
                    || func_source.contains(" * ");

                if has_arithmetic {
                    issues.push(
                        "Pre-Solidity 0.8 arithmetic without SafeMath. No overflow protection"
                            .to_string(),
                    );
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
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
        let detector = UncheckedMathDetector::new();
        assert_eq!(detector.name(), "Unchecked Math Operations");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
