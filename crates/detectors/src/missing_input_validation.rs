use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for missing input parameter validation
pub struct MissingInputValidationDetector {
    base: BaseDetector,
}

impl MissingInputValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-input-validation".to_string()),
                "Missing Input Validation".to_string(),
                "Detects functions missing critical input parameter validation like zero address checks or bounds validation".to_string(),
                vec![DetectorCategory::Validation],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for MissingInputValidationDetector {
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
            if let Some(validation_issue) = self.check_missing_validation(function, ctx) {
                let message = format!(
                    "Function '{}' missing input validation. {} \
                    Missing validation can lead to unexpected behavior, zero address transfers, or invalid state.",
                    function.name.name,
                    validation_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(20)   // CWE-20: Improper Input Validation
                .with_cwe(1284) // CWE-1284: Improper Validation of Specified Quantity in Input
                .with_fix_suggestion(format!(
                    "Add input validation to '{}'. \
                    Implement: (1) Zero address checks for address parameters, \
                    (2) Bounds validation for numeric inputs, \
                    (3) Array length validation, \
                    (4) require() statements at function start, \
                    (5) OpenZeppelin Address library for address validation.",
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

impl MissingInputValidationDetector {
    fn check_missing_validation(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let func_name = &function.name.name;

        // Simple pattern-based checks

        // Pattern 1: Function signature has address parameter but no zero check
        let has_address_param = func_source.contains("address ") && !func_source.contains("returns");
        let has_zero_check = func_source.contains("!= address(0)") ||
                            func_source.contains("require(") ||
                            func_source.contains("Address.isContract");

        if has_address_param && !has_zero_check && self.is_critical_function(func_name) {
            return Some("Critical function with address parameter lacks zero address validation".to_string());
        }

        // Pattern 2: Transfer/withdraw functions without amount validation
        if (func_name.contains("transfer") || func_name.contains("withdraw")) &&
           func_source.contains("uint") {
            let has_amount_check = func_source.contains("require(") ||
                                   func_source.contains("amount > 0") ||
                                   func_source.contains("value > 0");

            if !has_amount_check {
                return Some("Transfer/withdraw function lacks amount validation".to_string());
            }
        }

        // Pattern 3: Array parameter without length check
        if func_source.contains("memory") && func_source.contains("[]") {
            let has_length_check = func_source.contains(".length") &&
                                  (func_source.contains("require") || func_source.contains("if"));

            if !has_length_check && self.is_critical_function(func_name) {
                return Some("Function with array parameter lacks length validation".to_string());
            }
        }

        None
    }

    fn is_critical_function(&self, func_name: &str) -> bool {
        let critical_names = [
            "transfer", "transferFrom", "approve", "mint", "burn",
            "withdraw", "deposit", "swap", "stake", "unstake",
            "claim", "redeem", "liquidate", "borrow", "repay"
        ];

        let name_lower = func_name.to_lowercase();
        critical_names.iter().any(|&critical| name_lower.contains(critical))
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
        let detector = MissingInputValidationDetector::new();
        assert_eq!(detector.name(), "Missing Input Validation");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
