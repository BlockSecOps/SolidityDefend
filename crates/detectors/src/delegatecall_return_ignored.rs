use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for ignored delegatecall return values
///
/// This detector identifies cases where delegatecall is performed but the return
/// value (success/failure) is not properly checked or validated.
///
/// **Vulnerability Pattern:**
/// - Delegatecall used as statement without capturing return value
/// - Return value captured but not validated with require/assert
/// - Only return data captured, not success boolean
/// - Assembly delegatecall result not checked before continuing
/// - Try-catch with empty catch block
///
/// **Risk:**
/// - Silent failures that go undetected
/// - Contract assumes operation succeeded when it failed
/// - State corruption due to partial updates
/// - Critical operations failing without notice
/// - Fund loss due to undetected transfer failures
///
/// **Real-world Impact:**
/// - Proxy upgrades that fail silently
/// - Failed initializations leaving contracts in broken state
/// - State corruption in batch operations
/// - Silent fund transfer failures
///
/// **CWE Mapping:**
/// - CWE-252: Unchecked Return Value
///
/// **Severity:** High
pub struct DelegatecallReturnIgnoredDetector {
    base: BaseDetector,
}

impl DelegatecallReturnIgnoredDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("delegatecall-return-ignored".to_string()),
                "Delegatecall Return Value Ignored".to_string(),
                "Detects delegatecall operations without proper return value checking".to_string(),
                vec![DetectorCategory::ExternalCalls, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Check if function has unchecked delegatecall
    fn has_unchecked_delegatecall(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        let source = self.get_function_source(function, ctx);

        // Check if function contains delegatecall
        if !source.contains("delegatecall") {
            return None;
        }

        // Check for statement-position delegatecall (most obvious case)
        if self.has_statement_delegatecall(&source) {
            return Some(
                "Delegatecall used as statement without capturing return value. \
                Always capture: (bool success, bytes memory data) = target.delegatecall(...)".to_string()
            );
        }

        // Check for captured but not validated
        if self.has_unvalidated_delegatecall(&source) {
            return Some(
                "Delegatecall return value captured but not validated. \
                Add require(success, ...) or if (!success) revert(...)".to_string()
            );
        }

        // Check for only data captured, not success
        if self.has_data_only_capture(&source) {
            return Some(
                "Delegatecall captures only return data, not success status. \
                Use (bool success, bytes memory data) to capture both".to_string()
            );
        }

        // Check for assembly delegatecall without proper checking
        if self.has_unchecked_assembly_delegatecall(&source) {
            return Some(
                "Assembly delegatecall result not properly validated. \
                Check result: switch result case 0 { revert(...) } default { return(...) }".to_string()
            );
        }

        None
    }

    /// Check for statement-position delegatecall (no assignment)
    fn has_statement_delegatecall(&self, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();

        for line in &lines {
            let trimmed = line.trim();

            // Look for delegatecall as statement (not assigned)
            if trimmed.contains("delegatecall(") {
                // Check if it's used as a statement (ends with ;)
                // and not part of an assignment or declaration
                if !trimmed.contains("(bool") &&
                   !trimmed.contains("= ") &&
                   !trimmed.contains("let ") &&
                   trimmed.contains(");") {
                    return true;
                }

                // Check for direct usage without assignment
                if trimmed.starts_with("implementation.delegatecall") ||
                   trimmed.starts_with("target.delegatecall") ||
                   trimmed.starts_with("library.delegatecall") {
                    if !line.contains("(bool") && !line.contains("= ") {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if delegatecall return is captured but not validated
    fn has_unvalidated_delegatecall(&self, source: &str) -> bool {
        // Look for pattern: (bool success, ...) = delegatecall(...)
        // but no subsequent require(success) or if (!success)

        if !source.contains("(bool success") && !source.contains("(bool result") {
            return false;
        }

        let has_delegatecall = source.contains("delegatecall(");
        if !has_delegatecall {
            return false;
        }

        // Check if success is validated
        let has_require_success = source.contains("require(success") ||
                                   source.contains("require(result");
        let has_if_check = source.contains("if (!success)") ||
                           source.contains("if(!success)") ||
                           source.contains("if (!result)") ||
                           source.contains("if(!result)");
        let has_assert = source.contains("assert(success)") ||
                         source.contains("assert(result)");

        // If delegatecall result captured but not validated
        if !has_require_success && !has_if_check && !has_assert {
            // Check if it's just returned (also problematic)
            if source.contains("return success") || source.contains("return result") {
                return true;
            }
            return true;
        }

        false
    }

    /// Check if only data is captured, not success
    fn has_data_only_capture(&self, source: &str) -> bool {
        // Look for pattern: (, bytes memory data) = delegatecall(...)
        // or: bytes memory data = delegatecall(...)

        let has_delegatecall = source.contains("delegatecall(");
        if !has_delegatecall {
            return false;
        }

        // Pattern: (, bytes memory result) - success ignored
        if source.contains("(, bytes memory") || source.contains("(,bytes memory") {
            return true;
        }

        false
    }

    /// Check for unchecked assembly delegatecall
    fn has_unchecked_assembly_delegatecall(&self, source: &str) -> bool {
        if !source.contains("assembly") || !source.contains("delegatecall") {
            return false;
        }

        // Look for assembly block with delegatecall
        let in_assembly = source.contains("assembly {") &&
                          source.contains("delegatecall(");

        if !in_assembly {
            return false;
        }

        // Check if result is checked
        let has_switch_check = source.contains("switch result") ||
                               source.contains("switch success");
        let has_case_zero = source.contains("case 0");
        let has_if_check = source.contains("if iszero(result)") ||
                          source.contains("if iszero(success)");

        // If no proper checking
        if !has_switch_check && !has_if_check {
            return true;
        }

        // If switch exists but no case 0 (failure case)
        if has_switch_check && !has_case_zero {
            return true;
        }

        false
    }

    /// Get function source code
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let lines: Vec<&str> = ctx.source_code.lines().collect();
        if start > 0 && end <= lines.len() {
            let start_idx = start.saturating_sub(1);
            lines[start_idx..end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check if function is a fallback/receive (special handling)
    fn is_fallback_or_receive(&self, function: &ast::Function<'_>) -> bool {
        matches!(
            function.function_type,
            ast::FunctionType::Fallback | ast::FunctionType::Receive
        )
    }
}

impl Default for DelegatecallReturnIgnoredDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DelegatecallReturnIgnoredDetector {
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
            if let Some(issue_description) = self.has_unchecked_delegatecall(function, ctx) {
                let func_type = if self.is_fallback_or_receive(function) {
                    "fallback/receive function"
                } else {
                    "function"
                };

                let message = format!(
                    "Delegatecall in {} '{}' does not properly check return value. {} \
                    Real-world impact: Silent failures can lead to state corruption, failed upgrades, \
                    and fund loss. Similar to issues in proxy contracts where failed initializations \
                    went undetected.",
                    func_type, function.name.name, issue_description
                );

                let finding = self.base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(252);

                findings.push(finding);
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
        let detector = DelegatecallReturnIgnoredDetector::new();
        assert_eq!(detector.id().0, "delegatecall-return-ignored");
        assert_eq!(detector.name(), "Delegatecall Return Value Ignored");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_default() {
        let detector = DelegatecallReturnIgnoredDetector::default();
        assert_eq!(detector.id().0, "delegatecall-return-ignored");
    }
}
