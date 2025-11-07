use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for emergency function abuse vulnerabilities
pub struct EmergencyFunctionAbuseDetector {
    base: BaseDetector,
}

impl Default for EmergencyFunctionAbuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EmergencyFunctionAbuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("emergency-function-abuse".to_string()),
                "Emergency Function Abuse".to_string(),
                "Detects emergency functions without time-locks or multi-sig protection, enabling admin abuse".to_string(),
                vec![DetectorCategory::Auth, DetectorCategory::AccessControl],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for EmergencyFunctionAbuseDetector {
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
            if self.has_emergency_abuse(function, ctx) {
                let message = format!(
                    "Function '{}' is an emergency function without time-lock or multi-signature \
                    protection. A single admin can execute emergency actions immediately, \
                    enabling potential abuse or rug pulls.",
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
                    .with_cwe(269) // CWE-269: Improper Privilege Management
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_fix_suggestion(format!(
                        "Add time-lock and multi-sig protection to emergency function '{}'. \
                    Example: Require time-lock delay (e.g., 24-48 hours) and multi-signature \
                    approval before emergency actions can be executed.",
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

impl EmergencyFunctionAbuseDetector {
    /// Check if function has emergency abuse vulnerability
    fn has_emergency_abuse(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Check if this is an emergency function
        let function_name = function.name.name.to_lowercase();
        let emergency_patterns = [
            "emergency",
            "emergencypause",
            "emergencywithdraw",
            "emergencyreward",
            "pause",
        ];

        let is_emergency_function = emergency_patterns
            .iter()
            .any(|pattern| function_name.contains(pattern));

        if !is_emergency_function {
            return false;
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Check if it's an emergency operation
        let is_emergency_op = func_source.contains("emergency")
            || func_source.contains("pause")
            || (func_source.contains("onlyOwner")
                && (func_source.contains("withdraw") || func_source.contains("transfer")));

        if !is_emergency_op {
            return false;
        }

        // Look for vulnerability patterns
        self.check_protection_mechanisms(&func_source, function)
    }

    /// Check for missing protection mechanisms
    fn check_protection_mechanisms(&self, source: &str, function: &ast::Function<'_>) -> bool {
        // Pattern 1: Explicit vulnerability comment
        let has_vulnerability_marker = source.contains("VULNERABILITY")
            && (source.contains("No time lock")
                || source.contains("no time-lock")
                || source.contains("no multi-sig")
                || source.contains("No time lock or governance"));

        // Pattern 2: Has admin access (onlyOwner, onlyGuardian)
        let has_admin_access = source.contains("onlyOwner")
            || source.contains("onlyGuardian")
            || source.contains("onlyAdmin");

        // Pattern 3: Missing time-lock protection
        let has_timelock = source.contains("timelock")
            || source.contains("delay")
            || source.contains("queuedTime")
            || source.contains("executeTime");

        // Pattern 4: Missing multi-sig protection
        let has_multisig = source.contains("multisig")
            || source.contains("multiSig")
            || source.contains("signatures")
            || source.contains("approvers");

        // Pattern 5: Emergency actions without governance
        let no_governance = !source.contains("governance")
            && !source.contains("vote")
            && !source.contains("proposal");

        // Check function visibility - must be external/public to be vulnerable
        let is_public = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        // Vulnerable if has explicit marker
        if has_vulnerability_marker {
            return true;
        }

        // Vulnerable if has admin access but no protection
        if is_public && has_admin_access && !has_timelock && !has_multisig {
            return true;
        }

        // Vulnerable if emergency function without governance protection
        if is_public && has_admin_access && no_governance && !has_timelock {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = EmergencyFunctionAbuseDetector::new();
        assert_eq!(detector.name(), "Emergency Function Abuse");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
