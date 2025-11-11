use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for user-controlled delegatecall targets
///
/// This detector identifies delegatecall operations where the target address
/// is controlled by user input or function parameters, allowing arbitrary
/// code execution in the contract's context.
///
/// **Vulnerability:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
/// **Severity:** Critical
///
/// ## Description
///
/// User-controlled delegatecall allows attackers to:
/// 1. Execute arbitrary code in contract's storage context
/// 2. Modify any state variable
/// 3. Drain all funds from the contract
/// 4. Take complete control of the contract
///
pub struct DelegatecallUserControlledDetector {
    base: BaseDetector,
}

impl Default for DelegatecallUserControlledDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatecallUserControlledDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("delegatecall-user-controlled".to_string()),
                "User-Controlled Delegatecall".to_string(),
                "Detects delegatecall operations where the target address is controlled by user input"
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for DelegatecallUserControlledDetector {
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
            if let Some(risk_description) = self.has_user_controlled_delegatecall(function, ctx) {
                let message = format!(
                    "Function '{}' performs delegatecall with user-controlled target. {} \
                    This allows arbitrary code execution in the contract's storage context, \
                    enabling complete takeover and fund theft.",
                    function.name.name, risk_description
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
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_cwe(494) // CWE-494: Download of Code Without Integrity Check
                    .with_fix_suggestion(format!(
                        "Remove user control over delegatecall target in '{}'. \
                    Use a whitelist of approved addresses: mapping(address => bool) approvedTargets; \
                    Or avoid delegatecall entirely and use regular external calls.",
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

impl DelegatecallUserControlledDetector {
    /// Check if function has user-controlled delegatecall
    fn has_user_controlled_delegatecall(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        // Must have function body
        function.body.as_ref()?;

        // Get function source
        let func_source = self.get_function_source(function, ctx);

        // Check for delegatecall
        if !func_source.contains("delegatecall") {
            return None;
        }

        // Check if target is user-controlled
        if self.is_target_user_controlled(&func_source, function) {
            return Some(format!(
                "Delegatecall target is derived from function parameters or user input, \
                allowing callers to specify arbitrary code to execute."
            ));
        }

        None
    }

    /// Check if delegatecall target is user-controlled
    fn is_target_user_controlled(&self, source: &str, function: &ast::Function<'_>) -> bool {
        // Check if any function parameter is used as target
        for param in &function.parameters {
            if let Some(param_name) = &param.name {
                let param_str = param_name.name;

                // Check if parameter type is address
                let type_str = format!("{:?}", param.type_name);
                if !type_str.to_lowercase().contains("address") {
                    continue;
                }

                // Check if this parameter is used in delegatecall
                if source.contains(&format!("{}.delegatecall", param_str))
                    || source.contains(&format!("delegatecall({}", param_str))
                    || source.contains(&format!("target = {}", param_str))
                    || source.contains(&format!("_target = {}", param_str))
                    || source.contains(&format!("to = {}", param_str))
                    || source.contains(&format!("_to = {}", param_str))
                {
                    return true;
                }
            }
        }

        // Check for msg.sender delegatecall (less common but still user-controlled)
        if source.contains("msg.sender.delegatecall") || source.contains("msg.sender).delegatecall")
        {
            return true;
        }

        // Check for implementation parameter patterns
        if (source.contains("address _implementation")
            || source.contains("address implementation")
            || source.contains("address target")
            || source.contains("address _target")
            || source.contains("address to")
            || source.contains("address _to"))
            && source.contains("delegatecall")
        {
            // Check if it's a function parameter (appears before function body)
            if source.lines().take(5).any(|line| {
                line.contains("address _implementation")
                    || line.contains("address target")
                    || line.contains("address _target")
                    || line.contains("address to")
                    || line.contains("address _to")
            }) {
                return true;
            }
        }

        false
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
        let detector = DelegatecallUserControlledDetector::new();
        assert_eq!(detector.name(), "User-Controlled Delegatecall");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "delegatecall-user-controlled");
    }
}
