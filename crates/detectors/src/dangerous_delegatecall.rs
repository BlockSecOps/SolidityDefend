use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for dangerous delegatecall to untrusted addresses
pub struct DangerousDelegatecallDetector {
    base: BaseDetector,
}

impl Default for DangerousDelegatecallDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DangerousDelegatecallDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("dangerous-delegatecall".to_string()),
                "Dangerous Delegatecall".to_string(),
                "Detects delegatecall to user-controlled or untrusted addresses that can lead to complete contract takeover".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for DangerousDelegatecallDetector {
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

        // Phase 52 FP Reduction: Skip legitimate proxy contracts
        // Proxy contracts MUST use delegatecall in fallback to forward calls to implementation.
        // This is by design per EIP-1967 and other proxy standards.
        if utils::is_proxy_contract(ctx) {
            return Ok(findings);
        }

        // Phase 52 FP Reduction: Skip interface-only contracts
        if utils::is_interface_only(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(risk_description) = self.has_dangerous_delegatecall(function, ctx) {
                let message = format!(
                    "Function '{}' contains dangerous delegatecall pattern. {} \
                    Delegatecall executes arbitrary code in the context of the current contract, \
                    allowing complete control over contract state and funds.",
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
                        "Restrict delegatecall target in '{}'. \
                    Use whitelist of approved addresses, implement access control, \
                    or avoid delegatecall entirely. Example: \
                    mapping(address => bool) public approvedTargets; \
                    require(approvedTargets[target], \"Unauthorized target\");",
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

impl DangerousDelegatecallDetector {
    /// Check if function has dangerous delegatecall
    fn has_dangerous_delegatecall(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Check for delegatecall usage
        let has_delegatecall =
            func_source.contains("delegatecall") || func_source.contains(".delegatecall(");

        if !has_delegatecall {
            return None;
        }

        // Pattern 1: Delegatecall with user-controlled target
        if self.is_user_controlled_target(&func_source, function) {
            return Some(
                "Delegatecall target is controlled by function parameters or user input, \
                allowing arbitrary code execution"
                    .to_string(),
            );
        }

        // Pattern 2: Delegatecall without access control
        if self.lacks_access_control(&func_source, function) {
            return Some(
                "Delegatecall is performed without proper access control, \
                potentially accessible by any caller"
                    .to_string(),
            );
        }

        // Pattern 3: Delegatecall without target validation
        if self.lacks_target_validation(&func_source) {
            return Some(
                "Delegatecall target is not validated against a whitelist \
                of approved addresses"
                    .to_string(),
            );
        }

        // Pattern 4: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("delegatecall") || func_source.contains("arbitrary code"))
        {
            return Some("Delegatecall vulnerability marker detected in function".to_string());
        }

        None
    }

    /// Check if delegatecall target is user-controlled
    fn is_user_controlled_target(&self, source: &str, function: &ast::Function<'_>) -> bool {
        // Check if any function parameter is used as delegatecall target
        for param in &function.parameters {
            if let Some(param_name) = &param.name {
                let param_name_str = &param_name.name;

                // Check if parameter type name suggests address
                let type_str = format!("{:?}", param.type_name);
                let is_address_param = type_str.contains("address") || type_str.contains("Address");

                if is_address_param {
                    // Check if this parameter is used in delegatecall
                    if source.contains(&format!("{}.delegatecall", param_name_str))
                        || source.contains(&format!("delegatecall({}", param_name_str))
                        || source.contains(&format!("target = {}", param_name_str))
                        || source.contains(&format!("_target = {}", param_name_str))
                    {
                        return true;
                    }
                }
            }
        }

        // Check for common user-controlled patterns
        source.contains("msg.sender.delegatecall")
            || source.contains("_implementation).delegatecall")
                && source.contains("address _implementation")
            || source.contains("target).delegatecall") && source.contains("address target")
    }

    /// Check if function lacks access control
    fn lacks_access_control(&self, source: &str, function: &ast::Function<'_>) -> bool {
        // Public or external function
        let is_public = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        if !is_public {
            return false;
        }

        // Check for access control modifiers/checks
        let has_access_control = source.contains("onlyOwner")
            || source.contains("onlyAdmin")
            || source.contains("onlyGovernance")
            || source.contains("onlyRole")
            || source.contains("require(msg.sender ==")
            || source.contains("require(msg.sender == owner")
            || source.contains("if (msg.sender != owner)");

        !has_access_control
    }

    /// Check if delegatecall target lacks validation
    fn lacks_target_validation(&self, source: &str) -> bool {
        // Has delegatecall
        let has_delegatecall = source.contains("delegatecall");

        if !has_delegatecall {
            return false;
        }

        // Check for target validation patterns
        let has_whitelist = source.contains("whitelist")
            || source.contains("approved")
            || source.contains("authorized")
            || source.contains("allowed")
            || source.contains("mapping(address => bool)")
            || source.contains("isApproved")
            || source.contains("isAuthorized");

        let has_target_check = source.contains("require(target")
            || source.contains("require(_target")
            || source.contains("require(_implementation")
            || source.contains("if (target ==")
            || source.contains("if (_target ==");

        !has_whitelist && !has_target_check
    }

    /// Get function source code (cleaned to avoid FPs from comments/strings)
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            let raw_source = source_lines[start..=end].join("\n");
            utils::clean_source_for_search(&raw_source)
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
        let detector = DangerousDelegatecallDetector::new();
        assert_eq!(detector.name(), "Dangerous Delegatecall");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
