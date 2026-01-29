use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for unprotected delegatecall in fallback functions
///
/// This detector identifies fallback or receive functions that perform delegatecall
/// without proper access control, allowing any caller to execute arbitrary code.
///
/// **Vulnerability:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
/// **Severity:** High
///
/// ## Description
///
/// Unprotected delegatecall in fallback functions is dangerous because:
/// 1. Fallback executes on any call to non-existent functions
/// 2. No explicit function signature required
/// 3. Can be triggered with simple ETH transfers
/// 4. Often used in proxy patterns without proper validation
///
pub struct FallbackDelegatecallUnprotectedDetector {
    base: BaseDetector,
}

impl Default for FallbackDelegatecallUnprotectedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FallbackDelegatecallUnprotectedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("fallback-delegatecall-unprotected".to_string()),
                "Unprotected Fallback Delegatecall".to_string(),
                "Detects delegatecall in fallback/receive functions without proper access control"
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for FallbackDelegatecallUnprotectedDetector {
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
        // This is by design per EIP-1967 and other proxy standards (Safe, OpenZeppelin, etc.).
        if utils::is_proxy_contract(ctx) {
            return Ok(findings);
        }

        // Phase 52 FP Reduction: Skip interface-only contracts
        if utils::is_interface_only(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(risk_description) =
                self.has_unprotected_fallback_delegatecall(function, ctx)
            {
                let message = format!(
                    "Function '{}' performs delegatecall in fallback/receive without access control. {} \
                    This allows any caller to execute arbitrary code by calling non-existent functions \
                    or sending ETH to the contract.",
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
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_fix_suggestion(format!(
                        "Add access control to fallback function '{}'. \
                    Validate implementation address before delegatecall. \
                    Use modifiers like 'onlyOwner' or check msg.sender explicitly. \
                    Consider using OpenZeppelin's transparent or UUPS proxy patterns.",
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

impl FallbackDelegatecallUnprotectedDetector {
    /// Check if fallback/receive function has unprotected delegatecall
    fn has_unprotected_fallback_delegatecall(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        // Must have function body
        function.body.as_ref()?;

        // Check if this is fallback or receive function
        if !self.is_fallback_or_receive(function) {
            return None;
        }

        // Get function source
        let func_source = self.get_function_source(function, ctx);

        // Check for delegatecall
        if !func_source.contains("delegatecall") {
            return None;
        }

        // Check for access control
        if self.has_access_control(&func_source, function) {
            return None;
        }

        Some(format!(
            "Fallback/receive function performs delegatecall without validating the caller. \
            Any address can trigger this by calling a non-existent function or sending ETH."
        ))
    }

    /// Check if function is fallback or receive
    fn is_fallback_or_receive(&self, function: &ast::Function<'_>) -> bool {
        // Check function type
        matches!(
            function.function_type,
            ast::FunctionType::Fallback | ast::FunctionType::Receive
        ) || function.name.name.to_lowercase() == "fallback"
            || function.name.name.to_lowercase() == "receive"
            || function.name.name.is_empty() // Unnamed functions are fallback
    }

    /// Check if function has proper access control
    fn has_access_control(&self, source: &str, function: &ast::Function<'_>) -> bool {
        // Check for access control modifiers
        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();
            if modifier_name.contains("only")
                || modifier_name.contains("auth")
                || modifier_name.contains("access")
                || modifier_name.contains("role")
            {
                return true;
            }
        }

        // Check for inline access control
        source.contains("require(msg.sender ==")
            || source.contains("require(msg.sender == owner")
            || source.contains("require(msg.sender == admin")
            || source.contains("if (msg.sender != owner)")
            || source.contains("if (msg.sender != admin)")
            || source.contains("onlyOwner")
            || source.contains("onlyAdmin")
            || source.contains("hasRole")
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
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        assert_eq!(detector.name(), "Unprotected Fallback Delegatecall");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "fallback-delegatecall-unprotected");
    }
}
