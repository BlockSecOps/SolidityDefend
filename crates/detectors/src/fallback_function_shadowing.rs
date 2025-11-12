use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for fallback function shadowing vulnerabilities
///
/// This detector identifies cases where a proxy contract's fallback function
/// or explicit proxy functions shadow functions intended for the implementation contract.
///
/// **Vulnerability Pattern:**
/// - Proxy defines public/external functions with same names as implementation
/// - Fallback function has hardcoded selector checks that intercept calls
/// - Missing transparent proxy pattern (no ifAdmin modifier)
/// - Receive function shadows implementation's receive logic
/// - Function selectors conflict between proxy and implementation
///
/// **Risk:**
/// - Functions in implementation become unreachable
/// - State corruption due to misrouted calls
/// - Critical functions like upgrade/pause become ineffective
/// - Unexpected behavior when users call shadowed functions
///
/// **Real-world Impact:**
/// - Multiple proxy implementations with misrouted admin functions
/// - Upgrade functions that don't actually upgrade
/// - Pause mechanisms that don't pause implementation
///
/// **CWE Mapping:**
/// - CWE-670: Always-Incorrect Control Flow Implementation
///
/// **Severity:** Medium
pub struct FallbackFunctionShadowingDetector {
    base: BaseDetector,
}

impl FallbackFunctionShadowingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("fallback-function-shadowing".to_string()),
                "Fallback Function Shadowing".to_string(),
                "Detects when proxy functions shadow implementation functions".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Upgradeable],
                Severity::Medium,
            ),
        }
    }

    /// Check if contract looks like a proxy
    fn is_proxy_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Check if contract name suggests it's a proxy
        if contract_name.contains("proxy") {
            return true;
        }

        // Check if contract has fallback with delegatecall
        if source.contains("fallback") && source.contains("delegatecall") {
            return true;
        }

        // Check for EIP-1967 storage slots (proxy pattern)
        if source.contains("eip1967.proxy.implementation") {
            return true;
        }

        false
    }

    /// Check if function could shadow implementation functions
    fn has_shadowing_risk(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        let func_name = function.name.name.to_lowercase();
        let source = self.get_function_source(function, ctx);

        // Skip if function is internal or private (can't shadow)
        match function.visibility {
            ast::Visibility::Internal | ast::Visibility::Private => return None,
            _ => {}
        }

        // Check for common proxy admin functions that might shadow implementation
        let risky_function_names = [
            "upgrade", "upgradeto", "setimplementation", "changeimplementation",
            "transferownership", "changeowner", "setowner",
            "pause", "unpause",
            "initialize", "init",
            "getadmin", "getowner", "getimplementation", "getversion",
        ];

        for risky_name in &risky_function_names {
            if func_name.contains(risky_name) {
                // Check if this is in a proxy contract
                if self.is_proxy_contract(ctx) {
                    // Check if function doesn't use ifAdmin pattern
                    if !self.has_if_admin_pattern(&source, ctx) {
                        return Some(format!(
                            "Function '{}' may shadow implementation's function. In transparent proxies, use ifAdmin pattern to separate admin and user calls",
                            function.name.name
                        ));
                    }
                }
            }
        }

        None
    }

    /// Check if fallback function has hardcoded selector checks
    fn has_hardcoded_selectors(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        let source = self.get_function_source(function, ctx);

        // Check if fallback/receive function
        if !matches!(function.function_type, ast::FunctionType::Fallback | ast::FunctionType::Receive) {
            return None;
        }

        // Look for hardcoded selector checks
        if source.contains("msg.sig ==") || source.contains("msg.sig!=") || source.contains("selector ==") {
            // Check if there are multiple selector checks (likely routing logic)
            let selector_checks = source.matches("msg.sig").count() + source.matches("selector ==").count();
            if selector_checks > 0 {
                return Some(
                    "Fallback function has hardcoded selector checks. This can shadow implementation functions. \
                    Consider using Diamond pattern with storage-based routing or transparent proxy pattern".to_string()
                );
            }
        }

        // Check for hardcoded bytes4 selectors in fallback
        if source.contains("bytes4 private constant") && source.contains("SELECTOR") {
            let selector_defs = source.matches("bytes4 private constant").count();
            if selector_defs > 0 {
                return Some(
                    "Fallback defines hardcoded function selectors. These selectors will be intercepted and never reach implementation. \
                    Use storage-based selector routing instead".to_string()
                );
            }
        }

        None
    }

    /// Check if contract uses ifAdmin pattern (transparent proxy)
    fn has_if_admin_pattern(&self, source: &str, ctx: &AnalysisContext) -> bool {
        let contract_source = &ctx.source_code;

        // Check for ifAdmin modifier
        if contract_source.contains("modifier ifAdmin") {
            return true;
        }

        // Check for admin check pattern
        if source.contains("msg.sender == admin") || source.contains("msg.sender == _getAdmin") {
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

    /// Check if receive function exists alongside fallback
    fn has_receive_shadowing(&self, ctx: &AnalysisContext) -> Option<String> {
        let mut has_receive = false;
        let mut has_fallback_with_delegatecall = false;

        for function in ctx.get_functions() {
            match function.function_type {
                ast::FunctionType::Receive => {
                    has_receive = true;
                }
                ast::FunctionType::Fallback => {
                    let source = self.get_function_source(function, ctx);
                    if source.contains("delegatecall") {
                        has_fallback_with_delegatecall = true;
                    }
                }
                _ => {}
            }
        }

        // If proxy has receive function, it shadows implementation's receive
        if has_receive && has_fallback_with_delegatecall && self.is_proxy_contract(ctx) {
            return Some(
                "Proxy defines receive() function which shadows implementation's receive logic. \
                Consider delegating receive to implementation or documenting why proxy handles ETH".to_string()
            );
        }

        None
    }
}

impl Default for FallbackFunctionShadowingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FallbackFunctionShadowingDetector {
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

        // Skip if not a proxy contract
        if !self.is_proxy_contract(ctx) {
            return Ok(findings);
        }

        // Check for receive function shadowing
        if let Some(issue) = self.has_receive_shadowing(ctx) {
            let message = format!(
                "Contract '{}' has receive function shadowing. {}",
                ctx.contract.name.name, issue
            );

            let finding = self.base
                .create_finding(
                    ctx,
                    message,
                    ctx.contract.name.location.start().line() as u32,
                    ctx.contract.name.location.start().column() as u32,
                    ctx.contract.name.name.len() as u32,
                )
                .with_cwe(670);

            findings.push(finding);
        }

        // Check each function for shadowing risks
        for function in ctx.get_functions() {
            // Check for shadowing risk in regular functions
            if let Some(risk_description) = self.has_shadowing_risk(function, ctx) {
                let message = format!(
                    "Function '{}' in proxy contract may shadow implementation. {} \
                    Real-world impact: Similar to issues in various proxy implementations where admin functions were shadowed.",
                    function.name.name, risk_description
                );

                let finding = self.base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(670);

                findings.push(finding);
            }

            // Check for hardcoded selectors in fallback
            if let Some(selector_issue) = self.has_hardcoded_selectors(function, ctx) {
                let message = format!(
                    "Fallback function '{}' has hardcoded selector routing. {}",
                    function.name.name, selector_issue
                );

                let finding = self.base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(670);

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
        let detector = FallbackFunctionShadowingDetector::new();
        assert_eq!(detector.id().0, "fallback-function-shadowing");
        assert_eq!(detector.name(), "Fallback Function Shadowing");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_default() {
        let detector = FallbackFunctionShadowingDetector::default();
        assert_eq!(detector.id().0, "fallback-function-shadowing");
    }
}
