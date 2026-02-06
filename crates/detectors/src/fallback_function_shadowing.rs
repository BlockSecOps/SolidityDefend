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
                vec![
                    DetectorCategory::AccessControl,
                    DetectorCategory::Upgradeable,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Get contract source code (scoped to just this contract, not the whole file)
    /// FP Reduction: Avoids flagging non-proxy contracts that share a file with a proxy
    fn get_contract_source(&self, contract: &ast::Contract<'_>, ctx: &AnalysisContext) -> String {
        let start = contract.location.start().line();
        let end = contract.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start > 0 && end <= source_lines.len() {
            let start_idx = start.saturating_sub(1);
            source_lines[start_idx..end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check if contract looks like a proxy
    /// FP Reduction: Uses contract-scoped source instead of file-level source
    /// to avoid flagging non-proxy contracts that happen to share a file with a proxy
    fn is_proxy_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Check if contract name suggests it's a proxy
        if contract_name.contains("proxy") {
            return true;
        }

        // Check if THIS contract has fallback with delegatecall (not just any contract in the file)
        if source.contains("fallback") && source.contains("delegatecall") {
            return true;
        }

        // Check for EIP-1967 storage slots within this contract
        if source.contains("eip1967.proxy.implementation") {
            return true;
        }

        false
    }

    /// Check if a function is a standard proxy admin/infrastructure function
    /// that is DESIGNED to exist in the proxy contract itself.
    /// These are NOT shadowing -- they are core proxy functionality.
    /// Note: Not currently used in has_shadowing_risk to avoid false negatives
    /// on non-transparent proxy contracts that define these functions.
    #[allow(dead_code)]
    fn is_standard_proxy_function(&self, func_name: &str, func_source: &str) -> bool {
        // Standard proxy admin functions that modify proxy state (with access control)
        let proxy_admin_functions = [
            "upgradeto",
            "upgradetoandcall",
            "changeadmin",
            "setimplementation",
            "changeimplementation",
        ];

        // Standard proxy getter/view functions (always safe in proxy)
        let proxy_view_functions = ["implementation", "admin", "getimplementation", "getadmin"];

        // View/getter functions in proxy are always safe -- they read proxy state
        for view_fn in &proxy_view_functions {
            if func_name == *view_fn {
                return true;
            }
        }

        // Admin functions with access control are standard proxy functionality
        for admin_fn in &proxy_admin_functions {
            if func_name.contains(admin_fn) && self.has_access_control(func_source) {
                return true;
            }
        }

        false
    }

    /// Check if function has any form of access control
    /// Used by is_standard_proxy_function for proxy admin function identification
    #[allow(dead_code)]
    fn has_access_control(&self, func_source: &str) -> bool {
        // Modifier-based access control
        func_source.contains("onlyOwner")
            || func_source.contains("onlyAdmin")
            || func_source.contains("onlyProxyAdmin")
            || func_source.contains("ifAdmin")
            // Require-based access control
            || func_source.contains("require(msg.sender == admin")
            || func_source.contains("require(msg.sender == owner")
            || func_source.contains("require(msg.sender == _admin")
            || func_source.contains("msg.sender == _getAdmin")
            || func_source.contains("msg.sender == getAdmin")
            || func_source.contains("_checkAdmin")
            || func_source.contains("_checkOwner")
            || func_source.contains("require(msg.sender ==")
    }

    /// Check if function could shadow implementation functions
    fn has_shadowing_risk(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let func_name = function.name.name.to_lowercase();
        let source = self.get_function_source(function, ctx);

        // Skip if function is internal or private (can't shadow)
        match function.visibility {
            ast::Visibility::Internal | ast::Visibility::Private => return None,
            _ => {}
        }

        // Check for common proxy admin functions that might shadow implementation
        let risky_function_names = [
            "upgrade",
            "upgradeto",
            "setimplementation",
            "changeimplementation",
            "transferownership",
            "changeowner",
            "setowner",
            "pause",
            "unpause",
            "initialize",
            "init",
            "getadmin",
            "getowner",
            "getimplementation",
            "getversion",
        ];

        for risky_name in &risky_function_names {
            if func_name.contains(risky_name) {
                // Check if this is in a proxy contract
                if self.is_proxy_contract(ctx) {
                    // FP Reduction: Check for broader access control patterns,
                    // not just ifAdmin modifier
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
    fn has_hardcoded_selectors(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let source = self.get_function_source(function, ctx);

        // Check if fallback/receive function
        if !matches!(
            function.function_type,
            ast::FunctionType::Fallback | ast::FunctionType::Receive
        ) {
            return None;
        }

        // Look for hardcoded selector checks
        if source.contains("msg.sig ==")
            || source.contains("msg.sig!=")
            || source.contains("selector ==")
        {
            // Check if there are multiple selector checks (likely routing logic)
            let selector_checks =
                source.matches("msg.sig").count() + source.matches("selector ==").count();
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

    /// Check if contract uses ifAdmin/transparent proxy pattern
    /// FP Reduction: Uses contract-scoped source and recognizes common transparent
    /// proxy admin-separation patterns (not just generic access control)
    fn has_if_admin_pattern(&self, source: &str, ctx: &AnalysisContext) -> bool {
        let contract_source = self.get_contract_source(ctx.contract, ctx);

        // Check for ifAdmin modifier in THIS contract (standard transparent proxy pattern)
        if contract_source.contains("modifier ifAdmin") {
            return true;
        }

        // Check for transparent proxy admin check patterns in the function
        // These specifically separate admin vs user paths (not just generic access control)
        if source.contains("msg.sender == admin")
            || source.contains("msg.sender == _getAdmin")
            || source.contains("msg.sender == getAdmin")
            || source.contains("msg.sender == _admin")
            || source.contains("ifAdmin")
            || source.contains("onlyProxyAdmin")
            || source.contains("_checkAdmin")
        {
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
    /// FP Reduction: Skip receive functions that delegate to the implementation
    /// (this is proper transparent proxy behavior, not shadowing)
    fn has_receive_shadowing(&self, ctx: &AnalysisContext) -> Option<String> {
        let mut has_receive = false;
        let mut receive_delegates = false;
        let mut has_fallback_with_delegatecall = false;

        for function in ctx.get_functions() {
            match function.function_type {
                ast::FunctionType::Receive => {
                    has_receive = true;
                    let source = self.get_function_source(function, ctx);
                    // FP Reduction: If receive() delegates to implementation, it's not shadowing
                    if source.contains("_delegate") || source.contains("delegatecall") {
                        receive_delegates = true;
                    }
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

        // FP Reduction: If receive() delegates to implementation, it's not shadowing
        // This is the correct transparent proxy pattern
        if receive_delegates {
            return None;
        }

        // Only flag if proxy has a receive function that does NOT delegate
        if has_receive && has_fallback_with_delegatecall && self.is_proxy_contract(ctx) {
            return Some(
                "Proxy defines receive() function which shadows implementation's receive logic. \
                Consider delegating receive to implementation or documenting why proxy handles ETH"
                    .to_string(),
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

            let finding = self
                .base
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

                let finding = self
                    .base
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

                let finding = self
                    .base
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
