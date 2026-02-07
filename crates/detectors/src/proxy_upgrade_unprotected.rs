use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for unprotected proxy upgrade functions
///
/// This detector identifies upgradeable proxy contracts where the upgrade function
/// lacks proper access control, allowing anyone to upgrade the implementation contract.
///
/// **Vulnerability:** CWE-284 (Improper Access Control)
/// **Severity:** Critical
///
/// ## Real-World Exploits
///
/// - **Wormhole Bridge ($320M, 2022)**: Attacker upgraded implementation to malicious contract
/// - **Audius ($6M, 2022)**: Unprotected delegatecall allowed arbitrary code execution
///
pub struct ProxyUpgradeUnprotectedDetector {
    base: BaseDetector,
}

impl Default for ProxyUpgradeUnprotectedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyUpgradeUnprotectedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("proxy-upgrade-unprotected".to_string()),
                "Unprotected Proxy Upgrade".to_string(),
                "Detects proxy upgrade functions without proper access control, allowing anyone to replace the implementation contract"
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for ProxyUpgradeUnprotectedDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        for function in ctx.get_functions() {
            if let Some(risk_description) = self.has_unprotected_upgrade(function, ctx) {
                let message = format!(
                    "Function '{}' is an unprotected proxy upgrade function. {} \
                    This allows any address to upgrade the implementation contract, \
                    potentially leading to complete takeover with fund theft and data manipulation.",
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
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_cwe(306) // CWE-306: Missing Authentication for Critical Function
                    .with_fix_suggestion(format!(
                        "Add access control to '{}'. \
                    Use modifiers like 'onlyOwner', 'onlyAdmin', or implement role-based access control. \
                    Example: function {}(...) external onlyOwner {{ ... }}",
                        function.name.name, function.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ProxyUpgradeUnprotectedDetector {
    /// Check if function is an unprotected proxy upgrade function
    fn has_unprotected_upgrade(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        // Must have a function body
        function.body.as_ref()?;

        // Get function source code
        let func_source = self.get_function_source(function, ctx);

        // Check if this is an upgrade function
        if !self.is_upgrade_function(function, &func_source) {
            return None;
        }

        // Must be public or external
        let is_public_or_external = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        if !is_public_or_external {
            return None;
        }

        // Check for access control
        if self.has_access_control(&func_source, function) {
            return None;
        }

        // Check if it modifies implementation storage
        if !self.modifies_implementation(&func_source) {
            return None;
        }

        Some(format!(
            "The upgrade function '{}' is {} and lacks access control modifiers. \
            It modifies implementation storage without verifying msg.sender permissions.",
            function.name.name,
            match function.visibility {
                ast::Visibility::Public => "public",
                ast::Visibility::External => "external",
                _ => "accessible",
            }
        ))
    }

    /// Check if function name or pattern suggests upgrade functionality
    fn is_upgrade_function(&self, function: &ast::Function<'_>, source: &str) -> bool {
        let name_lower = function.name.name.to_lowercase();

        // Common upgrade function names
        let upgrade_names = [
            "upgradeto",
            "upgrade",
            "setimplementation",
            "updateimplementation",
            "changeimplementation",
            "replaceimplementation",
            "_authorizeupgrade", // UUPS pattern
            "upgradetoandcall",
        ];

        // Check function name
        if upgrade_names
            .iter()
            .any(|pattern| name_lower.contains(pattern))
        {
            return true;
        }

        // Check if source modifies implementation-related storage
        source.contains("_implementation =") || source.contains("implementation =")
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
                || modifier_name.contains("admin")
                || modifier_name.contains("owner")
                || modifier_name.contains("governance")
            {
                return true;
            }
        }

        // Check for inline access control in source
        source.contains("require(msg.sender ==")
            || source.contains("require(msg.sender == owner")
            || source.contains("require(msg.sender == admin")
            || source.contains("if (msg.sender != owner)")
            || source.contains("if (msg.sender != admin)")
            || source.contains("onlyOwner")
            || source.contains("onlyAdmin")
            || source.contains("onlyGovernance")
            || source.contains("onlyRole")
            || source.contains("hasRole")
    }

    /// Check if function modifies implementation storage
    fn modifies_implementation(&self, source: &str) -> bool {
        // Direct storage variable assignment
        if source.contains("_implementation =") || source.contains("implementation =") {
            return true;
        }

        // Assembly sstore to EIP-1967 slots
        if source.contains("sstore") && source.contains("eip1967.proxy.implementation") {
            return true;
        }

        // Storage slot modification patterns
        if source.contains("sstore")
            && (source.contains("IMPLEMENTATION_SLOT") || source.contains("implementation"))
        {
            return true;
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
        let detector = ProxyUpgradeUnprotectedDetector::new();
        assert_eq!(detector.name(), "Unprotected Proxy Upgrade");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "proxy-upgrade-unprotected");
    }
}
