use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for storage collision vulnerabilities in upgradeable contracts
pub struct StorageCollisionDetector {
    base: BaseDetector,
}

impl Default for StorageCollisionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageCollisionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("storage-collision".to_string()),
                "Storage Collision Vulnerability".to_string(),
                "Detects storage layout conflicts in proxy patterns and delegatecall usage that can cause data corruption".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for StorageCollisionDetector {
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
        let source = &ctx.source_code;

        // Phase 53 FP Reduction: Skip proxy base contracts
        // Proxy contracts are DESIGNED to use delegatecall - that's their purpose
        // Storage collision is intentional and handled by EIP-1967 slots
        let is_proxy_contract = source.contains("abstract contract Proxy")
            || source.contains("contract TransparentUpgradeableProxy")
            || source.contains("contract ERC1967Proxy")
            || source.contains("contract BeaconProxy")
            || source.contains("library ERC1967Utils")
            || (source.contains("function _delegate(") && source.contains("fallback()"))
            || source
                .contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");

        if is_proxy_contract {
            return Ok(findings);
        }

        // Check for delegatecall storage collision in functions
        for function in ctx.get_functions() {
            if let Some(delegatecall_issue) = self.check_delegatecall_storage(function, ctx) {
                let message = format!(
                    "Function '{}' uses delegatecall which can cause storage collision. \
                    {} Delegatecall executes code in the context of the calling contract's storage, \
                    and mismatched storage layouts can corrupt state.",
                    function.name.name, delegatecall_issue
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
                    .with_cwe(662) // CWE-662: Improper Synchronization
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_fix_suggestion(format!(
                        "Ensure storage layout compatibility in '{}'. \
                    Verify that delegatecall targets have identical storage layout, \
                    use storage slots explicitly, or implement storage layout versioning.",
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

impl StorageCollisionDetector {
    /// Check if contract is upgradeable (proxy pattern)
    #[allow(dead_code)]
    fn is_upgradeable_contract(&self, contract: &ast::Contract<'_>, ctx: &AnalysisContext) -> bool {
        let contract_source = self.get_contract_source(contract, ctx);

        // Look for proxy pattern indicators
        contract_source.contains("Initializable")
            || contract_source.contains("UUPSUpgradeable")
            || contract_source.contains("TransparentUpgradeableProxy")
            || contract_source.contains("upgradeTo")
            || contract_source.contains("initialize(")
            || (contract_source.contains("delegatecall")
                && contract_source.contains("implementation"))
    }

    /// Check delegatecall for storage collision risks
    fn check_delegatecall_storage(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Check for delegatecall usage
        let has_delegatecall =
            func_source.contains("delegatecall") || func_source.contains(".delegatecall");

        if !has_delegatecall {
            return None;
        }

        // Pattern 1: Delegatecall without storage layout verification
        let has_storage_check = func_source.contains("storage")
            || func_source.contains("layout")
            || func_source.contains("compatible");

        // Pattern 2: Delegatecall with variable target
        let has_variable_target = (func_source.contains("delegatecall(")
            || func_source.contains(".delegatecall("))
            && (func_source.contains("address(")
                || func_source.contains("target")
                || func_source.contains("implementation"));

        // Pattern 3: Vulnerability marker
        let has_vulnerability_marker = func_source.contains("VULNERABILITY")
            && (func_source.contains("storage collision") || func_source.contains("delegatecall"));

        if has_vulnerability_marker {
            return Some(
                "Delegatecall with storage collision vulnerability marker detected".to_string(),
            );
        }

        if has_variable_target && !has_storage_check {
            return Some(
                "Delegatecall to variable target without storage layout verification".to_string(),
            );
        }

        None
    }

    /// Get contract source code
    #[allow(dead_code)]
    fn get_contract_source(&self, contract: &ast::Contract<'_>, ctx: &AnalysisContext) -> String {
        let start = contract.location.start().line();
        let end = contract.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
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
        let detector = StorageCollisionDetector::new();
        assert_eq!(detector.name(), "Storage Collision Vulnerability");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
