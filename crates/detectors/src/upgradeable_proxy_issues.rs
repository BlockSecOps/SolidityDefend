use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::{is_secure_example_file, is_test_contract};

/// Detector for upgradeable proxy pattern vulnerabilities
pub struct UpgradeableProxyIssuesDetector {
    base: BaseDetector,
}

impl Default for UpgradeableProxyIssuesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UpgradeableProxyIssuesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("upgradeable-proxy-issues".to_string()),
                "Upgradeable Proxy Issues".to_string(),
                "Detects vulnerabilities in upgradeable proxy patterns including storage collisions, initialization issues, and unsafe upgrades".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for UpgradeableProxyIssuesDetector {
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

        // Phase 10: Skip test contracts and secure examples
        if is_test_contract(ctx) || is_secure_example_file(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(proxy_issue) = self.check_upgradeable_proxy_issues(function, ctx) {
                let message = format!(
                    "Function '{}' has upgradeable proxy vulnerability. {} \
                    Improper proxy patterns can lead to storage corruption, unauthorized upgrades, or complete contract takeover.",
                    function.name.name, proxy_issue
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
                    .with_cwe(665) // CWE-665: Improper Initialization
                    .with_cwe(913) // CWE-913: Improper Control of Dynamically-Managed Code Resources
                    .with_fix_suggestion(format!(
                        "Fix proxy implementation in '{}'. \
                    Use storage gaps for future upgrades, implement initializer modifiers, \
                    add upgrade delay with timelock, validate implementation addresses, \
                    use UUPS pattern with _authorizeUpgrade, and emit events for all upgrades.",
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

impl UpgradeableProxyIssuesDetector {
    /// Check if contract is actually a proxy contract (Phase 6: Tightened)
    fn is_proxy_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // Strong proxy signals - require EIP-1967 slots OR explicit proxy inheritance
        let has_eip1967_slots = source.contains("IMPLEMENTATION_SLOT")
            || source.contains("_IMPLEMENTATION_SLOT")
            || source.contains("EIP1967")
            || source.contains("ERC1967")
            || source.contains("0x360894a13ba1a3210667c828492db98dca3e2076");

        let has_explicit_proxy_inheritance = source.contains("TransparentUpgradeableProxy")
            || source.contains("UUPSUpgradeable")
            || source.contains("BeaconProxy")
            || source.contains("ERC1967Proxy");

        // Delegatecall with implementation is strong signal
        let has_delegatecall_pattern = source.contains("delegatecall")
            && (source.contains("implementation") || source.contains("_implementation"));

        // Phase 6: Require at least one strong signal
        // Skip generic "upgradeable" patterns without delegatecall
        has_eip1967_slots || has_explicit_proxy_inheritance || has_delegatecall_pattern
    }

    /// Check if function has admin protection
    fn has_admin_protection(&self, func_source: &str) -> bool {
        func_source.contains("onlyOwner")
            || func_source.contains("onlyAdmin")
            || func_source.contains("onlyProxyAdmin")
            || func_source.contains("require(msg.sender == admin")
            || func_source.contains("require(msg.sender == owner")
            || func_source.contains("_checkAdmin")
            || func_source.contains("_checkOwner")
    }

    /// Check for upgradeable proxy vulnerabilities
    fn check_upgradeable_proxy_issues(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        // First check if this is actually a proxy contract
        if !self.is_proxy_contract(ctx) {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check if function is related to proxy/upgrade functionality
        let is_proxy_related = func_source.contains("delegatecall")
            || func_source.contains("implementation")
            || func_source.contains("upgrade")
            || func_source.contains("initialize")
            || function.name.name.to_lowercase().contains("upgrade")
            || function.name.name.to_lowercase().contains("initialize");

        if !is_proxy_related {
            return None;
        }

        // Pattern 1: Unprotected upgrade function
        let is_upgrade_function = func_source.contains("upgrade")
            || func_source.contains("implementation")
            || function.name.name.to_lowercase().contains("upgrade");

        let lacks_access_control = is_upgrade_function
            && !func_source.contains("onlyOwner")
            && !func_source.contains("onlyAdmin")
            && !func_source.contains("require(msg.sender");

        if lacks_access_control {
            return Some(
                "Upgrade function lacks proper access control, \
                anyone can upgrade contract to malicious implementation"
                    .to_string(),
            );
        }

        // Pattern 2: Initialize function can be called multiple times
        let is_initialize = func_source.contains("initialize")
            || function.name.name.to_lowercase().contains("initialize");

        let no_initialization_guard = is_initialize
            && !func_source.contains("initializer")
            && !func_source.contains("initialized")
            && !func_source.contains("require(!initialized");

        if no_initialization_guard {
            return Some(
                "Initialize function lacks initialization guard, \
                can be called multiple times to reset contract state"
                    .to_string(),
            );
        }

        // Pattern 3: Missing storage gap for future upgrades
        let contract_source = ctx.source_code.as_str();

        let is_upgradeable_contract = contract_source.contains("Initializable")
            || contract_source.contains("UUPSUpgradeable")
            || contract_source.contains("upgradeable");

        let no_storage_gap = is_upgradeable_contract
            && !contract_source.contains("__gap")
            && !contract_source.contains("uint256[50]");

        if no_storage_gap && is_proxy_related {
            return Some(
                "Upgradeable contract missing storage gap, \
                future upgrades may cause storage collision"
                    .to_string(),
            );
        }

        // Pattern 4: Unsafe delegatecall without implementation validation
        let uses_delegatecall = func_source.contains("delegatecall");

        let no_impl_validation = uses_delegatecall
            && !func_source.contains("require")
            && !func_source.contains("isContract");

        if no_impl_validation {
            return Some(
                "Delegatecall without validating implementation address, \
                can delegate to non-contract or malicious code"
                    .to_string(),
            );
        }

        // Pattern 5: No upgrade delay/timelock
        // Phase 6: Skip if function has admin protection (admin-gated upgrades are acceptable)
        let has_timelock = func_source.contains("timelock")
            || func_source.contains("delay")
            || func_source.contains("timestamp")
            || func_source.contains("pendingImplementation");

        let immediate_upgrade =
            is_upgrade_function && !has_timelock && !self.has_admin_protection(&func_source);

        if immediate_upgrade {
            return Some(
                "Upgrade executes immediately without timelock delay, \
                no time for users to exit before malicious upgrade"
                    .to_string(),
            );
        }

        // Pattern 6: Constructor instead of initializer
        let is_constructor = function.name.name == "constructor";

        let constructor_in_upgradeable = is_constructor
            && (contract_source.contains("upgradeable")
                || contract_source.contains("Initializable"));

        if constructor_in_upgradeable {
            return Some(
                "Upgradeable contract uses constructor instead of initializer, \
                constructor code only runs for implementation, not proxy"
                    .to_string(),
            );
        }

        // Pattern 7: Selfdestruct in implementation
        // Phase 6: Only flag if selfdestruct is actually callable (in public/external function)
        let has_selfdestruct = func_source.contains("selfdestruct");

        let is_callable = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        if has_selfdestruct && is_proxy_related && is_callable {
            return Some(
                "Implementation contract contains selfdestruct in callable function, \
                can destroy implementation leaving proxy pointing to empty address"
                    .to_string(),
            );
        }

        // Pattern 8: No upgrade event emission
        // Phase 6: Skip for internal/private functions (they're helper functions)
        let emits_event = func_source.contains("emit");

        let no_upgrade_event = is_upgrade_function && !emits_event && is_callable;

        if no_upgrade_event {
            return Some(
                "Upgrade function doesn't emit event, \
                users cannot track contract upgrades"
                    .to_string(),
            );
        }

        // Pattern 9: UUPS without _authorizeUpgrade override
        let is_uups =
            contract_source.contains("UUPS") || contract_source.contains("UUPSUpgradeable");

        let no_authorize_override =
            is_uups && !contract_source.contains("_authorizeUpgrade") && is_upgrade_function;

        if no_authorize_override {
            return Some(
                "UUPS pattern without _authorizeUpgrade override, \
                missing upgrade authorization check"
                    .to_string(),
            );
        }

        // Pattern 10: Transparent proxy with function selector clash
        let is_transparent_proxy = contract_source.contains("TransparentUpgradeableProxy")
            || func_source.contains("admin()")
            || func_source.contains("implementation()");

        let potential_clash = is_transparent_proxy
            && (func_source.contains("admin") || func_source.contains("implementation"))
            && !func_source.contains("ifAdmin");

        if potential_clash {
            return Some(
                "Transparent proxy may have function selector clash, \
                admin functions could conflict with implementation functions"
                    .to_string(),
            );
        }

        None
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
        let detector = UpgradeableProxyIssuesDetector::new();
        assert_eq!(detector.name(), "Upgradeable Proxy Issues");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
