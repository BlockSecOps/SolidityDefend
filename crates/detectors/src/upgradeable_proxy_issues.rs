use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for upgradeable proxy pattern vulnerabilities
pub struct UpgradeableProxyIssuesDetector {
    base: BaseDetector,
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
    /// Check for upgradeable proxy vulnerabilities
    fn check_upgradeable_proxy_issues(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
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
            return Some(format!(
                "Upgrade function lacks proper access control, \
                anyone can upgrade contract to malicious implementation"
            ));
        }

        // Pattern 2: Initialize function can be called multiple times
        let is_initialize = func_source.contains("initialize")
            || function.name.name.to_lowercase().contains("initialize");

        let no_initialization_guard = is_initialize
            && !func_source.contains("initializer")
            && !func_source.contains("initialized")
            && !func_source.contains("require(!initialized");

        if no_initialization_guard {
            return Some(format!(
                "Initialize function lacks initialization guard, \
                can be called multiple times to reset contract state"
            ));
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
            return Some(format!(
                "Upgradeable contract missing storage gap, \
                future upgrades may cause storage collision"
            ));
        }

        // Pattern 4: Unsafe delegatecall without implementation validation
        let uses_delegatecall = func_source.contains("delegatecall");

        let no_impl_validation = uses_delegatecall
            && !func_source.contains("require")
            && !func_source.contains("isContract");

        if no_impl_validation {
            return Some(format!(
                "Delegatecall without validating implementation address, \
                can delegate to non-contract or malicious code"
            ));
        }

        // Pattern 5: No upgrade delay/timelock
        let has_timelock = func_source.contains("timelock")
            || func_source.contains("delay")
            || func_source.contains("timestamp");

        let immediate_upgrade = is_upgrade_function && !has_timelock;

        if immediate_upgrade {
            return Some(format!(
                "Upgrade executes immediately without timelock delay, \
                no time for users to exit before malicious upgrade"
            ));
        }

        // Pattern 6: Constructor instead of initializer
        let is_constructor = function.name.name == "constructor";

        let constructor_in_upgradeable = is_constructor
            && (contract_source.contains("upgradeable")
                || contract_source.contains("Initializable"));

        if constructor_in_upgradeable {
            return Some(format!(
                "Upgradeable contract uses constructor instead of initializer, \
                constructor code only runs for implementation, not proxy"
            ));
        }

        // Pattern 7: Selfdestruct in implementation
        let has_selfdestruct = func_source.contains("selfdestruct");

        if has_selfdestruct && is_proxy_related {
            return Some(format!(
                "Implementation contract contains selfdestruct, \
                can destroy implementation leaving proxy pointing to empty address"
            ));
        }

        // Pattern 8: No upgrade event emission
        let emits_event = func_source.contains("emit");

        let no_upgrade_event = is_upgrade_function && !emits_event;

        if no_upgrade_event {
            return Some(format!(
                "Upgrade function doesn't emit event, \
                users cannot track contract upgrades"
            ));
        }

        // Pattern 9: UUPS without _authorizeUpgrade override
        let is_uups =
            contract_source.contains("UUPS") || contract_source.contains("UUPSUpgradeable");

        let no_authorize_override =
            is_uups && !contract_source.contains("_authorizeUpgrade") && is_upgrade_function;

        if no_authorize_override {
            return Some(format!(
                "UUPS pattern without _authorizeUpgrade override, \
                missing upgrade authorization check"
            ));
        }

        // Pattern 10: Transparent proxy with function selector clash
        let is_transparent_proxy = contract_source.contains("TransparentUpgradeableProxy")
            || func_source.contains("admin()")
            || func_source.contains("implementation()");

        let potential_clash = is_transparent_proxy
            && (func_source.contains("admin") || func_source.contains("implementation"))
            && !func_source.contains("ifAdmin");

        if potential_clash {
            return Some(format!(
                "Transparent proxy may have function selector clash, \
                admin functions could conflict with implementation functions"
            ));
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
