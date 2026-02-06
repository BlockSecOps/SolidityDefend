use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for missing upgrade events
///
/// Detects upgradeable contracts that don't emit standard events when upgraded.
/// Missing events make it impossible for monitoring tools to track upgrades.
///
/// Vulnerable pattern:
/// ```solidity
/// function _authorizeUpgrade(address newImpl) internal override onlyOwner {
///     // Missing: emit Upgraded(newImpl);
/// }
/// ```
pub struct UpgradeEventMissingDetector {
    base: BaseDetector,
}

impl Default for UpgradeEventMissingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UpgradeEventMissingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("upgrade-event-missing"),
                "Missing Upgrade Events".to_string(),
                "Detects upgradeable contracts that don't emit events when upgraded. \
                 Standard events (Upgraded, AdminChanged, BeaconUpgraded) are essential \
                 for monitoring tools, block explorers, and security monitoring."
                    .to_string(),
                vec![
                    DetectorCategory::Upgradeable,
                    DetectorCategory::BestPractices,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Check if contract is upgradeable
    fn is_upgradeable(&self, source: &str) -> bool {
        source.contains("Upgradeable")
            || source.contains("UUPSUpgradeable")
            || source.contains("_authorizeUpgrade")
            || source.contains("upgradeTo")
            || source.contains("upgradeToAndCall")
            || source.contains("TransparentUpgradeable")
            || source.contains("UpgradeableBeacon")
    }

    /// Find upgrade functions without event emission
    fn find_upgrade_without_event(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let upgrade_func_patterns = [
            "_authorizeUpgrade",
            "upgradeTo",
            "upgradeToAndCall",
            "_upgradeTo",
            "_setImplementation",
            "setImplementation",
            "_upgradeBeacon",
            "upgradeBeacon",
        ];

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            for pattern in &upgrade_func_patterns {
                if trimmed.contains(&format!("function {}", pattern))
                    || trimmed.contains(&format!("function {}", pattern))
                {
                    // Find function body
                    let func_end = self.find_function_end(&lines, line_num);
                    let func_body: String = lines[line_num..func_end].join("\n");

                    // Check for event emission
                    let has_upgrade_event = func_body.contains("emit Upgraded")
                        || func_body.contains("emit AdminChanged")
                        || func_body.contains("emit BeaconUpgraded")
                        || func_body.contains("emit ImplementationChanged")
                        || func_body.contains("emit ProxyUpgraded")
                        || func_body.contains("Upgraded(");

                    // Also check if it calls a function that emits
                    let delegates_event = func_body.contains("_upgradeTo(")
                        || func_body.contains("_upgradeToAndCall(")
                        || func_body.contains("super.");

                    if !has_upgrade_event && !delegates_event {
                        findings.push((line_num as u32 + 1, pattern.to_string()));
                    }
                }
            }
        }

        findings
    }

    /// Find admin change functions without event
    fn find_admin_change_without_event(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let admin_func_patterns = [
            "changeAdmin",
            "setAdmin",
            "_changeAdmin",
            "_setAdmin",
            "transferProxyAdmin",
        ];

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            for pattern in &admin_func_patterns {
                if trimmed.contains(&format!("function {}", pattern)) {
                    let func_end = self.find_function_end(&lines, line_num);
                    let func_body: String = lines[line_num..func_end].join("\n");

                    let has_admin_event = func_body.contains("emit AdminChanged")
                        || func_body.contains("emit ProxyAdminChanged")
                        || func_body.contains("AdminChanged(");

                    if !has_admin_event {
                        findings.push((line_num as u32 + 1, pattern.to_string()));
                    }
                }
            }
        }

        findings
    }

    /// Check for custom upgrade implementation without any events
    fn has_custom_upgrade_no_events(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        // Check for EIP-1967 slot writes without events
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for implementation slot writes
            if trimmed.contains("sstore(")
                && (trimmed.contains("IMPLEMENTATION_SLOT")
                    || trimmed.contains("_IMPLEMENTATION_SLOT")
                    || trimmed.contains("0x360894"))
            {
                // Check surrounding context for event
                let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                let context_end = std::cmp::min(line_num + 10, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                if !context.contains("emit Upgraded")
                    && !context.contains("emit Implementation")
                    && !context.contains("Upgraded(")
                {
                    return Some(line_num as u32 + 1);
                }
            }
        }

        None
    }

    /// Find the end of a function
    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => {
                        depth -= 1;
                        if started && depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for UpgradeEventMissingDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Only check upgradeable contracts
        if !self.is_upgradeable(source) {
            return Ok(findings);
        }

        // Check for upgrade functions without events
        let upgrades_no_event = self.find_upgrade_without_event(source);
        for (line, func_name) in upgrades_no_event {
            let message = format!(
                "Function '{}' in contract '{}' doesn't emit an upgrade event. \
                 Monitoring tools, block explorers, and security systems rely on \
                 standard events (Upgraded, AdminChanged) to track proxy upgrades.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(778) // CWE-778: Insufficient Logging
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add standard EIP-1967 events:\n\n\
                     event Upgraded(address indexed implementation);\n\
                     event AdminChanged(address previousAdmin, address newAdmin);\n\
                     event BeaconUpgraded(address indexed beacon);\n\n\
                     function _authorizeUpgrade(address newImpl) internal override {\n\
                         // authorization logic\n\
                         emit Upgraded(newImpl);\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Check for admin changes without events
        let admin_no_event = self.find_admin_change_without_event(source);
        for (line, func_name) in admin_no_event {
            let message = format!(
                "Function '{}' in contract '{}' changes admin without emitting AdminChanged event.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(778) // CWE-778: Insufficient Logging
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Emit AdminChanged event:\n\n\
                     function _changeAdmin(address newAdmin) internal {\n\
                         emit AdminChanged(_getAdmin(), newAdmin);\n\
                         _setAdmin(newAdmin);\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Check for custom upgrade without events
        if let Some(line) = self.has_custom_upgrade_no_events(source) {
            let message = format!(
                "Contract '{}' writes to implementation slot without emitting Upgraded event. \
                 This makes upgrades invisible to monitoring systems.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(778) // CWE-778: Insufficient Logging
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Emit Upgraded event when changing implementation:\n\n\
                     assembly {\n\
                         sstore(_IMPLEMENTATION_SLOT, newImpl)\n\
                     }\n\
                     emit Upgraded(newImpl);"
                        .to_string(),
                );

            findings.push(finding);
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
        let detector = UpgradeEventMissingDetector::new();
        assert_eq!(detector.name(), "Missing Upgrade Events");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_upgradeable() {
        let detector = UpgradeEventMissingDetector::new();

        assert!(detector.is_upgradeable("contract X is UUPSUpgradeable {}"));
        assert!(detector.is_upgradeable("function _authorizeUpgrade(address) {}"));
        assert!(detector.is_upgradeable("function upgradeTo(address) external {}"));
        assert!(!detector.is_upgradeable("contract SimpleToken {}"));
    }

    #[test]
    fn test_upgrade_without_event() {
        let detector = UpgradeEventMissingDetector::new();

        let no_event = r#"
            contract Impl is UUPSUpgradeable {
                function _authorizeUpgrade(address) internal override onlyOwner {
                    // no event
                }
            }
        "#;
        let findings = detector.find_upgrade_without_event(no_event);
        assert!(!findings.is_empty());

        let with_event = r#"
            contract Impl is UUPSUpgradeable {
                function _authorizeUpgrade(address newImpl) internal override onlyOwner {
                    emit Upgraded(newImpl);
                }
            }
        "#;
        let findings = detector.find_upgrade_without_event(with_event);
        assert!(findings.is_empty());
    }
}
