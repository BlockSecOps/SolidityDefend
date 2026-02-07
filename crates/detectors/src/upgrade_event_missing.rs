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

    /// Check if a function signature line declares a view or pure function
    fn is_view_or_pure(func_body: &str) -> bool {
        // Check the first line (signature) for view/pure modifiers
        if let Some(first_brace) = func_body.find('{') {
            let sig = &func_body[..first_brace];
            return sig.contains(" view ")
                || sig.contains(" pure ")
                || sig.contains(" view\n")
                || sig.contains(" pure\n");
        }
        false
    }

    /// Check if a function is a private/internal helper by examining its signature
    fn is_private_or_internal_helper(func_body: &str) -> bool {
        if let Some(first_brace) = func_body.find('{') {
            let sig = &func_body[..first_brace];
            return sig.contains(" private") || sig.contains(" internal");
        }
        false
    }

    /// Check if a function name matches exactly (not as a substring of a longer name).
    /// For example, "upgradeTo" should NOT match "upgradeToAndCall".
    fn matches_function_exactly(line: &str, pattern: &str) -> bool {
        let search = format!("function {}", pattern);
        if let Some(pos) = line.find(&search) {
            let after = pos + search.len();
            if after < line.len() {
                let next_char = line.as_bytes()[after] as char;
                // After the function name, we expect '(' or whitespace, not alphanumeric
                return next_char == '(' || next_char == ' ' || next_char == '\t';
            }
            return true;
        }
        false
    }

    /// Check if any caller in the source calls the given helper and emits an upgrade event
    fn caller_emits_upgrade_event(&self, source: &str, helper_name: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let call_pattern = format!("{}(", helper_name);

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            // Find functions that contain a call to the helper
            if trimmed.starts_with("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Skip the helper function itself
                let sig_pattern = format!("function {}", helper_name);
                if trimmed.contains(&sig_pattern) {
                    continue;
                }

                if func_body.contains(&call_pattern) {
                    // This function calls our helper -- check if it emits an event
                    if func_body.contains("emit Upgraded")
                        || func_body.contains("emit AdminChanged")
                        || func_body.contains("emit BeaconUpgraded")
                        || func_body.contains("emit ImplementationChanged")
                        || func_body.contains("emit ProxyUpgraded")
                        || func_body.contains("Upgraded(")
                    {
                        return true;
                    }
                    // Also check if the caller delegates to another function that emits
                    if func_body.contains("upgradeTo(")
                        || func_body.contains("_upgradeTo(")
                        || func_body.contains("_upgradeToAndCall(")
                        || func_body.contains("super.")
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if any caller in the source calls the given helper and emits an admin event
    fn caller_emits_admin_event(&self, source: &str, helper_name: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let call_pattern = format!("{}(", helper_name);

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                let sig_pattern = format!("function {}", helper_name);
                if trimmed.contains(&sig_pattern) {
                    continue;
                }

                if func_body.contains(&call_pattern) {
                    if func_body.contains("emit AdminChanged")
                        || func_body.contains("emit ProxyAdminChanged")
                        || func_body.contains("AdminChanged(")
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Find upgrade functions without event emission
    fn find_upgrade_without_event(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let upgrade_func_patterns = [
            "_authorizeUpgrade",
            "upgradeToAndCall",
            "upgradeTo",
            "_upgradeTo",
            "_setImplementation",
            "setImplementation",
            "_upgradeBeacon",
            "upgradeBeacon",
        ];

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            for pattern in &upgrade_func_patterns {
                if !Self::matches_function_exactly(trimmed, pattern) {
                    continue;
                }

                // Find function body
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Skip view/pure functions -- they cannot modify state
                if Self::is_view_or_pure(&func_body) {
                    continue;
                }

                // Extract just the function body (after opening brace) for call checks
                let body_only = func_body
                    .find('{')
                    .map(|pos| &func_body[pos..])
                    .unwrap_or(&func_body);

                // Check for event emission in the function itself
                let has_upgrade_event = body_only.contains("emit Upgraded")
                    || body_only.contains("emit AdminChanged")
                    || body_only.contains("emit BeaconUpgraded")
                    || body_only.contains("emit ImplementationChanged")
                    || body_only.contains("emit ProxyUpgraded")
                    || body_only.contains("Upgraded(");

                // Check if it calls a function that emits (use body_only to avoid
                // matching the function's own name in its signature)
                let delegates_event = body_only.contains("_upgradeTo(")
                    || body_only.contains("_upgradeToAndCall(")
                    || body_only.contains("upgradeTo(")
                    || body_only.contains("super.");

                if has_upgrade_event || delegates_event {
                    continue;
                }

                // For private/internal helpers, check if any caller emits the event
                if Self::is_private_or_internal_helper(&func_body) {
                    if self.caller_emits_upgrade_event(source, pattern) {
                        continue;
                    }
                }

                findings.push((line_num as u32 + 1, pattern.to_string()));
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
                if !Self::matches_function_exactly(trimmed, pattern) {
                    continue;
                }

                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Skip view/pure functions
                if Self::is_view_or_pure(&func_body) {
                    continue;
                }

                let has_admin_event = func_body.contains("emit AdminChanged")
                    || func_body.contains("emit ProxyAdminChanged")
                    || func_body.contains("AdminChanged(");

                if has_admin_event {
                    continue;
                }

                // For private/internal helpers, check if any caller emits the event
                if Self::is_private_or_internal_helper(&func_body) {
                    if self.caller_emits_admin_event(source, pattern) {
                        continue;
                    }
                }

                findings.push((line_num as u32 + 1, pattern.to_string()));
            }
        }

        findings
    }

    /// Find the enclosing function name for a given line number
    fn find_enclosing_function<'a>(
        &self,
        lines: &[&'a str],
        target_line: usize,
    ) -> Option<&'a str> {
        // Walk backwards from target_line to find the enclosing function declaration
        for i in (0..=target_line).rev() {
            let trimmed = lines[i].trim();
            if trimmed.starts_with("function ") {
                // Extract the function name
                if let Some(paren_pos) = trimmed.find('(') {
                    let name_part = &trimmed["function ".len()..paren_pos];
                    return Some(name_part.trim());
                }
            }
        }
        None
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

                if context.contains("emit Upgraded")
                    || context.contains("emit Implementation")
                    || context.contains("Upgraded(")
                {
                    continue;
                }

                // Check if the enclosing function is a helper called by a function that emits
                if let Some(func_name) = self.find_enclosing_function(&lines, line_num) {
                    if self.caller_emits_upgrade_event(source, func_name) {
                        continue;
                    }
                }

                return Some(line_num as u32 + 1);
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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

    #[test]
    fn test_no_false_positive_on_private_helper_with_caller_event() {
        let detector = UpgradeEventMissingDetector::new();

        // _setImplementation is a private helper; upgradeTo emits the event
        let source = r#"
            contract Proxy {
                function upgradeTo(address newImpl) external onlyAdmin {
                    _setImplementation(newImpl);
                    emit Upgraded(newImpl);
                }

                function _setImplementation(address newImpl) private {
                    bytes32 slot = IMPLEMENTATION_SLOT;
                    assembly {
                        sstore(slot, newImpl)
                    }
                }
            }
        "#;
        let findings = detector.find_upgrade_without_event(source);
        // Should NOT flag _setImplementation because upgradeTo emits Upgraded
        assert!(
            findings.is_empty(),
            "Expected no findings for private helper with caller emitting event, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_no_false_positive_on_private_admin_helper() {
        let detector = UpgradeEventMissingDetector::new();

        // _setAdmin is private, changeAdmin emits AdminChanged
        let source = r#"
            contract Proxy {
                function changeAdmin(address newAdmin) external onlyAdmin {
                    address prev = _getAdmin();
                    _setAdmin(newAdmin);
                    emit AdminChanged(prev, newAdmin);
                }

                function _setAdmin(address newAdmin) private {
                    bytes32 slot = ADMIN_SLOT;
                    assembly {
                        sstore(slot, newAdmin)
                    }
                }
            }
        "#;
        let findings = detector.find_admin_change_without_event(source);
        assert!(
            findings.is_empty(),
            "Expected no findings for private _setAdmin with caller emitting event, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_exact_function_name_matching() {
        let detector = UpgradeEventMissingDetector::new();

        // upgradeToAndCall calls upgradeTo which emits -- should not be double-flagged
        let source = r#"
            contract Proxy {
                function upgradeTo(address newImpl) external onlyAdmin {
                    _setImpl(newImpl);
                    emit Upgraded(newImpl);
                }

                function upgradeToAndCall(address newImpl, bytes memory data) external onlyAdmin {
                    upgradeTo(newImpl);
                    if (data.length > 0) {
                        (bool s, ) = newImpl.delegatecall(data);
                        require(s);
                    }
                }
            }
        "#;
        let findings = detector.find_upgrade_without_event(source);
        assert!(
            findings.is_empty(),
            "Expected no findings for upgradeToAndCall that delegates to upgradeTo, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_true_positive_upgrade_no_event() {
        let detector = UpgradeEventMissingDetector::new();

        // Vulnerable: upgradeTo with no event at all
        let source = r#"
            contract Proxy {
                function upgradeTo(address newImpl) external {
                    implementation = newImpl;
                }
            }
        "#;
        let findings = detector.find_upgrade_without_event(source);
        assert_eq!(
            findings.len(),
            1,
            "Expected 1 finding for upgradeTo with no event"
        );
        assert_eq!(findings[0].1, "upgradeTo");
    }

    #[test]
    fn test_true_positive_set_implementation_no_caller() {
        let detector = UpgradeEventMissingDetector::new();

        // Vulnerable: public setImplementation with no event and no caller that emits
        let source = r#"
            contract Proxy {
                function setImplementation(address newImpl) external {
                    implementation = newImpl;
                }
            }
        "#;
        let findings = detector.find_upgrade_without_event(source);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].1, "setImplementation");
    }

    #[test]
    fn test_skip_view_pure_functions() {
        // View function named upgradeTo should not be flagged (unusual but valid)
        assert!(UpgradeEventMissingDetector::is_view_or_pure(
            "function upgradeTo(address) external view { return; }"
        ));
        assert!(UpgradeEventMissingDetector::is_view_or_pure(
            "function _setImplementation(address) internal pure { revert(); }"
        ));
        assert!(!UpgradeEventMissingDetector::is_view_or_pure(
            "function upgradeTo(address) external { impl = newImpl; }"
        ));
    }

    #[test]
    fn test_custom_upgrade_no_events_with_caller() {
        let detector = UpgradeEventMissingDetector::new();

        // _setImplementation uses sstore on IMPLEMENTATION_SLOT, but
        // upgradeTo calls it and emits Upgraded -- should not flag
        let source = r#"
            contract Proxy {
                function upgradeTo(address newImpl) external onlyAdmin {
                    _setImplementation(newImpl);
                    emit Upgraded(newImpl);
                }

                function _setImplementation(address newImpl) private {
                    bytes32 slot = IMPLEMENTATION_SLOT;
                    assembly {
                        sstore(slot, newImpl)
                    }
                }
            }
        "#;
        let result = detector.has_custom_upgrade_no_events(source);
        assert!(
            result.is_none(),
            "Expected no finding for sstore in helper whose caller emits Upgraded"
        );
    }

    #[test]
    fn test_custom_upgrade_no_events_true_positive() {
        let detector = UpgradeEventMissingDetector::new();

        // sstore directly referencing IMPLEMENTATION_SLOT with no event anywhere
        let source = r#"
            contract Proxy {
                function upgradeTo(address newImpl) external {
                    assembly {
                        sstore(IMPLEMENTATION_SLOT, newImpl)
                    }
                }
            }
        "#;
        let result = detector.has_custom_upgrade_no_events(source);
        assert!(
            result.is_some(),
            "Expected finding for sstore to IMPLEMENTATION_SLOT with no event"
        );
    }
}
