use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for role escalation via upgrade vulnerabilities
///
/// Detects patterns where implementation contract constructors can
/// set high privileges, enabling role escalation during upgrades.
pub struct RoleEscalationUpgradeDetector {
    base: BaseDetector,
}

impl Default for RoleEscalationUpgradeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleEscalationUpgradeDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("role-escalation-upgrade"),
                "Role Escalation via Upgrade".to_string(),
                "Detects upgrade patterns where new implementation constructors \
                 can grant elevated privileges, bypassing access control."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Upgradeable],
                Severity::Critical,
            ),
        }
    }

    /// Find constructor privilege grants
    fn find_constructor_privileges(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let is_upgradeable = source.contains("Upgradeable")
            || source.contains("UUPSUpgradeable")
            || source.contains("TransparentUpgradeableProxy")
            || source.contains("initialize");

        if !is_upgradeable {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for constructor
            if trimmed.contains("constructor") && trimmed.contains("(") {
                let func_end = self.find_function_end(&lines, line_num);
                let constructor_body: String = lines[line_num..func_end].join("\n");

                // Check for privilege grants in constructor
                let has_privilege_grant = constructor_body.contains("_grantRole")
                    || constructor_body.contains("grantRole")
                    || constructor_body.contains("_setupRole")
                    || constructor_body.contains("owner =")
                    || constructor_body.contains("admin =")
                    || constructor_body.contains("DEFAULT_ADMIN_ROLE");

                if has_privilege_grant {
                    let issue = "Constructor grants roles in upgradeable contract".to_string();
                    findings.push((line_num as u32 + 1, issue));
                }
            }
        }

        findings
    }

    /// Find initializer privilege issues
    fn find_initializer_escalation(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for initialize functions
            if trimmed.contains("function initialize") || trimmed.contains("function __") {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for role escalation in reinitialize
                if func_body.contains("reinitializer") && func_body.contains("grantRole") {
                    let issue = "Reinitializer can grant new roles".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for missing role validation
                if func_body.contains("_grantRole") && !func_body.contains("onlyRole") {
                    let issue = "Role grants without caller validation".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find upgrade function privilege issues
    fn find_upgrade_privilege(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for upgrade functions
            if trimmed.contains("function upgrade")
                || trimmed.contains("function _authorizeUpgrade")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if upgrade can change access control
                let weak_protection = func_body.contains("onlyOwner")
                    && !func_body.contains("timelock")
                    && !func_body.contains("governance");

                if weak_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "constructor".to_string()
    }

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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for RoleEscalationUpgradeDetector {
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

        // Phase 53 FP Reduction: Skip proxy contracts
        // Proxy contracts set admin/implementation in constructor, which is expected behavior
        // They are not implementation contracts that get upgraded
        let is_proxy_contract = source.contains("abstract contract Proxy")
            || source.contains("contract TransparentUpgradeableProxy")
            || source.contains("contract ERC1967Proxy")
            || source.contains("contract BeaconProxy")
            || source.contains("library ERC1967Utils")
            || (source.contains("function _delegate(") && source.contains("fallback()"));

        if is_proxy_contract {
            return Ok(findings);
        }

        for (line, issue) in self.find_constructor_privileges(source) {
            let message = format!(
                "Constructor in contract '{}' grants privileges. {}. \
                 In upgradeable contracts, constructors run once per implementation, \
                 potentially granting unintended access.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(269)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Move privilege grants to initializer:\n\n\
                     1. Never grant roles in constructor for upgradeable contracts\n\
                     2. Use initializer modifier with proper access control\n\
                     3. Disable initializers in constructor: _disableInitializers()\n\n\
                     Example:\n\
                     constructor() {\n\
                         _disableInitializers();\n\
                     }\n\n\
                     function initialize(address admin) initializer public {\n\
                         __AccessControl_init();\n\
                         _grantRole(DEFAULT_ADMIN_ROLE, admin);\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name, issue) in self.find_initializer_escalation(source) {
            let message = format!(
                "Function '{}' in contract '{}' has role escalation risk. {}. \
                 Attackers may exploit re-initialization to gain elevated privileges.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(269)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect initializer role grants:\n\n\
                     1. Use reinitializer(version) for controlled upgrades\n\
                     2. Require admin role for re-initialization\n\
                     3. Limit which roles can be granted in reinitialize\n\
                     4. Emit events for all role changes"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_upgrade_privilege(source) {
            let message = format!(
                "Upgrade function '{}' in contract '{}' has weak protection. \
                 Owner-only upgrades without timelock allow rapid privilege changes.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(269)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Strengthen upgrade protection:\n\n\
                     1. Require timelock for upgrades\n\
                     2. Use governance vote for implementation changes\n\
                     3. Add upgrade delay period\n\n\
                     Example:\n\
                     function _authorizeUpgrade(address) internal override onlyTimelock {}"
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
        let detector = RoleEscalationUpgradeDetector::new();
        assert_eq!(detector.name(), "Role Escalation via Upgrade");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
