use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for unprotected beacon upgrade functions
///
/// Beacon proxies allow multiple proxy contracts to share a single implementation.
/// If the beacon's upgradeTo function lacks access control, an attacker can
/// upgrade all proxies at once.
///
/// Vulnerable pattern:
/// ```solidity
/// contract MyBeacon is UpgradeableBeacon {
///     function upgradeTo(address newImpl) public {  // No access control!
///         _upgradeTo(newImpl);
///     }
/// }
/// ```
pub struct BeaconUpgradeUnprotectedDetector {
    base: BaseDetector,
}

impl Default for BeaconUpgradeUnprotectedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaconUpgradeUnprotectedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("beacon-upgrade-unprotected"),
                "Unprotected Beacon Upgrade".to_string(),
                "Detects beacon contracts with unprotected upgrade functions that allow \
                 unauthorized changes to all beacon proxies simultaneously"
                    .to_string(),
                vec![
                    DetectorCategory::Upgradeable,
                    DetectorCategory::AccessControl,
                ],
                Severity::Critical,
            ),
        }
    }

    /// Check if contract is a beacon
    fn is_beacon_contract(&self, source: &str) -> bool {
        source.contains("UpgradeableBeacon")
            || source.contains("IBeacon")
            || source.contains("BeaconProxy")
            || (source.contains("implementation()") && source.contains("_upgradeTo"))
    }

    /// Find upgrade functions and check protection
    fn find_unprotected_upgrade_functions(&self, source: &str) -> Vec<(u32, String)> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            // Look for upgrade functions
            if (line.contains("function upgradeTo")
                || line.contains("function upgrade(")
                || line.contains("function setImplementation"))
                && (line.contains("public") || line.contains("external"))
            {
                // Check if it has access control modifiers
                let has_modifier = line.contains("onlyOwner")
                    || line.contains("onlyAdmin")
                    || line.contains("onlyRole")
                    || line.contains("auth");

                if has_modifier {
                    continue;
                }

                // Check function body for protection
                let func_body = self.get_function_body(&lines, i);
                let has_body_protection = func_body.contains("require(msg.sender")
                    || func_body.contains("require(_msgSender()")
                    || func_body.contains("hasRole(")
                    || func_body.contains("_checkOwner()")
                    || func_body.contains("if (msg.sender !=");

                if !has_body_protection {
                    // Extract function name
                    let func_name = self.extract_function_name(line);
                    issues.push(((i + 1) as u32, func_name));
                }
            }
        }

        issues
    }

    /// Get function body from lines starting at function definition
    fn get_function_body(&self, lines: &[&str], start: usize) -> String {
        let mut body = String::new();
        let mut depth = 0;
        let mut started = false;

        for line in lines.iter().skip(start) {
            for c in line.chars() {
                if c == '{' {
                    depth += 1;
                    started = true;
                } else if c == '}' {
                    depth -= 1;
                }
            }

            body.push_str(line);
            body.push('\n');

            if started && depth == 0 {
                break;
            }
        }

        body
    }

    /// Extract function name from line
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(start) = line.find("function ") {
            let after_function = &line[start + 9..];
            if let Some(end) = after_function.find('(') {
                return after_function[..end].trim().to_string();
            }
        }
        "upgradeTo".to_string()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for BeaconUpgradeUnprotectedDetector {
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

        if !self.is_beacon_contract(source) {
            return Ok(findings);
        }

        let issues = self.find_unprotected_upgrade_functions(source);

        for (line, func_name) in issues {
            let message = format!(
                "Beacon contract '{}' has unprotected upgrade function '{}'. \
                 An attacker can call this function to change the implementation \
                 for ALL beacon proxies simultaneously, affecting every user.",
                contract_name, func_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 0, func_name.len() as u32)
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_cwe(862) // CWE-862: Missing Authorization
                .with_confidence(Confidence::High)
                .with_fix_suggestion(format!(
                    "Add access control to '{}':\n\n\
                     function {}(address newImplementation) public onlyOwner {{\n\
                         _upgradeTo(newImplementation);\n\
                     }}\n\n\
                     Consider also adding a timelock for additional security.",
                    func_name, func_name
                ));

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
        let detector = BeaconUpgradeUnprotectedDetector::new();
        assert_eq!(detector.name(), "Unprotected Beacon Upgrade");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }

    #[test]
    fn test_is_beacon_contract() {
        let detector = BeaconUpgradeUnprotectedDetector::new();
        assert!(detector.is_beacon_contract("contract MyBeacon is UpgradeableBeacon {"));
        assert!(detector.is_beacon_contract("contract MyBeacon is IBeacon {"));
        assert!(!detector.is_beacon_contract("contract SimpleToken {"));
    }

    #[test]
    fn test_find_unprotected_functions() {
        let detector = BeaconUpgradeUnprotectedDetector::new();

        let unprotected = r#"
            function upgradeTo(address newImpl) public {
                _upgradeTo(newImpl);
            }
        "#;
        let issues = detector.find_unprotected_upgrade_functions(unprotected);
        assert!(!issues.is_empty());

        let protected = r#"
            function upgradeTo(address newImpl) public onlyOwner {
                _upgradeTo(newImpl);
            }
        "#;
        let issues = detector.find_unprotected_upgrade_functions(protected);
        assert!(issues.is_empty());
    }
}
