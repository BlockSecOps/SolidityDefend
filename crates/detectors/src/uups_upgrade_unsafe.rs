use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for unsafe UUPS _authorizeUpgrade implementations
///
/// UUPS contracts must properly implement _authorizeUpgrade with access control.
/// An empty or unprotected implementation allows anyone to upgrade the contract.
///
/// Vulnerable pattern:
/// ```solidity
/// function _authorizeUpgrade(address) internal override {}  // Empty!
/// ```
pub struct UupsUpgradeUnsafeDetector {
    base: BaseDetector,
}

impl Default for UupsUpgradeUnsafeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UupsUpgradeUnsafeDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("uups-upgrade-unsafe"),
                "Unsafe UUPS _authorizeUpgrade Implementation".to_string(),
                "Detects UUPS contracts with empty or unprotected _authorizeUpgrade, \
                 allowing unauthorized contract upgrades"
                    .to_string(),
                vec![
                    DetectorCategory::Upgradeable,
                    DetectorCategory::AccessControl,
                ],
                Severity::Critical,
            ),
        }
    }

    /// Find _authorizeUpgrade function and check for protection
    fn check_authorize_upgrade(&self, source: &str) -> Option<(u32, bool, bool)> {
        // Find _authorizeUpgrade function
        let pattern = "_authorizeUpgrade";

        for (line_num, line) in source.lines().enumerate() {
            if line.contains(pattern) && line.contains("function") {
                // Found the function, now analyze it
                let line_number = (line_num + 1) as u32;

                // Check if it has access control in the signature line
                let has_modifier_protection = line.contains("onlyOwner")
                    || line.contains("onlyAdmin")
                    || line.contains("onlyRole")
                    || line.contains("onlyProxy");

                // Get the function body
                let from_function = &source[source.find(line).unwrap_or(0)..];
                let body = self.extract_function_body(from_function);

                // Check if body is empty or has protection
                let is_empty = body.trim().is_empty()
                    || body.trim() == "{}"
                    || body.replace(['{', '}', ' ', '\n', '\t'], "").is_empty();

                let has_body_protection = body.contains("onlyOwner")
                    || body.contains("require(msg.sender")
                    || body.contains("require(_msgSender()")
                    || body.contains("hasRole(")
                    || body.contains("_checkOwner()")
                    || body.contains("_checkRole(")
                    || body.contains("if (msg.sender !=")
                    || body.contains("revert");

                let is_protected = has_modifier_protection || has_body_protection;

                return Some((line_number, is_empty, is_protected));
            }
        }
        None
    }

    /// Extract function body
    fn extract_function_body(&self, from_function: &str) -> String {
        if let Some(start) = from_function.find('{') {
            let body_start = &from_function[start..];
            let mut depth = 0;

            for (i, c) in body_start.char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return body_start[1..i].to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
        String::new()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }

    fn is_uups_contract(&self, source: &str) -> bool {
        source.contains("UUPSUpgradeable") || source.contains("_authorizeUpgrade")
    }
}

impl Detector for UupsUpgradeUnsafeDetector {
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

        if !self.is_uups_contract(source) {
            return Ok(findings);
        }

        if let Some((line, is_empty, is_protected)) = self.check_authorize_upgrade(source) {
            if !is_protected {
                let confidence = if is_empty {
                    Confidence::High
                } else {
                    Confidence::Medium
                };

                let message = if is_empty {
                    format!(
                        "UUPS contract '{}' has an empty _authorizeUpgrade function. \
                         Anyone can upgrade this contract to arbitrary code, leading to complete compromise.",
                        contract_name
                    )
                } else {
                    format!(
                        "UUPS contract '{}' has _authorizeUpgrade without apparent access control. \
                         Verify that upgrade authorization is properly restricted.",
                        contract_name
                    )
                };

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, "_authorizeUpgrade".len() as u32)
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_cwe(862) // CWE-862: Missing Authorization
                    .with_confidence(confidence)
                    .with_fix_suggestion(
                        "Add proper access control to _authorizeUpgrade:\n\n\
                         function _authorizeUpgrade(address newImplementation) internal override onlyOwner {\n\
                             // Optional: add additional checks\n\
                         }\n\n\
                         Or with OpenZeppelin AccessControl:\n\n\
                         function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}"
                            .to_string(),
                    );

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
        let detector = UupsUpgradeUnsafeDetector::new();
        assert_eq!(
            detector.name(),
            "Unsafe UUPS _authorizeUpgrade Implementation"
        );
        assert_eq!(detector.default_severity(), Severity::Critical);
    }

    #[test]
    fn test_check_authorize_upgrade() {
        let detector = UupsUpgradeUnsafeDetector::new();

        let empty_impl = r#"
            function _authorizeUpgrade(address) internal override {}
        "#;
        let result = detector.check_authorize_upgrade(empty_impl);
        assert!(result.is_some());
        let (_, is_empty, is_protected) = result.unwrap();
        assert!(is_empty);
        assert!(!is_protected);

        let protected_impl = r#"
            function _authorizeUpgrade(address) internal override onlyOwner {}
        "#;
        let result = detector.check_authorize_upgrade(protected_impl);
        assert!(result.is_some());
        let (_, _, is_protected) = result.unwrap();
        assert!(is_protected);
    }
}
