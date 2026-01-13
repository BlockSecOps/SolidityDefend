use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for UUPS implementations missing _disableInitializers()
///
/// UUPS (Universal Upgradeable Proxy Standard) implementations must call
/// _disableInitializers() in their constructor to prevent attackers from
/// initializing the implementation contract directly.
///
/// Vulnerable pattern:
/// ```solidity
/// contract MyUUPSToken is UUPSUpgradeable {
///     constructor() {} // Missing _disableInitializers()
/// }
/// ```
pub struct UupsMissingDisableInitializersDetector {
    base: BaseDetector,
}

impl Default for UupsMissingDisableInitializersDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UupsMissingDisableInitializersDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("uups-missing-disable-initializers"),
                "UUPS Missing _disableInitializers()".to_string(),
                "Detects UUPS upgradeable contracts that don't call _disableInitializers() \
                 in their constructor, leaving the implementation vulnerable to takeover"
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }

    /// Check if contract is a UUPS implementation
    fn is_uups_contract(&self, source: &str) -> bool {
        source.contains("UUPSUpgradeable")
            || source.contains("_authorizeUpgrade")
            || (source.contains("upgradeTo") && source.contains("Upgradeable"))
    }

    /// Check if constructor calls _disableInitializers
    fn constructor_has_disable_initializers(&self, source: &str) -> bool {
        // Find constructor
        if let Some(constructor_start) = source.find("constructor(") {
            let from_constructor = &source[constructor_start..];

            // Find the constructor body
            if let Some(body_start) = from_constructor.find('{') {
                let mut depth = 1;
                let body_content = &from_constructor[body_start + 1..];

                for (i, c) in body_content.char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                let constructor_body = &body_content[..i];
                                return constructor_body.contains("_disableInitializers()");
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        false
    }

    /// Check if contract has any constructor
    fn has_constructor(&self, source: &str) -> bool {
        source.contains("constructor(") || source.contains("constructor (")
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for UupsMissingDisableInitializersDetector {
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

        // Only check UUPS contracts
        if !self.is_uups_contract(source) {
            return Ok(findings);
        }

        let has_constructor = self.has_constructor(source);
        let has_disable = self.constructor_has_disable_initializers(source);

        // Flag if no constructor or constructor without _disableInitializers
        if !has_disable {
            let confidence = if !has_constructor {
                Confidence::High
            } else {
                Confidence::High // UUPS without disable is always critical
            };

            let message = format!(
                "UUPS contract '{}' does not call _disableInitializers() in constructor. \
                 An attacker can initialize the implementation contract directly and \
                 potentially call upgradeTo() to brick all proxies or take control.",
                contract_name
            );

            let line = ctx.contract.name.location.start().line() as u32;
            let column = ctx.contract.name.location.start().column() as u32;

            let finding = self
                .base
                .create_finding(ctx, message, line, column, contract_name.len() as u32)
                .with_cwe(665) // CWE-665: Improper Initialization
                .with_confidence(confidence)
                .with_fix_suggestion(
                    "Add a constructor that disables initializers:\n\n\
                     /// @custom:oz-upgrades-unsafe-allow constructor\n\
                     constructor() {\n\
                         _disableInitializers();\n\
                     }\n\n\
                     This is especially critical for UUPS contracts since the upgrade \
                     logic lives in the implementation."
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
        let detector = UupsMissingDisableInitializersDetector::new();
        assert_eq!(detector.name(), "UUPS Missing _disableInitializers()");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }

    #[test]
    fn test_is_uups_contract() {
        let detector = UupsMissingDisableInitializersDetector::new();
        assert!(detector.is_uups_contract("contract MyToken is UUPSUpgradeable {"));
        assert!(detector.is_uups_contract("function _authorizeUpgrade(address) internal override {}"));
        assert!(!detector.is_uups_contract("contract SimpleToken {"));
    }

    #[test]
    fn test_constructor_has_disable_initializers() {
        let detector = UupsMissingDisableInitializersDetector::new();

        let safe = "constructor() { _disableInitializers(); }";
        assert!(detector.constructor_has_disable_initializers(safe));

        let unsafe_code = "constructor() { }";
        assert!(!detector.constructor_has_disable_initializers(unsafe_code));
    }
}
