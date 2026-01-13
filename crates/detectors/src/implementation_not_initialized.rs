use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for uninitialized implementation contracts
///
/// Detects implementation contracts that can be initialized by an attacker.
/// This is the vulnerability that led to the $320M Wormhole exploit.
///
/// Vulnerable pattern:
/// ```solidity
/// contract Implementation is Initializable {
///     function initialize() public initializer { owner = msg.sender; }
///     // No constructor calling _disableInitializers()
/// }
/// ```
///
/// An attacker can call initialize() on the implementation contract directly,
/// becoming the owner and potentially compromising all proxies.
pub struct ImplementationNotInitializedDetector {
    base: BaseDetector,
}

impl Default for ImplementationNotInitializedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ImplementationNotInitializedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("implementation-not-initialized"),
                "Implementation Contract Not Initialized".to_string(),
                "Detects implementation contracts that lack _disableInitializers() in constructor, \
                 allowing attackers to initialize them directly and potentially compromise all proxies"
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }

    /// Check if contract appears to be an upgradeable implementation
    fn is_implementation_contract(&self, source: &str) -> bool {
        // Check for Initializable inheritance or patterns
        source.contains("Initializable")
            || source.contains("initializer")
            || source.contains("UUPSUpgradeable")
            || source.contains("Upgradeable")
            || source.contains("_disableInitializers")
    }

    /// Check if contract has an initialize function
    fn has_initialize_function(&self, source: &str) -> bool {
        source.contains("function initialize")
            || source.contains("function __")  // OpenZeppelin __ContractName_init pattern
    }

    /// Check if constructor calls _disableInitializers
    fn has_disable_initializers_in_constructor(&self, source: &str) -> bool {
        // Find constructor and check for _disableInitializers
        if let Some(constructor_start) = source.find("constructor(") {
            let constructor_section = &source[constructor_start..];
            // Find the closing brace of constructor
            if let Some(brace_end) = self.find_matching_brace(constructor_section) {
                let constructor_body = &constructor_section[..brace_end];
                return constructor_body.contains("_disableInitializers()");
            }
        }

        // Also check for /// @custom:oz-upgrades-unsafe-allow constructor pattern
        // with _disableInitializers in constructor
        if source.contains("@custom:oz-upgrades-unsafe-allow constructor") {
            if let Some(constructor_start) = source.find("constructor(") {
                let constructor_section = &source[constructor_start..];
                if let Some(brace_end) = self.find_matching_brace(constructor_section) {
                    let constructor_body = &constructor_section[..brace_end];
                    return constructor_body.contains("_disableInitializers()");
                }
            }
        }

        false
    }

    /// Check if contract has a constructor at all
    fn has_constructor(&self, source: &str) -> bool {
        source.contains("constructor(") || source.contains("constructor (")
    }

    /// Find matching closing brace
    fn find_matching_brace(&self, s: &str) -> Option<usize> {
        let mut depth = 0;
        let mut started = false;

        for (i, c) in s.char_indices() {
            match c {
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => {
                    depth -= 1;
                    if started && depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Get contract name from source
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for ImplementationNotInitializedDetector {
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

        // Check if this looks like an implementation contract
        if !self.is_implementation_contract(source) {
            return Ok(findings);
        }

        // Check if it has an initialize function
        if !self.has_initialize_function(source) {
            return Ok(findings);
        }

        // Check if constructor exists and calls _disableInitializers
        let has_constructor = self.has_constructor(source);
        let has_disable = self.has_disable_initializers_in_constructor(source);

        if !has_disable {
            let confidence = if !has_constructor {
                Confidence::High // No constructor at all - very likely vulnerable
            } else {
                Confidence::Medium // Has constructor but no _disableInitializers
            };

            let message = if !has_constructor {
                format!(
                    "Implementation contract '{}' has no constructor calling _disableInitializers(). \
                     An attacker can initialize the implementation directly, potentially gaining \
                     control over all proxy contracts. This was the root cause of the $320M Wormhole exploit.",
                    contract_name
                )
            } else {
                format!(
                    "Implementation contract '{}' has a constructor but does not call _disableInitializers(). \
                     The implementation contract can be initialized by an attacker.",
                    contract_name
                )
            };

            let line = ctx.contract.name.location.start().line() as u32;
            let column = ctx.contract.name.location.start().column() as u32;

            let finding = self
                .base
                .create_finding(ctx, message, line, column, contract_name.len() as u32)
                .with_cwe(665) // CWE-665: Improper Initialization
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_confidence(confidence)
                .with_fix_suggestion(format!(
                    "Add a constructor that calls _disableInitializers():\n\n\
                     /// @custom:oz-upgrades-unsafe-allow constructor\n\
                     constructor() {{\n\
                         _disableInitializers();\n\
                     }}\n\n\
                     This prevents the implementation contract from being initialized directly."
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
        let detector = ImplementationNotInitializedDetector::new();
        assert_eq!(detector.name(), "Implementation Contract Not Initialized");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_implementation_contract() {
        let detector = ImplementationNotInitializedDetector::new();
        assert!(detector.is_implementation_contract("contract MyToken is Initializable {"));
        assert!(detector.is_implementation_contract("contract MyToken is UUPSUpgradeable {"));
        assert!(detector.is_implementation_contract("function init() initializer {"));
        assert!(!detector.is_implementation_contract("contract SimpleToken {"));
    }

    #[test]
    fn test_has_disable_initializers() {
        let detector = ImplementationNotInitializedDetector::new();

        let safe_code = r#"
            constructor() {
                _disableInitializers();
            }
        "#;
        assert!(detector.has_disable_initializers_in_constructor(safe_code));

        let unsafe_code = r#"
            constructor() {
                // Missing _disableInitializers
            }
        "#;
        assert!(!detector.has_disable_initializers_in_constructor(unsafe_code));
    }
}
