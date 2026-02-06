use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for immutable variables in upgradeable contracts
///
/// Immutable variables are stored in the contract bytecode, not in storage.
/// In a proxy pattern, the implementation's bytecode is different from the proxy's.
/// This means immutable values set in the implementation constructor won't be
/// available when called through a proxy (proxies use delegatecall).
///
/// Problematic pattern:
/// ```solidity
/// contract UpgradeableToken is Initializable {
///     address immutable factory; // Stored in bytecode, not storage!
///
///     constructor(address _factory) {
///         factory = _factory; // This value won't be accessible through proxy
///     }
/// }
/// ```
pub struct ImmutableInUpgradeableDetector {
    base: BaseDetector,
}

impl Default for ImmutableInUpgradeableDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ImmutableInUpgradeableDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("immutable-in-upgradeable"),
                "Immutable in Upgradeable Contract".to_string(),
                "Detects immutable variables in upgradeable contracts where proxy patterns \
                 would not have access to the implementation's immutable values"
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    /// Check if contract is upgradeable
    fn is_upgradeable_contract(&self, source: &str) -> bool {
        source.contains("Initializable")
            || source.contains("Upgradeable")
            || source.contains("UUPSUpgradeable")
            || source.contains("TransparentUpgradeableProxy")
            || source.contains("function initialize")
            || source.contains("initializer")
    }

    /// Find immutable variable declarations
    fn find_immutable_variables(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut immutables = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains(" immutable ") && !line.trim().starts_with("//") {
                let var_info = self.extract_immutable_info(line);
                if let Some((var_type, var_name)) = var_info {
                    immutables.push(((i + 1) as u32, var_type, var_name));
                }
            }
        }

        immutables
    }

    /// Extract type and name of immutable variable
    fn extract_immutable_info(&self, line: &str) -> Option<(String, String)> {
        let trimmed = line.trim();

        // Parse: type [visibility] immutable name;
        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        let mut var_type = String::new();
        let mut var_name = String::new();
        let mut found_immutable = false;

        for (idx, part) in parts.iter().enumerate() {
            if *part == "immutable" {
                found_immutable = true;
                // Type is before immutable (possibly after visibility)
                for prev_idx in (0..idx).rev() {
                    let prev = parts[prev_idx];
                    if !["public", "private", "internal", "constant"].contains(&prev) {
                        var_type = prev.to_string();
                        break;
                    }
                }
            } else if found_immutable && !part.is_empty() && *part != "=" {
                // Next non-empty token after immutable is the name
                var_name = part.trim_end_matches(';').trim_end_matches('=').to_string();
                break;
            }
        }

        if !var_type.is_empty() && !var_name.is_empty() {
            Some((var_type, var_name))
        } else {
            None
        }
    }

    /// Check if immutable is intentional (e.g., in ERC1967 style upgrades)
    fn is_intentional_immutable(&self, source: &str, var_name: &str) -> bool {
        // Some patterns intentionally use immutables that are okay
        let intentional_patterns = [
            "_IMPLEMENTATION_SLOT",
            "_ADMIN_SLOT",
            "_BEACON_SLOT",
            "DOMAIN_SEPARATOR",
        ];

        for pattern in &intentional_patterns {
            if var_name.to_uppercase().contains(pattern) {
                return true;
            }
        }

        // If there's explicit documentation about immutable being intentional
        source.contains(&format!("// {} is intentionally immutable", var_name))
            || source.contains(&format!("/* {} is stored in bytecode", var_name))
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for ImmutableInUpgradeableDetector {
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
        // Proxy contracts (not implementations) CAN use immutables because they ARE the bytecode
        // that will be executed. Immutables like _admin in TransparentUpgradeableProxy are correct.
        let is_proxy_contract = source.contains("abstract contract Proxy")
            || source.contains("contract TransparentUpgradeableProxy")
            || source.contains("contract ERC1967Proxy")
            || source.contains("contract BeaconProxy")
            || source.contains("library ERC1967Utils")
            || (source.contains("function _delegate(") && source.contains("fallback()"));

        if is_proxy_contract {
            return Ok(findings);
        }

        // Only check upgradeable contracts
        if !self.is_upgradeable_contract(source) {
            return Ok(findings);
        }

        // Find immutable variables
        let immutables = self.find_immutable_variables(source);

        for (line, var_type, var_name) in immutables {
            // Skip intentional immutables
            if self.is_intentional_immutable(source, &var_name) {
                continue;
            }

            let message = format!(
                "Upgradeable contract '{}' has immutable variable '{}' of type '{}'. \
                 Immutable values are stored in bytecode, not storage. When called through \
                 a proxy (delegatecall), the proxy's bytecode is used, so this value will \
                 be unavailable or incorrect.",
                contract_name, var_name, var_type
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 0, var_name.len() as u32)
                .with_cwe(758) // CWE-758: Reliance on Undefined, Unspecified, or Implementation-Defined Behavior
                .with_cwe(665) // CWE-665: Improper Initialization
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(format!(
                    "Replace immutable variable '{}' with a regular storage variable \
                     initialized in the initialize() function:\n\n\
                     // Before (problematic):\n\
                     {} immutable {};\n\
                     constructor({} _value) {{ {} = _value; }}\n\n\
                     // After (correct for upgradeable):\n\
                     {} private {};\n\
                     function initialize({} _value) public initializer {{\n\
                         {} = _value;\n\
                     }}",
                    var_name,
                    var_type,
                    var_name,
                    var_type,
                    var_name,
                    var_type,
                    var_name,
                    var_type,
                    var_name
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
        let detector = ImmutableInUpgradeableDetector::new();
        assert_eq!(detector.name(), "Immutable in Upgradeable Contract");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }

    #[test]
    fn test_find_immutable_variables() {
        let detector = ImmutableInUpgradeableDetector::new();

        let source = r#"
            contract Test {
                address public immutable factory;
                uint256 private immutable chainId;
            }
        "#;

        let immutables = detector.find_immutable_variables(source);
        assert_eq!(immutables.len(), 2);
    }

    #[test]
    fn test_is_upgradeable() {
        let detector = ImmutableInUpgradeableDetector::new();

        assert!(
            detector.is_upgradeable_contract("contract MyToken is Initializable, ERC20Upgradeable")
        );
        assert!(!detector.is_upgradeable_contract("contract SimpleToken is ERC20"));
    }

    #[test]
    fn test_extract_immutable_info() {
        let detector = ImmutableInUpgradeableDetector::new();

        let info = detector.extract_immutable_info("address public immutable factory;");
        assert_eq!(info, Some(("address".to_string(), "factory".to_string())));

        let info = detector.extract_immutable_info("uint256 private immutable chainId;");
        assert_eq!(info, Some(("uint256".to_string(), "chainId".to_string())));
    }
}
