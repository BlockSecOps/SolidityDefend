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

    /// Known base contract names that indicate an upgradeable proxy implementation.
    const UPGRADEABLE_BASES: &'static [&'static str] = &[
        "Initializable",
        "UUPSUpgradeable",
        "TransparentUpgradeableProxy",
        "BeaconProxy",
        "ERC1967Upgrade",
        "ERC1967UpgradeUpgradeable",
        "OwnableUpgradeable",
        "AccessControlUpgradeable",
        "PausableUpgradeable",
        "ReentrancyGuardUpgradeable",
        "ERC20Upgradeable",
        "ERC721Upgradeable",
        "ERC1155Upgradeable",
        "GovernorUpgradeable",
        "UUPSUpgradeableGap",
    ];

    /// Check if contract is a library or abstract contract that should be skipped.
    fn should_skip_contract(&self, ctx: &AnalysisContext) -> bool {
        let contract = ctx.contract;

        // Skip library contracts -- they are not deployed as standalone implementations
        if contract.contract_type == ast::ContractType::Library {
            return true;
        }

        // Skip interface contracts -- they have no implementation
        if contract.contract_type == ast::ContractType::Interface {
            return true;
        }

        // Skip abstract contracts -- they cannot be deployed directly.
        // Check the source for "abstract contract <Name>" since the AST ContractType
        // does not distinguish abstract from concrete contracts.
        let contract_name = contract.name.name;
        let abstract_pattern = format!("abstract contract {}", contract_name);
        if ctx.source_code.contains(&abstract_pattern) {
            return true;
        }

        false
    }

    /// Check if contract inherits from known upgradeable base contracts using
    /// the AST inheritance list. Falls back to source-level matching when the
    /// AST inheritance list is empty (e.g., when the parser does not populate it).
    fn is_implementation_contract(&self, ctx: &AnalysisContext) -> bool {
        let contract = ctx.contract;

        // Primary check: use the structured AST inheritance list
        if !contract.inheritance.is_empty() {
            for spec in contract.inheritance.iter() {
                let base_name = spec.base.name;
                if Self::UPGRADEABLE_BASES
                    .iter()
                    .any(|&known| base_name == known)
                {
                    return true;
                }
                // Also catch any base whose name ends with "Upgradeable"
                if base_name.ends_with("Upgradeable") {
                    return true;
                }
            }
        }

        // Fallback: source-level check scoped to the contract definition line.
        // Look for "contract <Name> is ... Initializable" etc.
        let source = &ctx.source_code;
        let contract_name = contract.name.name;

        // Find the contract definition line: "contract Foo is Bar, Baz {"
        if let Some(def_line) = source.lines().find(|line| {
            let trimmed = line.trim();
            trimmed.starts_with(&format!("contract {}", contract_name))
                || trimmed.starts_with(&format!("abstract contract {}", contract_name))
        }) {
            // Only look at what comes after "is" on that line
            if let Some(is_pos) = def_line.find(" is ") {
                let inheritance_part = &def_line[is_pos..];
                for &base in Self::UPGRADEABLE_BASES {
                    if inheritance_part.contains(base) {
                        return true;
                    }
                }
                // Catch any base ending in "Upgradeable"
                if inheritance_part.contains("Upgradeable") {
                    return true;
                }
            }
        }

        false
    }

    /// Check if contract has an initialize function.
    /// Scopes the search to function definitions to avoid matching comments or strings.
    fn has_initialize_function(&self, source: &str) -> bool {
        source.lines().any(|line| {
            let trimmed = line.trim();
            // Skip comment lines
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                return false;
            }
            trimmed.contains("function initialize") || trimmed.contains("function __") // OpenZeppelin __ContractName_init pattern
        })
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

        // Skip libraries, interfaces, and abstract contracts
        if self.should_skip_contract(ctx) {
            return Ok(findings);
        }

        // Check if this contract inherits from known upgradeable base contracts
        if !self.is_implementation_contract(ctx) {
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
    use crate::types::test_utils::create_test_context;

    #[test]
    fn test_detector_properties() {
        let detector = ImplementationNotInitializedDetector::new();
        assert_eq!(detector.name(), "Implementation Contract Not Initialized");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_implementation_contract_with_initializable() {
        let detector = ImplementationNotInitializedDetector::new();
        // Source-level fallback: contract definition line contains "Initializable"
        let ctx = create_test_context(
            "contract TestContract is Initializable {\n    function initialize() public {}\n}",
        );
        assert!(detector.is_implementation_contract(&ctx));
    }

    #[test]
    fn test_is_implementation_contract_with_uups() {
        let detector = ImplementationNotInitializedDetector::new();
        let ctx = create_test_context(
            "contract TestContract is UUPSUpgradeable {\n    function initialize() public {}\n}",
        );
        assert!(detector.is_implementation_contract(&ctx));
    }

    #[test]
    fn test_is_not_implementation_contract_standalone() {
        let detector = ImplementationNotInitializedDetector::new();
        // A standalone contract with no upgradeable inheritance should NOT be flagged
        let ctx = create_test_context(
            "contract TestContract {\n    constructor() {}\n    function doSomething() public {}\n}",
        );
        assert!(!detector.is_implementation_contract(&ctx));
    }

    #[test]
    fn test_is_not_implementation_contract_no_proxy_keyword() {
        let detector = ImplementationNotInitializedDetector::new();
        // Even if a contract has "initializer" in a comment, it should not match
        // since we check the contract definition line, not the whole source
        let ctx = create_test_context(
            "contract TestContract {\n    // initializer pattern\n    constructor() {}\n}",
        );
        assert!(!detector.is_implementation_contract(&ctx));
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

    #[test]
    fn test_skip_library_contracts() {
        let detector = ImplementationNotInitializedDetector::new();
        // Libraries should always be skipped regardless of source content
        let ctx =
            create_test_context("library TestContract {\n    function initialize() public {}\n}");
        // The test context creates a Contract type, but the should_skip_contract
        // checks contract_type. Since create_test_context produces ContractType::Contract,
        // we verify the source-level fallback path does not flag libraries.
        // For a true library, the AST contract_type would be Library.
        // Here we just verify the source-level check does not match "library TestContract"
        // as having upgradeable inheritance.
        assert!(!detector.is_implementation_contract(&ctx));
    }

    #[test]
    fn test_skip_abstract_contract() {
        let detector = ImplementationNotInitializedDetector::new();
        let ctx = create_test_context(
            "abstract contract TestContract is Initializable {\n    function initialize() public virtual {}\n}",
        );
        // Abstract contracts should be skipped
        assert!(detector.should_skip_contract(&ctx));
    }

    #[test]
    fn test_has_initialize_function() {
        let detector = ImplementationNotInitializedDetector::new();
        assert!(detector.has_initialize_function("function initialize() public initializer {}"));
        assert!(detector.has_initialize_function("function __MyContract_init() internal {}"));
        assert!(!detector.has_initialize_function("function doSomething() public {}"));
        // Comments should not match
        assert!(!detector.has_initialize_function("// function initialize() public {}"));
    }

    #[test]
    fn test_true_positive_upgradeable_without_disable() {
        let detector = ImplementationNotInitializedDetector::new();
        let source = r#"contract TestContract is Initializable, UUPSUpgradeable {
    uint256 public value;

    function initialize(uint256 _value) public initializer {
        value = _value;
    }
}"#;
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        // Should produce a finding because it inherits Initializable + has initialize()
        // but no constructor with _disableInitializers()
        assert!(
            !findings.is_empty(),
            "Expected a finding for vulnerable upgradeable contract"
        );
    }

    #[test]
    fn test_true_negative_safe_upgradeable() {
        let detector = ImplementationNotInitializedDetector::new();
        let source = r#"contract TestContract is Initializable, UUPSUpgradeable {
    uint256 public value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(uint256 _value) public initializer {
        value = _value;
    }
}"#;
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        // Should NOT produce a finding because _disableInitializers() is called
        assert!(
            findings.is_empty(),
            "Should not flag a properly secured implementation"
        );
    }

    #[test]
    fn test_true_negative_standalone_contract() {
        let detector = ImplementationNotInitializedDetector::new();
        let source = r#"contract TestContract {
    uint256 public value;

    constructor(uint256 _value) {
        value = _value;
    }

    function doSomething() public {}
}"#;
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        // Should NOT produce a finding -- standalone contract, not upgradeable
        assert!(
            findings.is_empty(),
            "Should not flag standalone contracts without proxy patterns"
        );
    }
}
