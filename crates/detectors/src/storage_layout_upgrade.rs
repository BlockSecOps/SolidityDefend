//! Storage Layout Upgrade Violation Detection
//!
//! Detects upgradeable proxy patterns with storage layout violations that cause
//! state corruption during upgrades.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct StorageLayoutUpgradeDetector {
    base: BaseDetector,
}

impl StorageLayoutUpgradeDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("storage-layout-upgrade".to_string()),
                "Storage Layout Upgrade Violation".to_string(),
                "Detects upgradeable contracts with storage layout violations that cause state corruption during upgrades".to_string(),
                vec![
                    DetectorCategory::Upgradeable,
                    DetectorCategory::Logic,
                ],
                Severity::Critical,
            ),
        }
    }

    fn check_storage_patterns(&self, ctx: &AnalysisContext) -> Vec<(String, u32, String)> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Phase 53 FP Reduction: Skip proxy contracts
        // Proxy contracts use EIP-1967 storage slots exclusively, not regular state variables
        // They don't need storage gaps because their storage is in fixed slots
        let is_proxy_contract = source.contains("abstract contract Proxy")
            || source.contains("contract TransparentUpgradeableProxy")
            || source.contains("contract ERC1967Proxy")
            || source.contains("contract BeaconProxy")
            || source.contains("library ERC1967Utils")
            || (source.contains("function _delegate(") && source.contains("fallback()"))
            || source.contains("IMPLEMENTATION_SLOT")
            || source
                .contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");

        if is_proxy_contract {
            return findings;
        }

        // Phase 54 FP Reduction: Skip Diamond storage libraries
        if self.is_diamond_storage_library(source, &source_lower) {
            return findings;
        }

        // Phase 54 FP Reduction: Skip EIP-7201 namespaced storage
        if self.uses_eip7201_namespaced_storage(source, &source_lower) {
            return findings;
        }

        // Check if contract is upgradeable
        let is_upgradeable = source_lower.contains("upgradeable")
            || source_lower.contains("initializer")
            || source_lower.contains("initialize")
            || source_lower.contains("uups")
            || source_lower.contains("diamond")
            || source_lower.contains("facet");

        // If contract has a constructor, it's not upgradeable (upgradeable contracts use initializers)
        let has_constructor =
            source_lower.contains("constructor()") || source_lower.contains("constructor(");

        if !is_upgradeable || has_constructor {
            return findings;
        }

        // Check for EIP-2535 Diamond storage pattern (should skip most checks)
        let uses_diamond_storage = (source_lower.contains("diamond")
            || source_lower.contains("facet"))
            && source_lower.contains("keccak256")
            && (source_lower.contains("storage_position")
                || source_lower.contains("storage.slot")
                || source_lower.contains("diamond.storage")
                || (source_lower.contains("bytes32")
                    && source_lower.contains("constant")
                    && source_lower.contains("position")));

        // Check for EIP-1967 namespaced storage pattern
        let uses_namespaced_storage = source_lower.contains("eip1967")
            || (source_lower.contains("keccak256")
                && source_lower.contains("bytes32")
                && source_lower.contains("constant")
                && (source_lower.contains(".slot") || source_lower.contains("_slot")))
            || (source_lower.contains("bytes32")
                && source_lower.contains("slot")
                && source_lower.contains("assembly"));

        // If using diamond or namespaced storage patterns, skip most checks
        if uses_diamond_storage || uses_namespaced_storage {
            return findings; // These patterns are safe by design
        }

        // Pattern 1: Missing storage gap in base contracts
        if source_lower.contains("contract")
            && (source_lower.contains("abstract") || source_lower.contains("is"))
        {
            let has_gap = source_lower.contains("__gap")
                || source_lower.contains("_gap")
                || source_lower.contains("reserved")
                || (source_lower.contains("uint256[") && source_lower.contains("private"));

            if !has_gap && is_upgradeable {
                findings.push((
                    "Upgradeable contract missing storage gap (future upgrade will corrupt state)".to_string(),
                    0,
                    "Add storage gap: uint256[50] private __gap; Reserve slots for future variables. This allows adding new state variables in future versions without corrupting storage layout.".to_string(),
                ));
            }
        }

        // Pattern 2: Storage gap that's too small
        if source_lower.contains("__gap") || source_lower.contains("_gap") {
            // Check for small gaps (less than 20 slots is risky)
            let has_small_gap = source_lower.contains("[1]")
                || source_lower.contains("[2]")
                || source_lower.contains("[3]")
                || source_lower.contains("[4]")
                || source_lower.contains("[5]")
                || source_lower.contains("[10]")
                || source_lower.contains("[15]");

            if has_small_gap {
                findings.push((
                    "Storage gap is very small (< 20 slots) - may be insufficient for future upgrades".to_string(),
                    0,
                    "Use larger gap: uint256[50] private __gap; Standard practice is 50 slots to allow flexibility for future upgrades. Small gaps limit upgrade options.".to_string(),
                ));
            }
        }

        // Pattern 3: REMOVED - Constants don't use storage slots and are safe

        // Pattern 4: Complex inheritance without gap
        let inheritance_count = source_lower.matches(" is ").count();
        if inheritance_count > 1 && !source_lower.contains("__gap") {
            findings.push((
                "Multiple inheritance without storage gaps (complex upgrade path)".to_string(),
                0,
                "Add gaps to all base contracts: Each inherited contract should have its own storage gap to prevent layout conflicts during upgrades. Use: uint256[50] private __gap;".to_string(),
            ));
        }

        // Pattern 5-7: REMOVED - Structs, mappings, and arrays are legitimate when properly managed
        // These are standard patterns in well-designed contracts and don't indicate vulnerabilities

        // Pattern 8: Using delete keyword on complex types
        if source_lower.contains("delete ")
            && (source_lower.contains("struct") || source_lower.contains("mapping"))
        {
            findings.push((
                "Uses delete on complex types (upgrade compatibility concern)".to_string(),
                0,
                "Be aware: delete behavior on structs/mappings may have subtle implications for upgrades. Document cleanup behavior. Consider explicit field clearing for important state transitions.".to_string(),
            ));
        }

        // Pattern 9: REMOVED - Storage pointers are standard practice and safe when layout is preserved

        // Pattern 10: No initialization gap reduction tracking
        if source_lower.contains("__gap") && source_lower.contains("uint256") {
            // Check if there's a comment documenting gap usage
            let documents_gap = source_lower.contains("// gap reduced")
                || source_lower.contains("// was __gap[50]")
                || source_lower.contains("/// @custom:storage-gap");

            if !documents_gap {
                findings.push((
                    "Storage gap without documentation (gap reduction tracking recommended)".to_string(),
                    0,
                    "Document gaps: // uint256[50] private __gap; // Reduced by X when adding Y variables. Track gap reductions to prevent double-spending storage slots across upgrades.".to_string(),
                ));
            }
        }

        // Pattern 11: Initializer without gap adjustment warning
        if source_lower.contains("initializer") || source_lower.contains("initialize") {
            // Check if contract adds new state variables after initializer
            let has_state_vars_after_init = source_lower.contains("initializer")
                && source_lower.contains("uint256")
                || source_lower.contains("address")
                || source_lower.contains("mapping");

            if has_state_vars_after_init && !source_lower.contains("__gap") {
                findings.push((
                    "Initializer with state variables but no storage gap (upgrade blocker)".to_string(),
                    0,
                    "Critical: Adding state variables in upgraded implementation will change storage layout. Add gap: uint256[50] private __gap; Reduce gap when adding new variables.".to_string(),
                ));
            }
        }

        // Pattern 12: Diamond proxy without explicit storage slots
        if source_lower.contains("diamond") || source_lower.contains("facet") {
            let uses_explicit_slots = source_lower.contains("bytes32")
                && (source_lower.contains("position") || source_lower.contains("slot"));

            if !uses_explicit_slots {
                findings.push((
                    "diamond proxy without explicit slot definition (facet collision risk)".to_string(),
                    0,
                    "Use explicit slot: bytes32 constant STORAGE_SLOT = keccak256('myapp.storage.v1'); Access via assembly or struct with explicit slot. Prevents storage collisions between facets.".to_string(),
                ));
            }
        }

        // Pattern 13: REMOVED - Internal libraries are common and don't indicate vulnerabilities

        findings
    }

    /// Phase 54 FP Reduction: Check for Diamond storage library patterns
    fn is_diamond_storage_library(&self, source: &str, source_lower: &str) -> bool {
        // LibDiamond pattern
        if source.contains("LibDiamond") || source.contains("library Diamond") {
            return true;
        }

        // AppStorage pattern (common in Diamond implementations)
        if source.contains("AppStorage") || source.contains("appStorage") {
            return true;
        }

        // DiamondStorage pattern
        if source.contains("DiamondStorage") || source.contains("diamondStorage") {
            return true;
        }

        // Storage lib with explicit slot
        if source_lower.contains("storage")
            && source_lower.contains("library")
            && source_lower.contains("slot")
        {
            return true;
        }

        false
    }

    /// Phase 54 FP Reduction: Check for EIP-7201 namespaced storage
    fn uses_eip7201_namespaced_storage(&self, source: &str, source_lower: &str) -> bool {
        // EIP-7201 specific patterns
        if source.contains("eip7201") || source.contains("EIP7201") {
            return true;
        }

        // Namespaced storage annotation
        if source.contains("@custom:storage-location") {
            return true;
        }

        // OpenZeppelin namespaced storage pattern
        if source.contains("StorageSlot") && source.contains("getAddressSlot") {
            return true;
        }

        // Storage struct with explicit slot calculation
        if source_lower.contains("struct")
            && source_lower.contains("storage")
            && source.contains("keccak256")
            && (source.contains("erc7201:") || source.contains("eip7201:"))
        {
            return true;
        }

        // Check for explicit storage slot patterns
        if source.contains("bytes32 private constant")
            && source.contains("keccak256")
            && (source.contains("storage.") || source.contains(".storage"))
        {
            return true;
        }

        false
    }
}

impl Default for StorageLayoutUpgradeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for StorageLayoutUpgradeDetector {
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

        let issues = self.check_storage_patterns(ctx);

        for (message, line_offset, remediation) in issues {
            let severity = if message.contains("missing storage gap")
                || message.contains("corrupt")
                || message.contains("upgrade blocker")
            {
                Severity::Critical
            } else if message.contains("struct modification")
                || message.contains("multiple inheritance")
                || message.contains("arrays of structs")
            {
                Severity::High
            } else {
                Severity::Medium
            };

            let finding = self
                .base
                .create_finding_with_severity(ctx, message, line_offset, 0, 20, severity)
                .with_fix_suggestion(remediation)
                .with_cwe(1321); // CWE-1321: Improperly Controlled Modification of Object Prototype Attributes

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
    use crate::types::test_utils::*;

    #[test]
    fn test_detector_properties() {
        let detector = StorageLayoutUpgradeDetector::new();
        assert_eq!(detector.id().to_string(), "storage-layout-upgrade");
        assert_eq!(detector.name(), "Storage Layout Upgrade Violation");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detects_missing_storage_gap() {
        let detector = StorageLayoutUpgradeDetector::new();
        let source = r#"
            contract UpgradeableToken {
                uint256 public totalSupply;
                mapping(address => uint256) public balances;

                function initialize() public initializer {
                    totalSupply = 1000000;
                }
                // Missing: uint256[50] private __gap;
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| f.message.contains("gap")));
    }

    #[test]
    fn test_detects_small_storage_gap() {
        let detector = StorageLayoutUpgradeDetector::new();
        let source = r#"
            contract UpgradeableBase {
                uint256 public value;
                uint256[5] private __gap; // Too small!
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(
            result
                .iter()
                .any(|f| f.message.contains("small") || f.message.contains("insufficient"))
        );
    }

    #[test]
    fn test_detects_struct_usage() {
        // Pattern intentionally removed: Structs are legitimate when properly managed
        // This test now verifies that structs alone don't trigger false positives
        let detector = StorageLayoutUpgradeDetector::new();
        let source = r#"
            contract UpgradeableSystem {
                struct User {
                    uint256 balance;
                    address addr;
                }

                mapping(address => User) public users;

                function initialize() public initializer {
                    // Setup
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Structs are legitimate - should only flag if missing storage gap
        let has_struct_specific_finding = result
            .iter()
            .any(|f| f.message.contains("struct") && !f.message.contains("gap"));
        assert!(
            !has_struct_specific_finding,
            "Structs should not be flagged as inherently unsafe"
        );
    }

    #[test]
    fn test_detects_multiple_inheritance_without_gap() {
        let detector = StorageLayoutUpgradeDetector::new();
        let source = r#"
            contract Base1 {
                uint256 public value1;
            }

            contract Base2 {
                uint256 public value2;
            }

            contract UpgradeableImpl is Base1, Base2 {
                uint256 public value3;

                function initialize() public initializer {
                    value1 = 1;
                    value2 = 2;
                    value3 = 3;
                }
                // Missing: gaps in base contracts
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(
            result
                .iter()
                .any(|f| f.message.contains("inheritance") || f.message.contains("gap"))
        );
    }

    #[test]
    fn test_detects_array_of_structs() {
        // Pattern intentionally removed: Arrays of structs are legitimate when properly managed
        // This test now verifies that arrays of structs don't trigger false positives
        let detector = StorageLayoutUpgradeDetector::new();
        let source = r#"
            contract UpgradeableRegistry {
                struct Record {
                    uint256 id;
                    address owner;
                }

                Record[] public records;

                function initialize() public initializer {}
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Arrays of structs are legitimate - should only flag if missing storage gap
        let has_array_struct_specific_finding = result.iter().any(|f| {
            f.message.contains("array")
                && f.message.contains("struct")
                && !f.message.contains("gap")
        });
        assert!(
            !has_array_struct_specific_finding,
            "Arrays of structs should not be flagged as inherently unsafe"
        );
    }

    #[test]
    fn test_safe_upgradeable_contract() {
        let detector = StorageLayoutUpgradeDetector::new();
        let source = r#"
            contract SafeUpgradeable {
                uint256 public value;
                address public owner;

                // Proper storage gap for future variables
                uint256[50] private __gap; // Allows adding 50 new variables

                function initialize(address _owner) public initializer {
                    owner = _owner;
                    value = 0;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Should have minimal critical findings
        let critical_findings: Vec<_> = result
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(critical_findings.is_empty());
    }

    #[test]
    fn test_detects_diamond_without_explicit_slots() {
        let detector = StorageLayoutUpgradeDetector::new();
        let source = r#"
            contract DiamondFacet {
                uint256 public data;

                function initialize() public {
                    data = 100;
                }
                // Missing: explicit storage slot definition
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(
            result
                .iter()
                .any(|f| f.message.contains("diamond") || f.message.contains("explicit slot"))
        );
    }

    #[test]
    fn test_well_designed_upgradeable_contract() {
        let detector = StorageLayoutUpgradeDetector::new();
        let source = r#"
            abstract contract BaseUpgradeable {
                uint256 public baseValue;
                uint256[49] private __gap; // 50 - 1 used = 49 remaining
            }

            contract ImplementationV1 is BaseUpgradeable {
                uint256 public implValue;

                // Document gap reduction
                /// @custom:storage-gap Reduced from 50 to 49 when adding implValue
                uint256[49] private __implementationGap;

                function initialize() public initializer {
                    baseValue = 1;
                    implValue = 2;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Should have minimal or no critical findings
        let critical_findings: Vec<_> = result
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(critical_findings.len() <= 1);
    }
}
