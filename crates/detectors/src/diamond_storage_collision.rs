use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for Diamond proxy storage collision vulnerabilities
pub struct DiamondStorageCollisionDetector {
    base: BaseDetector,
}

impl DiamondStorageCollisionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("diamond-storage-collision".to_string()),
                "Diamond Storage Collision".to_string(),
                "Detects storage collision risks in Diamond facets caused by direct storage variable declarations instead of using the Diamond Storage pattern for namespace isolation".to_string(),
                vec![DetectorCategory::Diamond, DetectorCategory::Upgradeable],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for DiamondStorageCollisionDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        // Check if this looks like a Diamond facet contract
        let is_potential_facet = self.is_potential_diamond_facet(&ctx.source_code);

        if !is_potential_facet {
            return Ok(findings);
        }

        // Check for storage collision issues
        let contract = ctx.contract;
        let contract_source = self.get_contract_source(contract, ctx);

        // Pattern 1: Direct storage variables without Diamond Storage pattern
        if self.has_direct_storage_variables(&contract_source) {
            let has_diamond_storage = self.uses_diamond_storage_pattern(&contract_source);

            if !has_diamond_storage {
                let message = format!(
                    "Contract '{}' declares storage variables directly without using Diamond Storage pattern. \
                        This creates collision risk when multiple facets share the same proxy storage. \
                        Direct storage at sequential slots (0, 1, 2...) will collide across facets, \
                        corrupting state and causing critical failures.",
                    contract.name.name
                );

                let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            contract.name.location.start().line() as u32,
                            contract.name.location.start().column() as u32,
                            contract.name.name.len() as u32,
                        )
                        .with_cwe(1321) // CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
                        .with_fix_suggestion(format!(
                            "Implement Diamond Storage pattern for '{}': \
                            (1) Create a library with 'bytes32 constant STORAGE_POSITION = keccak256(\"diamond.storage.{}\")' \
                            (2) Define a struct containing all storage variables, \
                            (3) Create a function returning 'Storage storage ds' using assembly to set slot to STORAGE_POSITION, \
                            (4) Access all storage through this function instead of direct variables, \
                            (5) Use unique namespace per facet to guarantee isolation.",
                            contract.name.name,
                            contract.name.name.to_lowercase()
                        ));

                findings.push(finding);
            }
        }

        // Pattern 2: Missing namespace isolation even with library pattern
        if contract_source.contains("library") && contract_source.contains("Storage") {
            let issues = self.check_storage_pattern_correctness(&contract_source);

            for issue in issues {
                let message = format!(
                    "Contract '{}' storage pattern issue: {} \
                        Improper Diamond Storage implementation can still lead to collisions.",
                    contract.name.name, issue
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        contract.name.location.start().line() as u32,
                        contract.name.location.start().column() as u32,
                        contract.name.name.len() as u32,
                    )
                    .with_cwe(1321)
                    .with_fix_suggestion(format!(
                        "Fix storage pattern in '{}': \
                            (1) Ensure STORAGE_POSITION uses unique namespace with keccak256, \
                            (2) Verify assembly block correctly sets 'ds.slot := position', \
                            (3) Make STORAGE_POSITION constant to prevent modification, \
                            (4) Use consistent pattern across all facets, \
                            (5) Document storage layout for each facet.",
                        contract.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DiamondStorageCollisionDetector {
    fn is_potential_diamond_facet(&self, source: &str) -> bool {
        // Check for common Diamond-related indicators
        let diamond_indicators = [
            "facet",
            "Facet",
            "diamond",
            "Diamond",
            "diamondCut",
            "diamondStorage",
            "STORAGE_POSITION",
            "LibDiamond",
        ];

        diamond_indicators
            .iter()
            .any(|indicator| source.contains(indicator))
            || source.contains("delegatecall") // Diamond uses delegatecall pattern
    }

    fn has_direct_storage_variables(&self, source: &str) -> bool {
        // Check for storage variable declarations at contract level
        let storage_patterns = [
            "uint256 public",
            "uint256 private",
            "uint256 internal",
            "address public",
            "address private",
            "address internal",
            "mapping(",
            "bool public",
            "bool private",
            "bool internal",
            "bytes32 public",
            "bytes32 private",
            "bytes32 internal",
        ];

        // Must have contract keyword and storage variables
        if !source.contains("contract") {
            return false;
        }

        storage_patterns
            .iter()
            .any(|pattern| source.contains(pattern))
    }

    fn uses_diamond_storage_pattern(&self, source: &str) -> bool {
        // Check for Diamond Storage pattern indicators
        let has_storage_position =
            source.contains("STORAGE_POSITION") || source.contains("storagePosition");
        let has_keccak_namespace = source.contains("keccak256") && source.contains("storage");
        let has_assembly_slot = source.contains("assembly") && source.contains(".slot");
        let has_storage_struct = source.contains("struct") && source.contains("Storage");

        // Should have most of these indicators
        let indicator_count = [
            has_storage_position,
            has_keccak_namespace,
            has_assembly_slot,
            has_storage_struct,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        indicator_count >= 3
    }

    fn check_storage_pattern_correctness(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: STORAGE_POSITION not constant
        if source.contains("STORAGE_POSITION") && !source.contains("constant STORAGE_POSITION") {
            issues.push("STORAGE_POSITION should be constant to prevent modification".to_string());
        }

        // Pattern 2: Missing keccak256 for namespace
        if source.contains("STORAGE_POSITION") && !source.contains("keccak256") {
            issues.push(
                "STORAGE_POSITION must use keccak256 for unique namespace generation".to_string(),
            );
        }

        // Pattern 3: Assembly slot assignment looks wrong
        if source.contains("assembly")
            && source.contains("slot")
            && !source.contains("ds.slot")
            && !source.contains("s.slot")
        {
            issues.push(
                    "Assembly block should assign storage position to struct slot (ds.slot := position)".to_string(),
                );
        }

        // Pattern 4: Generic storage namespace (collision risk)
        if source.contains("keccak256") {
            let generic_namespaces = ["storage", "data", "state", "variables"];
            if generic_namespaces
                .iter()
                .any(|ns| source.contains(&format!("\"{}\"", ns)))
            {
                issues.push(
                    "Generic storage namespace detected. Use unique namespace like 'diamond.storage.facetName' to prevent collisions".to_string(),
                );
            }
        }

        // Pattern 5: Multiple storage positions in one contract
        let storage_position_count = source.matches("STORAGE_POSITION").count();
        if storage_position_count > 1 {
            issues.push(
                "Multiple STORAGE_POSITION constants detected. Each facet should use a single, unique storage namespace".to_string(),
            );
        }

        issues
    }

    fn get_contract_source(&self, contract: &ast::Contract<'_>, ctx: &AnalysisContext) -> String {
        let start = contract.location.start().line();
        let end = contract.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

impl Default for DiamondStorageCollisionDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DiamondStorageCollisionDetector::new();
        assert_eq!(detector.name(), "Diamond Storage Collision");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "diamond-storage-collision");
        assert!(detector.categories().contains(&DetectorCategory::Diamond));
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::Upgradeable)
        );
    }

    #[test]
    fn test_is_potential_diamond_facet() {
        let detector = DiamondStorageCollisionDetector::new();

        assert!(detector.is_potential_diamond_facet("contract MyFacet { }"));
        assert!(detector.is_potential_diamond_facet("library LibDiamond { }"));
        assert!(detector.is_potential_diamond_facet("function diamondCut() {}"));
        assert!(detector.is_potential_diamond_facet("bytes32 constant STORAGE_POSITION"));
        assert!(!detector.is_potential_diamond_facet("contract Token { }"));
    }

    #[test]
    fn test_has_direct_storage_variables() {
        let detector = DiamondStorageCollisionDetector::new();

        let vulnerable_source = "contract Facet { uint256 public value; address public owner; }";
        assert!(detector.has_direct_storage_variables(vulnerable_source));

        let vulnerable_mapping = "contract Facet { mapping(address => uint256) public balances; }";
        assert!(detector.has_direct_storage_variables(vulnerable_mapping));

        let no_storage =
            "contract Facet { function getValue() external view returns (uint256) {} }";
        assert!(!detector.has_direct_storage_variables(no_storage));
    }

    #[test]
    fn test_uses_diamond_storage_pattern() {
        let detector = DiamondStorageCollisionDetector::new();

        let secure_pattern = r#"
            library LibDiamondStorage {
                bytes32 constant STORAGE_POSITION = keccak256("diamond.storage.facet");
                struct Storage {
                    uint256 value;
                }
                function diamondStorage() internal pure returns (Storage storage ds) {
                    bytes32 position = STORAGE_POSITION;
                    assembly { ds.slot := position }
                }
            }
        "#;
        assert!(detector.uses_diamond_storage_pattern(secure_pattern));

        let vulnerable_pattern = "contract Facet { uint256 public value; }";
        assert!(!detector.uses_diamond_storage_pattern(vulnerable_pattern));
    }

    #[test]
    fn test_check_storage_pattern_correctness() {
        let detector = DiamondStorageCollisionDetector::new();

        // Test non-constant STORAGE_POSITION
        let bad_constant = "bytes32 STORAGE_POSITION = keccak256('storage');";
        let issues = detector.check_storage_pattern_correctness(bad_constant);
        assert!(issues.iter().any(|i| i.contains("constant")));

        // Test missing keccak256
        let bad_namespace = "bytes32 constant STORAGE_POSITION = 0x123;";
        let issues = detector.check_storage_pattern_correctness(bad_namespace);
        assert!(issues.iter().any(|i| i.contains("keccak256")));

        // Test generic namespace
        let generic = r#"bytes32 constant STORAGE_POSITION = keccak256("storage");"#;
        let issues = detector.check_storage_pattern_correctness(generic);
        assert!(issues.iter().any(|i| i.contains("unique namespace")));

        // Test proper pattern
        let good_pattern = r#"
            bytes32 constant STORAGE_POSITION = keccak256("diamond.storage.myFacet");
            assembly { ds.slot := position }
        "#;
        let issues = detector.check_storage_pattern_correctness(good_pattern);
        assert!(issues.is_empty());
    }
}
