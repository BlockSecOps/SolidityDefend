use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for Diamond function selector collision vulnerabilities
pub struct DiamondSelectorCollisionDetector {
    base: BaseDetector,
}

impl DiamondSelectorCollisionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("diamond-selector-collision".to_string()),
                "Diamond Function Selector Collision".to_string(),
                "Detects function selector collisions in Diamond facets caused by duplicate selectors across facets or missing validation during diamondCut operations".to_string(),
                vec![DetectorCategory::Diamond, DetectorCategory::Upgradeable],
                Severity::High,
            ),
        }
    }
}

impl Detector for DiamondSelectorCollisionDetector {
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

        // Check if this looks like a Diamond proxy contract
        let is_diamond_contract = self.is_diamond_contract(&ctx.source_code);

        if !is_diamond_contract {
            return Ok(findings);
        }

        // Check for selector collision issues
        let contract = ctx.contract;

        // Skip interfaces - they don't have implementation
        if contract.contract_type == ast::ContractType::Interface {
            return Ok(findings);
        }

        let contract_source = self.get_contract_source(contract, ctx);

        // Check for diamondCut function
        if self.has_diamond_cut_function(&contract_source) {
            // Pattern 1: Missing selector uniqueness validation
            if !self.validates_selector_uniqueness(&contract_source) {
                let message = format!(
                    "Contract '{}' implements diamondCut without selector collision protection. \
                        When adding function selectors via FacetCutAction.Add, the contract must verify \
                        that selectorToFacet[selector] == address(0) before registration. Without this check, \
                        adding a selector that already exists will silently overwrite the existing facet mapping, \
                        redirecting calls to the wrong implementation and causing critical state corruption or security bypasses.",
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
                        .with_cwe(694) // CWE-694: Use of Multiple Resources with Duplicate Identifier
                        .with_fix_suggestion(format!(
                            "Add selector collision check in '{}': \
                            (1) Before adding selectors in diamondCut, verify 'require(selectorToFacet[selector] == address(0), \"Selector already exists\")' \
                            (2) For FacetCutAction.Add, check that selector is not already registered \
                            (3) For FacetCutAction.Replace, verify existing facet != address(0) \
                            (4) Implement facetFunctionSelectors() to audit all registered selectors \
                            (5) Consider selector registry with collision detection logic",
                            contract.name.name
                        ));

                findings.push(finding);
            }

            // Pattern 2: Missing FacetCutAction validation
            if !self.validates_facet_cut_action(&contract_source) {
                let message = format!(
                    "Contract '{}' diamondCut lacks FacetCutAction-specific validation. \
                        The Add action must check existingFacet == address(0), Replace must check existingFacet != address(0), \
                        and Remove must verify selector exists. Without action-specific checks, invalid operations \
                        can corrupt the facet registry causing undefined behavior.",
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
                        .with_cwe(694)
                        .with_fix_suggestion(format!(
                            "Implement action validation in '{}': \
                            (1) For Add: 'require(existingFacet == address(0), \"Selector exists\")' \
                            (2) For Replace: 'require(existingFacet != address(0) && existingFacet != newFacet, \"Invalid replace\")' \
                            (3) For Remove: 'require(existingFacet != address(0), \"Selector not found\")' \
                            (4) Add comprehensive validation for each FacetCutAction enum case",
                            contract.name.name
                        ));

                findings.push(finding);
            }

            // Pattern 3: Unsafe selectorToFacet mapping update
            if self.has_unsafe_selector_mapping_update(&contract_source) {
                let message = format!(
                    "Contract '{}' updates selectorToFacet mapping without collision prevention. \
                        Direct assignment 'selectorToFacet[selector] = facet' without checking existing value \
                        creates collision risk. Multiple facets with the same selector will overwrite each other, \
                        causing loss of functionality and potential security vulnerabilities.",
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
                        .with_cwe(694)
                        .with_fix_suggestion(format!(
                            "Secure selector mapping in '{}': \
                            (1) Always check 'address existingFacet = selectorToFacet[selector]' before update \
                            (2) Validate based on operation: Add requires existingFacet == 0, Replace requires existingFacet != 0 \
                            (3) Use helper functions: addSelector(), replaceSelector(), removeSelector() with built-in validation \
                            (4) Emit events for all selector changes for auditability \
                            (5) Implement selector conflict resolution strategy",
                            contract.name.name
                        ));

                findings.push(finding);
            }
        }

        // Pattern 4: Missing selector registry for collision detection
        if self.is_facet_management_contract(&contract_source)
            && !self.has_selector_registry(&contract_source)
        {
            let message = format!(
                "Contract '{}' manages facets without comprehensive selector registry. \
                    Tracking only selectorToFacet is insufficient - you need facetToSelectors for validation. \
                    Without bidirectional mapping, removing/replacing facets can leave orphaned selectors \
                    creating collision vulnerabilities.",
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
                .with_cwe(694)
                .with_fix_suggestion(format!(
                    "Implement full selector registry in '{}': \
                        (1) Add 'mapping(address => bytes4[]) facetToSelectors' for reverse lookup \
                        (2) Maintain synchronized updates to both mappings \
                        (3) Implement getAllSelectors() view function \
                        (4) Add getSelectorCollisions() to detect conflicts \
                        (5) Create comprehensive facet management library",
                    contract.name.name
                ));

            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DiamondSelectorCollisionDetector {
    fn is_diamond_contract(&self, source: &str) -> bool {
        let diamond_indicators = [
            "diamondCut",
            "FacetCut",
            "IDiamondCut",
            "selectorToFacet",
            "LibDiamond",
            "Diamond",
        ];

        diamond_indicators
            .iter()
            .any(|indicator| source.contains(indicator))
    }

    fn has_diamond_cut_function(&self, source: &str) -> bool {
        source.contains("function diamondCut")
            || source.contains("function _diamondCut")
            || (source.contains("diamondCut") && source.contains("FacetCut"))
    }

    fn validates_selector_uniqueness(&self, source: &str) -> bool {
        // Check for selector existence validation patterns
        let validation_patterns = [
            "selectorToFacet[selector] == address(0)",
            "selectorToFacet[selector] == address(0x0)",
            "existingFacet == address(0)",
            "require(selectorToFacet",
            "_selectorExists",
            "selectorExists",
        ];

        // Must have diamondCut/Add operation AND validation
        let has_add_operation = source.contains("FacetCutAction.Add")
            || source.contains("action == FacetCutAction.Add")
            || source.contains("Add:");

        if !has_add_operation {
            return true; // No Add operation, so no validation needed
        }

        validation_patterns
            .iter()
            .any(|pattern| source.contains(pattern))
    }

    fn validates_facet_cut_action(&self, source: &str) -> bool {
        // Check for action-specific validation
        let has_action_enum = source.contains("FacetCutAction") || source.contains("enum Action");

        if !has_action_enum {
            return false;
        }

        // Look for Add/Replace/Remove specific validation
        let add_validation = source.contains("Add")
            && (source.contains("== address(0)") || source.contains("!= address(0)"));
        let replace_validation = source.contains("Replace") && source.contains("!= address(0)");
        let remove_validation = source.contains("Remove") && source.contains("address(0)");

        // Should have validation for at least 2 action types
        [add_validation, replace_validation, remove_validation]
            .iter()
            .filter(|&&x| x)
            .count()
            >= 2
    }

    fn has_unsafe_selector_mapping_update(&self, source: &str) -> bool {
        // Check for direct mapping assignment without validation
        let has_selector_mapping = source.contains("selectorToFacet[")
            || source.contains("selectorToFacet [")
            || source.contains("_selectorToFacet[");

        if !has_selector_mapping {
            return false;
        }

        // Check if there's assignment without prior validation
        let has_direct_assignment = source.contains("selectorToFacet[") && source.contains("=");

        // Check for missing validation
        let has_validation = source.contains("require(selectorToFacet")
            || source.contains("if (selectorToFacet")
            || source.contains("existingFacet");

        has_direct_assignment && !has_validation
    }

    fn is_facet_management_contract(&self, source: &str) -> bool {
        // Check if contract manages facets
        let management_indicators = [
            "diamondCut",
            "addFacet",
            "replaceFacet",
            "removeFacet",
            "FacetCut",
            "selectorToFacet",
        ];

        management_indicators
            .iter()
            .filter(|indicator| source.contains(*indicator))
            .count()
            >= 2
    }

    fn has_selector_registry(&self, source: &str) -> bool {
        // Check for comprehensive selector tracking
        let has_forward_mapping = source.contains("selectorToFacet");
        let has_reverse_mapping = source.contains("facetToSelectors")
            || source.contains("facetFunctionSelectors")
            || source.contains("_facetSelectors");
        let has_selector_list = source.contains("bytes4[]")
            && (source.contains("selector") || source.contains("Selector"));

        has_forward_mapping && (has_reverse_mapping || has_selector_list)
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

impl Default for DiamondSelectorCollisionDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DiamondSelectorCollisionDetector::new();
        assert_eq!(detector.name(), "Diamond Function Selector Collision");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "diamond-selector-collision");
        assert!(detector.categories().contains(&DetectorCategory::Diamond));
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::Upgradeable)
        );
    }

    #[test]
    fn test_is_diamond_contract() {
        let detector = DiamondSelectorCollisionDetector::new();

        assert!(detector.is_diamond_contract("function diamondCut() {}"));
        assert!(detector.is_diamond_contract("mapping(bytes4 => address) selectorToFacet"));
        assert!(detector.is_diamond_contract("struct FacetCut { }"));
        assert!(detector.is_diamond_contract("library LibDiamond { }"));
        assert!(!detector.is_diamond_contract("contract Token { }"));
    }

    #[test]
    fn test_has_diamond_cut_function() {
        let detector = DiamondSelectorCollisionDetector::new();

        assert!(
            detector.has_diamond_cut_function("function diamondCut(FacetCut[] memory cuts) {}")
        );
        assert!(detector.has_diamond_cut_function("function _diamondCut() internal {}"));
        assert!(!detector.has_diamond_cut_function("function updateFacet() {}"));
    }

    #[test]
    fn test_validates_selector_uniqueness() {
        let detector = DiamondSelectorCollisionDetector::new();

        let secure_code = r#"
            function diamondCut(FacetCut[] memory cuts) {
                if (action == FacetCutAction.Add) {
                    require(selectorToFacet[selector] == address(0), "Selector exists");
                }
            }
        "#;
        assert!(detector.validates_selector_uniqueness(secure_code));

        let vulnerable_code = r#"
            function diamondCut(FacetCut[] memory cuts) {
                if (action == FacetCutAction.Add) {
                    selectorToFacet[selector] = facet;
                }
            }
        "#;
        assert!(!detector.validates_selector_uniqueness(vulnerable_code));

        // No Add operation - should return true (no validation needed)
        let no_add_code = r#"
            function diamondCut(FacetCut[] memory cuts) {
                if (action == FacetCutAction.Remove) {
                    delete selectorToFacet[selector];
                }
            }
        "#;
        assert!(detector.validates_selector_uniqueness(no_add_code));
    }

    #[test]
    fn test_validates_facet_cut_action() {
        let detector = DiamondSelectorCollisionDetector::new();

        let secure_code = r#"
            enum FacetCutAction { Add, Replace, Remove }
            function process(FacetCutAction action) {
                if (action == FacetCutAction.Add) {
                    require(existingFacet == address(0));
                } else if (action == FacetCutAction.Replace) {
                    require(existingFacet != address(0));
                } else if (action == FacetCutAction.Remove) {
                    require(existingFacet != address(0));
                }
            }
        "#;
        assert!(detector.validates_facet_cut_action(secure_code));

        let vulnerable_code = r#"
            enum FacetCutAction { Add, Replace, Remove }
            function process(FacetCutAction action) {
                selectorToFacet[selector] = facet;
            }
        "#;
        assert!(!detector.validates_facet_cut_action(vulnerable_code));
    }

    #[test]
    fn test_has_unsafe_selector_mapping_update() {
        let detector = DiamondSelectorCollisionDetector::new();

        let vulnerable_code = r#"
            function addSelector(bytes4 selector, address facet) {
                selectorToFacet[selector] = facet;
            }
        "#;
        assert!(detector.has_unsafe_selector_mapping_update(vulnerable_code));

        let secure_code = r#"
            function addSelector(bytes4 selector, address facet) {
                require(selectorToFacet[selector] == address(0));
                selectorToFacet[selector] = facet;
            }
        "#;
        assert!(!detector.has_unsafe_selector_mapping_update(secure_code));
    }

    #[test]
    fn test_has_selector_registry() {
        let detector = DiamondSelectorCollisionDetector::new();

        let complete_registry = r#"
            mapping(bytes4 => address) public selectorToFacet;
            mapping(address => bytes4[]) public facetToSelectors;
        "#;
        assert!(detector.has_selector_registry(complete_registry));

        let incomplete_registry = r#"
            mapping(bytes4 => address) public selectorToFacet;
        "#;
        assert!(!detector.has_selector_registry(incomplete_registry));
    }
}
