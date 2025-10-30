use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for Diamond Loupe standard violation
pub struct DiamondLoupeViolationDetector {
    base: BaseDetector,
}

impl DiamondLoupeViolationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("diamond-loupe-violation".to_string()),
                "Diamond Loupe Standard Violation".to_string(),
                "Detects missing or incorrect ERC-2535 Diamond Loupe functions required for introspection and facet discovery".to_string(),
                vec![
                    DetectorCategory::Diamond,
                    DetectorCategory::Upgradeable,
                    DetectorCategory::BestPractices,
                ],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for DiamondLoupeViolationDetector {
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

        // Check for Diamond Loupe compliance
        let contract = ctx.contract;
        let contract_source = self.get_contract_source(contract, ctx);

            // Only check contracts that implement Diamond pattern
            if !self.is_diamond_implementation(&contract_source) {
                return Ok(findings);
        }

            // Check for required loupe functions
            let missing_functions = self.get_missing_loupe_functions(&contract_source);

            if !missing_functions.is_empty() {
                let message = format!(
                    "Contract '{}' is a Diamond proxy but missing required ERC-2535 Loupe functions: {}. \
                    The Diamond Loupe standard defines 4 introspection functions that enable tools, users, \
                    and contracts to discover which facets and functions a Diamond implements. Without these, \
                    the Diamond becomes a black box, hindering integration, debugging, and security auditing.",
                    contract.name.name,
                    missing_functions.join(", ")
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
                    .with_cwe(573) // CWE-573: Improper Following of Specification by Caller
                    .with_fix_suggestion(format!(
                        "Implement missing Loupe functions in '{}': \
                        (1) facets() returning Facet[] array with address and selectors for each facet \
                        (2) facetFunctionSelectors(address _facet) returning bytes4[] of selectors for a facet \
                        (3) facetAddresses() returning address[] of all facet addresses \
                        (4) facetAddress(bytes4 _selector) returning address of facet for a selector \
                        (5) Implement IDiamondLoupe interface and add to supportsInterface",
                        contract.name.name
                    ));

                findings.push(finding);
            }

            // Pattern 2: Missing IDiamondLoupe interface support
            if !self.supports_loupe_interface(&contract_source) {
                let message = format!(
                    "Contract '{}' implements loupe functions but doesn't declare IDiamondLoupe interface support. \
                    The ERC-2535 standard requires supportsInterface(0x48e2b093) to return true for IDiamondLoupe. \
                    Without proper interface support, tools cannot reliably detect Diamond Loupe compliance.",
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
                    .with_cwe(573)
                    .with_fix_suggestion(format!(
                        "Add interface support to '{}': \
                        (1) Import 'import \"@openzeppelin/contracts/utils/introspection/IERC165.sol\"' \
                        (2) Implement supportsInterface: 'return interfaceId == type(IDiamondLoupe).interfaceId || interfaceId == type(IERC165).interfaceId' \
                        (3) IDiamondLoupe interface ID is 0x48e2b093 \
                        (4) Ensure DiamondLoupeFacet is added during initialization \
                        (5) Test interface detection with supportsInterface",
                        contract.name.name
                    ));

                findings.push(finding);
            }

            // Pattern 3: Incorrect facets() return type
            if self.has_facets_function(&contract_source)
                && !self.has_correct_facets_return_type(&contract_source)
            {
                let message = format!(
                    "Contract '{}' implements facets() with incorrect return type. \
                    ERC-2535 requires 'function facets() external view returns (Facet[] memory)' where \
                    Facet is 'struct Facet {{ address facetAddress; bytes4[] functionSelectors; }}'. \
                    Incorrect return types break compatibility with standard tooling.",
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
                    .with_cwe(573)
                    .with_fix_suggestion(format!(
                        "Fix facets() signature in '{}': \
                        (1) Define 'struct Facet {{ address facetAddress; bytes4[] functionSelectors; }}' \
                        (2) Signature must be 'function facets() external view returns (Facet[] memory facets_)' \
                        (3) Return array containing all facets with their selectors \
                        (4) Use storage layout: iterate through facetAddresses, get selectors for each \
                        (5) Ensure function is marked 'external view' not 'public'",
                        contract.name.name
                    ));

                findings.push(finding);
            }

            // Pattern 4: Missing Facet struct definition
            // Check both contract source AND full source (for file-level structs)
            let has_struct_in_contract = self.has_facet_struct_definition(&contract_source);
            let has_struct_in_file = self.has_facet_struct_definition(&ctx.source_code);

            if self.has_loupe_functions(&contract_source)
                && !has_struct_in_contract
                && !has_struct_in_file
            {
                let message = format!(
                    "Contract '{}' implements loupe functions but missing required Facet struct. \
                    ERC-2535 requires 'struct Facet {{ address facetAddress; bytes4[] functionSelectors; }}' \
                    for the facets() return value. Without this struct, the implementation is non-compliant.",
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
                    .with_cwe(573)
                    .with_fix_suggestion(format!(
                        "Add Facet struct to '{}': \
                        (1) Define 'struct Facet {{ address facetAddress; bytes4[] functionSelectors; }}' \
                        (2) Place struct in library or interface visible to loupe functions \
                        (3) Use struct in facets() return type \
                        (4) Ensure struct matches ERC-2535 specification exactly \
                        (5) Document struct fields for clarity",
                        contract.name.name
                    ));

                findings.push(finding);
            }

            // Pattern 5: Loupe functions not externally accessible
            if self.has_private_loupe_functions(&contract_source) {
                let message = format!(
                    "Contract '{}' implements loupe functions with incorrect visibility. \
                    All Diamond Loupe functions must be 'external view' to be accessible for introspection. \
                    Private, internal, or public functions violate the standard and prevent external access.",
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
                    .with_cwe(573)
                    .with_fix_suggestion(format!(
                        "Fix loupe function visibility in '{}': \
                        (1) Change all loupe functions to 'external view' \
                        (2) Remove 'public', 'internal', or 'private' modifiers \
                        (3) Ensure functions return correct types \
                        (4) Test external accessibility from contracts and tools \
                        (5) Verify gas efficiency with 'external' vs 'public'",
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

impl DiamondLoupeViolationDetector {
    fn is_diamond_contract(&self, source: &str) -> bool {
        let diamond_indicators = [
            "diamondCut",
            "FacetCut",
            "IDiamond",
            "LibDiamond",
            "Diamond",
            "facet",
        ];

        diamond_indicators
            .iter()
            .any(|indicator| source.contains(indicator))
    }

    fn is_diamond_implementation(&self, source: &str) -> bool {
        // Check if contract implements Diamond pattern (not just imports)
        let implementation_indicators = [
            "diamondCut",
            "selectorToFacet",
            "fallback()",
            "delegatecall",
        ];

        implementation_indicators
            .iter()
            .filter(|indicator| source.contains(*indicator))
            .count()
            >= 2
    }

    fn get_missing_loupe_functions(&self, source: &str) -> Vec<String> {
        let mut missing = Vec::new();

        // Check for each required loupe function
        if !self.has_facets_function(source) {
            missing.push("facets()".to_string());
        }

        if !self.has_facet_function_selectors(source) {
            missing.push("facetFunctionSelectors(address)".to_string());
        }

        if !self.has_facet_addresses(source) {
            missing.push("facetAddresses()".to_string());
        }

        if !self.has_facet_address(source) {
            missing.push("facetAddress(bytes4)".to_string());
        }

        missing
    }

    fn has_facets_function(&self, source: &str) -> bool {
        source.contains("function facets()")
    }

    fn has_facet_function_selectors(&self, source: &str) -> bool {
        source.contains("function facetFunctionSelectors(")
            || source.contains("function facetFunctionSelectors(address")
    }

    fn has_facet_addresses(&self, source: &str) -> bool {
        source.contains("function facetAddresses()")
    }

    fn has_facet_address(&self, source: &str) -> bool {
        source.contains("function facetAddress(")
            || source.contains("function facetAddress(bytes4")
    }

    fn has_loupe_functions(&self, source: &str) -> bool {
        // Check if contract has any loupe functions
        self.has_facets_function(source)
            || self.has_facet_function_selectors(source)
            || self.has_facet_addresses(source)
            || self.has_facet_address(source)
    }

    fn supports_loupe_interface(&self, source: &str) -> bool {
        // Check for IDiamondLoupe interface support
        let has_loupe_interface = source.contains("IDiamondLoupe")
            || source.contains("DiamondLoupe")
            || source.contains("0x48e2b093");

        let has_supports_interface = source.contains("supportsInterface");

        has_loupe_interface || (has_supports_interface && self.has_loupe_functions(source))
    }

    fn has_correct_facets_return_type(&self, source: &str) -> bool {
        // Check if facets() returns Facet[] memory
        source.contains("returns (Facet[] memory")
            || source.contains("returns(Facet[] memory")
            || source.contains("returns (Facet[]")
    }

    fn has_facet_struct_definition(&self, source: &str) -> bool {
        // Check for Facet struct with required fields
        let has_struct = source.contains("struct Facet");
        let has_address_field =
            source.contains("facetAddress") || source.contains("address facet");
        let has_selectors_field =
            source.contains("functionSelectors") || source.contains("bytes4[]");

        has_struct && has_address_field && has_selectors_field
    }

    fn has_private_loupe_functions(&self, source: &str) -> bool {
        // Check for loupe functions with wrong visibility
        let loupe_functions = [
            "function facets()",
            "function facetFunctionSelectors",
            "function facetAddresses()",
            "function facetAddress(",
        ];

        for func in &loupe_functions {
            if source.contains(func) {
                // Find the function declaration
                if let Some(func_pos) = source.find(func) {
                    let func_line_start = source[..func_pos].rfind('\n').unwrap_or(0);
                    let func_line_end = source[func_pos..]
                        .find('{')
                        .map(|p| func_pos + p)
                        .unwrap_or(source.len());
                    let func_decl = &source[func_line_start..func_line_end];

                    // Check if it's private, internal, or public (should be external)
                    if func_decl.contains("private")
                        || func_decl.contains("internal")
                        || (!func_decl.contains("external") && func_decl.contains("public"))
                    {
                        return true;
                    }
                }
            }
        }

        false
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

impl Default for DiamondLoupeViolationDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DiamondLoupeViolationDetector::new();
        assert_eq!(detector.name(), "Diamond Loupe Standard Violation");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "diamond-loupe-violation");
        assert!(detector.categories().contains(&DetectorCategory::Diamond));
        assert!(detector
            .categories()
            .contains(&DetectorCategory::Upgradeable));
        assert!(detector
            .categories()
            .contains(&DetectorCategory::BestPractices));
    }

    #[test]
    fn test_is_diamond_contract() {
        let detector = DiamondLoupeViolationDetector::new();

        assert!(detector.is_diamond_contract("function diamondCut() {}"));
        assert!(detector.is_diamond_contract("struct FacetCut { }"));
        assert!(detector.is_diamond_contract("interface IDiamond { }"));
        assert!(detector.is_diamond_contract("library LibDiamond { }"));
        assert!(!detector.is_diamond_contract("contract Token { }"));
    }

    #[test]
    fn test_has_loupe_functions() {
        let detector = DiamondLoupeViolationDetector::new();

        assert!(detector.has_facets_function("function facets() external view returns (Facet[] memory)"));
        assert!(detector.has_facet_function_selectors("function facetFunctionSelectors(address _facet)"));
        assert!(detector.has_facet_addresses("function facetAddresses() external view"));
        assert!(detector.has_facet_address("function facetAddress(bytes4 _selector)"));
    }

    #[test]
    fn test_get_missing_loupe_functions() {
        let detector = DiamondLoupeViolationDetector::new();

        // Missing all functions
        let incomplete = "contract Diamond { }";
        let missing = detector.get_missing_loupe_functions(incomplete);
        assert_eq!(missing.len(), 4);

        // Has all functions
        let complete = r#"
            function facets() external view returns (Facet[] memory) {}
            function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory) {}
            function facetAddresses() external view returns (address[] memory) {}
            function facetAddress(bytes4 _selector) external view returns (address) {}
        "#;
        let missing = detector.get_missing_loupe_functions(complete);
        assert_eq!(missing.len(), 0);

        // Missing some functions
        let partial = r#"
            function facets() external view returns (Facet[] memory) {}
            function facetAddresses() external view returns (address[] memory) {}
        "#;
        let missing = detector.get_missing_loupe_functions(partial);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"facetFunctionSelectors(address)".to_string()));
        assert!(missing.contains(&"facetAddress(bytes4)".to_string()));
    }

    #[test]
    fn test_has_correct_facets_return_type() {
        let detector = DiamondLoupeViolationDetector::new();

        let correct = "function facets() external view returns (Facet[] memory facets_)";
        assert!(detector.has_correct_facets_return_type(correct));

        let incorrect = "function facets() external view returns (address[] memory)";
        assert!(!detector.has_correct_facets_return_type(incorrect));
    }

    #[test]
    fn test_has_facet_struct_definition() {
        let detector = DiamondLoupeViolationDetector::new();

        let with_struct = r#"
            struct Facet {
                address facetAddress;
                bytes4[] functionSelectors;
            }
        "#;
        assert!(detector.has_facet_struct_definition(with_struct));

        let without_struct = "contract Diamond { }";
        assert!(!detector.has_facet_struct_definition(without_struct));

        let incomplete_struct = r#"
            struct Facet {
                address facetAddress;
            }
        "#;
        assert!(!detector.has_facet_struct_definition(incomplete_struct));
    }

    #[test]
    fn test_has_private_loupe_functions() {
        let detector = DiamondLoupeViolationDetector::new();

        let private_func = "function facets() private view returns (Facet[] memory)";
        assert!(detector.has_private_loupe_functions(private_func));

        let internal_func = "function facetAddresses() internal view returns (address[] memory)";
        assert!(detector.has_private_loupe_functions(internal_func));

        let external_func = "function facets() external view returns (Facet[] memory)";
        assert!(!detector.has_private_loupe_functions(external_func));
    }

    #[test]
    fn test_supports_loupe_interface() {
        let detector = DiamondLoupeViolationDetector::new();

        let with_interface = r#"
            contract Diamond is IDiamondLoupe {
                function supportsInterface(bytes4 interfaceId) external view returns (bool) {
                    return interfaceId == type(IDiamondLoupe).interfaceId;
                }
            }
        "#;
        assert!(detector.supports_loupe_interface(with_interface));

        let with_interface_id = r#"
            function supportsInterface(bytes4 interfaceId) external view returns (bool) {
                return interfaceId == 0x48e2b093;
            }
        "#;
        assert!(detector.supports_loupe_interface(with_interface_id));

        let without_interface = "contract Diamond { }";
        assert!(!detector.supports_loupe_interface(without_interface));
    }
}
