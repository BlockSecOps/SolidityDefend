use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for Diamond facet code existence checks
///
/// Detects Diamond pattern implementations that don't verify code exists at facet
/// addresses before delegatecall. If a facet self-destructs or never existed,
/// delegatecall returns success but does nothing.
///
/// Vulnerable pattern:
/// ```solidity
/// function _delegate(address facet) internal {
///     // Missing: require(facet.code.length > 0)
///     assembly {
///         let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
///         // delegatecall to empty address returns success!
///     }
/// }
/// ```
pub struct DiamondFacetCodeExistenceDetector {
    base: BaseDetector,
}

impl Default for DiamondFacetCodeExistenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DiamondFacetCodeExistenceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("diamond-facet-code-existence"),
                "Diamond Facet Code Existence".to_string(),
                "Detects Diamond proxy patterns that don't verify code exists at facet addresses. \
                 Delegatecall to an empty address (facet destroyed or never deployed) returns success, \
                 silently failing to execute any logic."
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Extract source code for only the current contract (not the whole file)
    fn get_contract_source(&self, ctx: &AnalysisContext) -> String {
        let start = ctx.contract.location.start().line();
        let end = ctx.contract.location.end().line();
        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check if the contract itself is a Diamond EIP-2535 pattern.
    /// Requires strong indicators in the contract-level source, not just the file.
    fn is_diamond_pattern(&self, contract_source: &str) -> bool {
        // Strong EIP-2535 Diamond indicators (any one is sufficient)
        let strong_indicators = [
            "diamondCut",
            "DiamondCut",
            "FacetCut",
            "IDiamond",
            "IDiamondCut",
            "IDiamondLoupe",
            "LibDiamond",
            "selectorToFacet",
            "facetAddress",
        ];

        if strong_indicators
            .iter()
            .any(|ind| contract_source.contains(ind))
        {
            return true;
        }

        // Combined indicator: must have both facet-related AND selector-related terms
        // in actual code (not just comments), plus delegatecall
        let has_facet_term = contract_source.contains("facet")
            && (contract_source.contains("address facet")
                || contract_source.contains("facetAddress")
                || contract_source.contains("_facet")
                || contract_source.contains("Facet"));
        let has_selector_dispatch =
            contract_source.contains("msg.sig") || contract_source.contains("msg.selector");
        let has_delegatecall = contract_source.contains("delegatecall");

        has_facet_term && has_selector_dispatch && has_delegatecall
    }

    /// Check if this contract is a known non-Diamond proxy pattern that should be skipped.
    fn is_non_diamond_proxy(&self, contract_source: &str, contract_name: &str) -> bool {
        let name_lower = contract_name.to_lowercase();

        // Known non-Diamond proxy name patterns
        let non_diamond_names = [
            "transparentproxy",
            "uupsproxy",
            "beaconproxy",
            "eip1967",
            "minimalproxy",
            "upgradeableproxy",
        ];
        if non_diamond_names.iter().any(|n| name_lower.contains(n)) {
            return true;
        }

        // EIP-1967 proxy pattern: uses implementation slot, no facet routing
        let has_eip1967_slot = contract_source.contains("eip1967.proxy.implementation")
            || contract_source.contains("IMPLEMENTATION_SLOT");
        let lacks_facet_routing = !contract_source.contains("selectorToFacet")
            && !contract_source.contains("facetAddress")
            && !contract_source.contains("FacetCut");

        if has_eip1967_slot && lacks_facet_routing {
            return true;
        }

        false
    }

    /// Check if the contract has a contract-level code existence check
    /// (extcodesize/isContract anywhere in the contract body, protecting all calls).
    fn has_contract_level_code_check(&self, contract_source: &str) -> bool {
        contract_source.contains("extcodesize")
            || contract_source.contains("isContract")
            || contract_source.contains(".code.length")
    }

    /// Find delegatecall without code existence check
    fn find_unsafe_delegatecalls(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for delegatecall in assembly
            if trimmed.contains("delegatecall(") {
                // Check surrounding context for code existence check
                let context_start = if line_num > 15 { line_num - 15 } else { 0 };
                let context_end = std::cmp::min(line_num + 5, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                // Check for various code existence patterns
                let has_code_check = context.contains("extcodesize")
                    || context.contains(".code.length")
                    || context.contains("code.length")
                    || context.contains("codesize")
                    || context.contains("isContract");

                if !has_code_check {
                    // Extract function/context name
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find fallback with delegatecall without code check
    fn find_unsafe_fallback(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for fallback function
            if trimmed.contains("fallback()") || trimmed.starts_with("fallback(") {
                // Check fallback body for delegatecall
                let func_end = std::cmp::min(line_num + 30, lines.len());
                let func_body: String = lines[line_num..func_end].join("\n");

                if func_body.contains("delegatecall") {
                    // Check for code existence check
                    if !func_body.contains("extcodesize")
                        && !func_body.contains(".code.length")
                        && !func_body.contains("isContract")
                    {
                        return Some(line_num as u32 + 1);
                    }
                }
            }
        }

        None
    }

    /// Check for facet registration without code check
    fn find_unsafe_facet_registration(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for facet registration/addition
            if (trimmed.contains("addFacet")
                || trimmed.contains("replaceFacet")
                || trimmed.contains("_addFunctions")
                || trimmed.contains("diamondCut"))
                && trimmed.contains("function")
            {
                // Check function body for code check
                let func_end = std::cmp::min(line_num + 20, lines.len());
                let func_body: String = lines[line_num..func_end].join("\n");

                if !func_body.contains("extcodesize")
                    && !func_body.contains(".code.length")
                    && !func_body.contains("isContract")
                    && !func_body.contains("require(facet")
                {
                    return Some(line_num as u32 + 1);
                }
            }
        }

        None
    }

    /// Find the containing function for a line
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
            if trimmed.contains("fallback()") || trimmed.starts_with("fallback(") {
                return "fallback".to_string();
            }
        }
        "unknown".to_string()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for DiamondFacetCodeExistenceDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let contract_name = self.get_contract_name(ctx);
        let contract_source = self.get_contract_source(ctx);

        // Skip non-Diamond proxy patterns (Transparent, UUPS, EIP-1967, Beacon)
        if self.is_non_diamond_proxy(&contract_source, &contract_name) {
            return Ok(findings);
        }

        // Only check actual Diamond EIP-2535 patterns (using contract source, not file source)
        if !self.is_diamond_pattern(&contract_source) {
            return Ok(findings);
        }

        // Skip if the contract already has code existence checks anywhere
        if self.has_contract_level_code_check(&contract_source) {
            return Ok(findings);
        }

        // Check for unsafe delegatecalls (using contract source, not file source)
        let unsafe_calls = self.find_unsafe_delegatecalls(&contract_source);
        for (line, func_name) in unsafe_calls {
            let message = format!(
                "Function '{}' in Diamond contract '{}' performs delegatecall without verifying \
                 code exists at the target address. If a facet is destroyed or never deployed, \
                 delegatecall returns success but executes no code, causing silent failures.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(476) // CWE-476: NULL Pointer Dereference (closest analog)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add code existence check before delegatecall:\n\n\
                     // Solidity check:\n\
                     require(facet.code.length > 0, \"Facet has no code\");\n\n\
                     // Or in assembly:\n\
                     assembly {\n\
                         if iszero(extcodesize(facet)) {\n\
                             revert(0, 0) // or custom error\n\
                         }\n\
                         // then delegatecall\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Check for unsafe fallback (using contract source)
        if let Some(line) = self.find_unsafe_fallback(&contract_source) {
            let message = format!(
                "Fallback function in Diamond contract '{}' performs delegatecall without \
                 checking facet code existence. This can cause silent failures for any call \
                 to the Diamond when the selected facet has been destroyed.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 20)
                .with_cwe(476) // CWE-476: NULL Pointer Dereference
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add code existence check in fallback:\n\n\
                     fallback() external payable {\n\
                         address facet = selectorToFacet[msg.sig];\n\
                         require(facet != address(0), \"Function not found\");\n\
                         require(facet.code.length > 0, \"Facet destroyed\");\n\
                         // delegatecall...\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Check for unsafe facet registration (using contract source)
        if let Some(line) = self.find_unsafe_facet_registration(&contract_source) {
            let message = format!(
                "Facet registration in Diamond contract '{}' doesn't verify code exists at \
                 the facet address. This allows registering non-existent or destroyed facets.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(476) // CWE-476: NULL Pointer Dereference
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Verify facet code exists during registration:\n\n\
                     function addFacet(address facet, bytes4[] calldata selectors) external {\n\
                         require(facet.code.length > 0, \"Invalid facet\");\n\
                         for (uint i = 0; i < selectors.length; i++) {\n\
                             selectorToFacet[selectors[i]] = facet;\n\
                         }\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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
        let detector = DiamondFacetCodeExistenceDetector::new();
        assert_eq!(detector.name(), "Diamond Facet Code Existence");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_diamond_pattern_strong_indicators() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        // Strong EIP-2535 indicators should match
        assert!(detector.is_diamond_pattern("function diamondCut() external {}"));
        assert!(detector.is_diamond_pattern("IDiamond.FacetCut[] memory cuts"));
        assert!(detector.is_diamond_pattern("IDiamondCut.FacetCut[] memory cut"));
        assert!(detector.is_diamond_pattern("mapping(bytes4 => address) selectorToFacet;"));
        assert!(detector.is_diamond_pattern("LibDiamond.diamondStorage()"));
        assert!(detector.is_diamond_pattern("IDiamondLoupe.Facet[] memory facets"));
    }

    #[test]
    fn test_is_diamond_pattern_combined_indicators() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        // Combined indicator: facet term + selector dispatch + delegatecall
        let diamond_fallback = r#"
            address facet = ds.selectorToFacet[msg.sig];
            assembly { let r := delegatecall(gas(), facet, 0, calldatasize(), 0, 0) }
        "#;
        assert!(detector.is_diamond_pattern(diamond_fallback));
    }

    #[test]
    fn test_is_diamond_pattern_rejects_non_diamond() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        // Generic terms should NOT match without strong indicators
        assert!(!detector.is_diamond_pattern("contract SimpleToken {}"));
        assert!(!detector.is_diamond_pattern("contract MyDiamond {}"));
        // "selectors" + delegatecall alone is not enough (common in regular proxies)
        assert!(!detector.is_diamond_pattern(
            "// route selectors\nassembly { delegatecall(gas(), impl, 0, 0, 0, 0) }"
        ));
        // "facets" alone is not enough
        assert!(!detector.is_diamond_pattern("// multiple facets of the system"));
    }

    #[test]
    fn test_is_non_diamond_proxy() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        // Transparent proxy by name
        assert!(detector.is_non_diamond_proxy("contract body", "TransparentProxy"));
        // UUPS proxy by name
        assert!(detector.is_non_diamond_proxy("contract body", "UUPSProxy"));
        // EIP-1967 proxy by storage slot pattern
        let eip1967_source = r#"
            bytes32 constant IMPLEMENTATION_SLOT = keccak256("eip1967.proxy.implementation");
            fallback() { delegatecall(gas(), impl, 0, 0, 0, 0) }
        "#;
        assert!(detector.is_non_diamond_proxy(eip1967_source, "MyProxy"));
        // Diamond proxy should NOT be excluded
        assert!(!detector.is_non_diamond_proxy(
            "mapping(bytes4 => address) selectorToFacet;",
            "DiamondProxy"
        ));
    }

    #[test]
    fn test_has_contract_level_code_check() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        assert!(detector.has_contract_level_code_check("size := extcodesize(facet)"));
        assert!(detector.has_contract_level_code_check("require(isContract(facet))"));
        assert!(detector.has_contract_level_code_check("require(facet.code.length > 0)"));
        assert!(!detector.has_contract_level_code_check("delegatecall(gas(), facet, 0, 0, 0, 0)"));
    }

    #[test]
    fn test_unsafe_delegatecall_detection() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        let unsafe_code = r#"
            contract Diamond {
                function _delegate(address facet) internal {
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        let findings = detector.find_unsafe_delegatecalls(unsafe_code);
        assert!(!findings.is_empty());

        let safe_code = r#"
            contract Diamond {
                function _delegate(address facet) internal {
                    require(facet.code.length > 0, "No code");
                    assembly {
                        let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        let findings = detector.find_unsafe_delegatecalls(safe_code);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_unsafe_fallback_detection() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        let unsafe_fallback = r#"
            contract Diamond {
                fallback() external payable {
                    address facet = selectorToFacet[msg.sig];
                    assembly {
                        let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        assert!(detector.find_unsafe_fallback(unsafe_fallback).is_some());
    }

    #[test]
    fn test_transparent_proxy_not_flagged() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        // A typical transparent proxy should NOT be flagged as Diamond
        let transparent_proxy = r#"
            contract TransparentProxy {
                bytes32 constant IMPLEMENTATION_SLOT = keccak256("eip1967.proxy.implementation");
                fallback() external payable {
                    address impl = _getImplementation();
                    assembly {
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        assert!(detector.is_non_diamond_proxy(transparent_proxy, "TransparentProxy"));
        assert!(!detector.is_diamond_pattern(transparent_proxy));
    }

    #[test]
    fn test_eip1967_proxy_not_flagged() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        let eip1967 = r#"
            contract EIP1967CompliantProxy {
                bytes32 constant IMPLEMENTATION_SLOT = keccak256("eip1967.proxy.implementation");
                function _delegate(address impl) private {
                    assembly {
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        assert!(detector.is_non_diamond_proxy(eip1967, "EIP1967CompliantProxy"));
    }

    #[test]
    fn test_real_diamond_still_detected() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        // A real Diamond proxy without code checks should still be detected
        let diamond = r#"
            contract DiamondProxy {
                mapping(bytes4 => address) selectorToFacet;
                fallback() external payable {
                    address facet = selectorToFacet[msg.sig];
                    assembly {
                        let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        assert!(!detector.is_non_diamond_proxy(diamond, "DiamondProxy"));
        assert!(detector.is_diamond_pattern(diamond));
        assert!(!detector.has_contract_level_code_check(diamond));
        assert!(detector.find_unsafe_fallback(diamond).is_some());
        assert!(!detector.find_unsafe_delegatecalls(diamond).is_empty());
    }

    #[test]
    fn test_diamond_with_code_check_not_flagged() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        // Diamond proxy WITH extcodesize should not be flagged
        let safe_diamond = r#"
            contract DiamondProxy {
                mapping(bytes4 => address) selectorToFacet;
                fallback() external payable {
                    address facet = selectorToFacet[msg.sig];
                    assembly {
                        if iszero(extcodesize(facet)) { revert(0, 0) }
                        let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        assert!(detector.is_diamond_pattern(safe_diamond));
        assert!(detector.has_contract_level_code_check(safe_diamond));
    }
}
