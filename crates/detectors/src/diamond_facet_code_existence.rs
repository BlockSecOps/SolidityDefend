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

    /// Check if contract is a Diamond pattern
    fn is_diamond_pattern(&self, source: &str) -> bool {
        source.contains("Diamond")
            || source.contains("IDiamond")
            || source.contains("diamondCut")
            || source.contains("DiamondCut")
            || source.contains("facets")
            || (source.contains("selectors") && source.contains("delegatecall"))
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
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Only check Diamond patterns
        if !self.is_diamond_pattern(source) {
            return Ok(findings);
        }

        // Check for unsafe delegatecalls
        let unsafe_calls = self.find_unsafe_delegatecalls(source);
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

        // Check for unsafe fallback
        if let Some(line) = self.find_unsafe_fallback(source) {
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

        // Check for unsafe facet registration
        if let Some(line) = self.find_unsafe_facet_registration(source) {
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
    fn test_is_diamond_pattern() {
        let detector = DiamondFacetCodeExistenceDetector::new();

        assert!(detector.is_diamond_pattern("contract MyDiamond {}"));
        assert!(detector.is_diamond_pattern("function diamondCut() external {}"));
        assert!(detector.is_diamond_pattern("IDiamond.FacetCut[] memory cuts"));
        assert!(!detector.is_diamond_pattern("contract SimpleToken {}"));
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
}
