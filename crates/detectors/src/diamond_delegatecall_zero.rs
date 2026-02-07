use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for Diamond delegatecall to zero address vulnerabilities
pub struct DiamondDelegatecallZeroDetector {
    base: BaseDetector,
}

impl DiamondDelegatecallZeroDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("diamond-delegatecall-zero".to_string()),
                "Diamond Delegatecall to Zero Address".to_string(),
                "Detects unsafe delegatecall in Diamond fallback that fails to validate facet address existence before execution".to_string(),
                vec![
                    DetectorCategory::Diamond,
                    DetectorCategory::Upgradeable,
                    DetectorCategory::ExternalCalls,
                ],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for DiamondDelegatecallZeroDetector {
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


        // Check if this looks like a Diamond proxy contract

        let is_diamond_contract = self.is_diamond_contract(&ctx.source_code);

        if !is_diamond_contract {
            return Ok(findings);
        }

        // Check for unsafe delegatecall issues
        let contract = ctx.contract;
        let contract_source = self.get_contract_source(contract, ctx);

        // Check for fallback function with delegatecall
        if self.has_fallback_delegatecall(&contract_source) {
            // Pattern 1: Missing address(0) validation
            if !self.validates_facet_not_zero(&contract_source) {
                let message = format!(
                    "Contract '{}' fallback performs delegatecall without validating facet != address(0). \
                        When a function selector is not registered in selectorToFacet, it returns address(0). \
                        Delegatecall to address(0) succeeds silently in assembly, returning success=true without \
                        executing any code. This creates false success responses for non-existent functions, \
                        breaking contract behavior and potentially bypassing security checks.",
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
                        .with_cwe(476) // CWE-476: NULL Pointer Dereference
                        .with_fix_suggestion(format!(
                            "Add facet validation in '{}' fallback: \
                            (1) After loading facet address, add 'require(facet != address(0), \"Function does not exist\")' \
                            (2) Check BEFORE delegatecall, not after \
                            (3) Use revert with custom error for gas efficiency: 'error FunctionNotFound(bytes4 selector)' \
                            (4) Consider explicit fallback failure rather than silent success \
                            (5) Validate facet in both Solidity and assembly implementations",
                            contract.name.name
                        ));

                findings.push(finding);
            }

            // Pattern 2: Missing code existence validation
            // Skip if zero-address validation exists (reduces risk significantly)
            if !self.validates_facet_code_exists(&contract_source)
                && !self.validates_facet_not_zero(&contract_source)
            {
                let message = format!(
                    "Contract '{}' fallback delegates without verifying facet has code. \
                        Even if facet != address(0), the address may be an EOA or a self-destructed contract \
                        with no code. Delegatecall to addresses without code succeeds silently, returning \
                        success=true. This allows unregistered selectors to succeed unexpectedly, \
                        bypassing access controls and validation logic.",
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
                        .with_cwe(476)
                        .with_fix_suggestion(format!(
                            "Add code existence check in '{}': \
                            (1) Validate 'require(facet.code.length > 0, \"Facet has no code\")' \
                            (2) In assembly, use EXTCODESIZE: 'if iszero(extcodesize(facet)) {{ revert(0, 0) }}' \
                            (3) Perform check immediately after loading facet address \
                            (4) Consider caching code validation during facet registration \
                            (5) Handle self-destructed facets gracefully",
                            contract.name.name
                        ));

                findings.push(finding);
            }

            // Pattern 3: Assembly delegatecall without validation
            // Skip if Solidity-level validation exists before assembly block
            if self.has_assembly_delegatecall_without_validation(&contract_source)
                && !self.validates_facet_not_zero(&contract_source)
            {
                let message = format!(
                    "Contract '{}' uses assembly delegatecall without proper validation. \
                        Assembly delegatecall bypasses Solidity's address validation, making it critical \
                        to manually check facet != 0 and extcodesize > 0. Missing validation in assembly \
                        is more dangerous because there are no implicit safety checks.",
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
                        .with_cwe(476)
                        .with_fix_suggestion(format!(
                            "Add assembly validation in '{}': \
                            (1) After loading facet: 'if iszero(facet) {{ revert(0, 0) }}' \
                            (2) Check code size: 'if iszero(extcodesize(facet)) {{ revert(0, 0) }}' \
                            (3) Place checks immediately before delegatecall opcode \
                            (4) Use consistent error handling (revert with error code) \
                            (5) Document assembly validation logic clearly",
                            contract.name.name
                        ));

                findings.push(finding);
            }

            // Pattern 4: Silent failure on missing selector
            if self.has_silent_failure_on_missing_selector(&contract_source) {
                let message = format!(
                    "Contract '{}' fallback silently succeeds when selector not found. \
                        Returning success for non-existent functions violates principle of least surprise. \
                        Callers expect reverts for undefined functions, not silent success. This can cause \
                        integration bugs, incorrect state assumptions, and security vulnerabilities in dependent contracts.",
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
                        .with_cwe(476)
                        .with_fix_suggestion(format!(
                            "Fail explicitly in '{}': \
                            (1) Revert immediately if facet == address(0): 'revert FunctionNotFound(msg.sig)' \
                            (2) Never allow fallback to succeed for unregistered selectors \
                            (3) Define custom error for clarity: 'error FunctionNotFound(bytes4 selector)' \
                            (4) Log failed selector lookups for monitoring \
                            (5) Consider fallback function that always reverts for safety",
                            contract.name.name
                        ));

                findings.push(finding);
            }

            // Pattern 5: Missing return data validation
            if self.has_unchecked_delegatecall_return(&contract_source) {
                let message = format!(
                    "Contract '{}' fallback doesn't validate delegatecall return success. \
                        Even with proper facet validation, the delegated call can fail (revert, out of gas, etc.). \
                        If success is not checked, failures are silently ignored, returning empty data as if the call succeeded. \
                        This masks errors and causes incorrect behavior in calling contracts.",
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
                        .with_cwe(476)
                        .with_fix_suggestion(format!(
                            "Check delegatecall success in '{}': \
                            (1) Capture success: '(bool success, bytes memory data) = facet.delegatecall(msg.data)' \
                            (2) Check result: 'if (!success) {{ if (data.length > 0) {{ revert with data }} else {{ revert() }} }}' \
                            (3) In assembly: 'if iszero(success) {{ revert(add(result, 32), mload(result)) }}' \
                            (4) Propagate revert data to preserve error messages \
                            (5) Never ignore success flag",
                            contract.name.name
                        ));

                findings.push(finding);
            }
        }

        // Pattern 6: Missing fallback function documentation
        if self.is_diamond_proxy(&contract_source)
            && self.has_fallback_delegatecall(&contract_source)
            && !self.has_fallback_documentation(&contract_source)
        {
            let message = format!(
                "Contract '{}' fallback delegatecall lacks documentation. \
                    Diamond fallback is security-critical as it routes all calls. Missing documentation \
                    of validation logic, security checks, and failure modes makes auditing difficult \
                    and increases risk of vulnerabilities.",
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
                .with_cwe(476)
                .with_fix_suggestion(format!(
                    "Document fallback in '{}': \
                        (1) Add NatSpec comments explaining delegatecall mechanism \
                        (2) Document validation steps: address(0) check, code existence, etc. \
                        (3) Explain failure modes and error handling \
                        (4) Note security assumptions and invariants \
                        (5) Provide examples of intended and unintended usage",
                    contract.name.name
                ));

            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DiamondDelegatecallZeroDetector {
    fn is_diamond_contract(&self, source: &str) -> bool {
        let diamond_indicators = [
            "diamondCut",
            "FacetCut",
            "selectorToFacet",
            "LibDiamond",
            "Diamond",
        ];

        diamond_indicators
            .iter()
            .any(|indicator| source.contains(indicator))
    }

    fn has_fallback_delegatecall(&self, source: &str) -> bool {
        // Check for fallback function with delegatecall
        let has_fallback = source.contains("fallback()") || source.contains("fallback (");
        let has_delegatecall = source.contains("delegatecall");

        has_fallback && has_delegatecall
    }

    fn validates_facet_not_zero(&self, source: &str) -> bool {
        // Check for address(0) validation
        let validation_patterns = [
            "require(facet != address(0)",
            "require(facetAddress != address(0)",
            "if (facet == address(0))",
            "if (facetAddress == address(0))",
            "facet != address(0)",
            "facet == address(0)",
            "iszero(facet)",
        ];

        // Must have delegatecall AND validation
        if !source.contains("delegatecall") {
            return true;
        }

        validation_patterns
            .iter()
            .any(|pattern| source.contains(pattern))
    }

    fn validates_facet_code_exists(&self, source: &str) -> bool {
        // Check for code existence validation
        let validation_patterns = [".code.length", "extcodesize", "EXTCODESIZE", "codesize"];

        validation_patterns
            .iter()
            .any(|pattern| source.contains(pattern))
    }

    fn has_assembly_delegatecall_without_validation(&self, source: &str) -> bool {
        // Check for assembly delegatecall
        if !source.contains("assembly") || !source.contains("delegatecall") {
            return false;
        }

        // Check if assembly block has delegatecall
        let has_assembly_delegatecall =
            source.contains("assembly") && source.contains("delegatecall");

        if !has_assembly_delegatecall {
            return false;
        }

        // Look for validation patterns in assembly
        let assembly_validation = [
            "iszero(facet)",
            "iszero(facetAddress)",
            "extcodesize",
            "if iszero",
        ];

        // Has assembly delegatecall but no validation
        !assembly_validation
            .iter()
            .any(|pattern| source.contains(pattern))
    }

    fn has_silent_failure_on_missing_selector(&self, source: &str) -> bool {
        // Check if fallback allows execution to continue when selector not found
        if !self.has_fallback_delegatecall(source) {
            return false;
        }

        // Check for explicit revert on missing selector
        let revert_patterns = [
            "revert",
            "require(facet != address(0)",
            "if (facet == address(0)) revert",
            "FunctionNotFound",
        ];

        // Has fallback but no revert for missing selector
        !revert_patterns
            .iter()
            .any(|pattern| source.contains(pattern))
    }

    fn has_unchecked_delegatecall_return(&self, source: &str) -> bool {
        // Check for delegatecall without success check
        if !source.contains("delegatecall") {
            return false;
        }

        // Look for success checking patterns
        let success_check_patterns = [
            "bool success",
            "(bool success,",
            "if (!success)",
            "if (success)",
            "require(success",
            "if iszero(success)",
            "switch result",  // Assembly switch on delegatecall result
            "switch success", // Assembly switch on success variable
            "case 0",         // Assembly case for failure
        ];

        // Has delegatecall but no success check
        !success_check_patterns
            .iter()
            .any(|pattern| source.contains(pattern))
    }

    fn is_diamond_proxy(&self, source: &str) -> bool {
        // Check if this is a Diamond proxy implementation
        let proxy_indicators = ["fallback", "delegatecall", "selectorToFacet"];

        proxy_indicators
            .iter()
            .filter(|indicator| source.contains(*indicator))
            .count()
            >= 2
    }

    fn has_fallback_documentation(&self, source: &str) -> bool {
        // Check for documentation near fallback function
        if let Some(fallback_pos) = source.find("fallback()") {
            // Look for comments in the 200 characters before fallback
            let start = fallback_pos.saturating_sub(200);
            let context = &source[start..fallback_pos];

            // Check for various comment styles (lenient - any comment near fallback counts)
            context.contains("///")
                || context.contains("/**")
                || context.contains("// @")
                || context.contains("// Safe")     // Security comment
                || context.contains("// Prevent")  // Security comment
                || context.contains("// Diamond")  // Diamond-specific comment
                || context.contains("//") // Any single-line comment near fallback
        } else {
            false
        }
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

impl Default for DiamondDelegatecallZeroDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DiamondDelegatecallZeroDetector::new();
        assert_eq!(detector.name(), "Diamond Delegatecall to Zero Address");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "diamond-delegatecall-zero");
        assert!(detector.categories().contains(&DetectorCategory::Diamond));
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::Upgradeable)
        );
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::ExternalCalls)
        );
    }

    #[test]
    fn test_is_diamond_contract() {
        let detector = DiamondDelegatecallZeroDetector::new();

        assert!(detector.is_diamond_contract("function diamondCut() {}"));
        assert!(detector.is_diamond_contract("mapping(bytes4 => address) selectorToFacet"));
        assert!(detector.is_diamond_contract("library LibDiamond { }"));
        assert!(!detector.is_diamond_contract("contract Token { }"));
    }

    #[test]
    fn test_has_fallback_delegatecall() {
        let detector = DiamondDelegatecallZeroDetector::new();

        let with_fallback = r#"
            fallback() external payable {
                address facet = selectorToFacet[msg.sig];
                facet.delegatecall(msg.data);
            }
        "#;
        assert!(detector.has_fallback_delegatecall(with_fallback));

        let without_fallback = r#"
            function execute() external {
                address facet = selectorToFacet[msg.sig];
                facet.delegatecall(msg.data);
            }
        "#;
        assert!(!detector.has_fallback_delegatecall(without_fallback));
    }

    #[test]
    fn test_validates_facet_not_zero() {
        let detector = DiamondDelegatecallZeroDetector::new();

        let validated = r#"
            fallback() external payable {
                address facet = selectorToFacet[msg.sig];
                require(facet != address(0), "Function not found");
                facet.delegatecall(msg.data);
            }
        "#;
        assert!(detector.validates_facet_not_zero(validated));

        let unvalidated = r#"
            fallback() external payable {
                address facet = selectorToFacet[msg.sig];
                facet.delegatecall(msg.data);
            }
        "#;
        assert!(!detector.validates_facet_not_zero(unvalidated));
    }

    #[test]
    fn test_validates_facet_code_exists() {
        let detector = DiamondDelegatecallZeroDetector::new();

        let validated = r#"
            fallback() external payable {
                address facet = selectorToFacet[msg.sig];
                require(facet.code.length > 0, "No code");
                facet.delegatecall(msg.data);
            }
        "#;
        assert!(detector.validates_facet_code_exists(validated));

        let unvalidated = r#"
            fallback() external payable {
                address facet = selectorToFacet[msg.sig];
                require(facet != address(0));
                facet.delegatecall(msg.data);
            }
        "#;
        assert!(!detector.validates_facet_code_exists(unvalidated));
    }

    #[test]
    fn test_has_assembly_delegatecall_without_validation() {
        let detector = DiamondDelegatecallZeroDetector::new();

        let unvalidated_assembly = r#"
            fallback() external payable {
                assembly {
                    let facet := sload(selector.slot)
                    let success := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
                }
            }
        "#;
        assert!(detector.has_assembly_delegatecall_without_validation(unvalidated_assembly));

        let validated_assembly = r#"
            fallback() external payable {
                assembly {
                    let facet := sload(selector.slot)
                    if iszero(facet) { revert(0, 0) }
                    let success := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
                }
            }
        "#;
        assert!(!detector.has_assembly_delegatecall_without_validation(validated_assembly));
    }

    #[test]
    fn test_has_silent_failure_on_missing_selector() {
        let detector = DiamondDelegatecallZeroDetector::new();

        let silent_failure = r#"
            fallback() external payable {
                address facet = selectorToFacet[msg.sig];
                facet.delegatecall(msg.data);
            }
        "#;
        assert!(detector.has_silent_failure_on_missing_selector(silent_failure));

        let explicit_revert = r#"
            fallback() external payable {
                address facet = selectorToFacet[msg.sig];
                require(facet != address(0), "Function not found");
                facet.delegatecall(msg.data);
            }
        "#;
        assert!(!detector.has_silent_failure_on_missing_selector(explicit_revert));
    }

    #[test]
    fn test_has_unchecked_delegatecall_return() {
        let detector = DiamondDelegatecallZeroDetector::new();

        let unchecked = r#"
            fallback() external payable {
                address facet = selectorToFacet[msg.sig];
                facet.delegatecall(msg.data);
            }
        "#;
        assert!(detector.has_unchecked_delegatecall_return(unchecked));

        let checked = r#"
            fallback() external payable {
                address facet = selectorToFacet[msg.sig];
                (bool success, bytes memory data) = facet.delegatecall(msg.data);
                require(success, "Delegatecall failed");
            }
        "#;
        assert!(!detector.has_unchecked_delegatecall_return(checked));
    }
}
