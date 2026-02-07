use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for upgrade ABI incompatibility issues
///
/// Detects patterns that indicate potential ABI breaking changes in upgradeable contracts.
/// When functions are removed or signatures change, dependent contracts break permanently.
///
/// Research shows 1,990 ABI removals on Ethereum caused integration failures.
///
/// Vulnerable patterns:
/// - Removing public/external functions
/// - Changing function signatures
/// - Removing events that integrations depend on
pub struct UpgradeAbiIncompatibilityDetector {
    base: BaseDetector,
}

impl Default for UpgradeAbiIncompatibilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UpgradeAbiIncompatibilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("upgrade-abi-incompatibility"),
                "Upgrade ABI Incompatibility".to_string(),
                "Detects potential ABI breaking changes in upgradeable contracts. Removing or \
                 changing public functions can permanently break integrating contracts. Research \
                 shows thousands of ABI removals on Ethereum have caused integration failures."
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Check if contract appears to be an implementation version
    fn is_implementation_version(&self, source: &str) -> Option<String> {
        let lines: Vec<&str> = source.lines().collect();

        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("contract ") {
                // Look for V2, V3, etc. in contract name
                if trimmed.contains("V2")
                    || trimmed.contains("V3")
                    || trimmed.contains("V4")
                    || trimmed.contains("v2")
                    || trimmed.contains("v3")
                    || trimmed.contains("Upgraded")
                {
                    // Extract contract name
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        return Some(parts[1].trim_end_matches('{').to_string());
                    }
                }
            }
        }
        None
    }

    /// Check for deprecated/removed function indicators
    fn has_deprecated_indicators(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for @deprecated comments
            if trimmed.contains("@deprecated") || trimmed.contains("DEPRECATED") {
                if let Some(next_func) = self.find_next_function(&lines, line_num) {
                    findings.push((line_num as u32 + 1, next_func));
                }
            }

            // Check for functions that just revert
            if (trimmed.contains("function ") && trimmed.contains("external"))
                || (trimmed.contains("function ") && trimmed.contains("public"))
            {
                // Check if function body is just a revert
                let func_end = std::cmp::min(line_num + 5, lines.len());
                let func_context: String = lines[line_num..func_end].join("\n");

                if func_context.contains("revert(")
                    && (func_context.contains("Deprecated")
                        || func_context.contains("deprecated")
                        || func_context.contains("Removed")
                        || func_context.contains("removed"))
                {
                    if let Some(func_name) = self.extract_function_name(trimmed) {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find functions that override with incompatible signatures
    fn has_signature_changes(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for override with different parameters
            if trimmed.contains("function ") && trimmed.contains("override") {
                // Check for comments indicating signature change
                let context_start = if line_num > 3 { line_num - 3 } else { 0 };
                let context: String = lines[context_start..=line_num].join("\n");

                if context.contains("// Changed")
                    || context.contains("// Modified")
                    || context.contains("// New signature")
                    || context.contains("/* Changed")
                {
                    if let Some(func_name) = self.extract_function_name(trimmed) {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Check for removed standard interface functions
    fn check_missing_standard_functions(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();

        // Check for ERC20 partial implementation
        if source.contains("ERC20") || source.contains("IERC20") {
            let required_funcs = [
                "transfer",
                "transferFrom",
                "approve",
                "balanceOf",
                "allowance",
            ];
            for func in required_funcs {
                if !source.contains(&format!("function {}", func)) {
                    let line = self.find_contract_line(source);
                    findings.push((line, format!("Missing ERC20 function: {}", func)));
                }
            }
        }

        // Check for ERC721 partial implementation
        if source.contains("ERC721") || source.contains("IERC721") {
            let required_funcs = ["transferFrom", "safeTransferFrom", "approve", "ownerOf"];
            for func in required_funcs {
                // Check for standard function presence
                if !source.contains(&format!("function {}", func))
                    && !source.contains(&format!("function {}", func))
                {
                    let line = self.find_contract_line(source);
                    findings.push((line, format!("Missing ERC721 function: {}", func)));
                }
            }
        }

        findings
    }

    /// Find the next function after a given line
    fn find_next_function(&self, lines: &[&str], start: usize) -> Option<String> {
        for i in start..lines.len() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        None
    }

    /// Extract function name from declaration
    fn extract_function_name(&self, line: &str) -> Option<String> {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return Some(after_func[..paren_pos].trim().to_string());
            }
        }
        None
    }

    /// Find contract declaration line
    fn find_contract_line(&self, source: &str) -> u32 {
        for (i, line) in source.lines().enumerate() {
            if line.trim().starts_with("contract ") {
                return i as u32 + 1;
            }
        }
        1
    }

    /// Check if contract is upgradeable
    fn is_upgradeable(&self, source: &str) -> bool {
        source.contains("Upgradeable")
            || source.contains("Initializable")
            || source.contains("UUPSUpgradeable")
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for UpgradeAbiIncompatibilityDetector {
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

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Only check upgradeable contracts or version contracts
        if !self.is_upgradeable(source) && self.is_implementation_version(source).is_none() {
            return Ok(findings);
        }

        // Check for deprecated function indicators
        let deprecated = self.has_deprecated_indicators(source);
        for (line, func_name) in deprecated {
            let message = format!(
                "Function '{}' in contract '{}' appears to be deprecated. \
                 Removing public functions from upgradeable contracts breaks all dependent \
                 contracts permanently. Consider keeping a compatibility wrapper.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(439) // CWE-439: Behavioral Change in New Version
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(format!(
                    "Keep a compatibility wrapper for removed functions:\n\n\
                     /// @notice Deprecated: Use newFunction() instead\n\
                     function {}(...) external returns (...) {{\n\
                         return newFunction(...);\n\
                     }}",
                    func_name
                ));

            findings.push(finding);
        }

        // Check for signature changes
        let sig_changes = self.has_signature_changes(source);
        for (line, func_name) in sig_changes {
            let message = format!(
                "Function '{}' in contract '{}' has a modified signature. \
                 Changing function signatures in upgradeable contracts breaks ABI compatibility \
                 and causes all integrating contracts to fail.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(439) // CWE-439: Behavioral Change in New Version
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Keep the original function signature and add a new function:\n\n\
                     // Keep original for compatibility\n\
                     function originalFunc(uint256 a) external returns (uint256) {\n\
                         return newFunc(a, defaultB);\n\
                     }\n\n\
                     // New function with additional parameters\n\
                     function newFunc(uint256 a, uint256 b) external returns (uint256) {\n\
                         // new implementation\n\
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
        let detector = UpgradeAbiIncompatibilityDetector::new();
        assert_eq!(detector.name(), "Upgrade ABI Incompatibility");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_implementation_version() {
        let detector = UpgradeAbiIncompatibilityDetector::new();

        let v2_code = "contract TokenV2 is Initializable {}";
        assert!(detector.is_implementation_version(v2_code).is_some());

        let v1_code = "contract Token is Initializable {}";
        assert!(detector.is_implementation_version(v1_code).is_none());
    }

    #[test]
    fn test_deprecated_detection() {
        let detector = UpgradeAbiIncompatibilityDetector::new();

        let deprecated_code = r#"
            contract TokenV2 {
                /// @deprecated Use newTransfer instead
                function transfer(address to, uint256 amount) external {
                    revert("Deprecated");
                }
            }
        "#;
        let findings = detector.has_deprecated_indicators(deprecated_code);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_extract_function_name() {
        let detector = UpgradeAbiIncompatibilityDetector::new();

        assert_eq!(
            detector.extract_function_name("function transfer(address to) external"),
            Some("transfer".to_string())
        );
        assert_eq!(
            detector
                .extract_function_name("function balanceOf(address) public view returns (uint256)"),
            Some("balanceOf".to_string())
        );
    }

    #[test]
    fn test_is_upgradeable() {
        let detector = UpgradeAbiIncompatibilityDetector::new();

        assert!(detector.is_upgradeable("contract X is Upgradeable {}"));
        assert!(detector.is_upgradeable("contract X is Initializable {}"));
        assert!(!detector.is_upgradeable("contract SimpleToken {}"));
    }
}
