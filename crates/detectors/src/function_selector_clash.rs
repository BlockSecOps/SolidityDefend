use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for function selector clashes in proxy contracts
///
/// In transparent proxy patterns, if the proxy and implementation have functions
/// with the same selector (first 4 bytes of keccak256(signature)), calls may be
/// routed incorrectly.
///
/// Known clashing selectors:
/// - proxyAdmin() and clash544284() both have selector 0x3e47158c
/// - owner() is a common clash target
pub struct FunctionSelectorClashDetector {
    base: BaseDetector,
}

impl Default for FunctionSelectorClashDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionSelectorClashDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("function-selector-clash"),
                "Function Selector Clash".to_string(),
                "Detects potential function selector collisions between proxy and implementation \
                 contracts that could cause calls to be routed incorrectly"
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Check if contract appears to be a proxy
    fn is_proxy_contract(&self, source: &str) -> bool {
        source.contains("TransparentUpgradeableProxy")
            || source.contains("ERC1967Proxy")
            || source.contains("Proxy")
            || source.contains("_implementation()")
            || source.contains("_fallback()")
            || source.contains("delegatecall")
    }

    /// Check if contract appears to be an implementation
    fn is_implementation_contract(&self, source: &str) -> bool {
        source.contains("Initializable")
            || source.contains("Upgradeable")
            || source.contains("initialize(")
    }

    /// Extract function signature from line (used in tests)
    #[cfg(test)]
    fn extract_function_signature(&self, line: &str) -> Option<String> {
        if let Some(start) = line.find("function ") {
            let after_function = &line[start + 9..];
            if let Some(paren_start) = after_function.find('(') {
                let name = after_function[..paren_start].trim();

                // Find the closing paren for parameters
                let from_paren = &after_function[paren_start..];
                if let Some(paren_end) = from_paren.find(')') {
                    let params = &from_paren[1..paren_end];
                    // Simplify params to just types
                    let param_types: Vec<&str> = params
                        .split(',')
                        .map(|p| p.trim().split_whitespace().next().unwrap_or(""))
                        .filter(|p| !p.is_empty())
                        .collect();

                    return Some(format!("{}({})", name, param_types.join(",")));
                }
            }
        }
        None
    }

    /// Check for known problematic function names
    fn check_problematic_functions(&self, source: &str) -> Vec<(String, u32)> {
        let mut issues = Vec::new();
        let problematic_names = ["admin", "implementation", "proxyAdmin", "changeAdmin"];
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            for name in &problematic_names {
                if line.contains(&format!("function {}(", name))
                    || line.contains(&format!("function {} (", name))
                {
                    // Skip if it's a proxy contract defining these
                    if !self.is_proxy_contract(source) || self.is_implementation_contract(source) {
                        issues.push(((*name).to_string(), (i + 1) as u32));
                    }
                }
            }
        }

        issues
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for FunctionSelectorClashDetector {
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

        // Check for implementation contracts with proxy-reserved function names
        if self.is_implementation_contract(source) {
            let issues = self.check_problematic_functions(source);

            for (func_name, line) in issues {
                let message = format!(
                    "Implementation contract '{}' has function '{}' which may clash with \
                     transparent proxy admin functions. This could cause unexpected routing \
                     behavior when called through a proxy.",
                    contract_name, func_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, func_name.len() as u32)
                    .with_cwe(436) // CWE-436: Interpretation Conflict
                    .with_confidence(Confidence::Medium)
                    .with_fix_suggestion(format!(
                        "Rename function '{}' to avoid selector clash with proxy admin functions. \
                         Consider using a different name like 'getAdmin()' or 'contractAdmin()'.",
                        func_name
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = FunctionSelectorClashDetector::new();
        assert_eq!(detector.name(), "Function Selector Clash");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_extract_function_signature() {
        let detector = FunctionSelectorClashDetector::new();

        let sig =
            detector.extract_function_signature("function transfer(address to, uint256 amount)");
        assert_eq!(sig, Some("transfer(address,uint256)".to_string()));

        let sig =
            detector.extract_function_signature("function admin() external view returns (address)");
        assert_eq!(sig, Some("admin()".to_string()));
    }

    #[test]
    fn test_check_problematic_functions() {
        let detector = FunctionSelectorClashDetector::new();

        let impl_with_admin = r#"
            contract MyImpl is Initializable {
                function admin() external view returns (address) {}
            }
        "#;
        let issues = detector.check_problematic_functions(impl_with_admin);
        assert!(!issues.is_empty());
    }
}
