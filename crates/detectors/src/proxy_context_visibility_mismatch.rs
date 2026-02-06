use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for proxy/implementation visibility mismatches
///
/// Detects when function visibility differs between proxy and implementation contracts.
/// In delegatecall context, implementation visibility applies, which can expose internal
/// functions unintentionally.
///
/// Vulnerable pattern:
/// ```solidity
/// contract Proxy {
///     function _admin() internal view returns (address); // internal
/// }
/// contract Implementation {
///     function _admin() public view returns (address); // public - exposed!
/// }
/// ```
pub struct ProxyContextVisibilityMismatchDetector {
    base: BaseDetector,
}

impl Default for ProxyContextVisibilityMismatchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyContextVisibilityMismatchDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("proxy-context-visibility-mismatch"),
                "Proxy Context Visibility Mismatch".to_string(),
                "Detects visibility differences between proxy and implementation functions. \
                 In delegatecall context, implementation visibility applies. Internal proxy \
                 functions that are public in implementation become externally callable."
                    .to_string(),
                vec![
                    DetectorCategory::Upgradeable,
                    DetectorCategory::AccessControl,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Check if contract appears to be an implementation
    fn is_implementation_contract(&self, source: &str) -> bool {
        source.contains("Upgradeable")
            || source.contains("Initializable")
            || source.contains("Implementation")
            || source.contains("Logic")
            || source.contains("UUPSUpgradeable")
    }

    /// Find functions with underscore prefix that are public/external
    fn find_public_underscore_functions(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for functions starting with underscore that are public/external
            if trimmed.contains("function _") {
                if trimmed.contains("public") || trimmed.contains("external") {
                    // Extract function name
                    if let Some(func_name) = self.extract_function_name(trimmed) {
                        let visibility = if trimmed.contains("external") {
                            "external"
                        } else {
                            "public"
                        };
                        findings.push((line_num as u32 + 1, func_name, visibility.to_string()));
                    }
                }
            }
        }

        findings
    }

    /// Find internal functions that could be overridden as public
    fn find_overridable_internal_functions(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for internal virtual functions
            if trimmed.contains("function ")
                && trimmed.contains("internal")
                && trimmed.contains("virtual")
            {
                if let Some(func_name) = self.extract_function_name(trimmed) {
                    // Check if function name suggests it should be internal
                    if func_name.starts_with('_')
                        || func_name.contains("Internal")
                        || func_name.contains("_impl")
                    {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find visibility changes in override functions
    fn find_visibility_override_changes(&self, source: &str) -> Vec<(u32, String, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for override functions
            if trimmed.contains("function ") && trimmed.contains("override") {
                // Check for visibility keywords
                let is_public = trimmed.contains("public");
                let is_external = trimmed.contains("external");

                // Check comments for visibility change indication
                let context_start = if line_num > 3 { line_num - 3 } else { 0 };
                let context: String = lines[context_start..=line_num].join("\n");

                if (is_public || is_external)
                    && (context.contains("// was internal")
                        || context.contains("// changed from")
                        || context.contains("// visibility change")
                        || context.contains("/* was internal"))
                {
                    if let Some(func_name) = self.extract_function_name(trimmed) {
                        let new_vis = if is_external { "external" } else { "public" };
                        findings.push((
                            line_num as u32 + 1,
                            func_name,
                            "internal".to_string(),
                            new_vis.to_string(),
                        ));
                    }
                }
            }
        }

        findings
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

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for ProxyContextVisibilityMismatchDetector {
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

        // Phase 53 FP Reduction: Skip Compound-style protocols
        // Compound uses underscore-prefixed PUBLIC functions intentionally for admin operations
        // e.g., _setPriceOracle, _setCloseFactor, _setCollateralFactor
        // This is a deliberate design pattern, not a visibility mismatch
        let is_compound_style = source.contains("Comptroller")
            || source.contains("comptroller")
            || source.contains("CToken")
            || source.contains("Compound")
            || source.contains("compound-protocol")
            || (source.contains("_set") && source.contains("admin"));

        if is_compound_style {
            return Ok(findings);
        }

        // Only check implementation contracts
        if !self.is_implementation_contract(source) {
            return Ok(findings);
        }

        // Check for public underscore-prefixed functions
        let public_underscore = self.find_public_underscore_functions(source);
        for (line, func_name, visibility) in public_underscore {
            let message = format!(
                "Function '{}' in contract '{}' is {} but has underscore prefix suggesting \
                 internal visibility. In proxy context, this function will be externally \
                 callable through the proxy, potentially exposing internal logic.",
                func_name, contract_name, visibility
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(732) // CWE-732: Incorrect Permission Assignment
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(format!(
                    "If this function should be internal, change visibility:\n\n\
                     function {}(...) internal ... {{\n\
                         // ...\n\
                     }}\n\n\
                     If it must be public, consider renaming to remove underscore prefix \
                     to clearly indicate external accessibility.",
                    func_name
                ));

            findings.push(finding);
        }

        // Check for visibility changes in overrides
        let visibility_changes = self.find_visibility_override_changes(source);
        for (line, func_name, old_vis, new_vis) in visibility_changes {
            let message = format!(
                "Function '{}' in contract '{}' changes visibility from {} to {}. \
                 This can expose internal proxy logic through the implementation when \
                 called via delegatecall.",
                func_name, contract_name, old_vis, new_vis
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(732) // CWE-732: Incorrect Permission Assignment
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Keep visibility consistent between proxy and implementation:\n\n\
                     // If internal in base, keep internal:\n\
                     function _internalFunc() internal override {\n\
                         // implementation\n\
                     }\n\n\
                     // If needs to be public, also make base public or use different function"
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
        let detector = ProxyContextVisibilityMismatchDetector::new();
        assert_eq!(detector.name(), "Proxy Context Visibility Mismatch");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_public_underscore_detection() {
        let detector = ProxyContextVisibilityMismatchDetector::new();

        let code = r#"
            contract Implementation is Upgradeable {
                function _admin() public view returns (address) {}
                function _upgrade() external {}
            }
        "#;
        let findings = detector.find_public_underscore_functions(code);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_is_implementation() {
        let detector = ProxyContextVisibilityMismatchDetector::new();

        assert!(detector.is_implementation_contract("contract X is Upgradeable {}"));
        assert!(detector.is_implementation_contract("contract X is Initializable {}"));
        assert!(detector.is_implementation_contract("contract XImplementation {}"));
        assert!(!detector.is_implementation_contract("contract SimpleToken {}"));
    }

    #[test]
    fn test_extract_function_name() {
        let detector = ProxyContextVisibilityMismatchDetector::new();

        assert_eq!(
            detector.extract_function_name("function _admin() public view"),
            Some("_admin".to_string())
        );
        assert_eq!(
            detector.extract_function_name("function upgrade(address impl) external"),
            Some("upgrade".to_string())
        );
    }
}
