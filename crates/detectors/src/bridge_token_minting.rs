//! Bridge Token Minting Access Control Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct TokenMintingDetector {
    base: BaseDetector,
}

impl TokenMintingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("bridge-token-mint-control".to_string()),
                "Bridge Token Minting Control".to_string(),
                "Detects unsafe token minting in bridge contracts".to_string(),
                vec![
                    DetectorCategory::CrossChain,
                    DetectorCategory::AccessControl,
                ],
                Severity::Critical,
            ),
        }
    }

    fn is_bridge_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        source.contains("bridge") || source.contains("relay") || source.contains("crosschain")
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let name = function.name.name.to_lowercase();

        if !name.contains("mint") && !name.contains("issue") {
            return issues;
        }

        // Only check external/public functions
        let is_external = matches!(
            function.visibility,
            ast::Visibility::External | ast::Visibility::Public
        );

        if !is_external {
            return issues;
        }

        // Get function source with comments stripped
        let func_source = self.get_function_source(function, ctx).to_lowercase();

        // Check for access control modifiers (now that AST parser populates them!)
        let has_modifier = !function.modifiers.is_empty();

        // Also check for inline require statements as additional validation
        let has_inline_check = func_source.contains("require(msg.sender");

        let has_access = has_modifier || has_inline_check;

        let validates_message = func_source.contains("verify")
            && (func_source.contains("message")
                || func_source.contains("proof")
                || func_source.contains("signature"));

        let has_limits = func_source.contains("max") && func_source.contains("amount");

        if !has_access {
            issues.push((
                format!("Unrestricted token minting in '{}'", function.name.name),
                Severity::Critical,
                "Add access control: modifier onlyBridge { require(msg.sender == bridge); _; }"
                    .to_string(),
            ));
        }

        if has_access && !validates_message {
            issues.push((
                format!("Missing message validation before minting in '{}'", function.name.name),
                Severity::Critical,
                "Add: require(verifyMessage(hash, proof)); require(!processed[hash]); processed[hash] = true;".to_string()
            ));
        }

        if has_access && validates_message && !has_limits {
            issues.push((
                format!("Missing mint amount limits in '{}'", function.name.name),
                Severity::High,
                "Add: require(amount <= MAX_MINT_AMOUNT);".to_string(),
            ));
        }

        issues
    }

    /// Get function source code with comments stripped to avoid false positives
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start >= source_lines.len() || end >= source_lines.len() {
            return String::new();
        }

        // Strip single-line comments to avoid matching keywords in comments
        source_lines[start..=end]
            .iter()
            .map(|line| {
                if let Some(comment_pos) = line.find("//") {
                    &line[..comment_pos]
                } else {
                    line
                }
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }
}

impl Default for TokenMintingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TokenMintingDetector {
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


        if !self.is_bridge_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            for (title, severity, remediation) in self.check_function(function, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        title,
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_cwe(269) // CWE-269: Improper Privilege Management
                    .with_fix_suggestion(remediation);
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
        let detector = TokenMintingDetector::new();
        assert_eq!(detector.name(), "Bridge Token Minting Control");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::CrossChain)
        );
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::AccessControl)
        );
    }
}
