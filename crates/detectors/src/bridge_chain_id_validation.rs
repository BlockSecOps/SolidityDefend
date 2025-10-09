//! Chain-ID Validation Detector for Bridge Contracts

use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

pub struct ChainIdValidationDetector {
    base: BaseDetector,
}

impl ChainIdValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-chainid-validation".to_string()),
                "Missing Chain-ID Validation".to_string(),
                "Detects missing chain-ID validation in bridge message processing".to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::High,
            ),
        }
    }

    fn is_bridge_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        source.contains("bridge") || source.contains("relay")
    }

    fn check_function(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<(Severity, String)> {
        let name = function.name.name.to_lowercase();

        if !name.contains("process") && !name.contains("execute") && !name.contains("receive") {
            return None;
        }

        // Only check external/public functions (skip internal/private helpers)
        let is_external = matches!(
            function.visibility,
            ast::Visibility::External | ast::Visibility::Public
        );

        if !is_external {
            return None;
        }

        // Extract only the function body source code to avoid matching comments
        let func_source = self.get_function_source(function, ctx).to_lowercase();

        // Look for actual validation using block.chainid (more specific than just "chainid")
        let validates_chain = (func_source.contains("block.chainid") || func_source.contains("block.chain.id")) &&
            (func_source.contains("==") || func_source.contains("require"));

        // Check if chainid is used in hash (parameters like sourceChainId or targetChainId)
        let in_hash = func_source.contains("keccak") &&
            (func_source.contains("chainid") || func_source.contains("chain_id"));

        if !validates_chain && !in_hash {
            Some((
                Severity::High,
                "Add chain-ID validation: require(message.destinationChainId == block.chainid); \
                 OR include chain-ID in message hash".to_string()
            ))
        } else if !validates_chain && in_hash {
            Some((
                Severity::Medium,
                "Add runtime validation: require(message.destinationChainId == block.chainid);".to_string()
            ))
        } else {
            None
        }
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
                // Remove everything after // to strip single-line comments
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

impl Default for ChainIdValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ChainIdValidationDetector {
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

        if !self.is_bridge_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some((severity, remediation)) = self.check_function(function, ctx) {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    format!("Missing chain-ID validation in '{}'", function.name.name),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    severity,
                )
                .with_fix_suggestion(remediation);

                findings.push(finding);
            }
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
        let detector = ChainIdValidationDetector::new();
        assert_eq!(detector.name(), "Missing Chain-ID Validation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert!(detector.categories().contains(&DetectorCategory::CrossChain));
    }
}
