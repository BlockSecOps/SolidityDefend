//! Bridge Message Verification Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct MessageVerificationDetector {
    base: BaseDetector,
}

impl MessageVerificationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("bridge-message-verification".to_string()),
                "Bridge Message Verification".to_string(),
                "Detects missing message verification in bridge contracts".to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::Critical,
            ),
        }
    }

    fn is_bridge_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        source.contains("bridge") || source.contains("relay")
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let name = function.name.name.to_lowercase();

        if !name.contains("process")
            && !name.contains("execute")
            && !name.contains("receive")
            && !name.contains("relay")
        {
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

        let has_sig = func_source.contains("ecrecover")
            || (func_source.contains("verify") && func_source.contains("sig"));
        let has_merkle = func_source.contains("merkle")
            && (func_source.contains("verify") || func_source.contains("proof"));

        // Check for replay protection more specifically - look for mapping/array access patterns
        // Need to be more specific than just "executed" + "[" because that matches:
        // - Event names like "emit MessageExecuted(...)"
        // - Array parameters like "bytes32[] calldata proof"
        // We want actual state variable access like "processedMessages[hash]"
        let has_replay =
            // Specific mapping names
            func_source.contains("processedmessages[") ||
            func_source.contains("executedmessages[") ||
            func_source.contains("usedmessages[") ||
            func_source.contains("processednonces[") ||
            func_source.contains("usednonces[") ||
            // Generic pattern: "processed" or "used" followed by "[" within reasonable distance
            // But not "emit SomethingExecuted" - check for actual state variable patterns
            (func_source.contains("processed[") ||
             func_source.contains("used[") ||
             func_source.contains("nonces["));

        if !has_sig && !has_merkle {
            issues.push((
                format!("Missing message verification in '{}'", function.name.name),
                Severity::Critical,
                "Add verification: require(verifyMerkleProof(root, proof, leaf) OR ecrecover(hash, v, r, s) == signer);".to_string()
            ));
        }

        if (has_sig || has_merkle) && !has_replay {
            issues.push((
                format!("Missing replay protection in '{}'", function.name.name),
                Severity::Critical,
                "Add: require(!processedMessages[msgHash]); processedMessages[msgHash] = true;"
                    .to_string(),
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

impl Default for MessageVerificationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MessageVerificationDetector {
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
        let detector = MessageVerificationDetector::new();
        assert_eq!(detector.name(), "Bridge Message Verification");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::CrossChain)
        );
    }
}
