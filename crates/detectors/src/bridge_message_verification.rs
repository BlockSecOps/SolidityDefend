//! Bridge Message Verification Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

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

    fn check_function(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let name = function.name.name.to_lowercase();

        if !name.contains("process") && !name.contains("execute") && !name.contains("receive") && !name.contains("relay") {
            return issues;
        }

        let source = &ctx.source_code.to_lowercase();

        let has_sig = source.contains("ecrecover") || (source.contains("verify") && source.contains("sig"));
        let has_merkle = source.contains("merkle") && (source.contains("verify") || source.contains("proof"));
        let has_replay = source.contains("processed") || source.contains("executed") || source.contains("used");

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
                "Add: require(!processedMessages[msgHash]); processedMessages[msgHash] = true;".to_string()
            ));
        }

        issues
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
                let finding = self.base.create_finding_with_severity(ctx, title, function.name.location.start().line() as u32, 0, 20, severity)
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
