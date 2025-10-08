//! Bridge Token Minting Access Control Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

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
                vec![DetectorCategory::CrossChain, DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }

    fn is_bridge_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        source.contains("bridge") || source.contains("relay") || source.contains("crosschain")
    }

    fn check_function(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let name = function.name.name.to_lowercase();

        if !name.contains("mint") && !name.contains("issue") {
            return issues;
        }

        let source = &ctx.source_code.to_lowercase();

        let has_access = source.contains("onlybridge") || source.contains("onlyowner") ||
            source.contains("onlyrole") || source.contains("require(msg.sender");

        let validates_message = source.contains("verify") && (source.contains("message") || source.contains("proof") || source.contains("signature"));

        let has_limits = source.contains("max") && source.contains("amount");

        if !has_access {
            issues.push((
                format!("Unrestricted token minting in '{}'", function.name.name),
                Severity::Critical,
                "Add access control: modifier onlyBridge { require(msg.sender == bridge); _; }".to_string()
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
                "Add: require(amount <= MAX_MINT_AMOUNT);".to_string()
            ));
        }

        issues
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
