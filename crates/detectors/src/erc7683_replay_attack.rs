//! ERC-7683 Cross-Chain Replay Attack Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ReplayAttackDetector {
    base: BaseDetector,
}

impl ReplayAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7683-cross-chain-replay".to_string()),
                "ERC-7683 Cross-Chain Replay".to_string(),
                "Detects missing chain-ID validation enabling cross-chain replay attacks"
                    .to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::Critical,
            ),
        }
    }

    fn is_erc7683_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("fillorder") || source.contains("settle"))
            && (source.contains("crosschain") || source.contains("bridge"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<(Severity, String)> {
        let name = function.name.name.to_lowercase();
        if !name.contains("fill") && !name.contains("settle") {
            return None;
        }

        let source = &ctx.source_code.to_lowercase();

        let validates_chain = (source.contains("chainid") || source.contains("chain.id"))
            && (source.contains("==") || source.contains("require"));
        let in_hash = source.contains("keccak") && source.contains("chainid");
        let uses_domain_sep = source.contains("domain") && source.contains("separator");

        if !validates_chain && !in_hash && !uses_domain_sep {
            Some((
                Severity::Critical,
                "Add chain-ID validation: require(order.destinationChainId == block.chainid, \"Wrong chain\"); \
                 OR include chain-ID in signature hash".to_string()
            ))
        } else if !validates_chain && (in_hash || uses_domain_sep) {
            Some((
                Severity::High,
                "Add explicit chain-ID validation: require(order.destinationChainId == block.chainid);".to_string()
            ))
        } else {
            None
        }
    }
}

impl Default for ReplayAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ReplayAttackDetector {
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

        if !self.is_erc7683_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some((severity, remediation)) = self.check_function(function, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("Missing chain-ID validation in '{}'", function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                    .with_cwe(346) // CWE-346: Origin Validation Error
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
