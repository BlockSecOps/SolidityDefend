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

        let source = &ctx.source_code.to_lowercase();

        let validates_chain = (source.contains("chainid") || source.contains("chain.id")) &&
            (source.contains("==") || source.contains("require"));

        let in_hash = source.contains("keccak") && source.contains("chainid");

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
