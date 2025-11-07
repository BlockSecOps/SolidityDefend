//! Cross-Chain Message Ordering Detector

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use anyhow::Result;
use std::any::Any;

pub struct CrossChainMessageOrderingDetector {
    base: BaseDetector,
}

impl CrossChainMessageOrderingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("cross-chain-message-ordering".to_string()),
                "Cross-Chain Message Ordering".to_string(),
                "Detects message ordering issues across chains".to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::High,
            ),
        }
    }
}

impl Default for CrossChainMessageOrderingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CrossChainMessageOrderingDetector {
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
        let lower = ctx.source_code.to_lowercase();

        if (lower.contains("relayer") || lower.contains("crosschain"))
            && !lower.contains("sequence")
            && !lower.contains("nonce")
        {
            findings.push(
                self.base
                    .create_finding(
                        ctx,
                        "Cross-chain messages lack sequence/nonce - ordering not guaranteed"
                            .to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Add sequence number: mapping(bytes32 => uint256) public messageNonce"
                            .to_string(),
                    ),
            );
        }
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
