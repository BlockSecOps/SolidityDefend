//! Optimistic Fraud Proof Timing Detector

use anyhow::Result;
use std::any::Any;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct OptimisticFraudProofTimingDetector {
    base: BaseDetector,
}

impl OptimisticFraudProofTimingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("optimistic-fraud-proof-timing".to_string()),
                "Optimistic Fraud Proof Timing".to_string(),
                "Detects fraud proof timing issues".to_string(),
                vec![DetectorCategory::L2],
                Severity::High,
            ),
        }
    }
}

impl Default for OptimisticFraudProofTimingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for OptimisticFraudProofTimingDetector {
    fn id(&self) -> DetectorId { self.base.id.clone() }
    fn name(&self) -> &str { &self.base.name }
    fn description(&self) -> &str { &self.base.description }
    fn categories(&self) -> Vec<DetectorCategory> { self.base.categories.clone() }
    fn default_severity(&self) -> Severity { self.base.default_severity }
    fn is_enabled(&self) -> bool { self.base.enabled }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lower = ctx.source_code.to_lowercase();

        if lower.contains("challengeperiod") || lower.contains("fraudproof") {
            if !lower.contains("require(block.timestamp") {
                findings.push(self.base.create_finding(
                    ctx,
                    "Challenge period not enforced - fraud proofs may be bypassed".to_string(),
                    1, 1, ctx.source_code.len() as u32,
                ).with_fix_suggestion("Enforce challenge period: require(block.timestamp >= startTime + CHALLENGE_PERIOD)".to_string()));
            }
        }
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any { self }
}
