//! Sovereign Rollup Validation Detector

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use anyhow::Result;
use std::any::Any;

pub struct SovereignRollupValidationDetector {
    base: BaseDetector,
}

impl SovereignRollupValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("sovereign-rollup-validation".to_string()),
                "Sovereign Rollup Validation".to_string(),
                "Detects sovereign rollup state validation issues".to_string(),
                vec![DetectorCategory::L2],
                Severity::Medium,
            ),
        }
    }
}

impl Default for SovereignRollupValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SovereignRollupValidationDetector {
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

        if (lower.contains("sovereign") || lower.contains("statetransition"))
            && !lower.contains("validate")
        {
            findings.push(self.base.create_finding(
                    ctx,
                    "Sovereign rollup state transition not validated - invalid states possible".to_string(),
                    1, 1, ctx.source_code.len() as u32,
                ).with_fix_suggestion("Validate state transitions: require(validateStateTransition(oldState, newState))".to_string()));
        }
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
