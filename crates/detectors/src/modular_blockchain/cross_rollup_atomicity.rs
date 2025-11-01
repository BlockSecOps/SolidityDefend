//! Cross-Rollup Atomicity Detector

use anyhow::Result;
use std::any::Any;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct CrossRollupAtomicityDetector {
    base: BaseDetector,
}

impl CrossRollupAtomicityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("cross-rollup-atomicity".to_string()),
                "Cross-Rollup Atomicity".to_string(),
                "Detects cross-rollup atomic operation issues".to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::Critical,
            ),
        }
    }
}

impl Default for CrossRollupAtomicityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CrossRollupAtomicityDetector {
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

        if lower.contains("crossrollup") || lower.contains("crosschain") {
            if !lower.contains("atomic") && !lower.contains("lock") {
                findings.push(self.base.create_finding(
                    ctx,
                    "Cross-rollup operation lacks atomicity guarantee - partial execution possible".to_string(),
                    1, 1, ctx.source_code.len() as u32,
                ).with_fix_suggestion("Implement two-phase commit or rollback mechanism".to_string()));
            }
        }
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
