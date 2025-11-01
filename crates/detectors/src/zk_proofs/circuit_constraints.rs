//! ZK Circuit Under-Constrained Detector
//!
//! Detects under-constrained ZK circuits where missing constraints allow
//! invalid proofs to be accepted.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ZKCircuitUnderConstrainedDetector {
    base: BaseDetector,
}

impl ZKCircuitUnderConstrainedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("zk-circuit-under-constrained".to_string()),
                "ZK Circuit Under-Constrained".to_string(),
                "Detects under-constrained ZK circuits with missing constraints".to_string(),
                vec![DetectorCategory::ZKRollup],
                Severity::Critical,
            ),
        }
    }
}

impl Default for ZKCircuitUnderConstrainedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ZKCircuitUnderConstrainedDetector {
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

        let is_zk_system = lower.contains("circuit")
            || lower.contains("constraint")
            || lower.contains("r1cs");

        if !is_zk_system {
            return Ok(findings);
        }

        // Pattern 1: Public inputs without range constraints
        if lower.contains("publicinput") {
            let has_range_check = lower.contains("require")
                && (lower.contains("<") || lower.contains(">") || lower.contains("<="));

            if !has_range_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Public inputs lack range constraints - circuit under-constrained".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add range constraints: require(publicInput < FIELD_SIZE, \"Input out of range\")".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No input validation for proof
        if lower.contains("verifyproof") {
            let validates_inputs = lower.contains("require(")
                || lower.contains("assert(");

            if !validates_inputs {
                let finding = self.base.create_finding(
                    ctx,
                    "Proof verification without input validation - under-constrained circuit risk".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate all public inputs before proof verification".to_string()
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
