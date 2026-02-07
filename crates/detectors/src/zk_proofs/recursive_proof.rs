//! ZK Recursive Proof Validation Detector
//!
//! Detects recursive proof validation issues in proof aggregation systems.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ZKRecursiveProofValidationDetector {
    base: BaseDetector,
}

impl ZKRecursiveProofValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("zk-recursive-proof-validation".to_string()),
                "ZK Recursive Proof Validation".to_string(),
                "Detects recursive proof validation issues".to_string(),
                vec![DetectorCategory::ZKRollup],
                Severity::High,
            ),
        }
    }
}

impl Default for ZKRecursiveProofValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ZKRecursiveProofValidationDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let lower = ctx.source_code.to_lowercase();

        let is_recursive = lower.contains("recursiveproof")
            || lower.contains("aggregate")
            || lower.contains("batchverify");

        if !is_recursive {
            return Ok(findings);
        }

        // Pattern 1: Batch proof verification without individual validation
        if lower.contains("batchverify") || lower.contains("aggregate") {
            let validates_each = lower.contains("for (") || lower.contains("while");

            if !validates_each {
                let finding = self.base.create_finding(
                    ctx,
                    "Batch proof verification without individual validation - malicious proof can poison batch".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate each proof individually before aggregation or use proper aggregation scheme".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No depth limit on recursion
        if is_recursive {
            let has_depth_check = lower.contains("depth")
                || lower.contains("level")
                || lower.contains("maxrecursion");

            if !has_depth_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Recursive proof without depth limit - DOS via excessive recursion".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add recursion depth limit: require(depth <= MAX_DEPTH, \"Recursion too deep\")".to_string()
                );

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
