//! Celestia Data Availability Detector
//!
//! Detects data availability layer issues in modular blockchain systems.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct CelestiaDataAvailabilityDetector {
    base: BaseDetector,
}

impl CelestiaDataAvailabilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("celestia-data-availability".to_string()),
                "Celestia Data Availability".to_string(),
                "Detects data availability issues in modular blockchains".to_string(),
                vec![DetectorCategory::DataAvailability],
                Severity::High,
            ),
        }
    }
}

impl Default for CelestiaDataAvailabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CelestiaDataAvailabilityDetector {
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

        let uses_da = lower.contains("celestia")
            || lower.contains("dataavailability")
            || lower.contains("blobdata");

        if !uses_da {
            return Ok(findings);
        }

        // Pattern 1: No DA proof verification
        if uses_da {
            let verifies_da = lower.contains("verifyda")
                || lower.contains("dataroot")
                || lower.contains("merkleproof");

            if !verifies_da {
                let finding = self.base.create_finding(
                    ctx,
                    "Data availability not verified - data may not be available on DA layer".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Verify DA proof: require(verifyDataRoot(dataRoot, proof), \"DA proof invalid\")".to_string()
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
