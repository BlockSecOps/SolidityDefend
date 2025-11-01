//! ZK Trusted Setup Bypass Detector
//!
//! Detects compromised or missing trusted setup validation in ZK systems.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ZKTrustedSetupBypassDetector {
    base: BaseDetector,
}

impl ZKTrustedSetupBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("zk-trusted-setup-bypass".to_string()),
                "ZK Trusted Setup Bypass".to_string(),
                "Detects compromised trusted setup validation".to_string(),
                vec![DetectorCategory::ZKRollup],
                Severity::High,
            ),
        }
    }
}

impl Default for ZKTrustedSetupBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ZKTrustedSetupBypassDetector {
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

        let is_zk_system = lower.contains("verifyproof")
            || lower.contains("groth16")
            || lower.contains("trustedsetup");

        if !is_zk_system {
            return Ok(findings);
        }

        // Pattern 1: Verifier parameters hardcoded without validation
        if lower.contains("verifyingkey") || lower.contains("vk") {
            let validates_params = lower.contains("require")
                && (lower.contains("alpha") || lower.contains("beta"));

            if !validates_params {
                let finding = self.base.create_finding(
                    ctx,
                    "Verifying key parameters not validated - compromised setup could be used".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate verifying key against known hash: require(keccak256(vk) == EXPECTED_VK_HASH)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No ceremony validation
        if is_zk_system {
            let has_ceremony_check = lower.contains("ceremony")
                || lower.contains("participants")
                || lower.contains("setuphash");

            if !has_ceremony_check {
                let finding = self.base.create_finding(
                    ctx,
                    "No trusted setup ceremony validation - setup provenance unknown".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Document and validate setup ceremony: // Setup hash: 0x... from ceremony with N participants".to_string()
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
