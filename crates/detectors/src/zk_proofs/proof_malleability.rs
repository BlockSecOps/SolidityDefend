//! ZK Proof Malleability Detector
//!
//! Detects proof malleability attacks where proofs can be modified while
//! remaining valid, allowing unauthorized operations.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ZKProofMalleabilityDetector {
    base: BaseDetector,
}

impl ZKProofMalleabilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("zk-proof-malleability".to_string()),
                "ZK Proof Malleability".to_string(),
                "Detects proof malleability attacks in ZK systems".to_string(),
                vec![DetectorCategory::ZKRollup],
                Severity::Critical,
            ),
        }
    }
}

impl Default for ZKProofMalleabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ZKProofMalleabilityDetector {
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

        // Check for ZK proof verification
        let is_zk_system = lower.contains("verifyproof")
            || lower.contains("zkproof")
            || lower.contains("snark")
            || lower.contains("plonk")
            || lower.contains("groth16");

        if !is_zk_system {
            return Ok(findings);
        }

        // Pattern 1: Proof verification without uniqueness check
        if lower.contains("verifyproof") {
            let checks_uniqueness = lower.contains("proofhash")
                || lower.contains("commitment")
                || lower.contains("nonce");

            if !checks_uniqueness {
                let finding = self.base.create_finding(
                    ctx,
                    "Proof verification lacks uniqueness check - same proof can be reused multiple times".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Include unique identifier in proof: require(!usedProofs[proofHash], \"Proof already used\")".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No binding to specific transaction
        if is_zk_system {
            let binds_to_tx = lower.contains("msg.sender")
                || lower.contains("tx.origin")
                || lower.contains("publicinput");

            if !binds_to_tx {
                let finding = self.base.create_finding(
                    ctx,
                    "ZK proof not bound to specific caller - proof can be replayed by different users".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Include msg.sender in public inputs: verifyProof(proof, [msg.sender, ...otherInputs])".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Missing signature over proof
        if lower.contains("verifyproof") {
            let has_signature = lower.contains("signature") || lower.contains("ecrecover");

            if !has_signature {
                let finding = self.base.create_finding(
                    ctx,
                    "No signature requirement over ZK proof - malleability via proof modification".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Require signature over proof hash: bytes32 proofHash = keccak256(proof); verify signature".to_string()
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
