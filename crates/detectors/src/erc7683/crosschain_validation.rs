//! ERC-7683 Cross-Chain Validation Detector
//!
//! Detects missing or weak cross-chain message validation in intent-based systems.

use anyhow::Result;
use std::any::Any;

use super::classification::is_intent_contract;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct IntentCrossChainValidationDetector {
    base: BaseDetector,
}

impl IntentCrossChainValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7683-crosschain-validation".to_string()),
                "ERC-7683 Cross-Chain Validation".to_string(),
                "Detects missing cross-chain message validation in intent settlement contracts"
                    .to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::Critical,
            ),
        }
    }
}

impl Default for IntentCrossChainValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for IntentCrossChainValidationDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        if !is_intent_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check for cross-chain indicators
        let is_crosschain = source_lower.contains("originchainid")
            || source_lower.contains("destinationchainid")
            || source_lower.contains("crosschain");

        if !is_crosschain {
            return Ok(findings);
        }

        // Check for proper chain ID validation
        let has_chain_validation = source_lower.contains("require")
            && source_lower.contains("chainid")
            && (source_lower.contains("==") || source_lower.contains("!="));

        if !has_chain_validation {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Missing cross-chain ID validation - intents can be replayed on wrong chains"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::Critical,
                )
                .with_fix_suggestion(
                    "Add chain ID validation:\n\
                 \n\
                 function settle(\n\
                     CrossChainOrder calldata order,\n\
                     bytes calldata originProof\n\
                 ) external {\n\
                     // ✅ Validate origin chain\n\
                     require(\n\
                         order.originChainId == EXPECTED_ORIGIN_CHAIN,\n\
                         \"Invalid origin chain\"\n\
                     );\n\
                     \n\
                     // ✅ Validate destination matches current chain\n\
                     require(\n\
                         order.destinationChainId == block.chainid,\n\
                         \"Wrong destination chain\"\n\
                     );\n\
                     \n\
                     // ✅ Verify cross-chain proof\n\
                     require(\n\
                         _verifyMerkleProof(originProof, order),\n\
                         \"Invalid proof\"\n\
                     );\n\
                     \n\
                     // Process settlement...\n\
                 }"
                    .to_string(),
                );
            findings.push(finding);
        }

        // Check for message proof verification
        let has_proof_verification = source_lower.contains("proof")
            && (source_lower.contains("verify") || source_lower.contains("merkle"));

        if is_crosschain && !has_proof_verification {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Missing cross-chain message proof verification - untrusted origin data"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Add Merkle proof verification:\n\
                 \n\
                 function _verifyMerkleProof(\n\
                     bytes32[] calldata proof,\n\
                     bytes32 leaf\n\
                 ) internal view returns (bool) {\n\
                     bytes32 computedHash = leaf;\n\
                     \n\
                     for (uint256 i = 0; i < proof.length; i++) {\n\
                         computedHash = _hashPair(computedHash, proof[i]);\n\
                     }\n\
                     \n\
                     return computedHash == merkleRoot;\n\
                 }"
                    .to_string(),
                );
            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
