//! AA User Operation Replay Detector
//!
//! Detects UserOperation replay vulnerabilities across bundlers and chains.
//! Prevents double-spending and cross-chain replay attacks.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::{cross_chain_patterns, modern_eip_patterns};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct AAUserOperationReplayDetector {
    base: BaseDetector,
}

impl AAUserOperationReplayDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-user-operation-replay".to_string()),
                "AA User Operation Replay".to_string(),
                "Detects UserOperation replay across bundlers and chains".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Default for AAUserOperationReplayDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AAUserOperationReplayDetector {
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

        // Check for AA wallet or EntryPoint
        let is_aa_contract = lower.contains("useroperation")
            || lower.contains("validateuserop")
            || lower.contains("handleops")
            || lower.contains("entrypoint");

        if !is_aa_contract {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Safe pattern detection with dynamic confidence

        // Level 1: Strong AA/meta-tx patterns (return early)
        if modern_eip_patterns::has_safe_metatx_pattern(ctx) {
            // Safe meta-tx pattern includes comprehensive nonce tracking and replay protection
            return Ok(findings);
        }

        // Level 2: Cross-chain protection patterns
        if cross_chain_patterns::has_nonce_replay_protection(ctx) {
            // Nonce-based replay protection prevents user operation replay
            if cross_chain_patterns::has_chain_id_validation(ctx) {
                // Chain ID validation prevents cross-chain replay
                return Ok(findings);
            }
        }

        // Pattern 1: Missing nonce validation
        let has_validate = lower.contains("validateuserop");
        if has_validate {
            let has_nonce_check =
                lower.contains("nonce") && (lower.contains("require(") || lower.contains("if ("));

            if !has_nonce_check {
                let finding = self.base.create_finding(
                    ctx,
                    "UserOperation validation lacks nonce check - replay attacks possible".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate and increment nonce: require(userOp.nonce == currentNonce++, \"Invalid nonce\")".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No chain ID validation for cross-chain deployment
        if is_aa_contract {
            let has_chain_id = lower.contains("chainid") || lower.contains("block.chainid");

            if !has_chain_id {
                let finding = self.base.create_finding(
                    ctx,
                    "Contract lacks chain ID validation - UserOps can be replayed across chains".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Include chain ID in UserOp hash: keccak256(abi.encode(userOp, block.chainid))".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: UserOp hash doesn't include all fields
        let has_hash_function = lower.contains("getuserophash")
            || lower.contains("hashoperation")
            || lower.contains("_hashoperation");

        if has_hash_function {
            // Check if hash includes critical fields
            let includes_sender = lower.contains("userop.sender") || lower.contains("sender");
            let includes_nonce = lower.contains("userop.nonce") || lower.contains("nonce");
            let includes_calldata = lower.contains("userop.calldata") || lower.contains("calldata");

            if !includes_sender || !includes_nonce || !includes_calldata {
                let finding = self.base.create_finding(
                    ctx,
                    "UserOp hash missing critical fields (sender/nonce/calldata) - replay via field substitution".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Include all UserOp fields in hash: sender, nonce, initCode, callData, callGasLimit, etc.".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: No executed operations tracking
        if is_aa_contract {
            let has_executed_tracking = lower.contains("executed[")
                || lower.contains("processedops")
                || lower.contains("usedops")
                || lower.contains("mapping(bytes32 => bool)");

            if !has_executed_tracking {
                let finding = self.base.create_finding(
                    ctx,
                    "No tracking of executed UserOps - same operation can be submitted multiple times".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Track executed ops: mapping(bytes32 => bool) public executedOps; require(!executedOps[opHash])".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: Nonce implementation allows replay
        if has_validate {
            // Check for proper nonce increment
            let has_nonce_increment = lower.contains("nonce++")
                || lower.contains("nonce += 1")
                || lower.contains("_nonce++");

            let checks_nonce_value = lower.contains("nonce ==") || lower.contains("nonce >=");

            if checks_nonce_value && !has_nonce_increment {
                let finding = self.base.create_finding(
                    ctx,
                    "Nonce checked but not incremented - same nonce can be reused".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Increment nonce after validation: currentNonce++ or _nonce = userOp.nonce + 1".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 6: EntryPoint address not validated
        if is_aa_contract {
            let references_entrypoint =
                lower.contains("entrypoint") || lower.contains("_entrypoint");

            let validates_entrypoint = lower.contains("msg.sender == entrypoint")
                || lower.contains("onlyentrypoint")
                || lower.contains("require(msg.sender ==");

            if references_entrypoint && !validates_entrypoint {
                let finding = self.base.create_finding(
                    ctx,
                    "EntryPoint address not validated - UserOps can be submitted from unauthorized contracts".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate EntryPoint: require(msg.sender == entryPoint, \"Only EntryPoint\")".to_string()
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
