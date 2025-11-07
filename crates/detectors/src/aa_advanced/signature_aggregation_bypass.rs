//! AA Signature Aggregation Bypass Detector
//!
//! Detects signature aggregation vulnerabilities where batch operations can be
//! executed without proper validation of all signatures in the aggregated batch.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct AASignatureAggregationBypassDetector {
    base: BaseDetector,
}

impl AASignatureAggregationBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-signature-aggregation-bypass".to_string()),
                "AA Signature Aggregation Bypass".to_string(),
                "Detects signature aggregation vulnerabilities in batch UserOperations".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Default for AASignatureAggregationBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AASignatureAggregationBypassDetector {
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

        // Check for signature aggregator implementation
        let is_aggregator = lower.contains("iaggregator")
            || lower.contains("aggregatesignatures")
            || lower.contains("validatesignatures");

        if !is_aggregator {
            return Ok(findings);
        }

        // Pattern 1: Batch validation without individual signature checks
        let has_batch_validate =
            lower.contains("validatesignatures") || lower.contains("aggregatesignatures");

        if has_batch_validate {
            let has_loop =
                lower.contains("for (") || lower.contains("for(") || lower.contains("while");

            let has_individual_verify = lower.contains("verify")
                && (lower.contains("signature") || lower.contains("ecrecover"));

            if !has_loop || !has_individual_verify {
                let finding = self.base.create_finding(
                    ctx,
                    "Batch signature validation lacks individual signature verification - partial validation bypass possible".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate each UserOp signature individually in a loop before batch acceptance".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Missing array length validation
        if has_batch_validate {
            let has_length_check = (lower.contains("userops.length")
                || lower.contains("signatures.length"))
                && (lower.contains("require(") || lower.contains("if ("));

            if !has_length_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Aggregator lacks UserOps/signatures length validation - mismatch can bypass validation".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Require userOps.length == signatures.length before processing batch".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Signature aggregation without unique operation IDs
        if is_aggregator {
            let has_operation_id = lower.contains("operationid")
                || lower.contains("opid")
                || lower.contains("userophis")
                || lower.contains("keccak256(abi.encode(userop");

            if !has_operation_id {
                let finding = self.base.create_finding(
                    ctx,
                    "Aggregated operations lack unique IDs - signature reuse across operations possible".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Generate unique operation ID for each UserOp: keccak256(abi.encode(userOp, nonce, chainId))".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Batch execution without failure handling
        let has_batch_execute = lower.contains("handleops")
            || lower.contains("executebatch")
            || (lower.contains("for (") && lower.contains("execute"));

        if has_batch_execute {
            let has_error_handling = lower.contains("try")
                || lower.contains("catch")
                || (lower.contains("success") && lower.contains("bool"));

            if !has_error_handling {
                let finding = self.base.create_finding(
                    ctx,
                    "Batch execution lacks error handling - one failed op can revert entire batch revealing valid signatures".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use try-catch for each operation in batch; don't revert entire batch on single failure".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: No duplicate UserOp detection
        if has_batch_validate {
            let has_duplicate_check = lower.contains("seen[")
                || lower.contains("processed[")
                || lower.contains("mapping")
                || lower.contains("set");

            if !has_duplicate_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Aggregator lacks duplicate UserOp detection - same operation can be included multiple times in batch".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Track processed UserOp hashes: mapping(bytes32 => bool) processedOps; prevent duplicates in batch".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 6: Aggregated signature without timestamp/expiry
        if is_aggregator {
            let has_timestamp = lower.contains("timestamp")
                || lower.contains("deadline")
                || lower.contains("expiry")
                || lower.contains("validuntil");

            if !has_timestamp {
                let finding = self.base.create_finding(
                    ctx,
                    "Aggregated signatures lack expiry timestamp - old signatures can be replayed indefinitely".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Include validUntil timestamp in aggregated signature data; reject expired batches".to_string()
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
