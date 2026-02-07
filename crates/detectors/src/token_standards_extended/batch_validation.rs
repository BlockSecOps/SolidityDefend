//! ERC-1155 Batch Validation Detector
//!
//! Detects missing batch validation in ERC-1155 implementations.
//! Array length mismatches can lead to loss of funds or exploits.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC1155BatchValidationDetector {
    base: BaseDetector,
}

impl ERC1155BatchValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc1155-batch-validation".to_string()),
                "ERC-1155 Batch Validation".to_string(),
                "Detects missing batch validation in ERC-1155 implementations".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Default for ERC1155BatchValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC1155BatchValidationDetector {
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

        // Check for ERC-1155
        let is_erc1155 = lower.contains("ierc1155")
            || lower.contains("erc1155")
            || lower.contains("safebatchtransferfrom");

        if !is_erc1155 {
            return Ok(findings);
        }

        // Pattern 1: safeBatchTransferFrom without array length validation
        if lower.contains("safebatchtransferfrom") {
            let has_length_check = lower.contains("ids.length == amounts.length")
                || lower.contains("require(ids.length == amounts.length");

            if !has_length_check {
                let finding = self.base.create_finding(
                    ctx,
                    "safeBatchTransferFrom lacks array length validation - mismatch can cause incorrect transfers".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add validation: require(ids.length == amounts.length, \"Length mismatch\")".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: balanceOfBatch without validation
        if lower.contains("balanceofbatch") {
            let has_batch_validation = lower.contains("accounts.length == ids.length")
                || lower.contains("require(accounts.length");

            if !has_batch_validation {
                let finding = self.base.create_finding(
                    ctx,
                    "balanceOfBatch lacks array length validation - can return incorrect balances".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate arrays: require(accounts.length == ids.length, \"Array length mismatch\")".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Custom batch functions without empty array check
        let has_batch_function = lower.contains("function batch")
            || lower.contains("function multimint")
            || lower.contains("function multiburn");

        if has_batch_function {
            let checks_empty = lower.contains(".length > 0")
                || lower.contains(".length == 0")
                || lower.contains("require(length");

            if !checks_empty {
                let finding = self.base.create_finding(
                    ctx,
                    "Batch function doesn't check for empty arrays - may waste gas or cause unexpected behavior".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add empty check: require(ids.length > 0, \"Empty array\")".to_string()
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
