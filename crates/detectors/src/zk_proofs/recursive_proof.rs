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

        // FP Reduction: Use per-contract source, not full-file source.
        // In multi-contract files, ctx.source_code is the full file, so ALL contracts
        // would match if ANY contract has ZK keywords.
        let contract_source = crate::utils::get_contract_source(ctx);
        let lower = contract_source.to_lowercase();

        // Require strong ZK proof context.
        // "aggregate" + "verify" is too generic — matches DeFi oracle aggregation,
        // signature aggregation, batch operations. Require ZK-specific keywords.
        let has_strong_zk_context = lower.contains("snark")
            || lower.contains("groth16")
            || lower.contains("plonk")
            || lower.contains("circuit")
            || lower.contains("zkproof")
            || lower.contains("zk_proof")
            || lower.contains("zk proof");

        // "aggregate" only counts as ZK if combined with strong ZK context
        let has_proof_aggregate = lower.contains("aggregate")
            && has_strong_zk_context
            && !lower.contains("aggregatedprice")
            && !lower.contains("aggregatesignature")
            && !lower.contains("aggregateslippage");

        // Function-level check: require ZK proof function names IN THIS contract
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let has_zk_proof_fn = contract_func_names.iter().any(|n| {
            n.contains("verifyproof")
                || n.contains("verify_proof")
                || n.contains("batchverify")
                || n.contains("recursiveproof")
                || n.contains("recursive_proof")
                || n.contains("aggregateproof")
                || n.contains("aggregate_proof")
                || n.contains("verifyrecursive")
                || n.contains("verify_recursive")
        });

        let is_recursive = (lower.contains("recursiveproof") || lower.contains("recursive_proof"))
            || (has_proof_aggregate && has_zk_proof_fn)
            || (lower.contains("batchverify") && has_zk_proof_fn);

        // Require at least one ZK-related function in THIS contract
        if !has_zk_proof_fn {
            return Ok(findings);
        }

        if !is_recursive {
            return Ok(findings);
        }

        // Pattern 1: Batch proof verification without individual validation
        if lower.contains("batchverify") || has_proof_aggregate {
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
