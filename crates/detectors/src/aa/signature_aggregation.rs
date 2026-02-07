//! AA Signature Aggregation Detector
//!
//! Detects vulnerabilities in ERC-4337 signature aggregation:
//! 1. No aggregator validation
//! 2. Missing signature count verification
//! 3. No signer deduplication
//! 4. Threshold bypass via aggregation

use anyhow::Result;
use std::any::Any;

use crate::aa::classification::*;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct AASignatureAggregationDetector {
    base: BaseDetector,
}

impl AASignatureAggregationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-signature-aggregation".to_string()),
                "AA Signature Aggregation Bypass".to_string(),
                "Detects vulnerabilities in signature aggregation allowing threshold bypass"
                    .to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Default for AASignatureAggregationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AASignatureAggregationDetector {
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


        if !uses_signature_aggregation(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let func_name = function.name.name.to_lowercase();

            if func_name.contains("aggregate") || func_name.contains("multisig") {
                let line = function.name.location.start().line() as u32;

                // Check 1: Aggregator validation
                if !validates_aggregator(function, ctx) {
                    findings.push(self.base.create_finding_with_severity(
                        ctx,
                        format!("'{}' - no aggregator validation, untrusted aggregator can be used", function.name.name),
                        line, 0, 20,
                        Severity::Medium,
                    ).with_fix_suggestion("Add trusted aggregator whitelist".to_string()));
                }

                // Check 2: Signature count
                if !checks_signature_count(function, ctx) {
                    findings.push(self.base.create_finding_with_severity(
                        ctx,
                        format!("'{}' - no signature count verification, threshold can be bypassed", function.name.name),
                        line, 0, 20,
                        Severity::High,
                    ).with_fix_suggestion("Require signers.length >= THRESHOLD".to_string()));
                }

                // Check 3: Signer deduplication
                if !checks_signer_uniqueness(function, ctx) {
                    findings.push(self.base.create_finding_with_severity(
                        ctx,
                        format!("'{}' - no signer deduplication, same signer can be counted multiple times", function.name.name),
                        line, 0, 20,
                        Severity::Medium,
                    ).with_fix_suggestion("Add duplicate signer check (nested loop or seen mapping)".to_string()));
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
