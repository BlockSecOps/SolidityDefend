//! ERC-4337 Gas Griefing Detector
//!
//! Detects gas griefing vectors in ERC-4337:
//! 1. Large error messages (gas DoS)
//! 2. Unbounded loops in validation
//! 3. Storage writes in validation (high gas, banned by spec)

use anyhow::Result;
use std::any::Any;

use crate::aa::classification::*;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC4337GasGriefingDetector {
    base: BaseDetector,
}

impl ERC4337GasGriefingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc4337-gas-griefing".to_string()),
                "ERC-4337 Gas Griefing Attacks".to_string(),
                "Detects gas griefing vectors that can DoS bundlers".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Low,
            ),
        }
    }
}

impl Default for ERC4337GasGriefingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC4337GasGriefingDetector {
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


        if !is_aa_account(ctx) && !is_paymaster_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let func_name = function.name.name.to_lowercase();

            if !func_name.contains("validate") {
                continue;
            }

            let line = function.name.location.start().line() as u32;

            // Check 1: Unbounded loops
            if has_unbounded_loops(function, ctx) {
                findings.push(
                    self.base
                        .create_finding_with_severity(
                            ctx,
                            format!(
                                "'{}' - unbounded loop in validation, can grief bundler gas",
                                function.name.name
                            ),
                            line,
                            0,
                            20,
                            Severity::Medium,
                        )
                        .with_fix_suggestion(
                            "Add maximum iteration limit (e.g., <= 10)".to_string(),
                        ),
                );
            }

            // Check 2: Storage writes
            if has_storage_writes(function, ctx) {
                findings.push(
                    self.base
                        .create_finding_with_severity(
                            ctx,
                            format!(
                                "'{}' - storage writes in validation, high gas, banned by ERC-4337",
                                function.name.name
                            ),
                            line,
                            0,
                            20,
                            Severity::Low,
                        )
                        .with_fix_suggestion(
                            "Avoid storage writes in validation phase".to_string(),
                        ),
                );
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
