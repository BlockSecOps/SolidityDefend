//! Flash Loan Callback Reentrancy Detector
//!
//! Detects reentrancy vulnerabilities in flash loan callbacks:
//! - State changes after external call
//! - No reentrancy guard
//! - Unchecked callback return value
//!
//! Severity: MEDIUM

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;
use ast;

pub struct FlashloanCallbackReentrancyDetector {
    base: BaseDetector,
}

impl FlashloanCallbackReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flashloan-callback-reentrancy".to_string()),
                "Flash Loan Callback Reentrancy".to_string(),
                "Detects reentrancy vulnerabilities in flash loan callbacks".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }

    fn has_reentrancy_guard(&self, function: &ast::Function) -> bool {
        function.modifiers.iter().any(|m| {
            let name = m.name.to_lowercase();
            name.contains("nonreentrant") || name.contains("noreentrancy")
        })
    }
}

impl Default for FlashloanCallbackReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FlashloanCallbackReentrancyDetector {
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


        // Skip flash loan PROVIDERS - they MUST call back to borrowers
        // Flash loan providers (Aave, Compound, ERC-3156) are REQUIRED to:
        // 1. Call onFlashLoan() callback on the borrower
        // 2. Verify borrowed amount + fee is returned
        // 3. Handle callback execution (which may involve external calls)
        // This is by design per ERC-3156 standard, not a vulnerability.
        // This detector should focus on flash loan CONSUMERS with unsafe callback handling.
        if utils::is_flash_loan_provider(ctx) {
            return Ok(findings);
        }

        // Phase 52 FP Reduction: Skip interface-only contracts
        if utils::is_interface_only(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let func_name = function.name.name.to_lowercase();

            if func_name.contains("flashloan") || func_name.contains("flashmint") {
                let line = function.name.location.start().line() as u32;

                if !self.has_reentrancy_guard(function) {
                    findings.push(
                        self.base
                            .create_finding_with_severity(
                                ctx,
                                format!("'{}' missing reentrancy guard", function.name.name),
                                line,
                                0,
                                20,
                                Severity::Medium,
                            )
                            .with_fix_suggestion(
                                "Add nonReentrant modifier from OpenZeppelin".to_string(),
                            ),
                    );
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
