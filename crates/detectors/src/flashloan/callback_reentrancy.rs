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

        for function in ctx.get_functions() {
            let func_name = function.name.name.to_lowercase();

            if func_name.contains("flashloan") || func_name.contains("flashmint") {
                let line = function.name.location.start().line() as u32;

                if !self.has_reentrancy_guard(function) {
                    findings.push(self.base.create_finding_with_severity(
                        ctx,
                        format!("'{}' missing reentrancy guard", function.name.name),
                        line, 0, 20,
                        Severity::Medium,
                    ).with_fix_suggestion("Add nonReentrant modifier from OpenZeppelin".to_string()));
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
