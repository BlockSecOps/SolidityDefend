//! EIP-7702 tx.origin Bypass Detector
//!
//! Detects contracts assuming tx.origin == msg.sender which breaks with EIP-7702 delegation.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct EIP7702TxOriginBypassDetector {
    base: BaseDetector,
}

impl EIP7702TxOriginBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("eip7702-txorigin-bypass".to_string()),
                "EIP-7702 tx.origin Bypass".to_string(),
                "Detects tx.origin authentication that fails with EIP-7702 delegation".to_string(),
                vec![DetectorCategory::Auth],
                Severity::High,
            ),
        }
    }
}

impl Default for EIP7702TxOriginBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EIP7702TxOriginBypassDetector {
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
        let source_lower = ctx.source_code.to_lowercase();

        if source_lower.contains("tx.origin") {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "tx.origin usage breaks with EIP-7702 delegation".to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "EIP-7702 breaks tx.origin assumptions:\n\
                 \n\
                 Before: tx.origin == msg.sender for EOAs\n\
                 After EIP-7702: tx.origin != msg.sender (msg.sender is delegate)\n\
                 \n\
                 Fix: Use msg.sender instead:\n\
                 require(msg.sender == owner, \"Not owner\");"
                        .to_string(),
                );
            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
