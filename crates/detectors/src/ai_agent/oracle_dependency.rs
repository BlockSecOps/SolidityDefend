//! Autonomous Contract Oracle Dependency Detector

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use anyhow::Result;
use std::any::Any;

pub struct AutonomousContractOracleDependencyDetector {
    base: BaseDetector,
}

impl AutonomousContractOracleDependencyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("autonomous-contract-oracle-dependency".to_string()),
                "Autonomous Contract Oracle Dependency".to_string(),
                "Detects oracle dependency creating single point of failure".to_string(),
                vec![DetectorCategory::Oracle],
                Severity::Medium,
            ),
        }
    }
}

impl Default for AutonomousContractOracleDependencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AutonomousContractOracleDependencyDetector {
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

        if lower.contains("autonomous") || lower.contains("autoexecute") {
            let oracle_count = lower.matches("oracle").count() + lower.matches("chainlink").count();
            let has_fallback = lower.contains("fallback") || lower.contains("backup");

            if oracle_count == 1 && !has_fallback {
                findings.push(
                    self.base
                        .create_finding(
                            ctx,
                            "Autonomous contract depends on single oracle - SPOF risk".to_string(),
                            1,
                            1,
                            ctx.source_code.len() as u32,
                        )
                        .with_fix_suggestion(
                            "Add fallback oracle: if (primaryOracle.isDown()) use backupOracle"
                                .to_string(),
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
