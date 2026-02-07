//! AI Agent Decision Manipulation Detector

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use anyhow::Result;
use std::any::Any;

pub struct AIAgentDecisionManipulationDetector {
    base: BaseDetector,
}

impl AIAgentDecisionManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("ai-agent-decision-manipulation".to_string()),
                "AI Agent Decision Manipulation".to_string(),
                "Detects AI decision manipulation via oracle/input poisoning".to_string(),
                vec![DetectorCategory::Oracle],
                Severity::High,
            ),
        }
    }
}

impl Default for AIAgentDecisionManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AIAgentDecisionManipulationDetector {
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

        if lower.contains("aidecision")
            || lower.contains("aiagent")
            || lower.contains("autonomousaction")
        {
            let has_input_validation = lower.contains("validate") || lower.contains("verify");
            let has_consensus = lower.contains("consensus") || lower.contains("multisig");

            if !has_input_validation && !has_consensus {
                findings.push(self.base.create_finding(
                    ctx,
                    "AI agent decisions lack input validation and consensus - manipulation possible".to_string(),
                    1, 1, ctx.source_code.len() as u32,
                ).with_fix_suggestion("Add multi-oracle consensus: require(consensusReached(oracleData, threshold))".to_string()));
            }
        }
        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
